"""Egzekwowanie reguł firmowych: tożsamość → dostęp → użycie → detekcja → decyzja.

Moduł nie ma własnych ról. Każda decyzja dotyczy roli z config.ROLES, w imieniu której działa
użytkownik albo agent; treść zapytania nie może jej zmienić.
"""
import json
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Iterable, Optional

from security.company_policies.audit import DEFAULT_AUDIT_PATH, AuditLog, content_digest
from security.company_policies.detection import (
    Classifier, ClassifierError, Hit, detect_deterministic, detect_destination, detect_semantic,
    llm_classifier,
)
from security.company_policies.policy import (
    DEFAULT_DOCUMENTS_DIR, DEFAULT_FIXTURES_DIR, DEFAULT_RELOAD_INTERVAL, DEFAULT_RULES_PATH, Policy,
    PolicyStore, Rule,
)
from security.common.roles import normalize_role
from security.common.spans import replace_spans
from security.common.verdicts import Verdict

STAGE = "company_policies"
SEVERITY = {"log_only": 1, "warn": 2, "redact": 3, "block": 4}
DESTINATIONS = ("internal", "external_llm", "external_destination")
DESTINATION_LABELS = {
    "internal": "for this purpose",
    "external_llm": "to external AI models",
    "external_destination": "to external addresses and services",
}
# Ile ostatnich wyników klasyfikatora semantycznego trzymać. Ten sam tekst (np. ten sam wynik
# narzędzia albo powtórzone pytanie) nie jest drugi raz wysyłany do lokalnego modelu.
SEMANTIC_CACHE_SIZE = 512


def violation_type(rule: Rule, role: str, destination: str) -> Optional[str]:
    """"access", gdy rola nie może widzieć tych informacji; "usage", gdy może, ale nie w tym celu."""
    if not rule.role_allowed(role):
        return "access"
    usage = {
        "internal": rule.summarize_internal,
        "external_llm": rule.external_llm,
        "external_destination": rule.external_destinations,
    }[destination]
    return "usage" if usage == "block" else None


def redact(text: str, labelled_spans: list[tuple[int, int, str]]) -> str:
    """Zastępuje fragmenty znacznikiem [ZASTRZEŻONE: ID]; nachodzące na siebie fragmenty są scalane."""
    return replace_spans(text, [(start, end, f"[ZASTRZEŻONE: {label}]") for start, end, label in labelled_spans])


class CompanyPolicyEngine:
    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH, classifier: Classifier = llm_classifier,
                 audit_path: Optional[Path] = DEFAULT_AUDIT_PATH,
                 documents_dir: Path = DEFAULT_DOCUMENTS_DIR, fixtures_dir: Path = DEFAULT_FIXTURES_DIR,
                 reload_interval: float = DEFAULT_RELOAD_INTERVAL,
                 known_roles: Optional[Callable[[], Iterable[str]]] = None):
        self.audit = AuditLog(audit_path)
        self.store = PolicyStore(rules_path, on_event=self.audit.write, documents_dir=documents_dir,
                                 fixtures_dir=fixtures_dir, reload_interval=reload_interval,
                                 known_roles=known_roles)
        self.classifier = classifier
        self._semantic_cache: OrderedDict = OrderedDict()
        self._semantic_cache_policy: Optional[Policy] = None
        self._semantic_lock = threading.Lock()

    def status(self) -> dict:
        return self.store.status()

    # ----------------------------- punkty pipeline'u ------------------------

    def check_input(self, role: str, text: str, destination: Optional[str] = None,
                    model: Optional[str] = None) -> Verdict:
        """Prompt użytkownika. `destination` wykrywane z treści, jeśli nie podano; model spoza
        Allowed Models traktowany jest jak zewnętrzny."""
        return self._check("input", role, text, destination, model=model)

    def filter_context(self, role: str, text: str, source: Optional[str] = None,
                       model: Optional[str] = None) -> Verdict:
        """Treść pobrana do kontekstu (RAG, pamięć, wynik narzędzia) — sprawdzana PRZED przekazaniem modelowi."""
        return self._check("retrieval", role, text, "internal", model=model, source=source)

    def filter_documents(self, role: str, documents: dict[str, str],
                         model: Optional[str] = None) -> dict[str, str]:
        """Zostawia tylko dokumenty, które rola może przekazać do modelu (zamaskowane, jeśli trzeba)."""
        allowed = {}
        for name, text in documents.items():
            verdict = self.filter_context(role, text, source=name, model=model)
            if verdict.decision != "block":
                allowed[name] = verdict.details.get("redacted_text", text)
        return allowed

    def check_tool_call(self, role: str, tool: str, args: dict) -> Verdict:
        """Argumenty wywołania narzędzia; narzędzia z External Tools wysyłają dane poza firmę."""
        policy = self.store.get()
        destination = "external_destination" if policy and tool in policy.external_tools else None
        text = json.dumps(args, ensure_ascii=False, default=str)
        return self._check("tool", role, text, destination, source=tool)

    def check_output(self, role: str, text: str) -> Verdict:
        """Odpowiedź modelu dla użytkownika — model mógł ujawnić informację z kontekstu."""
        return self._check("output", role, text, "internal")

    # ----------------------------- decyzja ----------------------------------

    def _check(self, point: str, role: str, text: str, destination: Optional[str],
               model: Optional[str] = None, source: Optional[str] = None) -> Verdict:
        started = time.perf_counter()
        role = normalize_role(role)
        text = text or ""
        digest = content_digest(text)
        details = {"point": point, "role": role, "source": source}
        policy = self.store.get()

        if policy is None:
            verdict = Verdict("block", "Polityka firmowa jest niedostępna (błędny plik reguł) — fail-closed.",
                              STAGE, details, is_blocked=True)
            return self._finish(verdict, text, digest, started, {})
        details["policy_version"] = policy.version
        if not policy.enabled:
            return self._finish(Verdict("pass", "Moduł polityk firmowych jest wyłączony", STAGE, details),
                                text, digest, started, {})

        if destination not in DESTINATIONS:
            destination = detect_destination(policy, text) or "internal"
        if model is not None and model not in policy.allowed_models and destination == "internal":
            destination = "external_llm"
        details["destination"] = destination

        latency = {}
        t = time.perf_counter()
        hits = detect_deterministic(policy, text)
        latency["deterministic"] = _ms(t)

        detector_error, semantic_rules = None, []
        if not hits:
            semantic_rules = [r for r in policy.active_rules
                              if r.semantic_classifier and violation_type(r, role, destination)]
            if semantic_rules:  # klasyfikator tylko wtedy, gdy jego wynik może coś zmienić
                t = time.perf_counter()
                try:
                    hits, result, cached = self._classify(policy, text, digest)
                    details["semantic"] = {"category": result.get("category"),
                                           "confidence": result.get("confidence"), "cached": cached}
                except ClassifierError as e:
                    detector_error = str(e)
                latency["semantic"] = _ms(t)

        if detector_error:
            verdict = self._detector_error_verdict(detector_error, semantic_rules, details)
        else:
            violations = [(h, kind) for h in hits if (kind := violation_type(h.rule, role, destination))]
            details["matched_rules"] = [h.rule.id for h in hits]
            verdict = self._decide(policy, text, violations, details) if violations else Verdict(
                "pass", "Zgodne z regulaminami firmy", STAGE, details)
        return self._finish(verdict, text, digest, started, latency)

    def _classify(self, policy: Policy, text: str, digest: str) -> tuple[list[Hit], dict, bool]:
        """detect_semantic z pamięcią ostatnich wyników; błędy klasyfikatora nie są zapamiętywane."""
        with self._semantic_lock:
            if self._semantic_cache_policy is not policy:  # nowa wersja reguł = nowe kategorie i progi
                self._semantic_cache.clear()
                self._semantic_cache_policy = policy
            if (cached := self._semantic_cache.get(digest)) is not None:
                self._semantic_cache.move_to_end(digest)
                return (*cached, True)

        hits, result = detect_semantic(policy, text, self.classifier)

        with self._semantic_lock:
            if self._semantic_cache_policy is policy:
                self._semantic_cache[digest] = (hits, result)
                if len(self._semantic_cache) > SEMANTIC_CACHE_SIZE:
                    self._semantic_cache.popitem(last=False)
        return hits, result, False

    def _decide(self, policy: Policy, text: str, violations: list[tuple[Hit, str]], details: dict) -> Verdict:
        violations.sort(key=lambda v: SEVERITY[v[0].rule.on_violation], reverse=True)
        primary, kind = violations[0]
        action = primary.rule.on_violation

        redacted_text = None
        if action == "redact":
            to_redact = [h for h, _ in violations if h.rule.on_violation == "redact"]
            if all(h.spans for h in to_redact):
                redacted_text = redact(text, [(s, e, h.rule.id) for h in to_redact for s, e in h.spans])
            else:
                action = "block"  # trafienie semantyczne / fingerprint nie wskazuje fragmentu do zamaskowania

        rule = primary.rule
        details.update({
            "rule_id": rule.id,
            "rule_ids": [h.rule.id for h, _ in violations],
            "document": rule.document,
            "section": rule.section,
            "category": rule.category,
            "classification": rule.classification,
            "layer": primary.layer,
            "methods": primary.methods,
            "confidence": round(primary.confidence, 3),
            "violation_type": kind,
            "on_violation": rule.on_violation,
            "notify": sorted({n for h, _ in violations for n in h.rule.notify}),
        })

        title = policy.titles.get(rule.document, rule.document)
        if kind == "usage":
            message = (f"Blocked pursuant to {rule.section} ({title}): this information must not "
                       f"be sent {DESTINATION_LABELS[details['destination']]}.")
        else:
            message = rule.refusal

        if action == "block":
            return Verdict("block", message, STAGE, details, is_blocked=True)
        if action == "redact":
            details["redacted_text"] = redacted_text
            return Verdict("redact", f"Information redacted pursuant to {rule.section} ({title}).",
                           STAGE, details)
        if action == "warn":
            details["warning"] = message
            return Verdict("warn", message, STAGE, details)
        return Verdict("pass", f"Violation {rule.id} logged only (log_only)", STAGE, details)

    def _detector_error_verdict(self, error: str, rules: list[Rule], details: dict) -> Verdict:
        action = max((r.on_detector_error for r in rules), key=SEVERITY.__getitem__)
        failing = [r.id for r in rules if r.on_detector_error == action]
        details.update({"detector_error": error, "layer": "semantic", "rule_ids": failing})
        ids = ", ".join(failing)
        if action == "block":
            return Verdict("block", f"Klasyfikator semantyczny jest niedostępny; reguły {ids} działają "
                           "w trybie fail-closed.", STAGE, details, is_blocked=True)
        message = f"Klasyfikator semantyczny jest niedostępny; reguły {ids} sprawdzono tylko deterministycznie."
        if action == "warn":
            details["warning"] = message
            return Verdict("warn", message, STAGE, details)
        return Verdict("pass", message, STAGE, details)

    def _finish(self, verdict: Verdict, text: str, digest: str, started: float, latency: dict) -> Verdict:
        latency["total"] = _ms(started)
        verdict.details["latency_ms"] = latency
        d = verdict.details
        self.audit.write({
            "event": "decision",
            "decision": verdict.decision,
            "point": d.get("point"),
            "role": d.get("role"),
            "source": d.get("source"),
            "destination": d.get("destination"),
            "rule_id": d.get("rule_id"),
            "rule_ids": d.get("rule_ids", []),
            "document": d.get("document"),
            "section": d.get("section"),
            "category": d.get("category"),
            "layer": d.get("layer"),
            "methods": d.get("methods"),
            "confidence": d.get("confidence"),
            "violation_type": d.get("violation_type"),
            "notify": d.get("notify", []),
            "detector_error": d.get("detector_error"),
            "policy_version": d.get("policy_version"),
            "latency_ms": latency,
            # Bez treści: tylko hash i długość, żeby log nie stał się kopią danych poufnych.
            "content_sha256": digest,
            "content_length": len(text),
        })
        return verdict


def _ms(since: float) -> float:
    return round((time.perf_counter() - since) * 1000, 3)
