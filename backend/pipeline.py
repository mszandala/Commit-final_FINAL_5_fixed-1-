"""Orkiestracja jednej tury rozmowy: strażnik promptu -> maskowanie -> chatbot z bramką narzędzi
-> filtr odpowiedzi -> log audytu.

Dwie strefy zaufania:
  - bezpieczeństwo: strażnik, detektor PII, sędzia — pracują na danych surowych,
  - chatbot: model odpowiadający użytkownikowi — widzi tylko wersję zamaskowaną.
Narzędzia wykonują się lokalnie na prawdziwych wartościach; maska leży na granicy wywołania chatbota.
"""
import time
import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Optional

from audit import logger as audit
from chatbot import agent
from config import (
    CHATBOT_ZONE_TOOLS,
    COLUMN_TYPES,
    DEFAULT_TOOL_RESULT_SCAN,
    PII_JUDGE_ENABLED,
    PUBLIC_SOURCE_TOOLS,
    ROLES,
    SETTINGS,
    TOOL_RESULT_SCAN,
)
from security import masking
from security.code_guard import check_code
from security.common.roles import normalize_role
from security.common.verdicts import Verdict
from security.masking import Vault, chatbot_action, label_for, role_policy
from security.pii.pii_detector import detect_pii
from security.pii.regex_detector import detect_regex_pii
from security.pii_judge import judge_entities
from security.prompt_guard import check_prompt
from security.tool_whitelist import ToolGate
from tools.registry import run_tool

MASKING_NOTE = (
    " Some values in the conversation are replaced by placeholders such as <EMAIL_1> or ID-3fa9c21b07,"
    " and some table cells show [REDACTED]. Treat placeholders as opaque values: copy them exactly,"
    " never alter, translate or guess them. You may pass them to tools as arguments."
)


def _system_prompt(role: str) -> str:
    allowed = ROLES.get(role, {}).get("allowed_tools", [])
    tools_str = ", ".join(allowed) if allowed else "none"
    role_note = (
        f"\nUser's current role is: '{role}'. "
        f"If you need to retrieve data or call tools, the ONLY tools authorized for this user's role are: [{tools_str}]. "
        f"Do not attempt to call any unauthorized tools."
    )
    masking = MASKING_NOTE if SETTINGS.mask_pii else ""
    return agent.SYSTEM + role_note + masking


@dataclass
class Conversation:
    """Stan jednej rozmowy. Historia należy do strefy chatbota, więc zawiera tylko dane zamaskowane."""
    role: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    history: Optional[list] = None
    vault: Vault = field(default_factory=Vault)
    user_texts: list = field(default_factory=list)     # surowe prompty: wartości, które użytkownik sam podał
    public_texts: list = field(default_factory=list)   # wyniki narzędzi czytających źródła publiczne
    turns: int = 0

    def __post_init__(self):
        self.role = normalize_role(self.role)


@dataclass
class TurnResult:
    reply: str                      # to, co widzi użytkownik
    blocked: bool
    block_reason: Optional[str]
    guard: Verdict
    masked_prompt: str              # to, co dostał chatbot
    prompt_entities: list           # encje z promptu + "decision": send / mask / block
    tool_calls: list                # {"tool", "args", "allowed"}; argumenty w postaci zamaskowanej
    output: dict                    # {"entities", "restored", "redacted", "blocked", "exempt"}
    leaks_to_chatbot: int           # ile wartości z sejfu znaleziono w wiadomościach do chatbota
    events: list                    # zdarzenia audytu tej tury (bez surowych wartości)
    verdict: Optional[dict] = None  # najważniejsza decyzja tury: {"decision", "stage", "reason"} albo None
    tokens: int = 0                 # tokeny zużyte przez wszystkie wywołania modelu w turze
    latency_ms: int = 0
    error: Optional[str] = None     # błąd wywołania modelu (tura nie dała odpowiedzi)
    verdicts: list = field(default_factory=list)          # wszystkie decyzje tury, od najważniejszej
    masked_for_model: list = field(default_factory=list)  # typy z promptu ukryte przed chatbotem


# Etapy tury zgłaszane przez on_progress.
STAGE_REQUEST = "checking_request"
STAGE_MODEL = "waiting_for_model"
STAGE_REPLY = "checking_reply"

Progress = Callable[[str, dict], None]     # (rodzaj: "stage" | "tool", dane)


@lru_cache(maxsize=256)
def _detect_cached(text: str, threshold: Optional[float]) -> tuple:
    return tuple(tuple(sorted(e.items())) for e in detect_pii(text, threshold=threshold))


def _well_formed(entity: dict) -> bool:
    """Odrzuca wykrycia, które nie mają budowy swojego typu (np. "rachunku" jako numer karty)."""
    text = entity["text"]
    digits = sum(c.isdigit() for c in text)
    return {
        # Próg celowo niski: detektor bywa myli typ liczby (np. SSN jako numer karty), a i tak warto ją ukryć.
        "CREDIT-CARD-NO": digits >= 4,
        "PHONE-NO": digits >= 4,
        "EMAIL": "@" in text,
        "SALARY": digits >= 1,
    }.get(entity["type"], True)


def _detect(text: str, threshold: Optional[float]) -> list[dict]:
    return [e for e in (dict(e) for e in _detect_cached(text, threshold)) if _well_formed(e)]


def _replace_spans(text: str, entities: list[dict], replacement) -> str:
    for e in sorted(entities, key=lambda e: e["start"], reverse=True):
        text = text[: e["start"]] + replacement(e) + text[e["end"]:]
    return text


def _label_sensitive(text: str, entities: list[dict]) -> str:
    """Wersja do logu: każda encja wrażliwa w kanale chatbota zamieniona na etykietę typu."""
    return _replace_spans(text, [e for e in entities if chatbot_action(e["type"]) != "allow"],
                          lambda e: label_for(e["type"]))


def mask_prompt(conv: Conversation, prompt: str, threshold: Optional[float] = None) -> tuple[str, list, bool]:
    """Maskuje prompt przed wysłaniem do chatbota. Zwraca (prompt, encje z decyzjami, czy blokada)."""
    entities = _detect(prompt, threshold)
    pending = []
    for e in entities:
        action = chatbot_action(e["type"]) if SETTINGS.mask_pii else "allow"
        e["decision"] = {"allow": "send", "redact": "mask", "block": "block"}.get(action, "mask")
        if action == "judge":
            pending.append(e)
    if pending and PII_JUDGE_ENABLED:
        for e, decision in zip(pending, judge_entities(conv.role, prompt, pending)):
            e["decision"] = decision

    blocked = any(e["decision"] == "block" for e in entities)
    masked = conv.vault.mask_entities(prompt, [e for e in entities if e["decision"] == "mask"])
    if SETTINGS.mask_pii:
        masked = conv.vault.mask_known(masked)
    audit.record(
        "prompt_masking", "security",
        decisions=[{"type": e["type"], "decision": e["decision"]} for e in entities],
        prompt=_label_sensitive(prompt, entities),
    )
    return masked, entities, blocked


class SecureToolGate:
    """Bramka narzędzi tury: whitelist roli, potem wykonanie lokalne i maskowanie wyniku.

    Zwraca agentowi tekst zamiast wyniku narzędzia — przy odmowie jest to komunikat odmowy,
    przy zgodzie zamaskowany wynik. Agent sam nie wykonuje więc żadnego narzędzia.
    """

    def __init__(self, conv: Conversation, threshold: Optional[float] = None,
                 on_progress: Optional[Progress] = None):
        self.conv = conv
        self.threshold = threshold
        self.whitelist = ToolGate(conv.role)
        self.on_progress = on_progress

    def _report(self, call: dict) -> None:
        if self.on_progress:
            self.on_progress("tool", call)
            self.on_progress("stage", {"stage": STAGE_MODEL})

    @property
    def calls(self) -> list[dict]:
        return self.whitelist.calls

    def __call__(self, name: str, args: dict) -> Optional[str]:
        refusal = self.whitelist(name, args)
        # Subagent dopisuje własne wywołania do `calls`, zanim to się skończy — trzymamy własny wpis.
        call = self.calls[-1]
        if refusal is not None:
            audit.record("tool_call", "security", tool=name, allowed=False, args=args, stage="tool_whitelist")
            self._report(call)
            return refusal

        # Kod do uruchomienia sprawdzamy tu, żeby odrzucenie było widoczne jako decyzja warstwy
        # bezpieczeństwa, a nie tylko jako tekst błędu narzędzia.
        if name == "run_python":
            verdict = check_code(str(args.get("code", "")))
            if verdict.is_blocked:
                call.update(allowed=False, stage="code_guard", reason=verdict.reason)
                audit.record("tool_call", "security", tool=name, allowed=False, args=args,
                             stage="code_guard", reason=verdict.reason)
                self._report(call)
                return f"Code rejected by security policy: {verdict.reason}"

        # Narzędzia działają lokalnie na prawdziwych wartościach. Wyjątek: subagent, którego
        # argument trafia z powrotem do modelu w chmurze.
        local = name not in CHATBOT_ZONE_TOOLS
        real_args = self.conv.vault.unmask_args(args) if local and SETTINGS.mask_pii else args
        result = masking.sanitize_paths(run_tool(name, real_args))
        masked, scan, stats = self._mask_result(name, result)
        if name in PUBLIC_SOURCE_TOOLS:
            self.conv.public_texts.append(masked)
        audit.record("tool_call", "local" if local else "chatbot", tool=name, allowed=True, args=args,
                     scan=scan, masked=stats, result_chars=len(masked))
        self._report(call)
        return masked

    def _mask_result(self, name: str, result: str) -> tuple[str, str, dict]:
        scan = TOOL_RESULT_SCAN.get(name, DEFAULT_TOOL_RESULT_SCAN)
        if not SETTINGS.mask_pii or scan == "none":
            return result, "none", {}
        vault = self.conv.vault
        if scan == "columns":
            masked, stats = masking.mask_csv(result, COLUMN_TYPES.get(name, {}), role_policy(self.conv.role), vault)
        else:
            found = detect_regex_pii(result) if scan == "regex" else _detect(result, self.threshold)
            sensitive = [e for e in found if chatbot_action(e["type"]) != "allow"]
            masked = vault.mask_entities(result, sensitive)
            stats = {"masked": len(sensitive)}
        return vault.mask_known(masked), scan, stats


def _plausible(entity: dict) -> bool:
    """Odsiewa oczywiste pomyłki detektora, zanim nieodwracalnie ukryjemy coś w odpowiedzi.

    GLiNER na polskim tekście oznacza zwykłe słowa ("Kobieta", "Wiek") jako osoby.
    """
    if entity["type"] == "NAME":
        words = entity["text"].split()
        return len(words) >= 2 and all(w[0].isupper() for w in words)
    return True


def filter_output(role: str, text: str, vault: Optional[Vault] = None, own_texts=(), public_texts=(),
                  threshold: Optional[float] = None, redact: bool = True) -> tuple[str, str, dict]:
    """Filtr odpowiedzi w kanale użytkownika.

    Nie ukrywa wartości, które użytkownik sam wpisał (`own_texts`) ani pochodzących ze źródeł
    publicznych (`public_texts`). Zwraca (tekst dla użytkownika, tekst do logu, statystyki);
    statystyki zawierają klucz "blocked" z typami, które wymuszają blokadę całej odpowiedzi.
    Przy `redact=False` nic nie jest ukrywane (typy trafiają do "found"), ale blokady nadal działają.
    """
    vault = vault or Vault()
    policy = role_policy(role)
    own = "\n".join(own_texts)
    exempt = own + "\n" + "\n".join(public_texts)
    spans = vault.token_spans(text)

    entities = [
        e for e in _detect(text, threshold)
        if _plausible(e) and not any(e["start"] < end and start < e["end"] for start, end in spans)
    ]
    to_replace, exempted, found = [], [], []
    for e in entities:
        action = policy.get(e["type"], "redact")
        e["action"] = action
        if action == "allow":
            continue
        if e["text"] in exempt:
            e["action"] = "exempt"
            exempted.append(e["type"])
        elif action == "redact" and not redact:
            e["action"] = "found"
            found.append(e["type"])
        else:
            to_replace.append(e)

    def visible(e):
        return vault.token_for(e["type"], e["text"]) if e["action"] == "pseudonymize" else label_for(e["type"])

    shown, stats = vault.render(_replace_spans(text, to_replace, visible), policy, own)
    stats["redacted"] += [e["type"] for e in to_replace if e["action"] == "redact"]
    stats["blocked"] += [e["type"] for e in to_replace if e["action"] == "block"]
    stats["exempt"] = exempted
    stats["found"] = found
    stats["entities"] = entities
    return shown, _label_sensitive(text, entities), stats


def _count_leaks(history: list, vault: Vault) -> int:
    """Ile wartości z sejfu występuje w wiadomościach wysłanych do chatbota (oczekiwane: 0)."""
    values = vault.raw_values()
    if not values:
        return 0
    chunks = []
    for m in history:
        get = m.get if isinstance(m, dict) else lambda k, d=None, m=m: getattr(m, k, d)
        chunks.append(str(get("content", "") or ""))
        for tc in get("tool_calls", None) or []:
            chunks.append(str(tc.function.arguments))
    sent = "\n".join(chunks)
    return sum(1 for v in values if v in sent)


def _clean(reason: str) -> str:
    return reason.replace("[OSTRZEŻENIE PROMPT GUARD] ", "")


def run_turn(conv: Conversation, user_message: str, threshold: Optional[float] = None,
             on_progress: Optional[Progress] = None) -> TurnResult:
    """Przeprowadza jedną wiadomość użytkownika przez całą warstwę bezpieczeństwa.

    `on_progress(rodzaj, dane)` dostaje kolejne etapy ("stage") i wywołania narzędzi ("tool").
    """
    started = time.perf_counter()
    events = audit.start_turn()
    conv.turns += 1
    if threshold is None:
        threshold = SETTINGS.pii_threshold
    gate = SecureToolGate(conv, threshold, on_progress)
    output = {"entities": [], "restored": [], "redacted": [], "blocked": [], "exempt": [], "found": []}
    leaks = 0

    def stage(name):
        if on_progress:
            on_progress("stage", {"stage": name})

    def finish(reply, verdict=None, masked_prompt="", entities=(), logged_reply="", error=None):
        blocked = bool(verdict and verdict["decision"] == "block")
        reason = verdict["stage"] if blocked else None
        tokens = sum(e.get("tokens", 0) for e in events if e["type"] == "llm_call")
        latency = int((time.perf_counter() - started) * 1000)
        audit.record("turn", "security", blocked=blocked, block_reason=reason, verdict=verdict,
                     reply=logged_reply, leaks_to_chatbot=leaks, vault_size=len(conv.vault),
                     tokens=tokens, latency_ms=latency)
        audit.flush(events, conversation=conv.id, role=conv.role, turn=conv.turns)
        # Ostrzeżenie strażnika zostaje obok decyzji innego etapu (np. redact), zamiast przez nią znikać.
        verdicts = [verdict] if verdict else []
        if flagged and not (verdict and verdict["stage"] == "prompt_guard"):
            verdicts.append({"decision": "warn", "stage": "prompt_guard", "reason": _clean(guard.reason)})
        masked = sorted({e["type"] for e in entities if e.get("decision") == "mask"})
        return TurnResult(reply, blocked, reason, guard, masked_prompt, list(entities), gate.calls,
                          output, leaks, events, verdict, tokens, latency, error,
                          verdicts=verdicts, masked_for_model=masked)

    def block(stage_name, reason):
        return {"decision": "block", "stage": stage_name, "reason": reason}

    # 1. Strażnik promptu (strefa bezpieczeństwa, dane surowe). W trybie "block" ostrzeżenie zatrzymuje turę.
    stage(STAGE_REQUEST)
    guard = check_prompt(conv.role, user_message)
    flagged = guard.decision == "warn"
    guard_blocks = guard.is_blocked or (flagged and SETTINGS.guard_mode == "block")
    audit.record("prompt_guard", "security", decision=guard.decision, blocked=guard_blocks,
                 details={k: v for k, v in guard.details.items() if k != "warning"})
    if guard_blocks:
        reason = _clean(guard.reason)
        return finish(f"Zapytanie zostało zablokowane: {reason}", block("prompt_guard", reason))

    # 2. Maskowanie promptu na granicy strefy chatbota
    masked_prompt, entities, blocked = mask_prompt(conv, user_message, threshold)
    if blocked:
        types = ", ".join(sorted({e["type"] for e in entities if e["decision"] == "block"}))
        reason = f"Zapytanie zawiera dane, których nie wolno wysyłać do modelu: {types}"
        return finish(f"Zapytanie zostało zablokowane: {reason}", block("pii_policy", reason),
                      masked_prompt, entities)
    conv.user_texts.append(user_message)

    # 3. Chatbot z bramką narzędzi
    stage(STAGE_MODEL)
    history = conv.history or [{"role": "system", "content": _system_prompt(conv.role)}]
    try:
        raw_reply, new_history = agent.run_agent(masked_prompt, history=history, tool_gate=gate)
    except agent.ResponseBlocked as exc:
        return finish(f"Odpowiedź została zablokowana: {exc}", block("tool_whitelist", str(exc)),
                      masked_prompt, entities)
    except Exception as exc:
        audit.record("error", "chatbot", error=type(exc).__name__)
        return finish(f"Błąd wykonania modelu: {exc}", None, masked_prompt, entities, error=str(exc))
    conv.history = new_history
    leaks = _count_leaks(new_history, conv.vault)

    # 4. Filtr odpowiedzi w kanale użytkownika
    stage(STAGE_REPLY)
    reply, logged_reply, output = filter_output(
        conv.role, raw_reply or "", conv.vault, conv.user_texts, conv.public_texts, threshold,
        redact=SETTINGS.mask_pii)
    audit.record("output_filter", "security", restored=output["restored"], redacted=output["redacted"],
                 blocked=output["blocked"], exempt=output["exempt"], found=output["found"])
    if output["blocked"]:
        types = ", ".join(sorted(set(output["blocked"])))
        reason = f"Odpowiedź zawiera dane, do których rola „{conv.role}” nie ma dostępu: {types}"
        return finish(f"Odpowiedź została zablokowana: {reason}", block("pii_policy", reason),
                      masked_prompt, entities, logged_reply)

    verdict = None
    if output["redacted"]:
        types = ", ".join(sorted(set(output["redacted"])))
        verdict = {"decision": "redact", "stage": "pii_policy", "reason": f"Ukryto dane: {types}"}
    elif flagged:
        verdict = {"decision": "warn", "stage": "prompt_guard", "reason": _clean(guard.reason)}
    return finish(reply, verdict, masked_prompt, entities, logged_reply)
