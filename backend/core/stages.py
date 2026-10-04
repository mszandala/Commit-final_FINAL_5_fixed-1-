"""Etapy sprawdzania jednej tury: zapytanie (przed modelem) i odpowiedź (po modelu).

Etapy nie wołają modelu ani nie wykonują narzędzi. Zwracają decyzję, a to, co z nią zrobić
(pokazać odmowę, wysłać prompt do modelu, zapisać wynik tury), należy do wywołującego.

Uwaga: etapy korzystają jeszcze z modułów `security/*`, które same czytają `config.py`
(strażnik promptu, klasyfikator intencji, wykrywanie odmów). Odcięcie ich od globalnej konfiguracji
jest osobnym krokiem.
"""
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Iterable, Optional

from audit import logger as audit
from security.common.verdicts import Verdict
from security.intent_classifier import CATEGORIES_PL as INTENT_CATEGORIES, IN_SCOPE, classify_intent
from security.pii.regex_detector import detect_regex_pii
from security.prompt_guard import check_prompt
from security.refusal_detector import CATEGORIES_PL as REFUSAL_CATEGORIES, assess_refusal

from .company import record_check, soften
from .context import TurnContext
from .pii import filter_output, label_sensitive, logged_prompt, mask_prompt

LOGGED_EXCERPT_CHARS = 300      # tyle z odrzuconego, zbyt długiego promptu trafia do logu
TOOL_PLACEHOLDER = "[tool]"


def block(stage: str, reason: str) -> dict:
    return {"decision": "block", "stage": stage, "reason": reason}


def _clean(reason: str) -> str:
    return reason.replace("[OSTRZEŻENIE PROMPT GUARD] ", "")


@lru_cache(maxsize=16)
def _tool_names_re(names: tuple) -> re.Pattern:
    # Nazwa narzędzia w odpowiedzi, także w odwróconych apostrofach. Model powtarza je z odmów bramki.
    return re.compile(r"`?\b(?:" + "|".join(map(re.escape, names)) + r")\b`?")


def hide_tool_names(text: str, names: Iterable[str]) -> tuple[str, int]:
    """Zamienia nazwy wewnętrznych narzędzi w odpowiedzi na neutralny znacznik. Zwraca (tekst, ile zamian)."""
    names = tuple(sorted(set(names), key=len, reverse=True))
    return _tool_names_re(names).subn(TOOL_PLACEHOLDER, text) if names else (text, 0)


# --- zapytanie ----------------------------------------------------------------------------------

@dataclass
class RequestDecision:
    """Wynik `check_request`. Przy `blocked` model nie jest wołany, a użytkownik dostaje `reply`."""
    blocked: bool
    reply: Optional[str] = None
    verdict: Optional[dict] = None          # przy blokadzie: {"decision": "block", "stage", "reason"}
    masked_prompt: str = ""                 # to, co dostaje chatbot (przy blokadzie: wersja do logu)
    entities: list = field(default_factory=list)
    guard: Optional[Verdict] = None
    flagged: bool = False                   # strażnik albo klasyfikator oflagował zapytanie
    guard_reason: Optional[str] = None
    policy_note: Optional[dict] = None      # ukrycie fragmentu albo ostrzeżenie regulaminów


def check_request(ctx: TurnContext, user_message: str, *, baseline_filters: Optional[dict] = None,
                  on_stage: Optional[Callable[[], None]] = None) -> RequestDecision:
    """Długość promptu -> strażnik i klasyfikator intencji -> regulaminy -> maskowanie.

    `baseline_filters` to ustawienia wdrożenia: tylko kontrole wyłączone względem nich trafiają do
    logu jako niespodzianka. `on_stage` jest wołane, gdy zaczyna się właściwe sprawdzanie zapytania.
    """
    policy, conv, threshold = ctx.policy, ctx.conv, ctx.threshold
    baseline = baseline_filters or {}

    off = sorted(name for name, on in policy.filters().items() if not on and baseline.get(name, True))
    if off:
        audit.record("filters_off", "security", filters=off)

    # 0. Długość promptu: zbyt długi nie trafia do żadnego modelu, także do strażników.
    max_chars = policy.controls.prompt_length.max_chars
    if policy.filter_on("prompt_length") and len(user_message) > max_chars:
        reason = f"Zapytanie ma {len(user_message)} znaków; limit to {max_chars}"
        audit.record("prompt_length", "security", chars=len(user_message), limit=max_chars)
        excerpt = logged_prompt(ctx, user_message[:LOGGED_EXCERPT_CHARS])
        return RequestDecision(
            True, f"Zapytanie zostało zablokowane: {reason}", block("prompt_length", reason),
            f"{excerpt} [... {len(user_message) - LOGGED_EXCERPT_CHARS} znaków pominięto]")

    # 1. Strażnik promptu (strefa bezpieczeństwa, dane surowe): wzorce regex jako pierwszy sygnał, potem
    #    klasyfikator intencji. Gdy klasyfikator działa, to on rozstrzyga — słowa kluczowe same już tylko
    #    ostrzegają, bo mylą się na zwykłych zapytaniach. W trybie "block" naruszenie zatrzymuje turę.
    if on_stage:
        on_stage()
    guard = (check_prompt(conv.role, user_message) if policy.filter_on("prompt_guard")
             else Verdict("pass", "", "prompt_guard"))
    flagged = guard.decision == "warn"
    guard_reason = _clean(guard.reason) if flagged else None
    block_mode = policy.controls.prompt_guard.mode == "block"
    intent_on = policy.filter_on("intent_classifier")
    guard_blocks = guard.is_blocked or (flagged and block_mode and not intent_on)
    audit.record("prompt_guard", "security", decision=guard.decision, blocked=guard_blocks,
                 reason=_clean(guard.reason) if flagged or guard_blocks else None,
                 details={k: v for k, v in guard.details.items() if k != "warning"})
    if intent_on and not guard_blocks:
        intent = classify_intent(conv.role, user_message, conv.user_texts, hint=guard_reason)
        violation = intent["category"] not in (None, IN_SCOPE)
        if violation:
            # Uzasadnienie może powtarzać dane z promptu; do logu idą etykiety typów (same reguły, bez GLiNER-a,
            # który w krótkim zdaniu oznacza słowo „Użytkownik" jako osobę).
            detail = label_sensitive(intent["reason"], detect_regex_pii(intent["reason"]), policy)
            guard_reason = INTENT_CATEGORIES[intent["category"]] + (f": {detail}" if detail else "")
            flagged, guard_blocks = True, block_mode
        audit.record("intent", "security", category=intent["category"], blocked=violation and block_mode,
                     reason=guard_reason if violation else None, error=intent["error"])
    if guard_blocks:
        reason = guard_reason or _clean(guard.reason)
        return RequestDecision(True, f"Zapytanie zostało zablokowane: {reason}", block("prompt_guard", reason),
                               logged_prompt(ctx, user_message), guard=guard, flagged=flagged,
                               guard_reason=guard_reason)

    # 2. Regulaminy firmowe na surowym prompcie: blokada, ukrycie fragmentu albo ostrzeżenie
    policy_note = None
    prompt = user_message
    if ctx.engine:
        checked, softened = soften(policy, ctx.engine, conv.role, user_message,
                                   ctx.engine.check_input(conv.role, user_message), point="input")
        record_check("input", checked, softened)
        if checked.decision == "block":
            return RequestDecision(True, f"Zapytanie zostało zablokowane: {checked.reason}",
                                   block(checked.stage, checked.reason), logged_prompt(ctx, user_message),
                                   guard=guard, flagged=flagged, guard_reason=guard_reason)
        if checked.decision == "redact":
            prompt = checked.details.get("redacted_text") or user_message
        if checked.decision in ("redact", "warn"):
            policy_note = {"decision": checked.decision, "stage": checked.stage, "reason": checked.reason}

    # 3. Maskowanie promptu na granicy strefy chatbota
    masked_prompt, entities, blocked = mask_prompt(conv, prompt, policy=policy, detect=ctx.detect,
                                                   threshold=threshold)
    if blocked:
        types = ", ".join(sorted({e["type"] for e in entities if e["decision"] == "block"}))
        reason = f"Zapytanie zawiera dane, których nie wolno wysyłać do modelu: {types}"
        return RequestDecision(True, f"Zapytanie zostało zablokowane: {reason}", block("pii_policy", reason),
                               masked_prompt, entities, guard, flagged, guard_reason, policy_note)
    conv.user_texts.append(user_message)
    return RequestDecision(False, masked_prompt=masked_prompt, entities=entities, guard=guard,
                           flagged=flagged, guard_reason=guard_reason, policy_note=policy_note)


# --- odpowiedź ----------------------------------------------------------------------------------

@dataclass
class ResponseDecision:
    """Wynik `check_response`. Przy `blocked` użytkownik dostaje `reply` zamiast odpowiedzi modelu."""
    blocked: bool
    reply: str
    logged_reply: str
    output: dict                            # {"entities", "restored", "redacted", "blocked", "exempt", "found"}
    verdict: Optional[dict] = None          # najważniejsza decyzja tury albo None
    refusal: Optional[dict] = None          # werdykt odmowy chatbota, jeśli ją wykryto


def check_response(ctx: TurnContext, raw_reply: str, user_message: str, request: RequestDecision, *,
                   denied_tools: list, tool_names: Iterable[str]) -> ResponseDecision:
    """Filtr odpowiedzi w kanale użytkownika -> regulaminy -> wykrywanie odmowy -> werdykt tury."""
    policy, conv = ctx.policy, ctx.conv
    reply, logged_reply, output = filter_output(
        conv.role, raw_reply or "", conv.vault, conv.user_texts, conv.public_texts, ctx.threshold,
        redact=policy.controls.pii.mask_in_chatbot_channel, judge=policy.controls.pii.judge_enabled,
        enforce=policy.filter_on("output_filter"), policy=policy, detect=ctx.detect)
    reply, hidden = hide_tool_names(reply, tool_names)
    logged_reply = hide_tool_names(logged_reply, tool_names)[0]
    audit.record("output_filter", "security", restored=output["restored"], redacted=output["redacted"],
                 blocked=output["blocked"], exempt=output["exempt"], found=output["found"],
                 tool_names_hidden=hidden)
    if output["blocked"]:
        types = ", ".join(sorted(set(output["blocked"])))
        reason = f"Odpowiedź zawiera dane, do których rola „{conv.role}” nie ma dostępu: {types}"
        return ResponseDecision(True, f"Odpowiedź została zablokowana: {reason}", logged_reply, output,
                                block("pii_policy", reason))

    policy_note = request.policy_note
    if ctx.engine:
        checked, softened = soften(policy, ctx.engine, conv.role, reply,
                                   ctx.engine.check_output(conv.role, reply), point="output",
                                   public_only=not conv.private_context)
        record_check("output", checked, softened)
        if checked.decision == "block":
            return ResponseDecision(True, f"Odpowiedź została zablokowana: {checked.reason}", logged_reply,
                                    output, block(checked.stage, checked.reason))
        if checked.decision == "redact":
            reply = checked.details.get("redacted_text") or reply
        if checked.decision in ("redact", "warn") and not (policy_note and policy_note["decision"] == "redact"):
            policy_note = {"decision": checked.decision, "stage": checked.stage, "reason": checked.reason}

    # Odmowa samego chatbota: warstwa niczego nie zablokowała, ale użytkownik nie dostał tego, o co prosił.
    # Słowa kluczowe i podobieństwo do wzorców tylko wskazują kandydata; rozstrzyga sędzia LLM.
    refusal_cfg = policy.controls.refusal_detection
    found = (assess_refusal(user_message, raw_reply or "", denied_tools=bool(denied_tools),
                            judge=refusal_cfg.judge_enabled)
             if refusal_cfg.enabled else None)
    if found:
        audit.record("refusal", "security", confirmed=found["refusal"], method=found["method"],
                     category=found["category"], score=found["score"], reason=found["reason"],
                     after_denied_tools=denied_tools)
    refusal = None
    if found and found["refusal"]:
        cause = (f"po odrzuceniu narzędzia: {', '.join(denied_tools)}" if denied_tools
                 else REFUSAL_CATEGORIES[found["category"]])
        refusal = {"decision": "refuse", "stage": "chatbot_refusal", "reason": f"Chatbot odmówił ({cause})"}

    # Jedna decyzja na turę, od najmocniejszej: ukrycie (PII, potem regulaminy), ostrzeżenie, odmowa chatbota.
    verdict = None
    if output["redacted"]:
        types = ", ".join(sorted(set(output["redacted"])))
        verdict = {"decision": "redact", "stage": "pii_policy", "reason": f"Ukryto dane: {types}"}
    elif policy_note and policy_note["decision"] == "redact":
        verdict = policy_note
    elif request.flagged:
        verdict = {"decision": "warn", "stage": "prompt_guard", "reason": request.guard_reason}
    elif policy_note:
        verdict = policy_note
    elif refusal:
        verdict = refusal
    return ResponseDecision(False, reply, logged_reply, output, verdict, refusal)
