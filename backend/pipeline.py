"""Orkiestracja jednej tury rozmowy: strażnik promptu -> maskowanie -> chatbot z bramką narzędzi
-> filtr odpowiedzi -> log audytu.

Dwie strefy zaufania:
  - bezpieczeństwo: strażnik, detektor PII, sędzia — pracują na danych surowych,
  - chatbot: model odpowiadający użytkownikowi — widzi tylko wersję zamaskowaną.
Narzędzia wykonują się lokalnie na prawdziwych wartościach; maska leży na granicy wywołania chatbota.

Decyzje (co sprawdzić, co zablokować, co ukryć) są w pakiecie `core`; ten plik to wiązanie dla aplikacji
demo: buduje politykę z żywej konfiguracji (`config.py` i ustawienia zmieniane z interfejsu), podaje
zależności (detektor PII, silnik regulaminów) i prowadzi pętlę chatbota. Nazwy, które testy i inne
moduły podmieniają albo importują (`detect_pii`, `MAX_PROMPT_CHARS`, `_detect`, `filter_output`…),
zostają tutaj i są czytane w chwili wywołania.
"""
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Optional

import config
from audit import logger as audit
from chatbot import agent, llm_client
from config import (
    CHATBOT_PII_POLICY,
    CHATBOT_ZONE_TOOLS,
    COMPANY_POLICIES_CLASSIFIER,
    COMPANY_POLICIES_FAIL_CLOSED,
    COMPANY_POLICIES_SEMANTIC_BLOCKS,
    COMPANY_POLICIES_STRICT_KEYWORDS,
    CONDUCT_RULES_FILE,
    COLUMN_TYPES,
    DATA_ACCESS,
    DEFAULT_FILTERS,
    DEFAULT_ROLE_PII_POLICY,
    DEFAULT_TOOL_RESULT_SCAN,
    GLOBAL_BLOCKED_PII,
    GLOBAL_REDACTED_PII,
    ID_TYPES,
    MAX_PROMPT_CHARS,
    MAX_TOOL_RESULT_CHARS,
    MAX_TURN_COST,
    MAX_TURN_TOKENS,
    PII_JUDGE_ENABLED,
    PUBLIC_SOURCE_TOOLS,
    REFUSAL_DETECTION_ENABLED,
    REFUSAL_JUDGE_ENABLED,
    RESOURCE_TOOLS,
    ROLES,
    SETTINGS,
    TOOL_RESULT_SCAN,
)
from core import Policy
from core.context import TurnContext
from core.notice import build_notice
from core.pii import (
    filter_output as _filter_output,
    mask_prompt as _mask_prompt,
    well_formed as _well_formed,
)
from core.session import Conversation
from core.stages import TOOL_PLACEHOLDER, check_request, check_response, hide_tool_names as _hide_tool_names
from core.tool_guard import ToolGuard
from security.company_policies import CompanyPolicyEngine
from security.company_policies.detection import build_classifier_messages, parse_classification
from security.common.verdicts import Verdict
from security.masking import Vault
from security.pii.pii_detector import detect_pii
from tools.registry import TOOL_MAP, run_tool

CHARS_PER_TOKEN = 4             # zgrubny przelicznik znaków na tokeny, jak w security/budget.py


# --- polityka z żywej konfiguracji ------------------------------------------------------------------

def filter_on(name: str) -> bool:
    """Czy filtr jest włączony w konfiguracji (można go wyłączyć z interfejsu); nieznany liczy się jako włączony."""
    return SETTINGS.filters.get(name, True)


def current_policy() -> Policy:
    """Migawka polityki z żywej konfiguracji na czas jednej tury (albo jednego wywołania filtra).

    Dziś źródłem jest `config.py` plus ustawienia zmieniane z interfejsu (`SETTINGS`, `ROLES`);
    wartości czytamy w chwili wywołania, więc zmiana z interfejsu działa od następnej tury.
    Docelowo to samo `Policy` pochodzi z pliku polityki (`core.PolicyStore`).
    """
    tool_names = set(TOOL_RESULT_SCAN) | set(PUBLIC_SOURCE_TOOLS) | set(CHATBOT_ZONE_TOOLS) | set(COLUMN_TYPES)
    return Policy.model_validate({
        "controls": {
            "prompt_length": {"enabled": filter_on("prompt_length"), "max_chars": MAX_PROMPT_CHARS},
            "prompt_guard": {"enabled": filter_on("prompt_guard"), "mode": SETTINGS.guard_mode},
            "intent_classifier": {"enabled": filter_on("intent_classifier")},
            "company_policies": {
                "enabled": filter_on("company_policies"), "classifier": COMPANY_POLICIES_CLASSIFIER,
                "strict_keywords": COMPANY_POLICIES_STRICT_KEYWORDS,
                "semantic_blocks": COMPANY_POLICIES_SEMANTIC_BLOCKS, "fail_closed": COMPANY_POLICIES_FAIL_CLOSED,
            },
            "tool_whitelist": {"enabled": filter_on("tool_whitelist")},
            "code_guard": {"enabled": filter_on("code_guard")},
            "output_filter": {"enabled": filter_on("output_filter")},
            "pii": {"mask_in_chatbot_channel": SETTINGS.mask_pii, "judge_enabled": PII_JUDGE_ENABLED,
                    "threshold": SETTINGS.pii_threshold},
            "refusal_detection": {"enabled": REFUSAL_DETECTION_ENABLED, "judge_enabled": REFUSAL_JUDGE_ENABLED},
        },
        "budgets": {
            "per_turn": {"max_tokens": MAX_TURN_TOKENS, "max_cost_usd": MAX_TURN_COST,
                         "max_tool_steps": config.MAX_TOOL_STEPS, "max_tool_result_chars": MAX_TOOL_RESULT_CHARS},
            "spending_limit_usd": config.MAX_SPENDING,
        },
        "pii": {"global_blocked": GLOBAL_BLOCKED_PII, "global_redacted": GLOBAL_REDACTED_PII,
                "chatbot_policy": CHATBOT_PII_POLICY, "default_role_policy": DEFAULT_ROLE_PII_POLICY,
                "id_types": ID_TYPES},
        "tool_defaults": {"scan": DEFAULT_TOOL_RESULT_SCAN},
        "tools": {name: {"scan": TOOL_RESULT_SCAN.get(name), "public": name in PUBLIC_SOURCE_TOOLS,
                         "chatbot_zone": name in CHATBOT_ZONE_TOOLS, "column_types": COLUMN_TYPES.get(name, {})}
                  for name in tool_names},
        "areas": {key: {"label": area["label"], "tools": area["tools"]} for key, area in DATA_ACCESS.items()},
        "resources": RESOURCE_TOOLS,
        "roles": {name: {"id": cfg.get("id", name), "description": cfg.get("description", ""),
                         "allowed_tools": cfg.get("allowed_tools", []), "allowed_pii": cfg.get("allowed_pii", []),
                         "pii_policy": cfg.get("pii_policy", {}), "daily_tokens": cfg.get("daily_token_budget", 1)}
                  for name, cfg in ROLES.items()},
    })


def _conduct_rules() -> str:
    return CONDUCT_RULES_FILE.read_text(encoding="utf-8") if CONDUCT_RULES_FILE.exists() else ""


def _notice(role: str, policy: Optional[Policy] = None) -> str:
    """Informacja od warstwy bezpieczeństwa dołączana do pierwszej wiadomości rozmowy."""
    return build_notice(role, policy or current_policy(), _conduct_rules())


# --- regulaminy firmowe -----------------------------------------------------------------------------

_policy_engine: Optional[CompanyPolicyEngine] = None


def _security_zone_classifier(text: str, categories: dict, policy) -> dict:
    """Klasyfikator semantyczny regulaminów wywoływany w strefie bezpieczeństwa zamiast przez
    providera z nagłówka rules.txt (w demie lokalnej Ollamy nie ma)."""
    reply = llm_client.chat(build_classifier_messages(text, categories), zone="security",
                            purpose="company_policy_classifier")
    return parse_classification(getattr(reply, "content", ""), categories)


def policy_engine() -> Optional[CompanyPolicyEngine]:
    """Silnik regulaminów firmowych albo None, gdy moduł jest wyłączony w konfiguracji."""
    global _policy_engine
    if not filter_on("company_policies"):
        return None
    if _policy_engine is None:
        _policy_engine = (CompanyPolicyEngine(classifier=_security_zone_classifier)
                          if COMPANY_POLICIES_CLASSIFIER == "security" else CompanyPolicyEngine())
    return _policy_engine


# --- wynik tury -------------------------------------------------------------------------------------

@dataclass
class TurnResult:
    reply: str                      # to, co widzi użytkownik
    blocked: bool
    block_reason: Optional[str]
    guard: Verdict
    masked_prompt: str              # to, co dostał chatbot
    prompt_entities: list           # encje z promptu + "decision": send / mask / block
    # {"tool", "args", "allowed"} oraz dla wykonanych: "tokens", "cost" (zużycie w trakcie wywołania,
    # np. subagenta) i "result_tokens" (szacunek tego, ile wynik dokłada do kontekstu modelu)
    tool_calls: list
    output: dict                    # {"entities", "restored", "redacted", "blocked", "exempt"}
    leaks_to_chatbot: int           # ile wartości z sejfu znaleziono w wiadomościach do chatbota
    events: list                    # zdarzenia audytu tej tury (bez surowych wartości)
    verdict: Optional[dict] = None  # najważniejsza decyzja tury: {"decision", "stage", "reason"} albo None
    tokens: int = 0                 # tokeny zużyte przez chatbota (strefa bezpieczeństwa liczona osobno)
    latency_ms: int = 0
    error: Optional[str] = None     # błąd wywołania modelu (tura nie dała odpowiedzi)
    cost: float = 0.0               # koszt chatbota w dolarach (zgłoszony przez dostawcę modelu)
    verdicts: list = field(default_factory=list)          # wszystkie decyzje tury, od najważniejszej
    masked_for_model: list = field(default_factory=list)  # typy z promptu ukryte przed chatbotem


# Etapy tury zgłaszane przez on_progress.
STAGE_REQUEST = "checking_request"
STAGE_MODEL = "waiting_for_model"
STAGE_REPLY = "checking_reply"

Progress = Callable[[str, dict], None]     # (rodzaj: "stage" | "tool", dane)


# --- detekcja PII (wiązanie detektora z pamięcią podręczną) -----------------------------------------

@lru_cache(maxsize=256)
def _detect_cached(text: str, threshold: Optional[float]) -> tuple:
    return tuple(tuple(sorted(e.items())) for e in detect_pii(text, threshold=threshold))


def _detect(text: str, threshold: Optional[float]) -> list[dict]:
    return [e for e in (dict(e) for e in _detect_cached(text, threshold)) if _well_formed(e, text)]


def mask_prompt(conv: Conversation, prompt: str, threshold: Optional[float] = None) -> tuple[str, list, bool]:
    """Maskuje prompt przed wysłaniem do chatbota. Zwraca (prompt, encje z decyzjami, czy blokada)."""
    return _mask_prompt(conv, prompt, policy=current_policy(), detect=_detect, threshold=threshold)


def filter_output(role: str, text: str, vault: Optional[Vault] = None, own_texts=(), public_texts=(),
                  threshold: Optional[float] = None, redact: bool = True, judge: bool = False,
                  enforce: bool = True) -> tuple[str, str, dict]:
    """Filtr odpowiedzi w kanale użytkownika (opis parametrów: `core.pii.filter_output`)."""
    return _filter_output(role, text, vault, own_texts, public_texts, threshold, redact, judge, enforce,
                          policy=current_policy(), detect=_detect)


def hide_tool_names(text: str) -> tuple[str, int]:
    """Zamienia nazwy wewnętrznych narzędzi w odpowiedzi na neutralny znacznik. Zwraca (tekst, ile zamian)."""
    return _hide_tool_names(text, TOOL_MAP)


# --- bramka narzędzi tury ---------------------------------------------------------------------------

class SecureToolGate:
    """Bramka narzędzi tury: decyzje `core.ToolGuard`, wykonanie lokalne i raportowanie postępu.

    Zwraca agentowi tekst zamiast wyniku narzędzia — przy odmowie jest to komunikat odmowy,
    przy zgodzie zamaskowany wynik. Agent sam nie wykonuje więc żadnego narzędzia.
    """

    def __init__(self, ctx: TurnContext, on_progress: Optional[Progress] = None,
                 events: Optional[list] = None, limits: Optional[dict] = None):
        self.ctx = ctx
        self.on_progress = on_progress
        self.events = events if events is not None else []
        self.guard = ToolGuard(ctx, self.spent, limits)

    def spent(self) -> tuple[int, float]:
        """Tokeny i koszt strefy chatbota od początku tury (model, subagent)."""
        calls = [e for e in self.events if e["type"] == "llm_call" and e["zone"] == "chatbot"]
        return sum(e.get("tokens", 0) for e in calls), sum(e.get("cost", 0) for e in calls)

    def _report(self, call: dict) -> None:
        if self.on_progress:
            self.on_progress("tool", call)
            self.on_progress("stage", {"stage": STAGE_MODEL})

    @property
    def calls(self) -> list[dict]:
        return self.guard.calls

    def __call__(self, name: str, args: dict) -> Optional[str]:
        decision = self.guard.before(name, args)
        call = decision.call
        if not decision.allowed:
            self._report(call)
            return decision.message

        tokens_before, cost_before = self.spent()
        result = run_tool(name, decision.real_args)
        tokens_after, cost_after = self.spent()
        outcome = self.guard.after(name, call, result)
        if not outcome.allowed:
            self._report(call)
            return outcome.text

        # Koszt wywołania: zużycie w jego trakcie (subagent) i to, ile wynik dokłada do kontekstu modelu.
        call.update(tokens=tokens_after - tokens_before, cost=cost_after - cost_before,
                    result_tokens=-(-len(outcome.text) // CHARS_PER_TOKEN))
        local = not self.ctx.policy.tool(name).chatbot_zone
        audit.record("tool_call", "local" if local else "chatbot", tool=name, allowed=True, args=args,
                     scan=outcome.scan, masked=outcome.stats, result_chars=len(outcome.text),
                     truncated_chars=outcome.cut, tokens=call["tokens"], cost=call["cost"],
                     result_tokens=call["result_tokens"])
        self._report(call)
        return outcome.text


# Wywołanie narzędzia wypisane jako tekst zamiast wykonane: <|tool_call>call:nazwa{...}<tool_call|>
_RAW_TOOL_CALL = re.compile(r"<\|?tool_call\|?>|\bcall:\w+\{")
_RETRY_MESSAGE = ("Your previous message contained a tool call written as plain text, so it was not executed. "
                  "If you need a tool, call it through the tool interface; otherwise answer in plain text.")


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


def run_turn(conv: Conversation, user_message: str, threshold: Optional[float] = None,
             on_progress: Optional[Progress] = None, limits: Optional[dict] = None) -> TurnResult:
    """Przeprowadza jedną wiadomość użytkownika przez całą warstwę bezpieczeństwa.

    `on_progress(rodzaj, dane)` dostaje kolejne etapy ("stage") i wywołania narzędzi ("tool").
    `limits` to pozostały budżet roli: {"tokens", "cost"}; zawęża limity jednej tury.
    """
    started = time.perf_counter()
    events = audit.start_turn()
    conv.turns += 1
    policy = current_policy()
    if threshold is None:
        threshold = policy.controls.pii.threshold
    ctx = TurnContext(conv, policy, _detect, policy_engine, threshold)
    gate = SecureToolGate(ctx, on_progress, events, limits)
    guard, flagged, guard_reason = None, False, None
    output = {"entities": [], "restored": [], "redacted": [], "blocked": [], "exempt": [], "found": []}
    leaks = 0
    refusal = None      # werdykt odmowy chatbota, jeśli ją wykryto

    def stage(name):
        if on_progress:
            on_progress("stage", {"stage": name})

    def finish(reply, verdict=None, masked_prompt="", entities=(), logged_reply="", error=None):
        blocked = bool(verdict and verdict["decision"] == "block")
        reason = verdict["stage"] if blocked else None
        # Do budżetu użytkownika liczy się tylko strefa chatbota. Strażnicy i sędziowie docelowo działają
        # na lokalnej infrastrukturze, więc ich zużycie zapisujemy osobno i nie obciążamy nim użytkownika.
        calls = [e for e in events if e["type"] == "llm_call"]
        tokens = sum(e.get("tokens", 0) for e in calls if e["zone"] == "chatbot")
        cost = sum(e.get("cost", 0) for e in calls if e["zone"] == "chatbot")
        security_tokens = sum(e.get("tokens", 0) for e in calls if e["zone"] != "chatbot")
        security_cost = sum(e.get("cost", 0) for e in calls if e["zone"] != "chatbot")
        latency = int((time.perf_counter() - started) * 1000)
        audit.record("turn", "security", blocked=blocked, block_reason=reason, verdict=verdict,
                     reply=logged_reply, leaks_to_chatbot=leaks, vault_size=len(conv.vault),
                     tokens=tokens, cost=cost, security_tokens=security_tokens,
                     security_cost=security_cost, latency_ms=latency)
        audit.flush(events, conversation=conv.id, role=conv.role, turn=conv.turns)
        # Ostrzeżenie strażnika zostaje obok decyzji innego etapu (np. redact), zamiast przez nią znikać.
        verdicts = [verdict] if verdict else []
        if flagged and not (verdict and verdict["stage"] == "prompt_guard"):
            verdicts.append({"decision": "warn", "stage": "prompt_guard", "reason": guard_reason})
        stopped = next((c for c in gate.calls if c.get("stage") == "budget"), None)
        if stopped:
            verdicts.append({"decision": "warn", "stage": "budget",
                             "reason": f"Przerwano wywołania narzędzi: {stopped['reason']}"})
        if refusal and refusal is not verdict:
            verdicts.append(refusal)
        masked = sorted({e["type"] for e in entities if e.get("decision") == "mask"})
        return TurnResult(reply, blocked, reason, guard, masked_prompt, list(entities), gate.calls,
                          output, leaks, events, verdict, tokens, latency, error, cost,
                          verdicts=verdicts, masked_for_model=masked)

    # 0-3. Zapytanie: długość, strażnik i intencja, regulaminy, maskowanie (core.check_request)
    request = check_request(ctx, user_message, baseline_filters=DEFAULT_FILTERS,
                            on_stage=lambda: stage(STAGE_REQUEST))
    guard, flagged, guard_reason = request.guard, request.flagged, request.guard_reason
    masked_prompt, entities = request.masked_prompt, request.entities
    if request.blocked:
        return finish(request.reply, request.verdict, masked_prompt, entities)

    # 4. Chatbot z bramką narzędzi
    stage(STAGE_MODEL)
    # Prompt systemowy chatbota zostaje nietknięty; informacje od warstwy idą w pierwszej wiadomości.
    sent = masked_prompt if conv.history else _notice(conv.role, policy) + masked_prompt
    try:
        raw_reply, new_history = agent.run_agent(sent, history=conv.history, tool_gate=gate)
    except agent.ResponseBlocked as exc:
        return finish(f"Odpowiedź została zablokowana: {exc}",
                      {"decision": "block", "stage": "tool_whitelist", "reason": str(exc)},
                      masked_prompt, entities)
    except Exception as exc:
        audit.record("error", "chatbot", error=type(exc).__name__)
        return finish(f"Błąd wykonania modelu: {exc}", None, masked_prompt, entities, error=str(exc))
    # Model czasem wypisuje wywołanie narzędzia jako tekst. Takiej odpowiedzi nie pokazujemy:
    # jedna ponowna próba, a potem błąd tury.
    if _RAW_TOOL_CALL.search(raw_reply or ""):
        audit.record("retry", "chatbot", reason="tool call written as text")
        try:
            raw_reply, new_history = agent.run_agent(_RETRY_MESSAGE, history=new_history, tool_gate=gate)
        except Exception as exc:
            audit.record("error", "chatbot", error=type(exc).__name__)
            return finish(f"Błąd wykonania modelu: {exc}", None, masked_prompt, entities, error=str(exc))
        if _RAW_TOOL_CALL.search(raw_reply or ""):
            audit.record("error", "chatbot", error="MalformedToolCall")
            return finish("Model nie zwrócił odpowiedzi.", None, masked_prompt, entities,
                          error="model zwrócił wywołanie narzędzia jako tekst zamiast odpowiedzi")
    conv.history = new_history
    leaks = _count_leaks(new_history, conv.vault)

    # 5. Odpowiedź: filtr w kanale użytkownika, regulaminy, odmowa chatbota, werdykt tury (core.check_response)
    stage(STAGE_REPLY)
    denied = sorted({c["tool"] for c in gate.calls if not c["allowed"]})
    response = check_response(ctx, raw_reply or "", user_message, request, denied_tools=denied,
                              tool_names=TOOL_MAP)
    output, refusal = response.output, response.refusal
    return finish(response.reply, response.verdict, masked_prompt, entities, response.logged_reply)
