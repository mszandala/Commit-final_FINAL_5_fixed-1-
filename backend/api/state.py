"""Stan serwera API: rozmowy, wiersze logu, budżety i odwzorowanie konfiguracji na config.py.

Wszystko żyje w pamięci procesu — restart serwera czyści rozmowy i log oraz przywraca konfigurację z .env.
"""
import copy
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import pipeline
from config import (
    CONTROLS,
    DATA_ACCESS,
    DEFAULT_ROLE_PII_POLICY,
    ID_TYPES,
    PII_SENSITIVITY_LEVELS,
    ROLES,
    SETTINGS,
    Settings,
)
from security.budget import Budget

# Typy PII, o których decyduje konfiguracja roli (reszta jest globalna albo dotyczy identyfikatorów).
ROLE_PII_TAGS = [t for t, action in DEFAULT_ROLE_PII_POLICY.items() if action == "redact" and t not in ID_TYPES]
AREA_TOOLS = {tool for area in DATA_ACCESS.values() for tool in area["tools"]}

ROLE_BY_ID = {cfg["id"]: name for name, cfg in ROLES.items()}

_DEFAULT_SETTINGS = asdict(SETTINGS)
_DEFAULT_ROLES = copy.deepcopy(ROLES)

budget = Budget()


# --- konfiguracja ----------------------------------------------------------------------------

def role_access(name: str, roles: dict = ROLES) -> list[str]:
    allowed = set(roles[name]["allowed_tools"])
    return [area for area, cfg in DATA_ACCESS.items() if set(cfg["tools"]) <= allowed]


def role_pii(name: str, roles: dict = ROLES) -> list[str]:
    return [t for t in ROLE_PII_TAGS if t in roles[name]["allowed_pii"]]


def set_role(name: str, access: list[str], pii: list[str]) -> None:
    """Zapisuje obszary dostępu i typy PII roli; narzędzia i typy spoza formularza zostają."""
    cfg = ROLES[name]
    kept_tools = [t for t in cfg["allowed_tools"] if t not in AREA_TOOLS]
    cfg["allowed_tools"] = [t for area in DATA_ACCESS if area in access for t in DATA_ACCESS[area]["tools"]] + kept_tools
    kept_pii = [t for t in cfg["allowed_pii"] if t not in ROLE_PII_TAGS]
    cfg["allowed_pii"] = [t for t in ROLE_PII_TAGS if t in pii] + kept_pii


def sensitivity_id(threshold: float) -> Optional[str]:
    return next((l["id"] for l in PII_SENSITIVITY_LEVELS if abs(l["threshold"] - threshold) < 1e-9), None)


def default_config() -> tuple[Settings, dict]:
    """Ustawienia i role startowe, bez ich stosowania."""
    return Settings(**_DEFAULT_SETTINGS), _DEFAULT_ROLES


def reset_config() -> None:
    for key, value in _DEFAULT_SETTINGS.items():
        setattr(SETTINGS, key, value)
    for name, cfg in _DEFAULT_ROLES.items():
        ROLES[name].clear()
        ROLES[name].update(copy.deepcopy(cfg))


# --- rozmowy ---------------------------------------------------------------------------------

@dataclass
class Session:
    conversation: pipeline.Conversation
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def get_session(role: str, conversation_id: Optional[str]) -> Optional[Session]:
    """Zwraca istniejącą rozmowę albo zakłada nową; None, gdy podane id nie istnieje."""
    with _sessions_lock:
        if conversation_id is None:
            session = Session(pipeline.Conversation(role))
            _sessions[session.conversation.id] = session
            return session
        return _sessions.get(conversation_id)


def drop_session(conversation_id: str) -> bool:
    with _sessions_lock:
        return _sessions.pop(conversation_id, None) is not None


# --- log -------------------------------------------------------------------------------------

_events: list[dict] = []
_events_lock = threading.Lock()


def _summarize(result: Optional[pipeline.TurnResult], verdict: Optional[dict], tools: list) -> tuple[str, Optional[str], str]:
    """Jeden wiersz logu na turę: (decyzja, etap, powód).

    Ostrzeżenie strażnika promptu nie ginie, gdy turę opisuje inny etap — trafia na koniec powodu.
    """
    decision, stage, reason = _decide(result, verdict, tools)
    warn = next((v for v in (result.verdicts if result else []) if v["decision"] == "warn"), None)
    if warn and stage != warn["stage"]:
        reason = f'{reason}; Oflagowano: {warn["reason"]}'
    return decision, stage, reason


def _decide(result: Optional[pipeline.TurnResult], verdict: Optional[dict], tools: list) -> tuple[str, Optional[str], str]:
    if result and result.error:
        return "Error", None, f"Błąd wywołania modelu: {result.error}"
    if verdict and verdict["decision"] == "block":
        return "Blocked", verdict["stage"], verdict["reason"]
    denied = next((c for c in tools if not c["allowed"]), None)
    if denied:
        return "Blocked", denied["stage"], f'{denied["tool"]}: {denied["reason"]}'
    if verdict and verdict["decision"] == "redact":
        return "Redacted", verdict["stage"], verdict["reason"]
    if verdict and verdict["decision"] == "warn":
        return "Allowed", verdict["stage"], f'Oflagowano: {verdict["reason"]}'
    if result and result.output.get("found"):
        types = ", ".join(sorted(set(result.output["found"])))
        return "Allowed", "pii_policy", f"Wykryto: {types} (maskowanie wyłączone)"
    return "Allowed", None, ""


def add_event(role: str, conversation_id: str, verdict: Optional[dict],
              result: Optional[pipeline.TurnResult] = None) -> dict:
    tools = result.tool_calls if result else []
    decision, stage, reason = _summarize(result, verdict, tools)
    cfg = ROLES[role]
    with _events_lock:
        event = {
            "id": len(_events) + 1,
            "time": datetime.now(timezone.utc),
            "user": cfg["user"],
            "role": cfg["label"],
            "role_id": cfg["id"],
            "conversation_id": conversation_id,
            "decision": decision,
            "stage": stage,
            "control": CONTROLS.get(stage, stage or ""),
            "reason": reason,
            "masked_for_model": result.masked_for_model if result else [],
            "model": next((e.get("model") for e in result.events
                           if e["type"] == "llm_call" and e["zone"] == "chatbot"), None) if result else None,
            "tokens": result.tokens if result else 0,
            "latency_ms": result.latency_ms if result else 0,
            "masked_prompt": result.masked_prompt if result else "",
            "tools": tools,
            "leaks_to_chatbot": result.leaks_to_chatbot if result else 0,
            "trail": result.events if result else [],
        }
        _events.append(event)
        return event


def list_events(after_id: Optional[int] = None, limit: int = 200, decision: Optional[str] = None) -> list[dict]:
    """Wiersze od najstarszego. Bez `after_id` ostatnie `limit` wierszy, z nim — kolejne `limit` po nim."""
    with _events_lock:
        rows = [e for e in _events if e["id"] > (after_id or 0) and (decision is None or e["decision"] == decision)]
    return rows[:limit] if after_id is not None else rows[-limit:]


def get_event(event_id: int) -> Optional[dict]:
    with _events_lock:
        return _events[event_id - 1] if 0 < event_id <= len(_events) else None


def reset_state() -> None:
    """Czyści rozmowy, log i budżety (testy)."""
    with _sessions_lock:
        _sessions.clear()
    with _events_lock:
        _events.clear()
    budget.reset()
