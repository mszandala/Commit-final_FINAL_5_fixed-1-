import json
import time
from contextvars import ContextVar
from typing import Optional

from config import AUDIT_LOG

# Zdarzenia bieżącej tury; pipeline ustawia kolektor, a moduły dopisują do niego przez record().
_collector: ContextVar[Optional[list]] = ContextVar("_audit_collector", default=None)


def start_turn() -> list:
    events: list = []
    _collector.set(events)
    return events


def record(event_type: str, zone: str, **fields) -> None:
    """Dopisuje zdarzenie do bieżącej tury. Pola nie mogą zawierać surowych wartości wrażliwych."""
    events = _collector.get()
    if events is not None:
        events.append({"ts": round(time.time(), 3), "type": event_type, "zone": zone, **fields})


def flush(events: list, **common) -> None:
    """Zapisuje zdarzenia tury do pliku JSONL (jedno zdarzenie na linię)."""
    _collector.set(None)
    if not events:
        return
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps({**common, **event}, ensure_ascii=False) + "\n")
