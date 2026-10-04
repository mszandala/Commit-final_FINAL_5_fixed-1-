import json
import logging
import sys
import threading
import time
from contextvars import ContextVar
from typing import Optional

from config import AUDIT_LOG, AUDIT_SINK

log = logging.getLogger("control_layer.audit")

# Dawny zapis podsumowań tur. Tury są teraz w bazie (audit/store.py); plik służy już tylko do
# jednorazowego przeniesienia starszych wpisów.
TURNS_LOG = AUDIT_LOG.with_name("turns.jsonl")

# Zdarzenia bieżącej tury; pipeline ustawia kolektor, a moduły dopisują do niego przez record().
_collector: ContextVar[Optional[list]] = ContextVar("_audit_collector", default=None)
# Zegar tury: (start tury, chwila poprzedniego zdarzenia) — z niego liczymy czas każdego kroku.
_clock: ContextVar[Optional[list]] = ContextVar("_audit_clock", default=None)

# Zapis jednej tury to jeden blok linii; blokada nie pozwala przeplatać bloków równoległych tur.
_write_lock = threading.Lock()
_warned = False


def start_turn() -> list:
    events: list = []
    _collector.set(events)
    now = time.perf_counter()
    _clock.set([now, now])
    return events


def record(event_type: str, zone: str, **fields) -> None:
    """Dopisuje zdarzenie do bieżącej tury. Pola nie mogą zawierać surowych wartości wrażliwych.

    `at_ms` to czas od początku tury, `ms` — od poprzedniego zdarzenia, czyli czas trwania kroku
    (zdarzenie jest zapisywane, gdy krok się kończy).
    """
    events = _collector.get()
    if events is None:
        return
    clock = _clock.get()
    now = time.perf_counter()
    events.append({"ts": round(time.time(), 3), "at_ms": int((now - clock[0]) * 1000),
                   "ms": int((now - clock[1]) * 1000), "type": event_type, "zone": zone, **fields})
    clock[1] = now


def _warn_once(exc: Exception) -> None:
    global _warned
    if not _warned:
        _warned = True
        log.warning("Nie można zapisać logu audytu do %s (%s). Tury działają dalej, a zdarzenia są w pamięci i "
                    "w bazie rozmów. Wskaż zapisywalny katalog zmienną STATE_DIR albo ustaw AUDIT_SINK=stdout.",
                    AUDIT_LOG, type(exc).__name__)


def flush(events: list, **common) -> None:
    """Zapisuje zdarzenia tury do wybranego ujścia (AUDIT_SINK): plik JSONL, stdout albo oba.

    Błąd zapisu pliku nie przerywa tury: log audytu jest wtedy niepełny, a ostrzeżenie pojawia się raz.
    """
    _collector.set(None)
    if not events:
        return
    lines = "".join(json.dumps({**common, **event}, ensure_ascii=False) + "\n" for event in events)
    if AUDIT_SINK in ("stdout", "both"):
        sys.stdout.write(lines)
        sys.stdout.flush()
    if AUDIT_SINK in ("file", "both"):
        try:
            with _write_lock:
                AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
                with open(AUDIT_LOG, "a", encoding="utf-8") as f:
                    f.write(lines)
        except OSError as exc:
            _warn_once(exc)


def load_turns(limit: int = 2000) -> list[dict]:
    """Ostatnie `limit` podsumowań tur z pliku; uszkodzone linie są pomijane."""
    if not TURNS_LOG.exists():
        return []
    rows = []
    with open(TURNS_LOG, encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows[-limit:]
