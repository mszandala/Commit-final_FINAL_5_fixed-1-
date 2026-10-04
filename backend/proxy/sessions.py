"""Sesje proxy: stan rozmowy po stronie warstwy (sejf wartości ukrytych przed modelem, pamięć podręczna).

Sesja jest potrzebna, bo model widzi znaczniki (<EMAIL_1>), a klient prawdziwe wartości: odwrócenie
znaczników w odpowiedzi i w argumentach narzędzi wymaga sejfu z tej samej rozmowy. Sejf zawiera surowe
dane wrażliwe, więc żyje wyłącznie w pamięci i wygasa po bezczynności.
"""
import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.session import Conversation
from core.stages import RequestDecision

CACHE_LIMIT = 2000


@dataclass
class Turn:
    """Jedna tura: od wiadomości użytkownika do odpowiedzi końcowej; może obejmować kilka żądań HTTP."""
    request: RequestDecision
    user_message: str
    model: str
    limits: dict = field(default_factory=dict)       # pozostały budżet roli: {"tokens", "cost"}
    tokens: int = 0
    cost: float = 0.0
    denied: set = field(default_factory=set)         # narzędzia odrzucone w tej turze
    degraded: bool = False                           # tura wznowiona bez zapisanego stanu (sesja wygasła)


@dataclass
class ProxySession:
    id: str
    client: str
    conv: Conversation
    lock: threading.RLock = field(default_factory=threading.RLock)
    turn: Optional[Turn] = None
    tool_cache: dict = field(default_factory=dict)   # tool_call_id -> wynik narzędzia po sprawdzeniu i maskowaniu
    text_cache: dict = field(default_factory=dict)   # skrót tekstu -> tekst po zamaskowaniu (historia rozmowy)
    turns: int = 0
    last_seen: float = 0.0

    def remember(self, cache: dict, key: str, value: str) -> None:
        if len(cache) >= CACHE_LIMIT:
            cache.pop(next(iter(cache)))
        cache[key] = value


def derived_session_id(client: str, messages: list) -> str:
    """Identyfikator rozmowy, gdy klient nie przysłał X-Session-Id: skrót klienta i pierwszej wiadomości
    użytkownika. Kolejne żądania tej samej rozmowy dają ten sam identyfikator."""
    first = next((m.get("content") for m in messages if m.get("role") == "user"), "")
    return hashlib.sha256(f"{client}\n{first}".encode("utf-8")).hexdigest()[:16]


class SessionStore:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._sessions: dict[tuple[str, str], ProxySession] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._sessions)

    def get(self, client: str, session_id: str, role: str, ttl: float, max_sessions: int) -> ProxySession:
        """Istniejąca, nieprzeterminowana sesja klienta o tej samej roli albo nowa."""
        now = self._clock()
        key = (client, session_id)
        with self._lock:
            for stale in [k for k, s in self._sessions.items() if now - s.last_seen > ttl]:
                del self._sessions[stale]
            session = self._sessions.get(key)
            if session is None or session.conv.role != Conversation(role).role:
                while len(self._sessions) >= max_sessions:
                    del self._sessions[min(self._sessions, key=lambda k: self._sessions[k].last_seen)]
                session = ProxySession(session_id, client, Conversation(role))
                self._sessions[key] = session
            session.last_seen = now
            return session
