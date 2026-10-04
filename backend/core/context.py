"""Kontekst jednej tury: wszystko, czego potrzebują etapy sprawdzania, podane jawnie.

Etapy nie sięgają po globalną konfigurację ani po konkretny detektor: dostają politykę (niezmienną
migawkę na czas tury) i zależności. Dzięki temu te same funkcje obsługują zarówno demo (polityka
zbudowana z żywej konfiguracji), jak i proxy (polityka z pliku).
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import Policy
from .session import Conversation

# (tekst, próg) -> lista encji {"type", "text", "start", "end", ...}; ma już odrzucać wykrycia
# o złej budowie (patrz core.pii.well_formed).
Detect = Callable[[str, Optional[float]], list]


@dataclass
class TurnContext:
    conv: Conversation
    policy: Policy
    detect: Detect
    engine_factory: Optional[Callable[[], Optional[Any]]] = None   # silnik regulaminów albo None, gdy wyłączony
    threshold: Optional[float] = None                              # próg detektora PII; None = domyślny
    _engine: Any = field(default=None, init=False, repr=False)
    _engine_resolved: bool = field(default=False, init=False, repr=False)

    def __post_init__(self):
        # Pseudonimy identyfikatorów (stałe HMAC zamiast kolejnych znaczników) wyznacza polityka tury.
        self.conv.vault.id_types = tuple(self.policy.pii.id_types)

    @property
    def role(self) -> str:
        return self.conv.role

    @property
    def engine(self) -> Optional[Any]:
        """Silnik regulaminów firmowych, tworzony przy pierwszym użyciu (może być kosztowny),
        więc tura zatrzymana wcześniej go nie ładuje."""
        if not self._engine_resolved:
            self._engine = self.engine_factory() if self.engine_factory else None
            self._engine_resolved = True
        return self._engine
