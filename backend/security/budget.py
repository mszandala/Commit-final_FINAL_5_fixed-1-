import threading
from datetime import date
from typing import Optional

from config import ROLES

CHARS_PER_TOKEN = 4     # zgrubny przelicznik do oceny wiadomości przed wysłaniem


class TokenBudget:
    """Dzienny budżet tokenów użytkownika danej roli. Stan żyje w pamięci procesu."""

    def __init__(self):
        self._lock = threading.Lock()
        self._day = date.today()
        self._used: dict[str, int] = {}

    def _roll_over(self) -> None:
        if date.today() != self._day:
            self._day = date.today()
            self._used.clear()

    def limit(self, role: str) -> int:
        return ROLES[role]["daily_token_budget"]

    def used(self, role: str) -> int:
        with self._lock:
            self._roll_over()
            return self._used.get(role, 0)

    def add(self, role: str, tokens: int) -> None:
        with self._lock:
            self._roll_over()
            self._used[role] = self._used.get(role, 0) + tokens

    def check(self, role: str, message: str) -> Optional[dict]:
        """Werdykt blokady, jeśli wiadomość nie mieści się w pozostałym budżecie; inaczej None."""
        needed = -(-len(message) // CHARS_PER_TOKEN)
        if self.used(role) + needed > self.limit(role):
            return {"decision": "block", "stage": "budget", "reason": "Dzienny budżet tokenów został wyczerpany"}
        return None

    def reset(self) -> None:
        with self._lock:
            self._used.clear()
