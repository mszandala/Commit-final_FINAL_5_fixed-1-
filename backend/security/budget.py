import sqlite3
import threading
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

import config
from config import MAX_SPENDING

if TYPE_CHECKING:
    from core.models import Policy

CHARS_PER_TOKEN = 4     # zgrubny przelicznik do oceny wiadomości przed wysłaniem


class Budget:
    """Dwa limity na rolę: dzienny budżet tokenów i łączny limit wydatków w dolarach.

    Zużycie jest zapisywane w SQLite, więc przetrwa restart serwera. Wydatki trafiają do tabeli
    `spending` w tym samym układzie, którego używa chat_testing.py (user_type = id roli).

    Limity i identyfikatory ról pochodzą z polityki, gdy podano jej źródło (`policy`: wywołanie zwracające
    aktualną politykę, więc zmiana pliku działa od następnego sprawdzenia). Bez niego (tryb zgodności dla
    dema) z config.py: ROLES i MAX_SPENDING.
    """

    def __init__(self, db_path: Optional[Path] = None, policy: Optional[Callable[[], "Policy"]] = None):
        self._path = db_path
        self._policy = policy
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path or config.SPENDING_DB)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS spending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_type TEXT NOT NULL,
                amount REAL NOT NULL,
                total_openrouter_usage REAL,
                model TEXT,
                created_at TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS token_usage (
                user_type TEXT NOT NULL,
                day TEXT NOT NULL,
                tokens INTEGER NOT NULL,
                PRIMARY KEY (user_type, day)
            )""")
        return conn

    def _query(self, sql: str, params: tuple) -> float:
        with self._lock, closing(self._connect()) as conn:
            return conn.execute(sql, params).fetchone()[0]

    def _role(self, role: str) -> tuple[str, int]:
        """(identyfikator roli w bazie, dzienny budżet tokenów); KeyError dla nieznanej roli."""
        if self._policy is not None:
            cfg = self._policy().role(role)
            if cfg is None:
                raise KeyError(role)
            return cfg.id, cfg.daily_tokens
        cfg = config.ROLES[role]
        return cfg["id"], cfg["daily_token_budget"]

    def _role_ids(self) -> list[str]:
        if self._policy is not None:
            return [cfg.id for cfg in self._policy().roles.values()]
        return [cfg["id"] for cfg in config.ROLES.values()]

    def spending_limit(self) -> float:
        """Łączny limit wydatków roli w dolarach."""
        return self._policy().budgets.spending_limit_usd if self._policy is not None else MAX_SPENDING

    def token_limit(self, role: str) -> int:
        return self._role(role)[1]

    def tokens_used(self, role: str) -> int:
        return int(self._query(
            "SELECT COALESCE(SUM(tokens), 0) FROM token_usage WHERE user_type = ? AND day = ?",
            (self._role(role)[0], date.today().isoformat())))

    def spent(self, role: str) -> float:
        return float(self._query(
            "SELECT COALESCE(SUM(amount), 0) FROM spending WHERE user_type = ?", (self._role(role)[0],)))

    def add(self, role: str, tokens: int, cost: float = 0.0, model: Optional[str] = None) -> None:
        role_id = self._role(role)[0]
        with self._lock, closing(self._connect()) as conn, conn:
            if tokens:
                conn.execute(
                    "INSERT INTO token_usage (user_type, day, tokens) VALUES (?, ?, ?) "
                    "ON CONFLICT (user_type, day) DO UPDATE SET tokens = tokens + excluded.tokens",
                    (role_id, date.today().isoformat(), tokens))
            if cost > 0:
                conn.execute(
                    "INSERT INTO spending (user_type, amount, total_openrouter_usage, model, created_at) "
                    "VALUES (?, ?, NULL, ?, ?)",
                    (role_id, cost, model, datetime.now(timezone.utc).isoformat()))

    def check(self, role: str, message: str) -> Optional[dict]:
        """Werdykt blokady, jeśli któryś limit jest wyczerpany; inaczej None."""
        limit = self.spending_limit()
        if self.spent(role) > limit:
            return {"decision": "block", "stage": "budget",
                    "reason": f"Przekroczono limit wydatków roli (${limit:.2f})"}
        needed = -(-len(message) // CHARS_PER_TOKEN)
        if self.tokens_used(role) + needed > self.token_limit(role):
            return {"decision": "block", "stage": "budget", "reason": "Dzienny budżet tokenów został wyczerpany"}
        return None

    def reset(self, role: Optional[str] = None) -> None:
        """Zeruje zużycie tokenów i wydatki jednej roli albo — bez argumentu — wszystkich ról."""
        role_ids = [self._role(role)[0]] if role else self._role_ids()
        marks = ", ".join("?" * len(role_ids))
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(f"DELETE FROM token_usage WHERE user_type IN ({marks})", role_ids)
            conn.execute(f"DELETE FROM spending WHERE user_type IN ({marks})", role_ids)
