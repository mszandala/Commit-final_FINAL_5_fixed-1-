import sqlite3
import threading
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import config
from config import MAX_SPENDING, ROLES

CHARS_PER_TOKEN = 4     # zgrubny przelicznik do oceny wiadomości przed wysłaniem


class Budget:
    """Dwa limity na rolę: dzienny budżet tokenów i łączny limit wydatków w dolarach (MAX_SPENDING).

    Zużycie jest zapisywane w SQLite, więc przetrwa restart serwera. Wydatki trafiają do tabeli
    `spending` w tym samym układzie, którego używa chat_testing.py (user_type = id roli).
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._path = db_path
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

    def token_limit(self, role: str) -> int:
        return ROLES[role]["daily_token_budget"]

    def tokens_used(self, role: str) -> int:
        return int(self._query(
            "SELECT COALESCE(SUM(tokens), 0) FROM token_usage WHERE user_type = ? AND day = ?",
            (ROLES[role]["id"], date.today().isoformat())))

    def spent(self, role: str) -> float:
        return float(self._query(
            "SELECT COALESCE(SUM(amount), 0) FROM spending WHERE user_type = ?", (ROLES[role]["id"],)))

    def add(self, role: str, tokens: int, cost: float = 0.0, model: Optional[str] = None) -> None:
        role_id = ROLES[role]["id"]
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
        if self.spent(role) > MAX_SPENDING:
            return {"decision": "block", "stage": "budget",
                    "reason": f"Przekroczono limit wydatków roli (${MAX_SPENDING:.2f})"}
        needed = -(-len(message) // CHARS_PER_TOKEN)
        if self.tokens_used(role) + needed > self.token_limit(role):
            return {"decision": "block", "stage": "budget", "reason": "Dzienny budżet tokenów został wyczerpany"}
        return None

    def reset(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM token_usage")
            conn.execute("DELETE FROM spending")
