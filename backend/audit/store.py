"""Trwały zapis rozmów: tury (wiersze logu API ze śladem kroków) i komentarze do rozmów.

Baza SQLite obok logu audytu. Treści są w tej samej, zamaskowanej postaci co w logu — surowe
wartości wrażliwe tu nie trafiają.
"""
import json
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from typing import Optional

from audit import logger

# Ścieżka czytana przy każdym połączeniu, żeby testy mogły ją podmienić.
DB_PATH = logger.AUDIT_LOG.with_name("conversations.db")

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS turns (
            id INTEGER PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            time TEXT NOT NULL,
            role_id TEXT NOT NULL,
            data TEXT NOT NULL
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS turns_conversation ON turns (conversation_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id TEXT NOT NULL,
            event_id INTEGER,
            author TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS comments_conversation ON comments (conversation_id)")
    return conn


# --- tury ------------------------------------------------------------------------------------

def add_turn(row: dict) -> None:
    """Zapisuje wiersz logu tury; `row["time"]` jako napis ISO, `row["id"]` nadaje wywołujący."""
    with _lock, closing(_connect()) as conn, conn:
        conn.execute("INSERT INTO turns (id, conversation_id, time, role_id, data) VALUES (?, ?, ?, ?, ?)",
                     (row["id"], row["conversation_id"], row["time"], row["role_id"],
                      json.dumps(row, ensure_ascii=False, default=str)))


def load_turns(limit: int = 2000) -> list[dict]:
    """Ostatnie `limit` tur, od najstarszej. Pusta baza przejmuje raz tury z dawnego pliku turns.jsonl."""
    with _lock, closing(_connect()) as conn, conn:
        if conn.execute("SELECT COUNT(*) FROM turns").fetchone()[0] == 0:
            for row in logger.load_turns(limit=10**9):
                conn.execute("INSERT OR IGNORE INTO turns (id, conversation_id, time, role_id, data) VALUES (?, ?, ?, ?, ?)",
                             (row["id"], row["conversation_id"], row["time"], row["role_id"],
                              json.dumps(row, ensure_ascii=False, default=str)))
        rows = conn.execute("SELECT data FROM turns ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [json.loads(r["data"]) for r in reversed(rows)]


# --- komentarze ------------------------------------------------------------------------------

def _comment(row: sqlite3.Row) -> dict:
    return {**dict(row), "time": datetime.fromisoformat(row["time"])}


def add_comment(conversation_id: str, text: str, author: str, event_id: Optional[int] = None) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with _lock, closing(_connect()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO comments (conversation_id, event_id, author, text, time) VALUES (?, ?, ?, ?, ?)",
            (conversation_id, event_id, author, text, now))
        row = conn.execute("SELECT * FROM comments WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _comment(row)


def list_comments(conversation_id: Optional[str] = None) -> list[dict]:
    """Komentarze jednej rozmowy albo — bez argumentu — wszystkie, od najstarszego."""
    query, params = "SELECT * FROM comments", ()
    if conversation_id is not None:
        query, params = query + " WHERE conversation_id = ?", (conversation_id,)
    with _lock, closing(_connect()) as conn:
        return [_comment(r) for r in conn.execute(query + " ORDER BY id", params).fetchall()]


def delete_comment(comment_id: int) -> bool:
    with _lock, closing(_connect()) as conn, conn:
        return conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,)).rowcount > 0


def comment_counts() -> dict[str, int]:
    with _lock, closing(_connect()) as conn:
        return {r[0]: r[1] for r in conn.execute(
            "SELECT conversation_id, COUNT(*) FROM comments GROUP BY conversation_id").fetchall()}


def clear() -> None:
    """Usuwa wszystkie tury i komentarze (testy)."""
    with _lock, closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM turns")
        conn.execute("DELETE FROM comments")
