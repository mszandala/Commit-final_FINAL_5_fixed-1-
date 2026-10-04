"""Module audit log: JSONL, one line per decision. Persists content hash and length instead of raw payload."""
import hashlib
import json
import os
import threading
import weakref
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from security.company_policies.policy import MODULE_DIR

DEFAULT_AUDIT_PATH = Path(os.getenv("COMPANY_POLICIES_AUDIT_LOG", MODULE_DIR / "logs" / "audit.jsonl"))


def content_digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Optional[Path] = DEFAULT_AUDIT_PATH, keep: int = 1000):
        self.path = Path(path) if path else None
        self.events: deque[dict] = deque(maxlen=keep)  # In-memory buffer of recent events
        self._lock = threading.Lock()
        self._file = None

    def write(self, event: dict) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with self._lock:
            self.events.append(event)
            if self.path is None:
                return
            if self._file is None:
                # File opened once rather than per decision; flushed after each line.
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._file = open(self.path, "a", encoding="utf-8")
                weakref.finalize(self, self._file.close)
            self._file.write(line)
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None
