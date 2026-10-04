"""Proxy zgodne z OpenAI, które stawia warstwę bezpieczeństwa między aplikacją a modelem."""
import threading
from typing import Optional

from .app import create_router
from .engine import ProxyEngine, ProxyError, ProxyResult
from .sessions import SessionStore

_engine: Optional[ProxyEngine] = None
_lock = threading.Lock()


def get_engine() -> ProxyEngine:
    """Wspólny silnik procesu (leniwie), do podpięcia w aplikacji."""
    global _engine
    with _lock:
        if _engine is None:
            _engine = ProxyEngine()
        return _engine


__all__ = ["ProxyEngine", "ProxyError", "ProxyResult", "SessionStore", "create_router", "get_engine"]
