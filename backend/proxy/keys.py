"""Klucze API klientów proxy: w pliku polityki leży tylko skrót SHA-256, nigdy jawny klucz."""
import hashlib
import secrets


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_key(prefix: str = "sk-ctl") -> str:
    return f"{prefix}-{secrets.token_urlsafe(24)}"
