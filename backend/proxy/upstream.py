"""Klient modelu, do którego proxy przekazuje zapytania (domyślnie OpenRouter, API zgodne z OpenAI)."""
from typing import Callable, Optional

import config

# Wywołanie modelu: parametry zapytania (słownik w formacie chat.completions) -> odpowiedź jako słownik.
Upstream = Callable[[dict], dict]


class UpstreamError(Exception):
    def __init__(self, status: Optional[int] = None, kind: str = "UpstreamError"):
        super().__init__(kind)
        self.status = status
        self.kind = kind


class OpenAIUpstream:
    """Przekazuje zapytanie do dostawcy zgodnego z OpenAI. Klucz i adres z konfiguracji procesu; klucz
    ustawiony w panelu konfiguracji (SETTINGS) ma pierwszeństwo przed zmienną środowiskową."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or config.OPENROUTER_BASE_URL
        self._api_key = api_key

    def _key(self) -> str:
        return self._api_key or config.SETTINGS.openrouter_api_key or config.OPENROUTER_API_KEY

    def __call__(self, params: dict) -> dict:
        from openai import APIConnectionError, APIStatusError, OpenAI
        key = self._key()
        if not key:
            raise UpstreamError(503, "MissingUpstreamKey")
        client = OpenAI(base_url=self.base_url, api_key=key, timeout=120)
        extra = {"extra_body": {"usage": {"include": True}}} if "openrouter" in self.base_url else {}
        try:
            return client.chat.completions.create(**params, **extra).model_dump()
        except APIStatusError as exc:
            raise UpstreamError(exc.status_code, type(exc).__name__) from None
        except APIConnectionError as exc:
            raise UpstreamError(502, type(exc).__name__) from None
