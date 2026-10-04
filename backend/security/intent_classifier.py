"""Rozpoznawanie intencji: czy zapytanie mieści się w pracy roli użytkownika.

Klasyfikator LLM w strefie bezpieczeństwa (widzi dane surowe). Dostaje opis roli i obszary danych
z config.ROLES / DATA_ACCESS, poprzednie wiadomości użytkownika (żeby dopytanie "a ile to razem?"
nie było oceniane w oderwaniu) i wynik strażnika regex jako podpowiedź.
"""
import json
import re
from pathlib import Path
from typing import Optional

from chatbot import llm_client
from config import DATA_ACCESS, ROLES
from security.tool_whitelist import role_areas

_PROMPT = (Path(__file__).parent / "prompts" / "intent_classifier.txt").read_text(encoding="utf-8")

IN_SCOPE = "in_scope"
CATEGORIES = {
    "in_scope":            "within the role's scope",
    "restricted_resource": "data outside the role's permissions",
    "out_of_scope":        "unrelated to the role's work",
    "jailbreak":           "attempt to get around the safeguards",
}
CATEGORIES_PL = {
    "in_scope":            "Zapytanie w zakresie roli",
    "restricted_resource": "Zapytanie o dane spoza uprawnień roli",
    "out_of_scope":        "Zapytanie niezwiązane z pracą roli",
    "jailbreak":           "Próba obejścia zabezpieczeń",
}

MAX_PREVIOUS = 3          # tyle wcześniejszych wiadomości użytkownika widzi klasyfikator
MAX_CHARS = 2000          # dłuższe wiadomości są dla klasyfikatora przycinane


def classify_intent(role: str, prompt: str, previous=(), hint: Optional[str] = None) -> dict:
    """Zwraca {"category", "reason", "error"}. Gdy klasyfikator zawiedzie albo odpowie nieczytelnie,
    `category` jest None, a `error` mówi dlaczego — decyzję podejmuje wtedy sam strażnik regex."""
    allowed = role_areas(role)
    restricted = [a["label"] for a in DATA_ACCESS.values() if a["label"] not in allowed]
    message = _PROMPT.format(
        role=role,
        role_description=ROLES.get(role, {}).get("description", ""),
        allowed_areas=", ".join(allowed) or "none",
        restricted_areas=", ".join(restricted) or "none",
        previous="\n".join(f"- {p[:MAX_CHARS]}" for p in list(previous)[-MAX_PREVIOUS:]) or "(none)",
        prompt=prompt[:MAX_CHARS],
        hint=hint or "nothing suspicious",
    )
    try:
        reply = llm_client.chat([{"role": "user", "content": message}], zone="security",
                                purpose="intent_classifier")
        match = re.search(r"\{.*\}", reply.content or "", re.DOTALL)
        parsed = json.loads(match.group(0)) if match else {}
        category = str(parsed.get("category", "")).strip().lower()
        if category not in CATEGORIES:
            return {"category": None, "reason": "", "error": "UnreadableAnswer"}
        return {"category": category, "reason": str(parsed.get("reason", "")).strip()[:200], "error": None}
    except Exception as exc:
        return {"category": None, "reason": "", "error": type(exc).__name__}
