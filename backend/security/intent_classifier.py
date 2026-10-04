"""Rozpoznawanie intencji: czy zapytanie mieści się w pracy roli użytkownika.

Klasyfikator LLM w strefie bezpieczeństwa (widzi dane surowe). Dostaje opis roli i obszary danych
z polityki (config.ROLES / DATA_ACCESS bez niej), poprzednie wiadomości użytkownika (żeby dopytanie "a ile to razem?"
nie było oceniane w oderwaniu) i wynik strażnika regex jako podpowiedź.
"""
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from chatbot import llm_client

if TYPE_CHECKING:
    from core.models import Policy

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


def _role_context(role: str, policy: Optional["Policy"]) -> tuple[str, list[str], list[str]]:
    """(opis roli, dostępne obszary danych, obszary niedostępne) z polityki; bez niej z config.py."""
    if policy is not None:
        cfg = policy.role(role)
        allowed = policy.role_areas(role)
        return (cfg.description if cfg else ""), allowed, [a.label for a in policy.areas.values()
                                                           if a.label not in allowed]
    import config
    from security.tool_whitelist import role_areas
    allowed = role_areas(role)
    return (config.ROLES.get(role, {}).get("description", ""), allowed,
            [a["label"] for a in config.DATA_ACCESS.values() if a["label"] not in allowed])


def classify_intent(role: str, prompt: str, previous=(), hint: Optional[str] = None,
                    policy: Optional["Policy"] = None) -> dict:
    """Zwraca {"category", "reason", "error"}. Gdy klasyfikator zawiedzie albo odpowie nieczytelnie,
    `category` jest None, a `error` mówi dlaczego — decyzję podejmuje wtedy sam strażnik regex."""
    description, allowed, restricted = _role_context(role, policy)
    message = _PROMPT.format(
        role=role,
        role_description=description,
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
