import re
from typing import TYPE_CHECKING, Optional

from security.common.roles import normalize_role
from security.common.verdicts import Verdict

if TYPE_CHECKING:
    from core.models import Policy

# Wzorzec "polecenie ignorowania": czasownik, do czterech słów dookreślających ("all previous", "wszystkie
# poprzednie", "o wszystkich") i rzecz, którą się ignoruje. Krótszy wzorzec z jednym słowem dookreślającym
# nie łapał kanonicznego "ignore all previous instructions" ani polskiego "instrukcje".
_IGNORE_VERBS = r"(?:ignor\w*|zignoruj\w*|disregard|forget|override|pomi[ńn]\w*|zapomnij|zlekceważ\w*)"
_MODIFIERS = (r"(?:all|any|every|the|your|of|previous|prior|above|earlier|former|those|these|about|"
              r"safety|security|system|content|ethical|bezpiecze\w*|systemow\w*|"
              r"wszystk\w*|wszelk\w*|poprzedni\w*|powyższ\w*|wcześniejsz\w*|dotychczasow\w*|swoje|twoje|moje|o)")
_TARGETS = (r"(?:instructions?|rules|prompts?|guidelines|directives|constraints|restrictions|"
            r"instrukcj\w*|zasad\w*|polece\w*|regu[łl]\w*|wytyczn\w*|ogranicze\w*|zabezpiecze\w*)")

# Wzorce znanych ataków (Jailbreak / Prompt Injection)
INJECTION_PATTERNS = [
    (r"\b(?:dan|do anything now)\b", "Wykryto sygnaturę jailbreak DAN (Do Anything Now)"),
    (rf"\b{_IGNORE_VERBS}\s+(?:{_MODIFIERS}\s+){{0,4}}{_TARGETS}", "Wykryto próbę ignorowania instrukcji systemowych"),
    (r"(?:from now on you are|od teraz jesteś|act as|wciel się w)", "Wykryto próbę nadpisania tożsamości / roli modelu"),
    (r"(?:new system directive|system prompt override|---BEGIN RESPONSE---)", "Wykryto próbę wstrzyknięcia dyrektywy systemowej"),
    (r"[A-Za-z0-9+/=]{50,}", "Wykryto potencjalnie zaciemniony ciąg Base64 / Payload"),
    (r"(?:jestem adminem|i am (?:the )?admin|bypass (?:all )?restrictions|bez ograniczeń)", "Wykryto próbę podszywania się pod administratora lub obejścia zasad"),
]

# Słowa kluczowe (rdzenie, bo polska odmiana) wskazujące zasób z config.RESOURCE_TOOLS.
RESOURCE_KEYWORDS = {
    "employee_data": [
        "salary", "salaries", "payroll", "monthlyincome", "monthly income", "employee", "attrition",
        "pensj", "wynagrodze", "zarob", "pracowni", "kadr", "rotacj",
    ],
    "client_data": [
        "customer", "client", "credit score", "credit_score", "churn",
        "klient", "scoring", "saldo", "salda",
    ],
    "bank_campaigns": [
        "campaign", "term deposit", "kampani", "lokat",
    ],
    "stock_prices": [
        "stock price", "closing price", "trading volume", "ticker", "nasdaq", "nyse",
        "notowa", "kurs akcji", "kursy akcji", "giełd",
    ],
    "earnings_calls": [
        "earnings call", "transcript", "telekonferencj", "transkrypcj",
    ],
}

RESOURCE_LABELS = {
    "employee_data":  "danych kadrowych i płacowych",
    "client_data":    "danych klientów banku",
    "bank_campaigns": "danych kampanii bankowych",
    "stock_prices":   "notowań giełdowych",
    "earnings_calls": "transkrypcji telekonferencji wynikowych",
}


_INJECTION_REGEXES = [(re.compile(p, re.IGNORECASE), d) for p, d in INJECTION_PATTERNS]


def _check_heuristic_injections(text: str) -> Optional[str]:
    """Szybka detekcja wzorców injection/jailbreak za pomocą regex."""
    for pattern, description in _INJECTION_REGEXES:
        if pattern.search(text):
            return description
    return None


def _role_access(canonical_role: str, policy: Optional["Policy"]) -> tuple[set, dict]:
    """(narzędzia roli, narzędzia każdego zasobu) z polityki; bez polityki z config.py (tryb zgodności)."""
    if policy is not None:
        cfg = policy.role(canonical_role)
        return (set(cfg.allowed_tools) if cfg else set()), policy.resources
    import config
    return set(config.ROLES.get(canonical_role, {}).get("allowed_tools", [])), config.RESOURCE_TOOLS


def _check_role_resource_access(canonical_role: str, text: str,
                                policy: Optional["Policy"] = None) -> Optional[tuple[str, str]]:
    """Sprawdza, czy zapytanie dotyczy zasobu, którego narzędzi rola nie ma w allowed_tools."""
    allowed_tools, resource_tools = _role_access(canonical_role, policy)
    text_lower = text.lower()

    for resource, keywords in RESOURCE_KEYWORDS.items():
        if not any(k in text_lower for k in keywords):
            continue
        tools = resource_tools.get(resource)
        if tools and allowed_tools.isdisjoint(tools):       # zasób bez przypisanych narzędzi nie ogranicza roli
            return resource, f"Rola '{canonical_role}' nie ma dostępu do {RESOURCE_LABELS[resource]}."
    return None


def check_prompt(role: str, user_prompt: str, policy: Optional["Policy"] = None) -> Verdict:
    """Ocenia zapytanie użytkownika pod kątem bezpieczeństwa i zgodności z rolą.

    Role i zasoby bierze z `policy`; bez niej z config.py (tryb zgodności dla starszych wywołań).

    Zgodnie z wymaganiem PoC:
      - Mechanizm NIE blokuje zapytania (is_blocked = False).
      - W razie wykrycia naruszenia lub ataku podnosi ostrzeżenie (decision = "warn").
      - Dla bezpiecznych zapytań zwraca decision = "pass".
    """
    canonical_role = normalize_role(role)
    clean_prompt = (user_prompt or "").strip()

    if not clean_prompt:
        return Verdict(
            decision="pass",
            reason="Pusty prompt",
            stage="prompt_guard",
            is_blocked=False,
            details={"role": canonical_role, "suspicious": False},
        )

    # 1. Sprawdzenie heurystyczne prób wstrzyknięć (Prompt Injection / Jailbreak)
    injection_reason = _check_heuristic_injections(clean_prompt)
    if injection_reason:
        return Verdict(
            decision="warn",
            reason=f"[OSTRZEŻENIE PROMPT GUARD] {injection_reason}",
            stage="prompt_guard",
            is_blocked=False,  # Celowo nie blokujemy - zgłaszamy ostrzeżenie
            details={
                "role": canonical_role,
                "suspicious": True,
                "attack_type": "Prompt_Injection",
                "warning": injection_reason,
            },
        )

    # 2. Sprawdzenie zgodności żądanego zasobu z rolą (RBAC Scope)
    resource_violation = _check_role_resource_access(canonical_role, clean_prompt, policy)
    if resource_violation:
        resource_name, violation_reason = resource_violation
        return Verdict(
            decision="warn",
            reason=f"[OSTRZEŻENIE PROMPT GUARD] {violation_reason}",
            stage="prompt_guard",
            is_blocked=False,  # Celowo nie blokujemy - zgłaszamy ostrzeżenie
            details={
                "role": canonical_role,
                "suspicious": False,
                "requested_resource": resource_name,
                "warning": violation_reason,
            },
        )

    # 3. Zapytanie zgodne z uprawnieniami
    return Verdict(
        decision="pass",
        reason="Prompt zgodny z rolą i bezpieczny",
        stage="prompt_guard",
        is_blocked=False,
        details={
            "role": canonical_role,
            "suspicious": False,
            "warning": None,
        },
    )
