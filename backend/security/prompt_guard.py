import json
import re
from pathlib import Path
from typing import Optional

from config import ROLES
from security.verdicts import Verdict

ROLE_ALIASES = {
    "basic_user": "podstawowy użytkownik",
    "user": "podstawowy użytkownik",
    "guest": "podstawowy użytkownik",
    "podstawowy użytkownik": "podstawowy użytkownik",
    "hr": "kadry",
    "kadry": "kadry",
    "admin": "administrator",
    "administrator": "administrator",
    "banker": "bankier",
    "it": "IT",
    "analyst": "analityk",
    "analityk": "analityk",
    "lawyer": "prawnik",
    "prawnik": "prawnik",
    "portfolio_manager": "Portfolio Manager",
    "pm": "Portfolio Manager",
    "Portfolio Manager": "Portfolio Manager",
}

# Wzorce znanych ataków (Jailbreak / Prompt Injection)
INJECTION_PATTERNS = [
    (r"\b(?:dan|do anything now)\b", "Wykryto sygnaturę jailbreak DAN (Do Anything Now)"),
    (r"(?:ignore|zignoruj)\s+(?:all|previous|wszystkie|poprzednie)?\s*(?:instructions|rules|zasady|polecenia)", "Wykryto próbę ignorowania instrukcji systemowych"),
    (r"(?:from now on you are|od teraz jesteś|act as|wciel się w)", "Wykryto próbę nadpisania tożsamości / roli modelu"),
    (r"(?:new system directive|system prompt override|---BEGIN RESPONSE---)", "Wykryto próbę wstrzyknięcia dyrektywy systemowej"),
    (r"[A-Za-z0-9+/=]{50,}", "Wykryto potencjalnie zaciemniony ciąg Base64 / Payload"),
    (r"(?:jestem adminem|i am (?:the )?admin|bypass (?:all )?restrictions|bez ograniczeń)", "Wykryto próbę podszywania się pod administratora lub obejścia zasad"),
]

# Słowa kluczowe wrażliwych zasobów do sprawdzania uprawnień roli
RESOURCE_KEYWORDS = {
    "employee_data": [
        "salary", "salaries", "pensje", "wynagrodzenia", "zarobki", "payroll",
        "employee record", "staff id", "dane pracownik", "bonus table",
    ],
    "client_data": [
        "client file", "litigation clients", "signed agreements", "akty notarialne",
        "dane klient", "umowy klient", "kyc",
    ],
    "bank_data": [
        "operating accounts", "nightly reconciliation", "rachunki operacyjne",
        "rezerwy banku", "internal ledger", "salda wewnętrzne",
    ],
    "stock_market": [
        "trading volume", "closing prices", "notowania", "brokerage order",
        "trading positions", "portfel akcji", "earnings call",
    ],
}


def normalize_role(role: str) -> str:
    """Normalizuje nazwę roli do formatu z config.ROLES."""
    clean = (role or "").strip().lower()
    return ROLE_ALIASES.get(clean, role)


def _check_heuristic_injections(text: str) -> Optional[str]:
    """Szybka detekcja wzorców injection/jailbreak za pomocą regex."""
    for pattern, description in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return description
    return None


def _check_role_resource_access(canonical_role: str, text: str) -> Optional[tuple[str, str]]:
    """Sprawdza, czy zapytanie odpytuje o zasób niezgodny z zakresem roli."""
    role_cfg = ROLES.get(canonical_role, {})
    allowed_tools = role_cfg.get("allowed_tools", [])
    text_lower = text.lower()

    # Sprawdzenie danych kadrowych (employee_data)
    if any(k in text_lower for k in RESOURCE_KEYWORDS["employee_data"]):
        if canonical_role not in ("kadry", "administrator") and not any("employee" in t or "hr" in t for t in allowed_tools):
            return "employee_data", f"Rola '{canonical_role}' nie ma dostępu do danych kadrowych i płacowych."

    # Sprawdzenie danych klientów bankowych (client_data)
    if any(k in text_lower for k in RESOURCE_KEYWORDS["client_data"]):
        if canonical_role not in ("bankier", "administrator") and not any("client" in t for t in allowed_tools):
            return "client_data", f"Rola '{canonical_role}' nie ma dostępu do danych klientów."

    # Sprawdzenie wewnętrznych kont banku (bank_data)
    if any(k in text_lower for k in RESOURCE_KEYWORDS["bank_data"]):
        if canonical_role not in ("bankier", "analityk", "administrator") and not any("bank" in t for t in allowed_tools):
            return "bank_data", f"Rola '{canonical_role}' nie ma dostępu do wewnętrznych operacji bankowych."

    # Sprawdzenie danych giełdowych (stock_market)
    if any(k in text_lower for k in RESOURCE_KEYWORDS["stock_market"]):
        if canonical_role not in ("analityk", "Portfolio Manager", "prawnik", "administrator") and not any("market" in t or "earnings" in t or "stock" in t for t in allowed_tools):
            return "stock_market", f"Rola '{canonical_role}' nie ma dostępu do danych giełdowych."

    return None


def check_prompt(role: str, user_prompt: str) -> Verdict:
    """Ocenia zapytanie użytkownika pod kątem bezpieczeństwa i zgodności z rolą.

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
    resource_violation = _check_role_resource_access(canonical_role, clean_prompt)
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
