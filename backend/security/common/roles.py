"""Nazwy ról: aliasy (angielskie, skróty) → nazwy z config.ROLES. Wspólne dla wszystkich strażników."""

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


def normalize_role(role: str) -> str:
    """Normalizuje nazwę roli do formatu z config.ROLES."""
    clean = (role or "").strip().lower()
    return ROLE_ALIASES.get(clean, role)
