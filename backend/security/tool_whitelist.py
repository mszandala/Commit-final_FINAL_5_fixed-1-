from typing import Optional

from config import DATA_ACCESS, ROLES


def is_allowed(role: str, tool: str) -> bool:
    return tool in ROLES.get(role, {}).get("allowed_tools", [])


def role_areas(role: str) -> list[str]:
    """Nazwy obszarów danych dostępnych dla roli — to pokazujemy modelowi zamiast nazw narzędzi."""
    allowed = set(ROLES.get(role, {}).get("allowed_tools", []))
    return [area["label"] for area in DATA_ACCESS.values() if set(area["tools"]) <= allowed]


class ToolGate:
    """Bramka dla agenta: przepuszcza narzędzia z whitelisty roli, resztę odrzuca.

    Każde wywołanie trafia do `calls` jako {"tool", "args", "allowed"}, a odrzucone dodatkowo
    z {"stage", "reason"} — z tego czyta interfejs.
    Na razie każde naruszenie traktujemy jak błąd modelu (pracuje dalej bez narzędzia);
    ocena intencji użytkownika (tool_violation_judge) dojdzie później.
    """

    def __init__(self, role: str):
        self.role = role
        self.calls: list[dict] = []

    @property
    def violations(self) -> list[dict]:
        return [c for c in self.calls if not c["allowed"]]

    def __call__(self, name: str, args: dict) -> Optional[str]:
        allowed = is_allowed(self.role, name)
        call = {"tool": name, "args": args, "allowed": allowed}
        if not allowed:
            call.update(stage="tool_whitelist", reason=f"Narzędzie niedostępne dla roli „{self.role}”")
        self.calls.append(call)
        if allowed:
            return None
        areas = ", ".join(role_areas(self.role)) or "none"
        return (
            f"Access denied: this data is not available for the user's role ('{self.role}'). "
            f"Data areas available to this role: {areas}. Do not make this call again. If an available area "
            "can answer the user's question, use it; otherwise tell the user this data is not available for "
            "their role. Do not mention the names of internal tools in your reply."
        )
