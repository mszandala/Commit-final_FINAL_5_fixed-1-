from typing import Optional

from config import ROLES


def is_allowed(role: str, tool: str) -> bool:
    return tool in ROLES.get(role, {}).get("allowed_tools", [])


class ToolGate:
    """Bramka dla agenta: przepuszcza narzędzia z whitelisty roli, resztę odrzuca.

    Każde wywołanie trafia do `calls` jako {"tool", "args", "allowed"} — z tego czyta interfejs.
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
        self.calls.append({"tool": name, "args": args, "allowed": allowed})
        if allowed:
            return None
        return (
            f"Access denied: tool '{name}' is not available for the current user's role. "
            "Do not call it again. Continue without it and tell the user "
            "that this data is not available for their role."
        )
