from typing import Callable, Optional

from security.company_policies.enforcer import CompanyPolicyEngine
from security.common.roles import normalize_role

ToolRunner = Callable[[str, dict], str]


def _run_registered_tool(name: str, args: dict) -> str:
    from tools.registry import run_tool  # import leniwy: rejestr ładuje wszystkie narzędzia
    return run_tool(name, args)


class PolicyToolGate:
    """Bramka dla `agent.run_agent(tool_gate=...)`: agent działa wyłącznie z uprawnieniami roli użytkownika.

    Kolejność: istniejąca bramka (np. security.tool_whitelist.ToolGate) → polityka dla argumentów
    narzędzia → wykonanie narzędzia → filtr wyniku, ZANIM trafi do kontekstu modelu.
    Agent używa tekstu zwróconego przez bramkę zamiast wyniku narzędzia, więc przefiltrowany
    wynik trafia do modelu bez zmian w agent.py.
    """

    def __init__(self, engine: CompanyPolicyEngine, role: str, inner: Optional[Callable] = None,
                 model: Optional[str] = None, runner: ToolRunner = _run_registered_tool):
        self.engine = engine
        self.role = normalize_role(role)
        self.inner = inner
        self.model = model
        self.runner = runner

    def __call__(self, name: str, args: dict) -> Optional[str]:
        if self.inner is not None and (refusal := self.inner(name, args)) is not None:
            return refusal

        verdict = self.engine.check_tool_call(self.role, name, args)
        if verdict.decision in ("block", "redact"):
            return (f"Access denied by company policy: {verdict.reason} "
                    "Do not call this tool again with this data. Tell the user the request is not allowed.")

        result = self.runner(name, args)
        filtered = self.engine.filter_context(self.role, result, source=name, model=self.model)
        if filtered.decision == "block":
            return f"Tool result withheld by company policy: {filtered.reason}"
        return filtered.details.get("redacted_text", result)
