"""Moduł „Dokumenty i regulaminy firmowe”: dodatkowe ograniczenia dla istniejących ról z config.ROLES.

Reguły: security/company_policies/rules.txt (hot reload). Użycie:

    from security.company_policies import get_engine
    engine = get_engine()
    engine.check_input("bankier", prompt)              # wejście
    engine.filter_context("bankier", tool_result)      # kontekst przed modelem
    engine.check_tool_call("bankier", name, args)      # wywołanie narzędzia
    engine.check_output("bankier", answer)             # wyjście
    PolicyToolGate(engine, "bankier", inner=ToolGate("bankier"))   # gotowa bramka dla agenta
"""
from typing import Optional

from security.company_policies.enforcer import CompanyPolicyEngine
from security.company_policies.gate import PolicyToolGate

_engine: Optional[CompanyPolicyEngine] = None


def get_engine() -> CompanyPolicyEngine:
    global _engine
    if _engine is None:
        _engine = CompanyPolicyEngine()
    return _engine


__all__ = ["CompanyPolicyEngine", "PolicyToolGate", "get_engine"]
