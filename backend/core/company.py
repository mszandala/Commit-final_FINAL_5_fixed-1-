"""Regulaminy firmowe: łagodzenie blokad opartych na słabym dowodzie i zapis decyzji w śladzie tury."""
from typing import Any

from audit import logger as audit
from security.company_policies.detection import detect_deterministic
from security.company_policies.enforcer import violation_type

from .models import Policy


def _warned(verdict):
    """Blokada zamieniona na ostrzeżenie; treść powodu przestaje mówić o zablokowaniu."""
    verdict.decision, verdict.is_blocked = "warn", False
    verdict.reason = verdict.reason.replace("Zablokowano zgodnie z", "Możliwe naruszenie:")
    return verdict, True


def soften(policy: Policy, engine: Any, role: str, text: str, verdict, point: str = "output",
           public_only: bool = False):
    """Zamienia na ostrzeżenie blokady oparte na słabym dowodzie. Zwraca (werdykt, czy złagodzono).

    Słaby dowód to:
      - niedostępny klasyfikator (chyba że `fail_closed`),
      - sama ocena tematu przez klasyfikator (chyba że `semantic_blocks`); przy danych
        wyłącznie ze źródeł publicznych (`public_only`) — zawsze, bo klasyfikator ocenia temat,
        a nie pochodzenie,
      - samo słowo kluczowe w wyniku narzędzia albo w odpowiedzi (chyba że `strict_keywords`);
        w prompcie słowo kluczowe blokuje.
    Znaczniki, wzorce i odciski plików blokują zawsze.
    """
    cfg = policy.controls.company_policies
    if verdict.decision != "block":
        return verdict, False
    if verdict.details.get("detector_error"):
        return (verdict, False) if cfg.fail_closed else _warned(verdict)
    if verdict.details.get("layer") == "semantic":
        return (verdict, False) if cfg.semantic_blocks and not public_only else _warned(verdict)
    if cfg.strict_keywords or point == "input" or verdict.details.get("layer") != "deterministic":
        return verdict, False
    store = engine.store.get()
    violating = [h for h in detect_deterministic(store, text)
                 if h.rule.on_violation == "block" and violation_type(h.rule, role, "internal")] if store else []
    if violating and all(h.methods == ["keyword"] for h in violating):
        return _warned(verdict)
    return verdict, False


def record_check(point: str, verdict, softened: bool = False) -> None:
    """Zapisuje decyzję regulaminów w śladzie tury (bez treści — moduł ma też własny log z hashami)."""
    d = verdict.details
    semantic = d.get("semantic") or {}
    audit.record("company_policy", "security", point=point, decision=verdict.decision,
                 rule_id=d.get("rule_id"), section=d.get("section"), violation=d.get("violation_type"),
                 layer=d.get("layer"), methods=d.get("methods"), detector_error=bool(d.get("detector_error")),
                 softened=softened, reason=verdict.reason if verdict.decision != "pass" else None,
                 classifier=({"category": semantic.get("category"), "confidence": semantic.get("confidence")}
                             if semantic else None))
