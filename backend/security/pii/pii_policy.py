from config import GLOBAL_BLOCKED_PII, GLOBAL_REDACTED_PII, ROLES
from security.common.spans import replace_spans
from security.common.verdicts import Verdict


def redact(text: str, entities: list[dict]) -> str:
    """Replaces entity spans with [TYPE] tags."""
    return replace_spans(text, [(e["start"], e["end"], f"[{e['type']}]") for e in entities])


def check_pii(role: str, text: str, entities: list[dict]) -> Verdict:
    """Deterministic PII policy verdict on entities from detect_pii for a given role.

    Precedence order: global block > role denied types (block) > global redact > pass.
    """
    # Configuration read on each invocation: ROLES changes take effect without restart.
    allowed = set(ROLES.get(role, {}).get("allowed_pii", []))
    always_blocked, always_masked = set(GLOBAL_BLOCKED_PII), set(GLOBAL_REDACTED_PII)
    blocked = [e for e in entities if e["type"] in always_blocked]
    masked = [e for e in entities if e["type"] in always_masked]
    denied = [e for e in entities
              if e["type"] not in allowed and e["type"] not in always_blocked and e["type"] not in always_masked]

    if blocked:
        return Verdict("block", f"Odpowiedź zawiera zawsze zablokowane dane: {_types(blocked)}",
                       "pii_policy", {"entities": blocked}, is_blocked=True)
    if denied:
        return Verdict("block", f"Rola '{role}' nie może zobaczyć danych: {_types(denied)}",
                       "pii_policy", {"entities": denied}, is_blocked=True)
    if masked:
        return Verdict("redact", f"Zamaskowano dane: {_types(masked)}", "pii_policy",
                       {"entities": masked, "redacted_text": redact(text, masked)})
    return Verdict("pass", "Brak danych niedozwolonych dla roli", "pii_policy")


def _types(entities: list[dict]) -> str:
    return ", ".join(sorted({e["type"] for e in entities}))
