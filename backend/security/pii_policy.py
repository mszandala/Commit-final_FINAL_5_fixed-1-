from config import GLOBAL_BLOCKED_PII, GLOBAL_REDACTED_PII, ROLES
from security.verdicts import Verdict


def redact(text: str, entities: list[dict]) -> str:
    """Zastępuje fragmenty encji znacznikiem [TYP]; encje nie mogą na siebie nachodzić."""
    for e in sorted(entities, key=lambda e: e["start"], reverse=True):
        text = text[: e["start"]] + f"[{e['type']}]" + text[e["end"]:]
    return text


def check_pii(role: str, text: str, entities: list[dict]) -> Verdict:
    """Deterministyczna decyzja o encjach z detect_pii dla danej roli.

    Kolejność: globalna blokada > typy spoza allowed_pii roli (blokada, do oceny przez
    pii_access_judge) > globalne maskowanie > przepuszczenie.
    """
    allowed = set(ROLES.get(role, {}).get("allowed_pii", []))
    blocked = [e for e in entities if e["type"] in GLOBAL_BLOCKED_PII]
    masked = [e for e in entities if e["type"] in GLOBAL_REDACTED_PII]
    denied = [e for e in entities
              if e["type"] not in allowed and e not in blocked and e not in masked]

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
