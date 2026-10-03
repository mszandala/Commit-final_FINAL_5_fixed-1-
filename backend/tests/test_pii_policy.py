from config import GLOBAL_BLOCKED_PII, GLOBAL_REDACTED_PII, ROLES
from security.pii_policy import check_pii, redact


def entity(text, full, type_):
    start = full.index(text)
    return {"type": type_, "text": text, "start": start, "end": start + len(text)}


def test_no_role_can_see_globally_blocked_pii():
    for cfg in ROLES.values():
        assert not set(cfg["allowed_pii"]) & set(GLOBAL_BLOCKED_PII)
        assert not set(cfg["allowed_pii"]) & set(GLOBAL_REDACTED_PII)


def test_password_blocked_even_for_admin():
    text = "Hasło to Admin123"
    verdict = check_pii("administrator", text, [entity("Admin123", text, "PASSWORD")])
    assert verdict.decision == "block" and verdict.is_blocked


def test_email_is_redacted_not_blocked():
    text = "Autor projektu: jan@example.com, firma Google."
    entities = [entity("jan@example.com", text, "EMAIL"), entity("Google", text, "ORGANIZATION")]
    verdict = check_pii("podstawowy użytkownik", text, entities)
    assert verdict.decision == "redact" and not verdict.is_blocked
    assert verdict.details["redacted_text"] == "Autor projektu: [EMAIL], firma Google."


def test_role_allowed_pii_passes():
    text = "Średnia pensja w Sales to 5993"
    assert check_pii("kadry", text, [entity("5993", text, "SALARY")]).decision == "pass"
    assert check_pii("Portfolio Manager", text, [entity("5993", text, "SALARY")]).decision == "pass"


def test_role_without_permission_is_blocked():
    text = "Średnia pensja w Sales to 5993"
    verdict = check_pii("podstawowy użytkownik", text, [entity("5993", text, "SALARY")])
    assert verdict.is_blocked
    assert "SALARY" in verdict.reason


def test_block_wins_over_redact():
    text = "mail a@b.pl, hasło Admin123"
    entities = [entity("a@b.pl", text, "EMAIL"), entity("Admin123", text, "PASSWORD")]
    assert check_pii("administrator", text, entities).decision == "block"


def test_redact_multiple_entities():
    text = "a@b.pl i +48 600 700 800"
    entities = [entity("a@b.pl", text, "EMAIL"), entity("+48 600 700 800", text, "PHONE-NO")]
    assert redact(text, entities) == "[EMAIL] i [PHONE-NO]"
