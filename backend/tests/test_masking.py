from config import ROLES
from security import masking
from security.masking import Vault, mask_csv, role_policy, sanitize_paths

EMAIL = "jan.kowalski@firma.pl"


def test_token_round_trip_and_reuse():
    vault = Vault()
    token = vault.token_for("EMAIL", EMAIL)
    assert token == "<EMAIL_1>"
    assert vault.token_for("EMAIL", EMAIL) == token
    assert vault.token_for("EMAIL", "inny@firma.pl") == "<EMAIL_2>"
    assert vault.unmask(f"napisz do {token}") == f"napisz do {EMAIL}"


def test_mask_entities_and_known_values():
    vault = Vault()
    text = f"mail {EMAIL} i telefon +48 600 700 800"
    masked = vault.mask_entities(text, [
        {"type": "EMAIL", "start": 5, "end": 5 + len(EMAIL)},
        {"type": "PHONE-NO", "start": text.index("+48"), "end": len(text)},
    ])
    assert masked == "mail <EMAIL_1> i telefon <PHONE_NO_1>"
    assert vault.mask_known(f"ponownie {EMAIL}") == "ponownie <EMAIL_1>"


def test_restore_tolerates_mangled_tokens():
    vault = Vault()
    vault.token_for("PHONE-NO", "+48 600 700 800")
    for mangled in ["<PHONE_NO_1>", "<phone_no_1>", "<PHONE-NO_1>", "[PHONE_NO_1]", "&lt;PHONE_NO_1&gt;",
                    "< PHONE NO 1 >", "<PHONE_NO 1>"]:
        assert vault.unmask(f"zadzwoń {mangled}.") == "zadzwoń +48 600 700 800.", mangled


def test_unknown_token_is_left_untouched():
    vault = Vault()
    vault.token_for("EMAIL", EMAIL)
    text = "zobacz <EMAIL_7>, (Q1 2018) i [REDACTED]"
    assert vault.unmask(text) == text
    assert vault.render(text, {"EMAIL": "allow"})[0] == text


def test_pseudonym_is_stable_and_reversible():
    first, second = Vault(), Vault()
    token = first.token_for("CLIENT-ID", "15647311")
    assert token.startswith("ID-") and "15647311" not in token
    assert second.token_for("CLIENT-ID", "15647311") == token
    assert first.token_for("EMPLOYEE-ID", "15647311") != token
    assert first.unmask_args({"column": "customer_id", "value": token, "limit": 1}) == {
        "column": "customer_id", "value": "15647311", "limit": 1}


def test_render_follows_role_policy():
    vault = Vault()
    email = vault.token_for("EMAIL", EMAIL)
    client = vault.token_for("CLIENT-ID", "15647311")
    text = f"{email} / {client}"

    shown, stats = vault.render(text, {"EMAIL": "allow", "CLIENT-ID": "allow"})   # polityka podana wprost
    assert shown == f"{EMAIL} / 15647311" and stats["restored"] == ["EMAIL", "CLIENT-ID"]

    shown, stats = vault.render(text, {"EMAIL": "redact", "CLIENT-ID": "pseudonymize"})
    assert shown == f"[EMAIL] / {client}" and stats["redacted"] == ["EMAIL"]

    shown, stats = vault.render(text, {"EMAIL": "block", "CLIENT-ID": "allow"})
    assert stats["blocked"] == ["EMAIL"] and EMAIL not in shown


def test_render_returns_values_the_user_typed():
    vault = Vault()
    token = vault.token_for("EMAIL", EMAIL)
    assert vault.render(token, {"EMAIL": "redact"}, own_text=f"mój mail to {EMAIL}")[0] == EMAIL


def test_role_policy_resolution():
    assert role_policy("kadry")["SALARY"] == "allow"
    assert role_policy("IT")["SALARY"] == "redact"
    assert role_policy("analityk")["CLIENT-ID"] == "pseudonymize"
    assert role_policy("bankier")["CLIENT-ID"] == "allow"
    assert role_policy("nieznana")["EMAIL"] == "redact"
    # miejsca, organizacje i projekty widzi każda rola, także bez wpisu w allowed_pii
    assert role_policy("podstawowy użytkownik")["LOCATION"] == "allow"
    assert role_policy("IT")["ORGANIZATION"] == role_policy("nieznana")["PROJECT"] == "allow"
    assert role_policy("podstawowy użytkownik")["PESEL"] == "redact"


def test_global_rules_apply_to_every_role(monkeypatch):
    for role in ROLES:
        policy = role_policy(role)
        assert policy["PASSWORD"] == policy["CREDIT-CARD-NO"] == "block"
        assert policy["EMAIL"] == policy["PHONE-NO"] == "redact"
    # nadpisanie roli może regułę globalną zaostrzyć, ale nie złagodzić
    monkeypatch.setitem(ROLES["kadry"], "pii_policy", {"EMAIL": "block", "PASSWORD": "allow"})
    assert role_policy("kadry")["EMAIL"] == "block"
    assert role_policy("kadry")["PASSWORD"] == "block"
    for role in ROLES:
        assert set(role_policy(role).values()) <= {"allow", "redact", "block", "pseudonymize"}


def test_mask_csv_applies_column_policy():
    text = ("customer_id,country,estimated_salary\n"
            "15647311,Spain,112542.58\n"
            "15634602,France,101348.88\n"
            "[truncated: 10 more characters]")
    columns = {"customer_id": "CLIENT-ID", "estimated_salary": "SALARY"}
    vault = Vault()

    masked, stats = mask_csv(text, columns, {"CLIENT-ID": "allow", "SALARY": "redact"}, vault)
    lines = masked.split("\n")
    assert lines[1] == f"{vault.token_for('CLIENT-ID', '15647311')},Spain,[REDACTED]"
    assert lines[3] == "[truncated: 10 more characters]"
    assert stats == {"pseudonymized": 2, "redacted": 2}
    assert "15647311" not in masked and "112542.58" not in masked

    masked, stats = mask_csv(text, columns, {"CLIENT-ID": "allow", "SALARY": "allow"}, Vault())
    assert "112542.58" in masked and "15647311" not in masked


def test_mask_csv_without_sensitive_columns_is_unchanged():
    text = "age,job\n30,student\n"
    assert mask_csv(text, {}, role_policy("analityk"), Vault()) == (text, {"pseudonymized": 0, "redacted": 0})


def test_sanitize_paths():
    root = str(masking.BASE_DIR.resolve())
    out = sanitize_paths(f"FileNotFoundError: [Errno 2] No such file: '{root}\\x.csv' oraz /home/user/app/main.py")
    assert root not in out and "/home/user" not in out and "<PATH>" in out
    trace = 'Traceback (most recent call last):\n  File "a.py", line 1, in <module>\nValueError: zły plik'
    assert sanitize_paths(trace) == "[stack trace removed]\nValueError: zły plik"


# --- znaczniki a detekcja: nawias z etykietą i cyframi nie jest znacznikiem z sejfu ----------------

def test_only_known_tokens_hide_text_from_detection():
    vault = Vault()
    token = vault.token_for("EMAIL", "jan.kowalski@firma.pl")             # <EMAIL_1>
    assert vault.token_spans(f"adres {token}") == [(6, 6 + len(token))]
    for text in ("(PESEL 89010212345)", "[PESEL 89010212345]", "<PESEL 89010212345>", "(tel 601234567)",
                 "<EMAIL_9>"):                                           # nieznany znacznik to zwykły tekst
        assert vault.token_spans(text) == [], text


def test_pii_in_brackets_is_not_a_way_around_the_reply_filter():
    """Model (albo atakujący, który mu każe) zapisuje PESEL jako "(PESEL ...)": filtr odpowiedzi ma go ukryć."""
    from core.pii import filter_output
    from core.models import Policy
    from security.pii.regex_detector import detect_regex_pii
    import pipeline

    def detect(text, threshold=None):
        return detect_regex_pii(text)

    for written in ("(PESEL 89010212345)", "[PESEL 89010212345]", "PESEL 89010212345"):
        shown, _, stats = filter_output("podstawowy użytkownik", f"Dane: {written}", policy=pipeline.current_policy(),
                                        detect=detect)
        assert "89010212345" not in shown and "PESEL" in stats["redacted"], written
