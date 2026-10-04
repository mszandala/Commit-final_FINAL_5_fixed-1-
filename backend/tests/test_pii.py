from security.pii.gliner_detector import detect_gliner_pii
from security.pii.pii_detector import detect_pii
from security.pii.regex_detector import detect_regex_pii

PHONE = "+48 600 700 800"

SENSITIVE_CASES = [
    ("I am working on a project SimpleText AI", "SimpleText AI"),
    ("The password is Admin123", "Admin123"),
    ("Boss earns 24 000 $", "24 000 $"),
    ("I am moving to USA", "USA"),
    ("She works at Google", "Google"),
]

CLEAN_TEXTS = [
    "The weather is very nice today",
    "Please summarize the general documentation",
    "How does the algorithm work in practice?",
]


def test_sensitive_cases_detected():
    """Weryfikuje, że przypadki testowe z wrażliwymi danymi są prawidłowo wykrywane."""
    for text, expected_fragment in SENSITIVE_CASES:
        entities = detect_pii(text)
        assert len(entities) > 0, f"Nie wykryto żadnej encji w: {text}"
        detected_texts = [e["text"] for e in entities]
        assert any(expected_fragment in t for t in detected_texts), (
            f"Oczekiwano fragmentu '{expected_fragment}', znaleziono: {detected_texts}"
        )


def test_clean_text_has_no_pii():
    """Weryfikuje brak fałszywych alarmów (false positives) dla neutralnych zdań."""
    for text in CLEAN_TEXTS:
        assert detect_pii(text) == [], f"Fałszywy alarm w neutralnym tekście: {text}"


def test_empty_text():
    assert detect_pii("   ") == []
    assert detect_pii("") == []
    assert detect_regex_pii("") == []
    assert detect_gliner_pii("") == []


def test_entity_has_type_text_and_position():
    text = f"Call me at {PHONE}"
    entities = detect_pii(text)
    assert entities == [{"type": "PHONE-NO", "text": PHONE, "start": 11, "end": 26}]
    assert text[11:26] == PHONE


def test_pii_beyond_model_window_is_detected():
    filler = "This is a filler sentence about nothing in particular. " * 150
    text = filler + f"Call me at {PHONE}"
    entities = detect_pii(text)
    phone_entities = [e for e in entities if e["type"] == "PHONE-NO" and e["text"] == PHONE]
    assert len(phone_entities) == 1
    matched = phone_entities[0]
    assert text[matched["start"]:matched["end"]] == PHONE


def test_name_and_email_detection():
    text = "Please contact John Smith at john.smith@example.com"
    entities = detect_pii(text)
    types = {e["type"] for e in entities}
    assert "NAME" in types
    assert "EMAIL" in types


def test_regex_detector_isolated():
    """Weryfikuje działanie modułu regex_detector niezależnie od modelu."""
    sample = "My password is SuperSecret456 and email is contact@firm.org and phone is +48 111 222 333"
    results = detect_regex_pii(sample)
    types = {r["type"] for r in results}
    assert types == {"PASSWORD", "EMAIL", "PHONE-NO"}
    for r in results:
        assert sample[r["start"]:r["end"]] == r["text"]


def test_gliner_detector_isolated():
    """Weryfikuje działanie modułu gliner_detector niezależnie od reguł."""
    sample = "Google headquarters are located in USA"
    results = detect_gliner_pii(sample)
    types = {r["type"] for r in results}
    assert "ORGANIZATION" in types
    assert "LOCATION" in types


def test_regex_detects_record_ids_and_cards():
    found = {(e["type"], e["text"]) for e in detect_regex_pii(
        "Podaj dane klienta o customer_id 15647311, pracownik o numerze 42, karta 4111 1111 1111 1111")}
    assert found == {("CLIENT-ID", "15647311"), ("EMPLOYEE-ID", "42"), ("CREDIT-CARD-NO", "4111 1111 1111 1111")}
    # ciąg cyfr bez poprawnej sumy kontrolnej nie jest kartą, a sama liczba nie jest identyfikatorem
    assert "CREDIT-CARD-NO" not in {e["type"] for e in detect_regex_pii("numer 1234 5678 9012 3456")}
    assert detect_regex_pii("The client asked about 2024 results") == []


def test_regex_password_keeps_first_letters():
    assert [e["text"] for e in detect_regex_pii("My password is SuperSecret456")] == ["SuperSecret456"]
    assert [e["text"] for e in detect_regex_pii("token: isis99")] == ["isis99"]


def test_regex_password_ignores_ordinary_sentences():
    for text in ["The token is invalid", "Reset your password using the link", "the secret to success"]:
        assert detect_regex_pii(text) == [], text
    assert [e["text"] for e in detect_regex_pii("password: hunter")] == ["hunter"]
    assert [e["text"] for e in detect_regex_pii("API_KEY=abcdef")] == ["abcdef"]


def test_regex_detects_structural_secrets():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI4ODA5MSJ9.Qd3Rl2mK9vXpA7sYbN0tZjFgH4wLcUeRoI1k"
    assert [(e["type"], e["text"]) for e in detect_regex_pii(f"use: Bearer {jwt}. It expires soon.")] == [("PASSWORD", jwt)]
    assert [e["text"] for e in detect_regex_pii("id AKIA4ZX9QWER7TYUIOP2 here")] == ["AKIA4ZX9QWER7TYUIOP2"]
    assert detect_regex_pii('-H "Authorization: Bearer YOUR_API_KEY_HERE"') == []


def test_pesel_is_its_own_type():
    assert [(e["type"], e["text"]) for e in detect_regex_pii("PESEL 44051401359")] == [("PESEL", "44051401359")]
    # błędna cyfra kontrolna, ale użytkownik sam nazwał numer
    assert [(e["type"], e["text"]) for e in detect_regex_pii("mój pesel to: 90010112345")] == [("PESEL", "90010112345")]
    # 11 cyfr bez kontekstu i bez poprawnej cyfry kontrolnej zostaje numerem telefonu
    assert [e["type"] for e in detect_regex_pii("zadzwoń 12345678901")] == ["PHONE-NO"]


def test_decimal_fractions_are_not_numbers_to_hide():
    for text in ["The value is approximately 22.459157718361045", "e^pi = 23,140692632779267", "1.4111111111111111"]:
        assert detect_regex_pii(text) == [], text
    assert [e["type"] for e in detect_regex_pii("tel 601-234-567")] == ["PHONE-NO"]


def test_regex_detection_wins_over_overlapping_model_entity(monkeypatch):
    """GLiNER bierze "customer_id 15634602" za imię i nazwisko; reguła CLIENT-ID ma pierwszeństwo."""
    from security.pii import pii_detector
    text = "Pokaż klienta customer_id 15634602, prowadzi go Jan Kowalski."
    start = text.index("customer_id")
    name = text.index("Jan Kowalski")
    monkeypatch.setattr(pii_detector, "detect_gliner_pii", lambda text, threshold=None: [
        {"type": "NAME", "text": "customer_id 15634602", "start": start, "end": start + 20},
        {"type": "NAME", "text": "Jan Kowalski", "start": name, "end": name + 12},
    ])
    found = [(e["type"], e["text"]) for e in pii_detector.detect_pii(text)]
    assert found == [("CLIENT-ID", "15634602"), ("NAME", "Jan Kowalski")]
