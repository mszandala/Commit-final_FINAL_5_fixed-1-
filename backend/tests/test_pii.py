from security.gliner_detector import detect_gliner_pii
from security.pii_detector import detect_pii
from security.regex_detector import detect_regex_pii

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
