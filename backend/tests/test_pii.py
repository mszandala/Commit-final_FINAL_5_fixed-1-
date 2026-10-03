from security.pii_detector import detect_pii

# Przypadki z pierwotnego PII_detector.py — model nie zgłasza w nich żadnego PII.
NO_PII = [
    "I am working on a project SimpleText AI",
    "The password is Admin123",
    "Boss earns 24 000 $",
    "I am moving to USA",
    "She works at Google",
]

PHONE = "+48 600 700 800"


def test_no_pii():
    for text in NO_PII:
        assert detect_pii(text) == []


def test_empty_text():
    assert detect_pii("   ") == []


def test_entity_has_type_text_and_position():
    text = f"Call me at {PHONE}"
    entities = detect_pii(text)
    assert entities == [{"type": "PHONE-NO", "text": PHONE, "start": 11, "end": 26}]
    assert text[11:26] == PHONE


def test_pii_beyond_model_window_is_detected():
    filler = "This is a filler sentence about nothing in particular. " * 150
    entities = detect_pii(filler + f"Call me at {PHONE}")
    assert [(e["type"], e["text"]) for e in entities] == [("PHONE-NO", PHONE)]
