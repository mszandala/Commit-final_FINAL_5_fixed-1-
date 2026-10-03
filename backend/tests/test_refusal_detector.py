import pytest

from security import refusal_detector
from security.refusal_detector import detect_refusal, sentences

REFUSALS = [
    "I'm sorry, but I am not authorized to access stock price data.",
    "Przykro mi, ale nie mam uprawnień do tych danych.",
    "I cannot make automated final decisions regarding employment.",
    "Here are two projects.\n\nI do not have permission to read salary data, though.",      # odmowa częściowa
]
ORDINARY = [
    "The following projects cover software testing:\n* awesome-testing",
    "Nie, w bazie projektów nie znaleziono projektu o tej nazwie.",
    "Dziękuję bardzo! Tobie również miłego dnia!",
    "",
]


def test_keywords_detect_refusals(monkeypatch):
    monkeypatch.setattr(refusal_detector, "REFUSAL_EMBEDDINGS_ENABLED", False)
    for reply in REFUSALS:
        assert detect_refusal(reply) == {"method": "keywords", "category": "generic", "score": None}, reply
    for reply in ORDINARY:
        assert detect_refusal(reply) is None, reply


def test_sentences():
    assert sentences("Pierwsze zdanie. Drugie!\n\n* punkt") == ["Pierwsze zdanie.", "Drugie!", "* punkt"]


@pytest.fixture(scope="module")
def embedder():
    """Model embeddingów; test jest pomijany, gdy nie ma go lokalnie i nie da się go pobrać."""
    refusal_detector._embedder.cache_clear()
    if refusal_detector._embedder() is None:
        pytest.skip("model embeddingów niedostępny")


def test_embeddings_catch_a_refusal_without_keywords_and_name_its_cause(embedder):
    found = detect_refusal("That is something my role is not permitted to look at.")
    assert found and found["method"] == "embedding" and found["score"] >= 0.5
    found = detect_refusal("Przykro mi, ale nie mam uprawnień do danych kadrowych.")
    assert found["method"] == "keywords" and found["category"] == "no_permission"
    assert detect_refusal("Średnia cena zamknięcia AAPL w styczniu wyniosła 187 dolarów.") is None
