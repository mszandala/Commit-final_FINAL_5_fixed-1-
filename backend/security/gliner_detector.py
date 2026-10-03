from functools import lru_cache
from typing import Optional

from gliner import GLiNER

from config import PII_MODEL, PII_THRESHOLD

# Mapowanie etykiet modelu zero-shot na kanoniczne kategorie PII/bezpieczeństwa
LABEL_MAP = {
    "person": "NAME",
    "organization": "ORGANIZATION",
    "location": "LOCATION",
    "financial amount": "SALARY",
    "money": "SALARY",
    "password": "PASSWORD",
    "project name": "PROJECT",
    "phone number": "PHONE-NO",
    "email address": "EMAIL",
    "credit card number": "CREDIT-CARD-NO",
    "api key": "PASSWORD",
}

GLINER_LABELS = list(LABEL_MAP.keys())

# Zaimki do wykluczenia z wykrywania osób (żeby nie generować fałszywych alarmów dla "I", "She", itp.)
PRONOUNS = {
    "i", "me", "my", "mine",
    "you", "your", "yours",
    "he", "him", "his",
    "she", "her", "hers",
    "we", "us", "our", "ours",
    "they", "them", "their", "theirs",
}


@lru_cache(maxsize=1)
def _load_model() -> GLiNER:
    """Ładuje model GLiNER w pamięci podręcznej."""
    return GLiNER.from_pretrained(PII_MODEL)


def _chunk_text(text: str, max_chars: int = 1000, overlap: int = 200):
    """Dzieli długi tekst na nakładające się okna, zachowując granice słów."""
    if len(text) <= max_chars:
        yield 0, text
        return

    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        if end < len(text):
            split_at = max(text.rfind(' ', start, end), text.rfind('\n', start, end))
            if split_at > start + 200:
                end = split_at
        yield start, text[start:end]
        if end >= len(text):
            break
        start = end - overlap


def detect_gliner_pii(text: str, threshold: Optional[float] = None) -> list[dict]:
    """Wykrywa encje semantyczne (organizacje, osoby, kwoty, lokalizacje, projekty) za pomocą GLiNER.

    Zwraca listę encji: [{"type", "text", "start", "end"}].
    """
    if not text or not text.strip():
        return []

    conf_threshold = threshold if threshold is not None else PII_THRESHOLD
    model = _load_model()
    entities: list[dict] = []

    for offset, chunk in _chunk_text(text):
        predictions = model.predict_entities(chunk, GLINER_LABELS, threshold=conf_threshold)
        for pred in predictions:
            raw_val = pred["text"].strip()
            if raw_val.lower() in PRONOUNS:
                continue

            g_start = offset + pred["start"]
            g_end = offset + pred["end"]
            matched_text = text[g_start:g_end]

            # Dopasowanie indeksów bez spacji brzegowych
            l_strip = len(matched_text) - len(matched_text.lstrip())
            r_strip = len(matched_text) - len(matched_text.rstrip())
            final_start = g_start + l_strip
            final_end = g_end - r_strip
            final_text = text[final_start:final_end]

            if not final_text:
                continue

            canonical_type = LABEL_MAP.get(pred["label"], pred["label"].upper())
            entities.append({
                "type": canonical_type,
                "text": final_text,
                "start": final_start,
                "end": final_end,
            })

    entities.sort(key=lambda e: (e["start"], -(e["end"] - e["start"])))
    return entities
