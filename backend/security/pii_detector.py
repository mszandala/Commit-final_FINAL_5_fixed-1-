from typing import Optional

from security.gliner_detector import detect_gliner_pii
from security.regex_detector import detect_regex_pii


def _merge_entities(entities: list[dict]) -> list[dict]:
    """Deduplikuje i scala encje, eliminując nakładające się kolizje.

    Sortuje po indeksie startowym (rosnąco) i długości (malejąco).
    """
    entities.sort(key=lambda e: (e["start"], -(e["end"] - e["start"])))
    merged: list[dict] = []
    for e in entities:
        if not merged:
            merged.append(e)
            continue
        last = merged[-1]
        # Jeśli bieżąca encja nachodzi na poprzednią, zachowujemy pierwszą (lub dłuższą)
        if e["start"] < last["end"]:
            continue
        merged.append(e)
    return merged


def detect_pii(text: str, threshold: Optional[float] = None) -> list[dict]:
    """Główna funkcja modułu: łączy detekcję regułową (regex) oraz model zero-shot (GLiNER).

    Zwraca posortowaną listę encji: [{"type", "text", "start", "end"}].
    """
    if not text or not text.strip():
        return []

    # 1. Błyskawiczna detekcja regułowa (<0.1ms): hasła, e-maile, telefony
    regex_entities = detect_regex_pii(text)

    # 2. Semantyczna detekcja zero-shot modelem GLiNER: organizacje, projekty, kwoty, lokalizacje, osoby
    gliner_entities = detect_gliner_pii(text, threshold=threshold)

    # 3. Połączenie wyników i usunięcie kolizji (z priorytetem dla reguł deterministycznych)
    return _merge_entities(regex_entities + gliner_entities)
