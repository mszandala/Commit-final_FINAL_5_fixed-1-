from typing import Optional

from security.pii.gliner_detector import detect_gliner_pii
from security.pii.regex_detector import detect_regex_pii
from security.common.spans import by_position


def _merge_entities(entities: list[dict]) -> list[dict]:
    """Deduplicates and merges entities, eliminating overlapping spans.

    Sorts by start index (ascending) and span length (descending).
    """
    entities.sort(key=by_position)
    merged: list[dict] = []
    for e in entities:
        if not merged:
            merged.append(e)
            continue
        last = merged[-1]
        # If current entity overlaps previous, preserve the first (or longer)
        if e["start"] < last["end"]:
            continue
        merged.append(e)
    return merged


def detect_pii(text: str, threshold: Optional[float] = None) -> list[dict]:
    """Main detection function: combines deterministic regex with zero-shot model (GLiNER).

    Returns sorted list of entities: [{"type", "text", "start", "end"}].
    """
    if not text or not text.strip():
        return []

    # 1. Fast deterministic regex detection: passwords, emails, phones
    regex_entities = detect_regex_pii(text)

    # 2. Semantic zero-shot detection with GLiNER: organizations, projects, amounts, locations, persons
    gliner_entities = detect_gliner_pii(text, threshold=threshold)

    # 3. Merge results and eliminate span collisions (deterministic regex takes precedence)
    return _merge_entities(regex_entities + gliner_entities)
