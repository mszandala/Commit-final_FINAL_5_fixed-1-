import re

# Wzorce regex dla danych deterministycznych (hasła, sekrety, numery telefonów, e-maile)
PASSWORD_PATTERN = re.compile(
    r'(?:password|pwd|secret|api[_-]?key|token)\s*[:=is\s]+(\S+)',
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r'(\+?\d[\d\s\-\(\)]{7,}\d)')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')


def detect_regex_pii(text: str) -> list[dict]:
    """Wykrywa dane wrażliwe za pomocą reguł regex: hasła/tokeny, e-maile, telefony.

    Zwraca listę encji: [{"type", "text", "start", "end"}], posortowaną wg pozycji w tekście.
    Czas wykonania: < 0.1ms.
    """
    if not text or not text.strip():
        return []

    entities = []

    # 1. Hasła i tokeny
    for m in PASSWORD_PATTERN.finditer(text):
        start, end = m.span(1)
        entities.append({
            "type": "PASSWORD",
            "text": text[start:end],
            "start": start,
            "end": end,
        })

    # 2. Adresy e-mail
    for m in EMAIL_PATTERN.finditer(text):
        entities.append({
            "type": "EMAIL",
            "text": m.group(0),
            "start": m.start(),
            "end": m.end(),
        })

    # 3. Numery telefonów
    for m in PHONE_PATTERN.finditer(text):
        entities.append({
            "type": "PHONE-NO",
            "text": m.group(0),
            "start": m.start(),
            "end": m.end(),
        })

    entities.sort(key=lambda e: (e["start"], -(e["end"] - e["start"])))
    return entities
