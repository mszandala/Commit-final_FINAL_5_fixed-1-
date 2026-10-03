import re

from security.common.spans import by_position

# Wzorce regex dla danych deterministycznych (hasła, sekrety, numery telefonów, e-maile)
PASSWORD_PATTERN = re.compile(
    r'(?:password|pwd|secret|api[_-]?key|token)(\s*[:=]\s*|\s+is\s+|\s+)(\S+)',
    re.IGNORECASE,
)
# Sekrety rozpoznawalne po samej budowie: token Bearer, JWT, klucz dostępowy AWS
SECRET_TOKEN_PATTERN = re.compile(
    r'(?:(?<=Bearer )[A-Za-z0-9\-_.=+/]{20,}[A-Za-z0-9\-_=+/]'
    r'|\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}'
    r'|\bAKIA[0-9A-Z]{16}\b)'
)
PHONE_PATTERN = re.compile(r'(\+?\d[\d\s\-\(\)]{7,}\d)')
# Grupa 1 = domena; z tego samego wzorca company_policies sprawdza, czy adres jest wewnętrzny.
EMAIL_PATTERN = re.compile(r'[\w.+-]+@([\w-]+(?:\.[\w-]+)+)')
CARD_PATTERN = re.compile(r'(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)')
# Identyfikatory rekordów: sama liczba nic nie znaczy, więc wymagamy słowa kluczowego tuż przed nią.
CLIENT_ID_PATTERN = re.compile(
    r'(?:customer[_ ]?id|client[_ ]?id|id\s+klienta|klient(?:a|em|owi)?\s+(?:o\s+)?(?:id|numerze))\D{0,12}?(\d{4,})',
    re.IGNORECASE,
)
EMPLOYEE_ID_PATTERN = re.compile(
    r'(?:employee[_ ]?(?:number|id)|id\s+pracownika|numer(?:ze)?\s+pracownika|pracownik(?:a|iem|owi)?\s+(?:o\s+)?(?:id|numerze))\D{0,12}?(\d+)',
    re.IGNORECASE,
)


# Zapisy dat i zakresów lat pasują do wzorca telefonu: 2024-01-05, 05-01-2024, 2018-2024, 2024 01 05.
_DATE_LIKE = re.compile(
    r'(?:(?:19|20)\d{2}[-\s](?:0?[1-9]|1[0-2])[-\s](?:0?[1-9]|[12]\d|3[01])'
    r'|(?:0?[1-9]|[12]\d|3[01])[-\s](?:0?[1-9]|1[0-2])[-\s](?:19|20)\d{2}'
    r'|(?:19|20)\d{2}\s?-\s?(?:19|20)\d{2})'
)


def is_date_like(text: str) -> bool:
    """Czy ciąg cyfr to data albo zakres lat, a nie numer telefonu."""
    return bool(_DATE_LIKE.fullmatch(text.strip()))


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


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
        start, end = m.span(2)
        # Bez dwukropka lub znaku równości to zwykle zwykłe zdanie ("the token is invalid"),
        # więc wymagamy, żeby wartość wyglądała jak sekret (zawierała cyfrę).
        if m.group(1).strip() not in (":", "=") and not any(c.isdigit() for c in m.group(2)):
            continue
        entities.append({
            "type": "PASSWORD",
            "text": text[start:end],
            "start": start,
            "end": end,
        })

    for m in SECRET_TOKEN_PATTERN.finditer(text):
        if not any(m.start() < e["end"] and e["start"] < m.end() for e in entities):
            entities.append({
                "type": "PASSWORD",
                "text": m.group(0),
                "start": m.start(),
                "end": m.end(),
            })

    # 2. Adresy e-mail
    for m in EMAIL_PATTERN.finditer(text):
        entities.append({
            "type": "EMAIL",
            "text": m.group(0),
            "start": m.start(),
            "end": m.end(),
        })

    # 3. Numery kart płatniczych: 13-19 cyfr z poprawną sumą kontrolną Luhna
    cards = []
    for m in CARD_PATTERN.finditer(text):
        if _luhn_ok(re.sub(r"\D", "", m.group(0))):
            cards.append(m.span())
            entities.append({
                "type": "CREDIT-CARD-NO",
                "text": m.group(0),
                "start": m.start(),
                "end": m.end(),
            })

    # 4. Numery telefonów (z pominięciem ciągów rozpoznanych jako karty)
    for m in PHONE_PATTERN.finditer(text):
        if any(m.start() < end and start < m.end() for start, end in cards) or is_date_like(m.group(0)):
            continue
        entities.append({
            "type": "PHONE-NO",
            "text": m.group(0),
            "start": m.start(),
            "end": m.end(),
        })

    # 5. Identyfikatory klientów i pracowników
    for entity_type, pattern in (("CLIENT-ID", CLIENT_ID_PATTERN), ("EMPLOYEE-ID", EMPLOYEE_ID_PATTERN)):
        for m in pattern.finditer(text):
            start, end = m.span(1)
            entities.append({
                "type": entity_type,
                "text": text[start:end],
                "start": start,
                "end": end,
            })

    entities.sort(key=by_position)
    return entities
