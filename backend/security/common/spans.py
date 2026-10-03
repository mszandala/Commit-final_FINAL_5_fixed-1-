"""Wspólne operacje na fragmentach tekstu dla detektorów PII i modułu company_policies."""


def by_position(entity: dict) -> tuple[int, int]:
    """Klucz sortowania encji: pozycja w tekście rosnąco, przy tym samym starcie dłuższa pierwsza."""
    return entity["start"], -(entity["end"] - entity["start"])


def replace_spans(text: str, spans) -> str:
    """Zastępuje fragmenty (start, end, zamiennik) w jednym przebiegu.

    Nachodzące na siebie fragmenty są scalane; scalony fragment dostaje zamiennik pierwszego z nich.
    """
    merged: list[list] = []
    for start, end, replacement in sorted(spans, key=lambda s: (s[0], s[1])):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, replacement])

    parts, cursor = [], 0
    for start, end, replacement in merged:
        parts += (text[cursor:start], replacement)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)
