import csv
import io
from pathlib import Path

from config import BASE_DIR

MAX_ROWS = 50
MAX_CHARS = 8000


def safe_path(name: str, subdir: str = "") -> Path:
    """Ścieżka wewnątrz data/<subdir>; wyjście poza ten katalog to błąd."""
    base = (BASE_DIR / subdir).resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base):
        raise ValueError(f"Unsafe path: {name}")
    return path


def clip(text: str) -> str:
    if len(text) <= MAX_CHARS:
        return text
    return text[:MAX_CHARS] + f"\n[truncated: {len(text) - MAX_CHARS} more characters]"


def read_csv_rows(
    path: Path,
    delimiter: str = ",",
    column: str = "",
    value: str = "",
    start_row: int = 0,
    limit: int = 20,
) -> str:
    """Zwraca nagłówek i do `limit` wierszy CSV, opcjonalnie tylko te, gdzie column == value."""
    if not path.exists():
        return f"File not found: {path.name}"
    limit = max(1, min(int(limit), MAX_ROWS))
    start_row = max(0, int(start_row))

    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        header = next(reader, None)
        if header is None:
            return "(empty file)"
        index = None
        if column:
            if column not in header:
                return f"Unknown column: {column}. Available columns: {', '.join(header)}"
            index = header.index(column)

        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(header)
        matched = written = 0
        for row in reader:
            if index is not None and (index >= len(row) or row[index] != str(value)):
                continue
            if matched >= start_row:
                writer.writerow(row)
                written += 1
                if written == limit:
                    break
            matched += 1

    if written == 0:
        return out.getvalue() + "(no matching rows)"
    return clip(out.getvalue())


def read_text_window(path: Path, offset: int = 0, max_chars: int = 6000) -> str:
    """Zwraca fragment pliku tekstowego od znaku `offset`."""
    if not path.exists():
        return f"File not found: {path.name}"
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    offset = max(0, int(offset))
    max_chars = max(1, min(int(max_chars), MAX_CHARS))
    chunk = text[offset : offset + max_chars]
    rest = len(text) - offset - len(chunk)
    if rest > 0:
        chunk += f"\n[{rest} more characters, continue with offset={offset + len(chunk)}]"
    return chunk or "(end of file)"
