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


OPERATIONS = ("count", "sum", "avg", "min", "max")
MAX_GROUPS = 50
# Statystyka z mniejszej grupy jest ukrywana: średnia z jednego wiersza to czyjaś konkretna wartość.
MIN_GROUP_ROWS = 5


def aggregate_csv(
    path: Path,
    delimiter: str = ",",
    operation: str = "count",
    column: str = "",
    group_by: str = "",
    filter_column: str = "",
    filter_value: str = "",
    sensitive_columns=(),
) -> str:
    """Liczy statystykę po WSZYSTKICH wierszach CSV (read_csv_rows zwraca najwyżej MAX_ROWS).

    `sensitive_columns` to kolumny z identyfikatorami i kwotami pojedynczych osób: nie można po nich
    grupować, bo wynik byłby listą tych wartości poza polityką kolumn.
    """
    if not path.exists():
        return f"File not found: {path.name}"
    if operation not in OPERATIONS:
        return f"Unknown operation: {operation}. Use one of: {', '.join(OPERATIONS)}"
    if operation != "count" and not column:
        return f"Operation '{operation}' needs a numeric column."
    if group_by in sensitive_columns:
        return f"Cannot group by '{group_by}': it identifies individual records."

    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        header = next(reader, None)
        if header is None:
            return "(empty file)"
        for name in (column, group_by, filter_column):
            if name and name not in header:
                return f"Unknown column: {name}. Available columns: {', '.join(header)}"
        position = {name: header.index(name) for name in (column, group_by, filter_column) if name}

        rows: dict[str, int] = {}
        values: dict[str, list[float]] = {}
        for row in reader:
            if len(row) < len(header):
                continue
            if filter_column and row[position[filter_column]] != str(filter_value):
                continue
            key = row[position[group_by]] if group_by else "all"
            rows[key] = rows.get(key, 0) + 1
            if operation != "count":
                try:
                    values.setdefault(key, []).append(float(row[position[column]]))
                except ValueError:
                    continue

    if not rows:
        return "(no matching rows)"
    if operation != "count" and not any(values.values()):
        return f"Column '{column}' has no numeric values."

    compute = {"sum": sum, "min": min, "max": max, "avg": lambda v: sum(v) / len(v)}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([group_by or "group", "rows", f"{operation}({column})" if column else "count"])
    groups = sorted(rows, key=lambda k: (-rows[k], k))
    for key in groups[:MAX_GROUPS]:
        if operation == "count":
            result = rows[key]
        elif rows[key] < MIN_GROUP_ROWS:
            result = f"[hidden: fewer than {MIN_GROUP_ROWS} rows]"
        elif not values.get(key):
            result = "(no numeric values)"
        else:
            result = round(compute[operation](values[key]), 2)
        writer.writerow([key, rows[key], result])
    if len(groups) > MAX_GROUPS:
        out.write(f"[{len(groups) - MAX_GROUPS} more groups not shown]\n")
    return out.getvalue()
