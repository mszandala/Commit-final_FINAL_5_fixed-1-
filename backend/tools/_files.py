from pathlib import Path
from typing import Optional

from config import BASE_DIR

BASE_DIR.mkdir(exist_ok=True)


def _safe_path(name: str) -> Path:
    path = (BASE_DIR / name).resolve()
    if not path.is_relative_to(BASE_DIR.resolve()):
        raise ValueError(f"Unsafe path: {name}")
    return path


def read_file(filename: str, start_line: int = 0, end_line: Optional[int] = None) -> str:
    """Read lines from a file in the data/ directory.

    Args:
        filename: Name of the file to read.
        start_line: First line to return (0-indexed, default 0).
        end_line: Last line to return inclusive (default: end of file).

    Returns:
        The requested lines as a string, or an error message.
    """
    path = _safe_path(filename)
    if not path.exists():
        return f"File not found: {filename}"
    lines = path.read_text(encoding="utf-8").splitlines(True)
    if end_line is None or end_line >= len(lines):
        end_line = len(lines)
    return "".join(lines[start_line : end_line])


def list_files() -> str:
    """List all files in the data/ directory, including subdirectories.

    Returns:
        Newline-separated list of relative file paths.
    """
    names = sorted(
        str(p.relative_to(BASE_DIR)).replace("\\", "/")
        for p in BASE_DIR.rglob("*")
        if p.is_file()
    )
    return "\n".join(names) if names else "(no files)"
