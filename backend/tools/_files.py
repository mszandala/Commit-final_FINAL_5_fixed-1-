from pathlib import Path
from typing import Optional

from config import BASE_DIR, CONTEXT_FOLDERS

BASE_DIR.mkdir(exist_ok=True)


def _safe_path(context_folder: str, name: str) -> Path:
    if context_folder not in CONTEXT_FOLDERS:
        raise ValueError(f"Invalid context folder: {context_folder}")

    context_dir = (BASE_DIR / context_folder).resolve()
    path = (context_dir / name).resolve()

    if not path.is_relative_to(context_dir):
        raise ValueError(f"Unsafe path: {name}")

    return path


def read_file(filename: str, start_line: int = 0, end_line: Optional[int] = None, context_folder: str = CONTEXT_FOLDERS[0]) -> str:
    """Read lines from a file in the selected context directory.

    Args:
        filename: Name of the file to read.
        start_line: First line to return (0-indexed, default 0).
        end_line: Last line to return inclusive (default: end of file).
        context_folder: Context folder to read from. Defaults to the first
            folder in CONTEXT_FOLDERS.

    Returns:
        The requested lines as a string, or an error message.
    """
    path = _safe_path(context_folder, filename)
    if not path.exists():
        return f"File not found: {filename}"
    lines = path.read_text(encoding="utf-8").splitlines(True)
    if end_line is None or end_line >= len(lines):
        end_line = len(lines)
    return "".join(lines[start_line:end_line])


def list_files(context_folder: str = CONTEXT_FOLDERS[0]) -> str:
    """List all files in the selected context directory, including subdirectories.

    Args:
        context_folder: Context folder to list. Defaults to the first
            folder in CONTEXT_FOLDERS.

    Returns:
        Newline-separated list of relative file paths.
    """
    context_dir = _safe_path(context_folder, "").resolve()

    names = sorted(
        str(p.relative_to(context_dir)).replace("\\", "/")
        for p in context_dir.rglob("*")
        if p.is_file()
    )

    return "\n".join(names) if names else "(no files)"