from tools.domain_helpers import read_text_window, safe_path

SUBDIR = "projects"
SUFFIX = "_README.md"
MAX_NAMES = 100


def list_projects(search: str = "") -> str:
    """List project documentation available in the company knowledge base.

    Args:
        search: Optional text that the project name must contain (case-insensitive).

    Returns:
        Newline-separated project names.
    """
    folder = safe_path("", SUBDIR)
    names = sorted(
        p.name[: -len(SUFFIX)] for p in folder.glob(f"*{SUFFIX}")
        if search.lower() in p.name.lower()
    )
    if not names:
        return "(no matching projects)"
    more = len(names) - MAX_NAMES
    lines = names[:MAX_NAMES]
    if more > 0:
        lines.append(f"[{more} more projects, narrow the search]")
    return "\n".join(lines)


def read_project(name: str, offset: int = 0, max_chars: int = 6000) -> str:
    """Read the documentation (README) of one project from the knowledge base.

    Args:
        name: Project name exactly as returned by list_projects.
        offset: Character position to start reading from (default 0).
        max_chars: Maximum number of characters to return (default 6000).

    Returns:
        The requested part of the document, or an error message.
    """
    return read_text_window(safe_path(name + SUFFIX, SUBDIR), offset, max_chars)
