"""Reading company policy documents in Markdown format.

Controlled paragraphs are annotated with `<!-- control: RULE_ID -->` directly preceding them.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED = (".md", ".txt")
_CONTROL = re.compile(r"<!--\s*control:\s*([A-Za-z0-9_-]+)\s*-->")


@dataclass
class DocParagraph:
    text: str
    controls: list[str] = field(default_factory=list)
    heading: bool = False


def read_paragraphs(path: Path) -> list[DocParagraph]:
    """Non-empty document lines; control tags are attached to the subsequent line."""
    path = Path(path)
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"{path.name}: nieobsługiwany format; prototyp czyta tylko "
                         f"{', '.join(SUPPORTED)} (konwerter .docx/.pdf → .md jest na roadmapie)")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as e:
        raise ValueError(f"{path.name}: plik nie jest poprawnym tekstem UTF-8") from e

    paragraphs, pending = [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if markers := _CONTROL.findall(line):
            pending += markers
            continue
        heading = line.startswith("#")
        paragraphs.append(DocParagraph(line.lstrip("#").strip() if heading else line, pending, heading))
        pending = []
    return paragraphs


def read_text(path: Path) -> str:
    return "\n".join(p.text for p in read_paragraphs(path))

