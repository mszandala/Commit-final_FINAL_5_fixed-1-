"""Wczytywanie i walidacja rules.txt: hot reload, ostatnia poprawna wersja, spójność z dokumentami."""
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from config import COMPANY_DOCUMENTS_DIR, COMPANY_FIXTURES_DIR, ROLES
from security.company_policies.docreader import SUPPORTED, DocParagraph, read_paragraphs, read_text
from security.common.roles import normalize_role

MODULE_DIR = Path(__file__).parent
DEFAULT_RULES_PATH = MODULE_DIR / "rules.txt"
DEFAULT_DOCUMENTS_DIR = COMPANY_DOCUMENTS_DIR
DEFAULT_FIXTURES_DIR = COMPANY_FIXTURES_DIR
# Jak często (w sekundach) sprawdzać, czy rules.txt lub dokumenty się zmieniły. Między sprawdzeniami
# kolejne zapytania nie dotykają dysku; edycja reguł działa najpóźniej po tym czasie.
DEFAULT_RELOAD_INTERVAL = float(os.getenv("COMPANY_POLICIES_RELOAD_INTERVAL", "1.0"))

ON_VIOLATION = ("block", "redact", "warn", "log_only")
ON_DETECTOR_ERROR = ("block", "warn", "log_only")
USAGE = ("allow", "block")
CLASSIFICATIONS = ("public", "internal", "confidential", "strictly_confidential")
FINGERPRINT_SHINGLE = 8  # długość n-gramu słów; 8 słów z rzędu to praktycznie zawsze cytat

HEADER_KEYS = {
    "Policy Version", "Enabled", "Semantic Provider", "Semantic Model", "Allowed Models",
    "Internal Domains", "External LLM Keywords", "External Destination Keywords", "External Tools",
}
RULE_KEYS = {
    "Rule", "Source", "Authored By", "Version", "Enabled", "Category", "Classification",
    "Description", "Allowed Roles", "External LLM", "External Destinations", "Summarize Internal",
    "Keywords", "Markers", "Regex", "Fingerprint", "Semantic Classifier", "Semantic Threshold",
    "On Violation", "On Detector Error", "Notify", "Required Refusal",
}
REQUIRED_RULE_KEYS = {
    "Rule", "Source", "Category", "Classification", "Allowed Roles", "On Violation", "Required Refusal",
}
REPEATABLE_KEYS = {"Regex"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    document: str
    section: str
    authored_by: str
    version: int
    enabled: bool
    category: str
    classification: str
    description: str
    allowed_roles: tuple[str, ...]  # "*" = wszystkie role, pusta krotka = nikt
    external_llm: str
    external_destinations: str
    summarize_internal: str
    keywords: tuple[str, ...]
    markers: tuple[str, ...]
    marker_patterns: tuple[re.Pattern, ...]  # skompilowane raz przy ładowaniu, nie przy każdym sprawdzeniu
    regex: tuple[re.Pattern, ...]
    fingerprint: tuple[str, ...]
    semantic_classifier: Optional[str]
    semantic_threshold: float
    on_violation: str
    on_detector_error: str
    notify: tuple[str, ...]
    refusal: str

    def role_allowed(self, role: str) -> bool:
        return "*" in self.allowed_roles or role in self.allowed_roles


@dataclass(frozen=True)
class Policy:
    version: str
    enabled: bool
    semantic_provider: str
    semantic_model: Optional[str]
    allowed_models: tuple[str, ...]
    internal_domains: tuple[str, ...]
    external_llm_keywords: tuple[str, ...]
    external_destination_keywords: tuple[str, ...]
    external_tools: tuple[str, ...]
    rules: tuple[Rule, ...]
    active_rules: tuple[Rule, ...]
    fingerprints: dict  # rule_id → frozenset hashy n-gramów z plików Fingerprint
    semantic_categories: dict  # kategoria klasyfikatora → opisy reguł (katalog dla modelu)
    titles: dict  # nazwa dokumentu → pierwszy nagłówek (do komunikatów o blokadzie)
    documents_dir: Path
    fixtures_dir: Path
    warnings: tuple[str, ...]


# ----------------------------- dokumenty ------------------------------------

_HEADING = re.compile(r"^(§\s*\d+)")
_POINT = re.compile(r"^(\d+)\.\s")


def control_markers(path: Path) -> dict[str, str]:
    """Komentarze „control: ID” z dokumentu → paragraf i ustęp, którego dotyczą ("§3 ust. 2")."""
    return _markers(read_paragraphs(path))


def _markers(paragraphs: list[DocParagraph]) -> dict[str, str]:
    found, section = {}, None
    for p in paragraphs:
        if m := _HEADING.match(p.text):
            section = m.group(1).replace(" ", "")
            target = section
        elif m := _POINT.match(p.text):
            target = f"{section} ust. {m.group(1)}"
        else:
            target = section
        for rule_id in p.controls:
            found[rule_id] = target
    return found


def document_files(documents_dir: Path) -> list[Path]:
    return sorted(p for p in Path(documents_dir).iterdir() if p.suffix.lower() in SUPPORTED)


class _Documents:
    """Dokumenty czytane najwyżej raz na jedno przeładowanie polityki (także błędy odczytu)."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self._cache: dict[str, object] = {}

    def paragraphs(self, name: str) -> list[DocParagraph]:
        if name not in self._cache:
            try:
                self._cache[name] = read_paragraphs(self.directory / name)
            except ValueError as e:
                self._cache[name] = e
        result = self._cache[name]
        if isinstance(result, ValueError):
            raise result
        return result

    def names(self) -> list[str]:
        return [p.name for p in document_files(self.directory)]


_WORD = re.compile(r"\w+")


def shingles(text: str) -> frozenset:
    """Hashe n-gramów słów; ten sam fragment daje te same hashe niezależnie od formatowania.

    Wbudowany hash() jest stały tylko w obrębie procesu, ale odciski są liczone od nowa przy
    każdym załadowaniu polityki, więc to wystarcza — i jest wielokrotnie szybsze od blake2b.
    """
    words = _WORD.findall(text.lower())
    n = FINGERPRINT_SHINGLE
    return frozenset(hash(tuple(words[i:i + n])) for i in range(len(words) - n + 1))


# ----------------------------- parser ---------------------------------------

def _blocks(text: str) -> list[list[tuple[int, str, str]]]:
    blocks, current = [], []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#"):
            continue
        if not line:
            if current:
                blocks.append(current)
                current = []
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise PolicyError(f"linia {no}: oczekiwano 'Klucz: wartość', jest '{line}'")
        current.append((no, key.strip(), value.strip()))
    if current:
        blocks.append(current)
    return blocks


def _fields(block, allowed: set[str], what: str) -> dict:
    fields: dict = {}
    for no, key, value in block:
        if key not in allowed:
            raise PolicyError(f"linia {no}: nieznany klucz '{key}' w {what}")
        if key in REPEATABLE_KEYS:
            fields.setdefault(key, []).append(value)
        elif key in fields:
            raise PolicyError(f"linia {no}: powtórzony klucz '{key}' w {what}")
        else:
            fields[key] = value
    return fields


def _list(value: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in value.split(",") if v.strip())


def _bool(value: str, what: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "tak", "yes"):
        return True
    if v in ("false", "nie", "no"):
        return False
    raise PolicyError(f"{what}: oczekiwano true/false, jest '{value}'")


def _choice(value: str, options: tuple, what: str) -> str:
    v = value.strip().lower()
    if v not in options:
        raise PolicyError(f"{what}: '{value}' spoza dozwolonych wartości {', '.join(options)}")
    return v


def _roles(value: str, what: str) -> tuple[str, ...]:
    items = _list(value)
    if items == ("none",):
        return ()
    if items == ("*",):
        return ("*",)
    roles = []
    for item in items:
        role = normalize_role(item)
        if role not in ROLES:
            raise PolicyError(f"{what}: nieznana rola '{item}' (dostępne: {', '.join(ROLES)})")
        roles.append(role)
    return tuple(roles)


def _rule(fields: dict, documents: _Documents, fixtures_dir: Path) -> Rule:
    rule_id = fields["Rule"]
    what = f"reguła {rule_id}"
    missing = REQUIRED_RULE_KEYS - fields.keys()
    if missing:
        raise PolicyError(f"{what}: brak pól {', '.join(sorted(missing))}")

    document, sep, section = fields["Source"].partition("|")
    if not sep:
        raise PolicyError(f"{what}: Source musi mieć postać 'dokument.md | §N ust. M'")
    document, section = document.strip(), section.strip()
    if not (documents.directory / document).is_file():
        raise PolicyError(f"{what}: dokument '{document}' nie istnieje")
    try:
        marked = _markers(documents.paragraphs(document)).get(rule_id)
    except ValueError as e:
        raise PolicyError(f"{what}: {e}") from e
    if marked != section:
        raise PolicyError(
            f"{what}: w {document} brak znacznika control: {rule_id} przy '{section}'"
            + (f" (znacznik jest przy '{marked}')" if marked else "")
        )

    try:
        regex = tuple(re.compile(p) for p in fields.get("Regex", []))
    except re.error as e:
        raise PolicyError(f"{what}: błędny Regex: {e}") from e

    fingerprint = _list(fields.get("Fingerprint", ""))
    for path in fingerprint:
        if not (fixtures_dir / path).is_file():
            raise PolicyError(f"{what}: plik Fingerprint '{path}' nie istnieje")

    classifier = fields.get("Semantic Classifier") or None
    try:
        threshold = float(fields.get("Semantic Threshold", "0.75"))
        version = int(fields.get("Version", "1"))
    except ValueError as e:
        raise PolicyError(f"{what}: {e}") from e
    if not 0.0 <= threshold <= 1.0:
        raise PolicyError(f"{what}: Semantic Threshold musi być w przedziale 0–1")

    keywords = tuple(k.lower() for k in _list(fields.get("Keywords", "")))
    markers = _list(fields.get("Markers", ""))
    if not (keywords or markers or regex or fingerprint or classifier):
        raise PolicyError(f"{what}: brak jakiejkolwiek metody detekcji")

    return Rule(
        id=rule_id,
        document=document,
        section=section,
        authored_by=fields.get("Authored By", "manual"),
        version=version,
        enabled=_bool(fields.get("Enabled", "true"), f"{what}: Enabled"),
        category=fields["Category"],
        classification=_choice(fields["Classification"], CLASSIFICATIONS, f"{what}: Classification"),
        description=fields.get("Description", ""),
        allowed_roles=_roles(fields["Allowed Roles"], f"{what}: Allowed Roles"),
        external_llm=_choice(fields.get("External LLM", "block"), USAGE, f"{what}: External LLM"),
        external_destinations=_choice(
            fields.get("External Destinations", "block"), USAGE, f"{what}: External Destinations"),
        summarize_internal=_choice(
            fields.get("Summarize Internal", "allow"), USAGE, f"{what}: Summarize Internal"),
        keywords=keywords,
        markers=markers,
        # Klauzule są pisane wielkimi literami; zwykłe „poufne” w zdaniu nie jest oznaczeniem dokumentu.
        marker_patterns=tuple(re.compile(rf"(?<!\w){re.escape(m)}(?!\w)") for m in markers),
        regex=regex,
        fingerprint=fingerprint,
        semantic_classifier=classifier,
        semantic_threshold=threshold,
        on_violation=_choice(fields["On Violation"], ON_VIOLATION, f"{what}: On Violation"),
        on_detector_error=_choice(
            fields.get("On Detector Error", "block"), ON_DETECTOR_ERROR, f"{what}: On Detector Error"),
        notify=_list(fields.get("Notify", "")),
        refusal=fields["Required Refusal"].strip().strip('"'),
    )


def _read_fixture(path: Path, rule_id: str) -> str:
    try:
        return read_text(path)
    except ValueError as e:
        raise PolicyError(f"reguła {rule_id}: {e}") from e


def _fingerprints(rules: list[Rule], documents: _Documents, fixtures_dir: Path) -> dict[str, frozenset]:
    """N-gramy plików Fingerprint każdej reguły, bez treści szablonowej.

    N-gram występujący w więcej niż jednym pliku albo w dokumentach regulaminowych to nagłówek,
    stopka lub formułka szablonu, a nie poufna treść, więc nie może wskazywać konkretnej reguły.
    """
    per_file = {p: shingles(_read_fixture(fixtures_dir / p, r.id)) for r in rules for p in r.fingerprint}
    seen, boilerplate = set(), set()
    for grams in per_file.values():
        boilerplate |= seen & grams
        seen |= grams
    for name in documents.names():
        try:
            boilerplate |= seen & shingles("\n".join(p.text for p in documents.paragraphs(name)))
        except ValueError:
            pass  # błędny dokument zgłaszają ostrzeżenia spójności
    return {r.id: frozenset().union(*(per_file[p] for p in r.fingerprint)) - boilerplate for r in rules}


def _semantic_categories(rules: tuple[Rule, ...]) -> dict[str, str]:
    categories: dict[str, list[str]] = {}
    for rule in rules:
        if rule.semantic_classifier:
            categories.setdefault(rule.semantic_classifier, []).append(rule.description)
    return {name: "; ".join(descs) for name, descs in categories.items()}


def parse_policy(text: str, documents_dir: Path = DEFAULT_DOCUMENTS_DIR,
                 fixtures_dir: Path = DEFAULT_FIXTURES_DIR) -> Policy:
    documents, fixtures_dir = _Documents(documents_dir), Path(fixtures_dir)
    blocks = _blocks(text)
    if not blocks:
        raise PolicyError("plik reguł jest pusty")
    header = _fields(blocks[0], HEADER_KEYS, "nagłówku polityki")
    if "Policy Version" not in header:
        raise PolicyError("pierwszy blok musi być nagłówkiem z 'Policy Version'")

    rules = []
    for block in blocks[1:]:
        if block[0][1] != "Rule":
            raise PolicyError(f"linia {block[0][0]}: blok reguły musi zaczynać się od 'Rule:'")
        rule = _rule(_fields(block, RULE_KEYS, f"regule z linii {block[0][0]}"), documents, fixtures_dir)
        if any(r.id == rule.id for r in rules):
            raise PolicyError(f"powtórzony identyfikator reguły {rule.id}")
        rules.append(rule)

    rule_ids = {r.id for r in rules}
    fingerprints = _fingerprints(rules, documents, fixtures_dir)
    warnings, titles = [], {}
    for name in documents.names():
        try:
            paragraphs = documents.paragraphs(name)
        except ValueError as e:
            warnings.append(str(e))
            continue
        titles[name] = next((p.text for p in paragraphs if p.heading), name)
        warnings += [f"{name}: komentarz control: {rule_id} ({section}) nie ma reguły"
                     for rule_id, section in _markers(paragraphs).items() if rule_id not in rule_ids]

    enabled = _bool(header.get("Enabled", "true"), "nagłówek: Enabled")
    active_rules = tuple(r for r in rules if r.enabled) if enabled else ()
    return Policy(
        version=header["Policy Version"],
        enabled=enabled,
        semantic_provider=header.get("Semantic Provider", "ollama").lower(),
        semantic_model=header.get("Semantic Model") or None,
        allowed_models=_list(header.get("Allowed Models", "")),
        internal_domains=tuple(d.lower() for d in _list(header.get("Internal Domains", ""))),
        external_llm_keywords=tuple(k.lower() for k in _list(header.get("External LLM Keywords", ""))),
        external_destination_keywords=tuple(
            k.lower() for k in _list(header.get("External Destination Keywords", ""))),
        external_tools=_list(header.get("External Tools", "")),
        rules=tuple(rules),
        active_rules=active_rules,
        fingerprints={r.id: fingerprints[r.id] for r in active_rules if fingerprints.get(r.id)},
        semantic_categories=_semantic_categories(active_rules),
        titles=titles,
        documents_dir=documents.directory,
        fixtures_dir=fixtures_dir,
        warnings=tuple(warnings),
    )


# ----------------------------- hot reload -----------------------------------

class PolicyStore:
    """Trzyma ostatnią poprawną wersję polityki i przeładowuje ją, gdy zmieni się treść pliku.

    Błędny plik nie wyłącza ochrony: zostaje poprzednia wersja, a `last_error` i zdarzenie
    `policy_reload_failed` sygnalizują problem. Bez żadnej poprawnej wersji `get()` zwraca None
    i silnik blokuje wszystko (fail-closed).

    Zmiany plików są sprawdzane najwyżej co `reload_interval` sekund; w międzyczasie `get()`
    zwraca politykę z pamięci bez żadnego odczytu z dysku.
    """

    def __init__(self, path: Path = DEFAULT_RULES_PATH, on_event: Optional[Callable[[dict], None]] = None,
                 documents_dir: Path = DEFAULT_DOCUMENTS_DIR, fixtures_dir: Path = DEFAULT_FIXTURES_DIR,
                 reload_interval: float = DEFAULT_RELOAD_INTERVAL):
        self.path = Path(path)
        self.documents_dir = Path(documents_dir)
        self.fixtures_dir = Path(fixtures_dir)
        self.reload_interval = reload_interval
        self.on_event = on_event or (lambda event: None)
        self.last_error: Optional[str] = None
        self.loaded_at: Optional[str] = None
        self._policy: Optional[Policy] = None
        self._signature: Optional[tuple] = None
        self._checked_at: Optional[float] = None
        self._lock = threading.Lock()

    def get(self) -> Optional[Policy]:
        now = time.monotonic()
        if self._checked_at is not None and now - self._checked_at < self.reload_interval:
            return self._policy
        self._checked_at = now
        try:
            raw = self.path.read_bytes()
        except OSError as e:
            self._fail(f"nie można odczytać {self.path.name}: {e}", None)
            return self._policy
        signature = (raw, self._files_signature())
        if signature == self._signature:
            return self._policy

        with self._lock:
            if signature != self._signature:
                try:
                    policy = parse_policy(raw.decode("utf-8"), self.documents_dir, self.fixtures_dir)
                except (PolicyError, UnicodeDecodeError, OSError) as e:
                    self._fail(str(e), signature)
                else:
                    self._policy, self._signature, self.last_error = policy, signature, None
                    self.loaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    self.on_event({
                        "event": "policy_loaded",
                        "policy_version": policy.version,
                        "active_rules": len(policy.active_rules),
                        "warnings": list(policy.warnings),
                    })
        return self._policy

    def _files_signature(self) -> tuple:
        """Nazwa, rozmiar i czas modyfikacji dokumentów i fixtures: edycja dokumentu też przeładowuje politykę.

        os.scandir zwraca metadane razem z listą plików (na Windows bez osobnego stat na plik).
        """
        parts = []
        for directory in (self.documents_dir, self.fixtures_dir):
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if entry.is_file():
                            st = entry.stat()
                            parts.append((str(directory), entry.name, st.st_size, st.st_mtime_ns))
            except OSError:
                parts.append((str(directory), None, 0, 0))
        return tuple(sorted(parts))

    def status(self) -> dict:
        policy = self.get()
        return {
            "policy_version": policy.version if policy else None,
            "enabled": policy.enabled if policy else False,
            "active_rules": len(policy.active_rules) if policy else 0,
            "total_rules": len(policy.rules) if policy else 0,
            "loaded_at": self.loaded_at,
            "last_error": self.last_error,
            "warnings": list(policy.warnings) if policy else [],
        }

    def _fail(self, error: str, signature: Optional[tuple]) -> None:
        if signature is not None:
            self._signature = signature  # ten sam błędny plik nie jest parsowany przy każdym zapytaniu
        if error == self.last_error:
            return
        self.last_error = error
        self.on_event({
            "event": "policy_reload_failed",
            "error": error,
            "kept_version": self._policy.version if self._policy else None,
        })
