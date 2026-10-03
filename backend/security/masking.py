import csv
import hashlib
import hmac
import io
import re
import secrets
from pathlib import Path
from typing import Optional

from config import (
    BASE_DIR,
    CHATBOT_PII_POLICY,
    DEFAULT_ROLE_PII_POLICY,
    GLOBAL_BLOCKED_PII,
    GLOBAL_REDACTED_PII,
    ID_TYPES,
    PSEUDONYM_KEY,
    ROLES,
)

_PSEUDONYM_KEY = (PSEUDONYM_KEY or secrets.token_hex(16)).encode()

# Krótkich wartości nie szukamy "na ślepo" w tekście — "5" czy "1102" trafiałyby wszędzie.
MIN_KNOWN_VALUE_LEN = 6

REDACTED_CELL = "[REDACTED]"

# Znacznik w nawiasach dowolnego rodzaju, z tolerancją na to, co model potrafi z nim zrobić:
# <EMAIL_1>, <email 1>, [EMAIL-1], &lt;EMAIL_1&gt;, <PHONE-NO_2>.
_TOKEN_RE = re.compile(
    r"(?:<|&lt;|\[|\()\s*([A-Za-z][A-Za-z_\- ]*?)[\s_\-]*(\d+)\s*(?:>|&gt;|\]|\))"
)
_PSEUDONYM_RE = re.compile(r"\b(?:ID|id|Id)[-_]([0-9a-fA-F]{10})\b")


def label_for(entity_type: str) -> str:
    """Etykieta w miejscu ukrytej wartości — ten sam format co pii_policy.redact: [TYP]."""
    return f"[{entity_type}]"


_SEVERITY = ["allow", "pseudonymize", "redact", "block"]


def role_policy(role: str) -> dict:
    """Polityka kanału użytkownika dla roli: typ -> allow / redact / block / pseudonymize."""
    cfg = ROLES.get(role, {})
    policy = dict(DEFAULT_ROLE_PII_POLICY)
    for entity_type in cfg.get("allowed_pii", []):
        policy[entity_type] = "allow"
    policy.update(cfg.get("pii_policy", {}))
    # Reguły globalne obowiązują każdą rolę; nadpisanie roli może je tylko zaostrzyć.
    for entity_types, action in ((GLOBAL_REDACTED_PII, "redact"), (GLOBAL_BLOCKED_PII, "block")):
        for entity_type in entity_types:
            current = policy.get(entity_type, "allow")
            policy[entity_type] = max(current, action, key=_SEVERITY.index)
    return policy


def chatbot_action(entity_type: str) -> str:
    """Co zrobić z typem w kanale chatbota; nieznany typ maskujemy."""
    return CHATBOT_PII_POLICY.get(entity_type, "redact")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", text.upper())


class Vault:
    """Sejf podstawień jednej rozmowy: wartość wrażliwa <-> znacznik widoczny dla chatbota.

    Zwykłe typy dostają kolejne znaczniki (<EMAIL_1>), identyfikatory — stały pseudonim HMAC
    (ID-3fa9c21b07), taki sam w każdej rozmowie, żeby dało się po nim grupować i liczyć.
    """

    def __init__(self):
        self._by_key: dict[str, tuple[str, str, str]] = {}   # klucz znacznika -> (znacznik, typ, wartość)
        self._by_value: dict[tuple[str, str], str] = {}      # (typ, wartość) -> znacznik
        self._counters: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._by_key)

    def token_for(self, entity_type: str, value: str) -> str:
        known = self._by_value.get((entity_type, value))
        if known:
            return known
        if entity_type in ID_TYPES:
            digest = hmac.new(_PSEUDONYM_KEY, f"{entity_type}:{value}".encode(), hashlib.sha256).hexdigest()
            token = f"ID-{digest[:10]}"
            key = digest[:10]
        else:
            self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
            name = re.sub(r"[^A-Z0-9]+", "_", entity_type.upper()).strip("_")
            token = f"<{name}_{self._counters[entity_type]}>"
            key = _slug(name) + str(self._counters[entity_type])
        self._by_key[key] = (token, entity_type, value)
        self._by_value[(entity_type, value)] = token
        return token

    def entries(self) -> list[tuple[str, str, str]]:
        return list(self._by_key.values())

    def raw_values(self) -> list[str]:
        """Wartości na tyle długie, że da się ich wiarygodnie szukać w tekście."""
        return [v for _, t, v in self._by_key.values() if len(v) >= MIN_KNOWN_VALUE_LEN and t not in ID_TYPES]

    def mask_entities(self, text: str, entities: list[dict]) -> str:
        """Zamienia wskazane encje ({"type","start","end"}) na znaczniki."""
        out = text
        for e in sorted(entities, key=lambda e: e["start"], reverse=True):
            out = out[: e["start"]] + self.token_for(e["type"], text[e["start"]:e["end"]]) + out[e["end"]:]
        return out

    def mask_known(self, text: str) -> str:
        """Maskuje wartości, które już są w sejfie, gdziekolwiek pojawią się ponownie."""
        for token, entity_type, value in sorted(self._by_key.values(), key=lambda x: -len(x[2])):
            if len(value) >= MIN_KNOWN_VALUE_LEN and entity_type not in ID_TYPES and value in text:
                text = text.replace(value, token)
        return text

    def _resolve(self, match: re.Match, pseudonym: bool) -> Optional[tuple[str, str, str]]:
        key = match.group(1).lower() if pseudonym else _slug(match.group(1)) + match.group(2)
        return self._by_key.get(key)

    def _substitute(self, text: str, replace) -> str:
        for pattern, pseudonym in ((_TOKEN_RE, False), (_PSEUDONYM_RE, True)):
            def repl(match, pseudonym=pseudonym):
                entry = self._resolve(match, pseudonym)
                # Nieznany znacznik zostaje w tekście bez zmian — nigdy nie zgadujemy wartości.
                return match.group(0) if entry is None else replace(entry, match.group(0))
            text = pattern.sub(repl, text)
        return text

    def unmask(self, text: str) -> str:
        """Podstawia prawdziwe wartości za wszystkie znaczniki (argumenty narzędzi lokalnych)."""
        return self._substitute(text, lambda entry, found: entry[2])

    def unmask_args(self, args: dict) -> dict:
        return {k: self.unmask(v) if isinstance(v, str) else v for k, v in args.items()}

    def render(self, text: str, policy: dict, own_text: str = "") -> tuple[str, dict]:
        """Wersja dla użytkownika: znacznik -> wartość, etykieta albo pseudonim, wg polityki roli.

        Wartości, które użytkownik sam wpisał (`own_text`), wracają do niego niezależnie od polityki.
        Zwraca (tekst, statystyki), gdzie statystyki to {"restored", "redacted", "blocked": [typy]}.
        """
        stats = {"restored": [], "redacted": [], "blocked": []}

        def replace(entry, found):
            token, entity_type, value = entry
            action = policy.get(entity_type, "redact")
            if action == "allow" or value in own_text:
                stats["restored"].append(entity_type)
                return value
            if action == "pseudonymize":
                return token
            stats["blocked" if action == "block" else "redacted"].append(entity_type)
            return label_for(entity_type)

        return self._substitute(text, replace), stats

    def token_spans(self, text: str) -> list[tuple[int, int]]:
        return [m.span() for p in (_TOKEN_RE, _PSEUDONYM_RE) for m in p.finditer(text)]


def mask_csv(text: str, column_types: dict, policy: dict, vault: Vault) -> tuple[str, dict]:
    """Stosuje politykę kolumn do wyniku narzędzia CSV (pierwsza linia to nagłówek).

    Identyfikatory zawsze wychodzą jako pseudonimy — rola z "allow" odzyska je w odpowiedzi.
    Pozostałe kolumny: "allow" zostaje bez zmian, każde inne działanie usuwa wartość.
    """
    lines = text.split("\n")
    header = next(csv.reader([lines[0]]), [])
    actions = {}
    for i, column in enumerate(header):
        entity_type = column_types.get(column)
        if entity_type in ID_TYPES:
            actions[i] = ("token", entity_type)
        elif entity_type and policy.get(entity_type, "redact") != "allow":
            actions[i] = ("redact", entity_type)
    stats = {"pseudonymized": 0, "redacted": 0}
    if not actions:
        return text, stats

    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)
    trailer = []
    for line in lines[1:]:
        row = next(csv.reader([line]), [])
        if len(row) != len(header):
            if line:
                trailer.append(line)    # np. "(no matching rows)" albo "[truncated: ...]"
            continue
        for i, (action, entity_type) in actions.items():
            if action == "token":
                row[i] = vault.token_for(entity_type, row[i])
                stats["pseudonymized"] += 1
            else:
                row[i] = REDACTED_CELL
                stats["redacted"] += 1
        writer.writerow(row)
    return out.getvalue() + "\n".join(trailer), stats


_PROJECT_ROOTS = sorted(
    {str(p) for p in (BASE_DIR.resolve(), *BASE_DIR.resolve().parents) if len(p.parts) > 1} | {str(Path.home())},
    key=len, reverse=True,
)
_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/(?:home|Users|usr|var|etc|opt|tmp)/)[^\s\"'<>|:*?]*")
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\):.*?(?=\n\S|\Z)", re.DOTALL)


def sanitize_paths(text: str) -> str:
    """Usuwa z wyniku narzędzia ścieżki systemowe i stack trace'y."""
    text = _TRACEBACK_RE.sub("[stack trace removed]", text)
    for root in _PROJECT_ROOTS:
        for variant in (root, root.replace("\\", "/"), root.replace("\\", "\\\\")):
            text = text.replace(variant, "<PATH>")
    return _PATH_RE.sub("<PATH>", text)
