import csv
import hashlib
import hmac
import io
import re
import secrets
from pathlib import Path
from typing import Iterable, Optional

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

# Short values are not searched blindly across text - "5" or "1102" would trigger false positives.
MIN_KNOWN_VALUE_LEN = 6

REDACTED_CELL = "[REDACTED]"

# Bracketed token in various formats, robust to model transformations:
# <EMAIL_1>, <email 1>, [EMAIL-1], &lt;EMAIL_1&gt;, <PHONE-NO_2>.
_TOKEN_RE = re.compile(
    r"(?:<|&lt;|\[|\()\s*([A-Za-z][A-Za-z_\- ]*?)[\s_\-]*(\d+)\s*(?:>|&gt;|\]|\))"
)
_PSEUDONYM_RE = re.compile(r"\b(?:ID|id|Id)[-_]([0-9a-fA-F]{10})\b")


def label_for(entity_type: str) -> str:
    """Label for redacted value - same format as pii_policy.redact: [TYPE]."""
    return f"[{entity_type}]"


_SEVERITY = ["allow", "pseudonymize", "redact", "block"]


def role_policy(role: str) -> dict:
    """User channel policy for role: type -> allow / redact / block / pseudonymize."""
    cfg = ROLES.get(role, {})
    policy = dict(DEFAULT_ROLE_PII_POLICY)
    for entity_type in cfg.get("allowed_pii", []):
        policy[entity_type] = "allow"
    policy.update(cfg.get("pii_policy", {}))
    # Global rules apply to every role; role override can only tighten them.
    for entity_types, action in ((GLOBAL_REDACTED_PII, "redact"), (GLOBAL_BLOCKED_PII, "block")):
        for entity_type in entity_types:
            current = policy.get(entity_type, "allow")
            policy[entity_type] = max(current, action, key=_SEVERITY.index)
    return policy


def chatbot_action(entity_type: str) -> str:
    """Action for entity type in chatbot channel; unknown types are masked by default."""
    return CHATBOT_PII_POLICY.get(entity_type, "redact")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", text.upper())


class Vault:
    """Substitution vault for a conversation turn: sensitive value <-> token visible to chatbot.

    Standard types receive sequential tokens (<EMAIL_1>), identifiers receive a stable HMAC pseudonym
    (ID-3fa9c21b07), identical across conversations to enable grouping and joins.
    """

    def __init__(self, id_types: Optional[Iterable[str]] = None):
        # Types converted into stable pseudonyms. None = fallback to config.py list;
        # policy overrides apply from the next vault instantiation.
        self.id_types: Optional[tuple[str, ...]] = tuple(id_types) if id_types is not None else None
        self._by_key: dict[str, tuple[str, str, str]] = {}   # token key -> (token, type, value)
        self._by_value: dict[tuple[str, str], str] = {}      # (type, value) -> token
        self._counters: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._by_key)

    def is_id_type(self, entity_type: str) -> bool:
        return entity_type in (self.id_types if self.id_types is not None else ID_TYPES)

    def token_for(self, entity_type: str, value: str) -> str:
        known = self._by_value.get((entity_type, value))
        if known:
            return known
        if self.is_id_type(entity_type):
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
        """Values long enough to be searched reliably in text."""
        return [v for _, t, v in self._by_key.values() if len(v) >= MIN_KNOWN_VALUE_LEN and not self.is_id_type(t)]

    def mask_entities(self, text: str, entities: list[dict]) -> str:
        """Substitutes specified entities ({"type","start","end"}) with tokens."""
        out = text
        for e in sorted(entities, key=lambda e: e["start"], reverse=True):
            out = out[: e["start"]] + self.token_for(e["type"], text[e["start"]:e["end"]]) + out[e["end"]:]
        return out

    def mask_known(self, text: str) -> str:
        """Masks values that are already in the vault whenever they appear again."""
        for token, entity_type, value in sorted(self._by_key.values(), key=lambda x: -len(x[2])):
            if len(value) >= MIN_KNOWN_VALUE_LEN and not self.is_id_type(entity_type) and value in text:
                text = text.replace(value, token)
        return text

    def _resolve(self, match: re.Match, pseudonym: bool) -> Optional[tuple[str, str, str]]:
        key = match.group(1).lower() if pseudonym else _slug(match.group(1)) + match.group(2)
        return self._by_key.get(key)

    def _substitute(self, text: str, replace) -> str:
        for pattern, pseudonym in ((_TOKEN_RE, False), (_PSEUDONYM_RE, True)):
            def repl(match, pseudonym=pseudonym):
                entry = self._resolve(match, pseudonym)
                # Unknown tokens remain unmodified - we never guess sensitive values.
                return match.group(0) if entry is None else replace(entry, match.group(0))
            text = pattern.sub(repl, text)
        return text

    def unmask(self, text: str) -> str:
        """Substitutes original values back for all tokens (for local tool arguments)."""
        return self._substitute(text, lambda entry, found: entry[2])

    def unmask_args(self, args: dict) -> dict:
        return {k: self.unmask(v) if isinstance(v, str) else v for k, v in args.items()}

    def render(self, text: str, policy: dict, own_text: str = "") -> tuple[str, dict]:
        """User channel view: token -> value, label, or pseudonym based on role policy.

        Values that the user provided in their own input (`own_text`) are returned unmasked.
        Returns (text, stats) where stats is {"restored", "redacted", "blocked": [types]}.
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
    """Applies column policy to CSV tool result (first row is header).

    Identifiers are always converted into pseudonyms - a role with 'allow' unmasks them in the reply.
    Other columns: 'allow' leaves content unchanged; any other action removes the cell value.
    """
    lines = text.split("\n")
    header = next(csv.reader([lines[0]]), [])
    actions = {}
    for i, column in enumerate(header):
        entity_type = column_types.get(column)
        if vault.is_id_type(entity_type):
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
                trailer.append(line)    # e.g. "(no matching rows)" or "[truncated: ...]"
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
    """Removes system paths and stack traces from tool output."""
    text = _TRACEBACK_RE.sub("[stack trace removed]", text)
    for root in _PROJECT_ROOTS:
        for variant in (root, root.replace("\\", "/"), root.replace("\\", "\\\\")):
            text = text.replace(variant, "<PATH>")
    return _PATH_RE.sub("<PATH>", text)
