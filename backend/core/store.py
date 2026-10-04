"""Ładowanie polityki z pliku YAML z przeładowaniem na żywo.

Polityka = plik YAML -> aktywny profil ścisłości -> nadpisania z interfejsu (osobny plik JSON).
Zmiana któregokolwiek z plików jest wykrywana przy najbliższym `get()` (porównanie czasu
modyfikacji i rozmiaru), więc nie trzeba restartować serwera ani polegać na zdarzeniach systemu
plików, które w kontenerach na Windows bywają zawodne.

Błędny plik nie zatrzymuje działającego serwera: obowiązuje ostatnia poprawna polityka, a błąd jest
widoczny w `status()`. Przy starcie błędny plik kończy się wyjątkiem `PolicyError`.
"""
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import yaml
from pydantic import ValidationError

from .models import Policy, ProfileOverride

log = logging.getLogger("control_layer.policy")

MAX_FILE_BYTES = 1_000_000
DEFAULT_PROFILE = "balanced"
PROFILE_SECTIONS = ("controls", "budgets")
MAX_REPORTED_CHANGES = 50


class PolicyError(Exception):
    """Plik polityki jest nieczytelny albo niepoprawny; `problems` to lista opisów po jednym błędzie."""

    def __init__(self, message: str, problems: Optional[list[str]] = None):
        super().__init__(message)
        self.problems = problems or []

    def __str__(self) -> str:
        return "\n".join([super().__str__(), *[f"  - {p}" for p in self.problems]])


# --- funkcje pomocnicze (czyste) ------------------------------------------------------------------

def deep_merge(base: dict, extra: dict) -> dict:
    """Nowy słownik: słowniki scalane rekurencyjnie, wszystko inne (także listy) nadpisywane."""
    out = dict(base)
    for key, value in extra.items():
        out[key] = deep_merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def leaf_paths(data: dict, prefix: str = "") -> list[str]:
    paths = []
    for key, value in data.items():
        path = f"{prefix}{key}"
        paths += leaf_paths(value, path + ".") if isinstance(value, dict) and value else [path]
    return paths


def diff(old: dict, new: dict) -> list[dict]:
    """Zmiany liści między dwiema wersjami polityki: [{"path", "old", "new"}], najwyżej MAX_REPORTED_CHANGES."""
    changes: list[dict] = []

    def walk(a: Any, b: Any, path: str) -> None:
        if len(changes) >= MAX_REPORTED_CHANGES:
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in list(a) + [k for k in b if k not in a]:
                walk(a.get(key), b.get(key), f"{path}.{key}" if path else str(key))
        elif a != b:
            changes.append({"path": path, "old": a, "new": b})

    walk(old, new, "")
    return changes


def _problems(exc: ValidationError, prefix: str = "") -> list[str]:
    out = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"]) or "(cała polityka)"
        message = error["msg"]
        if error["type"] == "extra_forbidden":
            message = "nieznany klucz (literówka?)"
        out.append(f"{prefix}{where}: {message}")
    return out


def _read_yaml(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise PolicyError(f"{path.name}: plik jest większy niż {MAX_FILE_BYTES} bajtów")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyError(f"Nie znaleziono pliku polityki: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{path.name}: nie można odczytać pliku ({type(exc).__name__})") from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (linia {mark.line + 1}, kolumna {mark.column + 1})" if mark else ""
        raise PolicyError(f"{path.name}: niepoprawny YAML{where}") from None
    if not isinstance(data, dict):
        raise PolicyError(f"{path.name}: plik musi zawierać mapę kluczy (jest pusty albo ma inny kształt)")
    return data


def _read_overrides(path: Optional[Path]) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError) as exc:
        raise PolicyError(f"{path.name}: niepoprawny plik nadpisań ({type(exc).__name__})") from None
    if not isinstance(data, dict):
        raise PolicyError(f"{path.name}: plik nadpisań musi zawierać obiekt JSON")
    return data


def build_policy(raw: dict, overrides: Optional[dict] = None) -> Policy:
    """Składa politykę: plik -> profil -> nadpisania. Sprawdza także profile nieaktywne,
    żeby błąd w jednym z nich wychodził od razu, a nie dopiero przy przełączeniu."""
    overrides = overrides or {}
    profiles = raw.get("profiles") or {}
    if not isinstance(profiles, dict):
        raise PolicyError("profiles: musi być mapą nazwa -> nadpisania")
    problems: list[str] = []
    for name, body in profiles.items():
        try:
            ProfileOverride.model_validate(body or {})
        except ValidationError as exc:
            problems += _problems(exc, f"profiles.{name}.")
    if problems:
        raise PolicyError("Niepoprawny profil ścisłości", problems)

    base = {k: v for k, v in raw.items() if k not in ("profile", "profiles", "profile_names")}
    base = deep_merge(base, {k: v for k, v in overrides.items() if k != "profile"})

    def assemble(name: str) -> Policy:
        merged = base
        for section in PROFILE_SECTIONS:
            patch = (profiles.get(name) or {}).get(section)
            if patch:
                # Profil leży pod nadpisaniami z interfejsu: te drugie wygrywają.
                merged = {**merged, section: deep_merge(deep_merge(raw.get(section, {}), patch),
                                                        overrides.get(section, {}))}
        return Policy.model_validate({**merged, "profile": name, "profile_names": tuple(profiles)})

    active = overrides.get("profile") or raw.get("profile") or DEFAULT_PROFILE
    if active not in profiles and not (active == DEFAULT_PROFILE and not profiles):
        raise PolicyError(f"Nieznany profil „{active}”", [f"dostępne profile: {', '.join(profiles) or '(brak)'}"])
    try:
        policy = assemble(active)
        for name in profiles:
            if name != active:
                assemble(name)
    except ValidationError as exc:
        raise PolicyError("Niepoprawna polityka", _problems(exc)) from None
    return policy


def policy_digest(policy: Policy) -> str:
    return hashlib.sha256(json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()[:16]


# --- magazyn ---------------------------------------------------------------------------------------

_default_store: Optional["PolicyStore"] = None
_default_lock = threading.Lock()


def get_store() -> "PolicyStore":
    """Wspólny magazyn polityki procesu (plik z POLICY_FILE albo policy/policy.yaml), tworzony przy
    pierwszym użyciu. Niepoprawny plik daje `PolicyError` przy każdej próbie, aż do poprawienia."""
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = PolicyStore()
        return _default_store


def reset_default_store() -> None:
    """Zapomina wspólny magazyn (testy, zmiana POLICY_FILE w trakcie działania procesu)."""
    global _default_store
    with _default_lock:
        _default_store = None


def default_policy_path() -> Path:
    return Path(os.getenv("POLICY_FILE") or Path(__file__).resolve().parents[2] / "policy" / "policy.yaml")


class PolicyStore:
    """Aktualna polityka z automatycznym przeładowaniem. Bezpieczny wątkowo; obiekt `Policy` jest
    niezmienny, więc wywołujący może go trzymać przez całą turę bez ryzyka, że zmieni się w trakcie."""

    def __init__(self, path: Optional[os.PathLike] = None, overrides_path: Optional[os.PathLike] = None,
                 on_reload: Optional[Callable[[Policy, list[dict]], None]] = None):
        self.path = Path(path) if path else default_policy_path()
        # Nadpisania z interfejsu: podana ścieżka, POLICY_OVERRIDES_FILE albo plik obok polityki. Zmienna pozwala
        # trzymać je w zapisywalnym katalogu stanu, gdy sama polityka jest zamontowana tylko do odczytu.
        self.overrides_path = Path(overrides_path or os.getenv("POLICY_OVERRIDES_FILE")
                                   or self.path.with_name(self.path.stem + ".overrides.json"))
        self._on_reload = on_reload
        self._lock = threading.RLock()
        self._policy: Optional[Policy] = None
        self._digest = ""
        self._sig: Optional[tuple] = None
        self._version = 0
        self._loaded_at: Optional[float] = None
        self._last_error: Optional[dict] = None
        self._last_changes: list[dict] = []
        self._overridden: list[str] = []
        with self._lock:
            self._load(initial=True)

    # --- odczyt ---

    def get(self) -> Policy:
        if self._signature() != self._sig:
            with self._lock:
                if self._signature() != self._sig:
                    self._load()
        return self._policy

    def status(self) -> dict:
        self.get()
        error = self._last_error
        return {
            "path": str(self.path), "version": self._version, "digest": self._digest,
            "profile": self._policy.profile, "profiles": list(self._policy.profile_names),
            "loaded_at": self._loaded_at, "overridden": list(self._overridden),
            "last_changes": list(self._last_changes), "error": error,
        }

    # --- nadpisania z interfejsu (decyzja A: plik polityki zostaje źródłem, interfejs go nadpisuje) ---

    def set_override(self, dotted_path: str, value: Any) -> Policy:
        """Zapisuje nadpisanie jednego klucza (np. `controls.prompt_guard.mode`). Niepoprawna wartość
        jest odrzucana wyjątkiem `PolicyError` i niczego nie zmienia."""
        with self._lock:
            overrides = _read_overrides(self.overrides_path)
            node = overrides
            *parents, leaf = dotted_path.split(".")
            for part in parents:
                node = node.setdefault(part, {})
                if not isinstance(node, dict):
                    raise PolicyError(f"Nie można nadpisać „{dotted_path}”: „{part}” nie jest sekcją")
            node[leaf] = value
            build_policy(_read_yaml(self.path), overrides)      # walidacja przed zapisem
            self._write_overrides(overrides)
            self._load()
            return self._policy

    def clear_overrides(self, dotted_path: Optional[str] = None) -> Policy:
        """Usuwa jedno nadpisanie albo wszystkie; wartości wracają do tych z pliku polityki."""
        with self._lock:
            if dotted_path is None:
                overrides: dict = {}
            else:
                overrides = _read_overrides(self.overrides_path)
                *parents, leaf = dotted_path.split(".")
                trail = [overrides]
                for part in parents:
                    child = trail[-1].get(part)
                    if not isinstance(child, dict):
                        break
                    trail.append(child)
                else:
                    trail[-1].pop(leaf, None)
                    for node, key in zip(reversed(trail[:-1]), reversed(parents)):
                        if not node[key]:
                            del node[key]
            self._write_overrides(overrides)
            self._load()
            return self._policy

    # --- wnętrze ---

    def _signature(self) -> tuple:
        sig = []
        for path in (self.path, self.overrides_path):
            try:
                stat = path.stat()
                sig.append((stat.st_mtime_ns, stat.st_size))
            except OSError:
                sig.append(None)
        return tuple(sig)

    def _write_overrides(self, overrides: dict) -> None:
        if not overrides:
            self.overrides_path.unlink(missing_ok=True)
            return
        tmp = self.overrides_path.with_name(self.overrides_path.name + ".tmp")
        tmp.write_text(json.dumps(overrides, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.overrides_path)

    def _load(self, initial: bool = False) -> None:
        sig = self._signature()
        try:
            overrides = _read_overrides(self.overrides_path)
            policy = build_policy(_read_yaml(self.path), overrides)
        except PolicyError as exc:
            self._sig = sig     # ten sam błędny plik nie jest parsowany przy każdym żądaniu
            if self._policy is None:
                raise
            self._last_error = {"message": str(exc).split("\n")[0], "problems": exc.problems, "at": time.time()}
            log.warning("Przeładowanie polityki nie powiodło się, obowiązuje poprzednia wersja: %s", exc)
            return
        self._sig = sig
        self._last_error = None
        self._overridden = leaf_paths(overrides)
        digest = policy_digest(policy)
        if digest == self._digest:
            return
        changes = diff(self._policy.model_dump(mode="json"), policy.model_dump(mode="json")) if self._policy else []
        self._policy, self._digest = policy, digest
        self._version += 1
        self._loaded_at = time.time()
        self._last_changes = changes
        if not initial:
            log.info("Polityka przeładowana (wersja %s, %s): %s", self._version, digest,
                     ", ".join(c["path"] for c in changes) or "bez zmian w treści")
            if self._on_reload:
                self._on_reload(policy, changes)
