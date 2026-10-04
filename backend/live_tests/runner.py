"""Scenariusze testowe: każdy z scenarios.json to tura czatu przez całą warstwę bezpieczeństwa.

Tryby (pole `mode`):
  live (domyślny) — prawdziwy model dostawcy; nic nie jest podmieniane atrapą.
  mock            — odpowiedzi modelu chatbota podaje skrypt scenariusza (pole `model`): bez kosztu i
                    deterministycznie. Dowodzi, co zrobi WARSTWA przy danej odpowiedzi modelu (np. wycieku),
                    a nie jak zachowa się model. Domyślnie działają tylko kontrole deterministyczne.

Warianty (pole `variants`): ten sam scenariusz uruchamiany z różną konfiguracją (np. zabezpieczenie włączone
i wyłączone) i pokazywany obok siebie.

Scenariusz bez wariantów i w trybie live zmienia konfigurację całego serwera na czas tury (stara ścieżka,
przywracana po turze), więc takie testy najlepiej uruchamiać, gdy nikt inny nie korzysta z czatu. Scenariusze
mock i z wariantami są IZOLOWANE: działają na kopii polityki tylko dla swojej tury i nie dotykają stanu serwera.
"""
import copy
import json
import re
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import pipeline
from config import DATA_ACCESS, ROLES, SETTINGS
from live_tests.isolated import MOCK_BASELINE, ScenarioChat, merge_config, policy_with

SCENARIOS_FILE = Path(__file__).with_name("scenarios.json")

# Limity, które scenariusz może zawęzić: klucz w scenarios.json -> zmienna w pipeline.
LIMITS = {"maxPromptChars": "MAX_PROMPT_CHARS", "maxTurnTokens": "MAX_TURN_TOKENS", "maxTurnCost": "MAX_TURN_COST"}
OUTCOMES = ("allowed", "blocked", "denied", "redacted", "error")
MODES = ("live", "mock")
NOTICE_END = "[End of notice]"      # koniec informacji warstwy dołączanej do pierwszej wiadomości
REPLY_CHARS = 1500

ROLE_BY_ID = {cfg["id"]: name for name, cfg in ROLES.items()}


def load_catalog() -> dict:
    """Grupy i scenariusze; plik jest czytany przy każdym wywołaniu, więc edycja działa bez restartu."""
    data = json.loads(SCENARIOS_FILE.read_text(encoding="utf-8"))
    ids = set()
    for s in data["scenarios"]:
        _validate(s, ids)
    return {"groups": data["groups"], "scenarios": data["scenarios"]}


def _validate(s: dict, ids: set) -> None:
    """Plik jest edytowany ręcznie, więc błędy mają mówić, który scenariusz i co jest nie tak."""
    name = s.get("id", "?")
    if name in ids:
        raise ValueError(f"Scenariusz {name}: powtórzony identyfikator")
    ids.add(name)
    if s["role"] not in ROLE_BY_ID:
        raise ValueError(f"Scenariusz {name}: nieznana rola {s['role']}")
    mode = s.get("mode", "live")
    if mode not in MODES:
        raise ValueError(f"Scenariusz {name}: nieznany tryb {mode!r} (dozwolone: {', '.join(MODES)})")
    if mode == "mock":
        script = s.get("model")
        if not script or not all(isinstance(step, dict) and ("reply" in step) != ("tool_calls" in step)
                                 for step in script):
            raise ValueError(f"Scenariusz {name}: tryb mock wymaga niepustego pola `model` z krokami "
                             f"{{\"reply\": ...}} albo {{\"tool_calls\": [...]}}")
    elif "model" in s:
        raise ValueError(f"Scenariusz {name}: pole `model` (skrypt atrapy) jest dozwolone tylko w trybie mock")
    variants = s.get("variants")
    if variants is not None:
        if not variants or any("id" not in v for v in variants):
            raise ValueError(f"Scenariusz {name}: `variants` musi być niepustą listą wariantów z polem `id`")
        if len({v["id"] for v in variants}) != len(variants):
            raise ValueError(f"Scenariusz {name}: identyfikatory wariantów muszą być unikalne")


# --- konfiguracja na czas scenariusza --------------------------------------------------------

_config_lock = threading.Lock()


def _set_access(name: str, areas: list[str]) -> None:
    """Obszary danych roli, jak w formularzu konfiguracji; narzędzia spoza obszarów zostają."""
    area_tools = {t for a in DATA_ACCESS.values() for t in a["tools"]}
    unknown = [a for a in areas if a not in DATA_ACCESS]
    if unknown:
        raise ValueError(f"Nieznane obszary danych: {unknown}")
    kept = [t for t in ROLES[name]["allowed_tools"] if t not in area_tools]
    ROLES[name]["allowed_tools"] = [t for a in areas for t in DATA_ACCESS[a]["tools"]] + kept


@contextmanager
def applied(config: Optional[dict]):
    """Stosuje zmiany konfiguracji scenariusza i przywraca poprzednie wartości po turze."""
    config = config or {}
    with _config_lock:
        saved = {
            "guard_mode": SETTINGS.guard_mode,
            "mask_pii": SETTINGS.mask_pii,
            "filters": dict(SETTINGS.filters),
            "roles": copy.deepcopy(ROLES),
            "limits": {var: getattr(pipeline, var) for var in LIMITS.values()},
        }
        try:
            if "guardMode" in config:
                SETTINGS.guard_mode = config["guardMode"]
            if "maskPii" in config:
                SETTINGS.mask_pii = config["maskPii"]
            unknown = [f for f in config.get("filters", {}) if f not in SETTINGS.filters]
            if unknown:
                raise ValueError(f"Nieznane filtry: {unknown}")
            SETTINGS.filters.update(config.get("filters", {}))
            for role_id, areas in config.get("roles", {}).items():
                _set_access(ROLE_BY_ID[role_id], areas)
            for key, value in config.get("limits", {}).items():
                setattr(pipeline, LIMITS[key], value)
            yield
        finally:
            SETTINGS.guard_mode, SETTINGS.mask_pii = saved["guard_mode"], saved["mask_pii"]
            SETTINGS.filters.clear()
            SETTINGS.filters.update(saved["filters"])
            for name, cfg in saved["roles"].items():       # na miejscu: inne moduły trzymają te słowniki
                ROLES[name].clear()
                ROLES[name].update(cfg)
            for var, value in saved["limits"].items():
                setattr(pipeline, var, value)


# --- ocena wyniku ----------------------------------------------------------------------------

# Separatory tysięcy i części dziesiętnych między cyframi: "6 959,17" i "6,959.17" -> "695917".
_DIGIT_SEPARATORS = re.compile(r"(?<=\d)[\s  ,.'](?=\d)")


def _appears(value: str, text: str) -> bool:
    if value.lower() in text.lower():
        return True
    if re.fullmatch(r"[\d.,]+", value):
        return _DIGIT_SEPARATORS.sub("", value) in _DIGIT_SEPARATORS.sub("", text)
    return False


def outcome_of(result: pipeline.TurnResult) -> str:
    if result.error:
        return "error"
    if result.blocked:
        return "blocked"
    if any(not c["allowed"] for c in result.tool_calls) or any(v["decision"] == "refuse" for v in result.verdicts):
        return "denied"
    if any(v["decision"] == "redact" for v in result.verdicts):
        return "redacted"
    return "allowed"


def _stages(result: pipeline.TurnResult) -> list[str]:
    stages = [v["stage"] for v in result.verdicts]
    stages += [c["stage"] for c in result.tool_calls if not c["allowed"] and c.get("stage")]
    return list(dict.fromkeys(stages))


def evaluate(expect: dict, result: pipeline.TurnResult, received: str = "") -> list[dict]:
    """Lista sprawdzeń {"name", "ok", "detail"}; scenariusz przechodzi, gdy wszystkie są ok.

    `received` to wszystko, co dostał model chatbota (dla `modelSaw` i `modelNeverSaw`)."""
    checks = []
    reply = result.reply or ""
    outcome = outcome_of(result)

    def check(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    if outcome == "error":
        check("model call", False, result.error)
    if "outcome" in expect:
        wanted = expect["outcome"] if isinstance(expect["outcome"], list) else [expect["outcome"]]
        check("outcome", outcome in wanted, f"expected {' or '.join(wanted)}, got {outcome}")
    if "stage" in expect:
        stages = _stages(result)
        check("control", set(stages) & set(expect["stage"]),
              f"expected {' or '.join(expect['stage'])}, got {', '.join(stages) or 'none'}")
    if "tool" in expect:
        names = expect["tool"]["name"]
        names = names if isinstance(names, list) else [names]
        allowed = expect["tool"].get("allowed", True)
        calls = [c for c in result.tool_calls if c["tool"] in names]
        made = ", ".join(f"{c['tool']} ({'allowed' if c['allowed'] else 'refused'})" for c in result.tool_calls)
        check("tool call", any(c["allowed"] is allowed for c in calls),
              f"expected {' or '.join(names)} {'allowed' if allowed else 'refused'}; calls: {made or 'none'}")
    for item in expect.get("contains", []):
        options = item if isinstance(item, list) else [item]
        check("reply contains", any(_appears(o, reply) for o in options), " or ".join(options))
    for value in expect.get("excludes", []):
        check("reply excludes", not _appears(value, reply), value)
    for value in expect.get("modelSaw", []):
        check("model received", _appears(value, received), value)
    for value in expect.get("modelNeverSaw", []):
        check("model never received", not _appears(value, received), value)
    if "masked" in expect:
        got = set(result.masked_for_model)
        want = set(expect["masked"])
        ok = got == set() if not want else want <= got
        check("hidden from model", ok,
              f"expected {', '.join(sorted(want)) or 'nothing'}, got {', '.join(sorted(got)) or 'nothing'}")
    return checks


def needs_live_model(ids: Optional[list[str]] = None) -> bool:
    """Czy wybrane scenariusze (domyślnie wszystkie) wołają prawdziwy model, czyli wymagają klucza dostawcy.
    Scenariusze mock działają bez klucza i sieci."""
    scenarios = load_catalog()["scenarios"]
    if ids:
        scenarios = [s for s in scenarios if s["id"] in ids]
    return any(s.get("mode", "live") == "live" for s in scenarios) if scenarios else True


def _isolated(scenario: dict) -> bool:
    return scenario.get("mode", "live") == "mock" or bool(scenario.get("variants"))


def _run_isolated(scenario: dict, variant: Optional[dict], on_turn: Optional[Callable]) -> dict:
    """Jedna tura (jeden wariant) na kopii polityki, bez zmiany globalnej konfiguracji serwera."""
    mock = scenario.get("mode", "live") == "mock"
    config = merge_config(MOCK_BASELINE if mock else {}, scenario.get("config") or {})
    config = merge_config(config, (variant or {}).get("config") or {})
    expect = (variant or {}).get("expect", scenario.get("expect", {}))
    label = (variant or {}).get("label") or (variant or {}).get("id")
    name = ROLE_BY_ID[scenario["role"]]
    conv = pipeline.Conversation(name)
    chat = ScenarioChat(scenario["model"] if mock else None)
    started = time.perf_counter()
    try:
        policy = policy_with(config, pipeline.current_policy(), ROLE_BY_ID)
        result = pipeline.run_turn(conv, scenario["prompt"], policy=policy, chat=chat)
    except Exception as exc:
        return {"id": scenario["id"], "variant": (variant or {}).get("id"), "label": label, "status": "error",
                "mode": scenario.get("mode", "live"), "checks": [], "error": f"{type(exc).__name__}: {exc}",
                "latencyMs": int((time.perf_counter() - started) * 1000)}

    event_id = on_turn(name, conv, result) if on_turn else None
    checks = evaluate(expect, result, chat.received())
    return {**_describe(scenario["id"], result, checks, event_id), "variant": (variant or {}).get("id"),
            "label": label, "mode": scenario.get("mode", "live"), "mockModel": chat.is_mock,
            "modelSaw": chat.last_user_view()[:REPLY_CHARS]}


def _describe(scenario_id: str, result: pipeline.TurnResult, checks: list, event_id) -> dict:
    calls = [e for e in result.events if e["type"] == "llm_call"]
    verdict = result.verdict or {}
    return {
        "id": scenario_id,
        "status": "error" if result.error else "passed" if all(c["ok"] for c in checks) else "failed",
        "checks": checks,
        "outcome": outcome_of(result),
        "stage": verdict.get("stage"),
        "reason": verdict.get("reason"),
        "reply": (result.reply or "")[:REPLY_CHARS],
        "maskedPrompt": result.masked_prompt,
        "maskedForModel": result.masked_for_model,
        "tools": [{"tool": c["tool"], "allowed": c["allowed"], "stage": c.get("stage")} for c in result.tool_calls],
        "modelCalls": len(calls),
        "tokens": sum(e.get("tokens", 0) for e in calls),
        "cost": round(sum(e.get("cost", 0) for e in calls), 6),
        "latencyMs": result.latency_ms,
        "eventId": event_id,
        "error": result.error,
    }


def _aggregate(scenario: dict, runs: list[dict]) -> dict:
    """Wynik scenariusza z wariantami: przechodzi, gdy przeszły wszystkie warianty; pola ogólne z pierwszego."""
    status = ("error" if any(r["status"] == "error" for r in runs)
              else "passed" if all(r["status"] == "passed" for r in runs) else "failed")
    flat = [{"name": f"[{r['label']}] {c['name']}", "ok": c["ok"], "detail": c["detail"]}
            for r in runs for c in r["checks"]]
    first = {k: v for k, v in runs[0].items() if k not in ("status", "checks", "variant", "label")}
    return {**first, "id": scenario["id"], "status": status, "checks": flat, "variants": runs}


def run_scenario(scenario: dict, on_turn: Optional[Callable] = None) -> dict:
    """Jedna tura scenariusza (albo po jednej turze na wariant). `on_turn(rola, rozmowa, wynik)` może zapisać
    turę w logu i zwrócić id wiersza logu."""
    if _isolated(scenario):
        runs = [_run_isolated(scenario, variant, on_turn) for variant in scenario.get("variants") or [None]]
        return runs[0] if len(runs) == 1 and not scenario.get("variants") else _aggregate(scenario, runs)
    name = ROLE_BY_ID[scenario["role"]]
    conv = pipeline.Conversation(name)
    started = time.perf_counter()
    try:
        with applied(scenario.get("config")):
            result = pipeline.run_turn(conv, scenario["prompt"])
    except Exception as exc:
        return {"id": scenario["id"], "status": "error", "checks": [],
                "error": f"{type(exc).__name__}: {exc}", "latencyMs": int((time.perf_counter() - started) * 1000)}

    event_id = on_turn(name, conv, result) if on_turn else None
    checks = evaluate(scenario.get("expect", {}), result)
    return {**_describe(scenario["id"], result, checks, event_id), "mode": "live"}


# --- przebieg w tle (dla API) ----------------------------------------------------------------

_run: Optional[dict] = None
_run_lock = threading.Lock()


def current_run() -> Optional[dict]:
    with _run_lock:
        return copy.deepcopy(_run)


def start_run(ids: Optional[list[str]] = None, on_turn: Optional[Callable] = None) -> dict:
    """Uruchamia wybrane scenariusze (domyślnie wszystkie) po kolei w osobnym wątku."""
    global _run
    scenarios = load_catalog()["scenarios"]
    if ids:
        unknown = set(ids) - {s["id"] for s in scenarios}
        if unknown:
            raise ValueError(f"Nieznane scenariusze: {sorted(unknown)}")
        scenarios = [s for s in scenarios if s["id"] in ids]
    with _run_lock:
        if _run and _run["status"] == "running":
            raise RuntimeError("Testy już trwają")
        _run = {"id": uuid.uuid4().hex[:8], "status": "running", "startedAt": datetime.now(timezone.utc).isoformat(),
                "finishedAt": None, "model": SETTINGS.model, "ids": [s["id"] for s in scenarios],
                "current": None, "results": {}}
        run = _run

    def work():
        for scenario in scenarios:
            with _run_lock:
                run["current"] = scenario["id"]
            result = run_scenario(scenario, on_turn)
            with _run_lock:
                run["results"][scenario["id"]] = result
        with _run_lock:
            run.update(status="done", current=None, finishedAt=datetime.now(timezone.utc).isoformat())

    threading.Thread(target=work, daemon=True).start()
    return current_run()
