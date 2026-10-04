"""Scenariusze mock i warianty ON/OFF (live_tests): jedno źródło dla interfejsu i testów regresji.

Wszystkie scenariusze `mode: mock` uruchamiają się tu offline (detektor na wyrażeniach regularnych, prawdziwy
model zabroniony), więc te same pliki pokazują demonstrację w interfejsie i pilnują, żeby się nie psuła.
"""
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

import pipeline
from audit import logger as audit_logger
from chatbot import llm_client
from config import ROLES, SETTINGS
from live_tests import runner
from live_tests.isolated import MOCK_BASELINE, ScenarioChat, merge_config, policy_with, strip_notice, tool_call_step
from security import refusal_detector
from security.pii.regex_detector import detect_regex_pii

CATALOG = runner.load_catalog()["scenarios"]
MOCK_SCENARIOS = [s for s in CATALOG if s.get("mode") == "mock"]


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    """Bez sieci i bez modeli: prawdziwe wywołanie modelu zgłasza błąd i jest zapisywane."""
    calls = []

    def forbidden(messages, **kwargs):
        calls.append(kwargs.get("purpose") or kwargs.get("zone"))
        raise RuntimeError("prawdziwe wywołanie modelu jest tu zabronione")

    monkeypatch.setattr(llm_client, "chat", forbidden)
    monkeypatch.setattr(pipeline, "detect_pii", lambda text, threshold=None: detect_regex_pii(text))
    monkeypatch.setattr(refusal_detector, "REFUSAL_EMBEDDINGS_ENABLED", False)
    monkeypatch.setattr(audit_logger, "AUDIT_LOG", tmp_path / "events.jsonl")
    pipeline._detect_cached.cache_clear()
    return calls


def failures(result):
    return [f"{c['name']}: {c['detail']}" for c in result["checks"] if not c["ok"]] or [result.get("error")]


# --- scenariusze z pliku jako testy regresji ----------------------------------------------------------------------

def test_catalog_has_the_four_demo_scenarios_with_both_variants():
    demo = {s["id"]: s for s in CATALOG if s["group"] == "demo"}
    assert set(demo) == {"demo-output-leak", "demo-malicious-code", "demo-masking", "demo-data-exfiltration"}
    for scenario in demo.values():
        assert scenario["mode"] == "mock" and [v["id"] for v in scenario["variants"]] == ["on", "off"]
        assert scenario["standard"]


@pytest.mark.parametrize("scenario", MOCK_SCENARIOS, ids=[s["id"] for s in MOCK_SCENARIOS])
def test_mock_scenario_passes_offline(scenario, offline):
    result = runner.run_scenario(scenario)
    assert result["status"] == "passed", failures(result)
    assert offline == []                                         # żadnego prawdziwego wywołania modelu
    for variant in result["variants"]:
        assert variant["mockModel"] is True and variant["mode"] == "mock"


def test_variants_really_differ_on_vs_off():
    leak = runner.run_scenario(next(s for s in CATALOG if s["id"] == "demo-output-leak"))
    on, off = leak["variants"]
    assert "[EMAIL]" in on["reply"] and "anna.nowak@firma.pl" not in on["reply"]
    assert "anna.nowak@firma.pl" in off["reply"] and off["outcome"] == "allowed"

    masking = runner.run_scenario(next(s for s in CATALOG if s["id"] == "demo-masking"))
    on, off = masking["variants"]
    assert "<PESEL_1>" in on["modelSaw"] and "89010212345" not in on["modelSaw"]
    assert "89010212345" in off["modelSaw"]                      # co dostałby dostawca modelu bez maskowania

    exfil = runner.run_scenario(next(s for s in CATALOG if s["id"] == "demo-data-exfiltration"))
    on, off = exfil["variants"]
    assert on["modelCalls"] == 0 and on["outcome"] == "blocked" and on["stage"] == "company_policies"
    assert off["modelCalls"] == 1 and off["outcome"] == "allowed"


def test_code_guard_scenario_explains_the_second_layer():
    scenario = next(s for s in CATALOG if s["id"] == "demo-malicious-code")
    assert "second layer" in scenario["note"]
    on, off = runner.run_scenario(scenario)["variants"]
    assert on["outcome"] == "denied" and off["outcome"] == "allowed"
    assert "Code rejected" in on["reply"] and "Code rejected" in off["reply"]     # w obu przypadkach kod nie działa


# --- izolacja: scenariusze nie zmieniają stanu serwera ---------------------------------------------------------------

def test_isolated_runs_leave_the_server_settings_untouched(monkeypatch):
    def forbidden(config):
        raise AssertionError("scenariusz izolowany nie może używać starej ścieżki z mutacją globalnej konfiguracji")

    monkeypatch.setattr(runner, "applied", forbidden)
    before = (dict(SETTINGS.filters), SETTINGS.guard_mode, SETTINGS.mask_pii, copy.deepcopy(ROLES),
              pipeline.MAX_PROMPT_CHARS)
    for scenario in MOCK_SCENARIOS:
        assert runner.run_scenario(scenario)["status"] == "passed"
    after = (dict(SETTINGS.filters), SETTINGS.guard_mode, SETTINGS.mask_pii, copy.deepcopy(ROLES),
             pipeline.MAX_PROMPT_CHARS)
    assert before == after


def test_scenarios_can_run_in_parallel_without_interfering():
    """Przy starej ścieżce (mutacja globalnych ustawień) równoległe warianty ON i OFF by się nawzajem psuły."""
    jobs = MOCK_SCENARIOS * 4
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(runner.run_scenario, jobs))
    assert [r["status"] for r in results] == ["passed"] * len(jobs), [failures(r) for r in results if r["status"] != "passed"]


def test_a_scenario_does_not_disturb_a_normal_turn_running_alongside():
    conv = pipeline.Conversation("kadry")
    chat = ScenarioChat([{"reply": "ok"}])
    result = pipeline.run_turn(conv, "Cześć", chat=chat)
    assert result.reply == "ok" and result.verdict is None or result.verdict["decision"] != "block"
    assert SETTINGS.filters["output_filter"] is True or "output_filter" in SETTINGS.filters


# --- policy_with -----------------------------------------------------------------------------------------------------

def test_policy_with_translates_the_scenario_config_onto_a_copy():
    base = pipeline.current_policy()
    role_by_id = runner.ROLE_BY_ID
    changed = policy_with({"guardMode": "warn", "maskPii": False, "filters": {"code_guard": False},
                           "limits": {"maxPromptChars": 40, "maxTurnTokens": 5, "maxTurnCost": 0.5},
                           "policy": {"controls.pii.threshold": 0.85}}, base, role_by_id)
    assert changed.controls.prompt_guard.mode == "warn" and changed.controls.pii.mask_in_chatbot_channel is False
    assert not changed.filter_on("code_guard") and changed.controls.prompt_length.max_chars == 40
    assert changed.budgets.per_turn.max_tokens == 5 and changed.budgets.per_turn.max_cost_usd == 0.5
    assert changed.controls.pii.threshold == 0.85
    assert base.filter_on("code_guard") and base.controls.pii.threshold != 0.85        # oryginał nietknięty


def test_policy_with_changes_the_data_areas_of_a_role():
    base = pipeline.current_policy()
    changed = policy_with({"roles": {"hr": ["projects", "hr", "clients"]}}, base, runner.ROLE_BY_ID)
    assert changed.is_tool_allowed("kadry", "read_client_records") and not base.is_tool_allowed("kadry", "read_client_records")
    assert changed.is_tool_allowed("kadry", "read_employee_records")


@pytest.mark.parametrize("config", [
    {"filters": {"nie_ma_takiego": True}},
    {"roles": {"hr": ["nie_ma_obszaru"]}},
    {"policy": {"controls.nie_ma.klucza": 1}},
    {"policy": {"controls.pii.nie_ma": 1}},
    {"policy": {"controls.pii.threshold": 7}},
])
def test_policy_with_rejects_bad_config(config):
    with pytest.raises(ValueError):
        policy_with(config, pipeline.current_policy(), runner.ROLE_BY_ID)


def test_merge_config_merges_dictionaries_and_replaces_values():
    base = {"guardMode": "block", "filters": {"a": True, "b": True}, "limits": {"maxPromptChars": 10}}
    merged = merge_config(base, {"guardMode": "warn", "filters": {"b": False}})
    assert merged == {"guardMode": "warn", "filters": {"a": True, "b": False}, "limits": {"maxPromptChars": 10}}
    assert base["filters"]["b"] is True                                     # wejście nietknięte
    assert MOCK_BASELINE["filters"] == {"intent_classifier": False, "company_policies": False}


# --- atrapa modelu ---------------------------------------------------------------------------------------------------

NOTICE = "[Security layer notice.]\nzasady\n[End of notice]\n\n"


def test_scenario_chat_follows_the_script_and_fills_placeholders():
    chat = ScenarioChat([tool_call_step("run_python", code="print(1)"), {"reply": "Wynik: {tool_result} dla {prompt}"}])
    first = chat([{"role": "user", "content": NOTICE + "Policz"}], tools=[])
    assert first.tool_calls[0].function.name == "run_python" and first.tool_calls[0].function.arguments == {"code": "print(1)"}
    second = chat([{"role": "user", "content": NOTICE + "Policz"}, first, {"role": "tool", "content": "1"}])
    assert second.content == "Wynik: 1 dla Policz" and second.tool_calls is None
    assert chat.is_mock and len(chat.calls) == 2


def test_scenario_chat_reports_a_script_that_ran_out():
    chat = ScenarioChat([{"reply": "jedna"}])
    chat([{"role": "user", "content": "a"}])
    with pytest.raises(RuntimeError, match="Skrypt atrapy"):
        chat([{"role": "user", "content": "b"}])


def test_scenario_chat_records_what_the_model_received_without_the_notice():
    chat = ScenarioChat([{"reply": "x"}])
    chat([{"role": "system", "content": "tajny prompt"}, {"role": "user", "content": NOTICE + "pytanie <EMAIL_1>"}])
    assert chat.received() == "pytanie <EMAIL_1>" and chat.last_user_view() == "pytanie <EMAIL_1>"
    assert "zasady" not in chat.received() and "tajny prompt" not in chat.received()
    assert strip_notice("bez noty") == "bez noty"


def test_scenario_chat_without_a_script_delegates_to_the_real_model(monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(kw.get("zone")) or SimpleNamespace(
        role="assistant", content="prawdziwa odpowiedź", tool_calls=None))
    chat = ScenarioChat(None)
    assert not chat.is_mock
    assert chat([{"role": "user", "content": "hej"}]).content == "prawdziwa odpowiedź" and seen == ["chatbot"]
    assert chat.received() == "hej"


# --- walidacja katalogu ----------------------------------------------------------------------------------------------

def write_catalog(tmp_path, monkeypatch, *scenarios):
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps({"groups": [], "scenarios": list(scenarios)}), encoding="utf-8")
    monkeypatch.setattr(runner, "SCENARIOS_FILE", path)


BASE = {"id": "s", "group": "demo", "title": "t", "role": "hr", "prompt": "p", "expect": {}}


@pytest.mark.parametrize("scenario, message", [
    ({**BASE, "role": "nieznana"}, "nieznana rola"),
    ({**BASE, "mode": "turbo"}, "nieznany tryb"),
    ({**BASE, "mode": "mock"}, "wymaga niepustego pola `model`"),
    ({**BASE, "mode": "mock", "model": [{"reply": "a", "tool_calls": []}]}, "wymaga niepustego pola `model`"),
    ({**BASE, "mode": "mock", "model": [{"zly": 1}]}, "wymaga niepustego pola `model`"),
    ({**BASE, "model": [{"reply": "a"}]}, "tylko w trybie mock"),
    ({**BASE, "variants": []}, "niepustą listą"),
    ({**BASE, "variants": [{"label": "bez id"}]}, "polem `id`"),
    ({**BASE, "variants": [{"id": "x"}, {"id": "x"}]}, "unikalne"),
])
def test_catalog_validation_names_the_scenario_and_the_problem(tmp_path, monkeypatch, scenario, message):
    write_catalog(tmp_path, monkeypatch, scenario)
    with pytest.raises(ValueError, match=message) as error:
        runner.load_catalog()
    assert "Scenariusz s" in str(error.value)


def test_catalog_rejects_duplicate_ids(tmp_path, monkeypatch):
    write_catalog(tmp_path, monkeypatch, BASE, BASE)
    with pytest.raises(ValueError, match="powtórzony identyfikator"):
        runner.load_catalog()


# --- agregacja wariantów -----------------------------------------------------------------------------------------------

def scenario_with(variants, **extra):
    return {**BASE, "id": "agg", "mode": "mock", "role": "basic_user", "prompt": "Cześć", "model": [{"reply": "ok"}],
            "variants": variants, **extra}


def test_aggregate_status_is_failed_when_any_variant_fails_and_names_it():
    result = runner.run_scenario(scenario_with([
        {"id": "a", "label": "Pierwszy", "expect": {"outcome": "allowed"}},
        {"id": "b", "label": "Drugi", "expect": {"outcome": "blocked"}},
    ]))
    assert result["status"] == "failed" and [v["status"] for v in result["variants"]] == ["passed", "failed"]
    broken = [c for c in result["checks"] if not c["ok"]]
    assert broken and broken[0]["name"].startswith("[Drugi] ")


def test_aggregate_status_is_error_when_a_variant_cannot_run():
    result = runner.run_scenario(scenario_with([
        {"id": "a", "label": "Dobry", "expect": {"outcome": "allowed"}},
        {"id": "b", "label": "Zły", "config": {"filters": {"nie_ma": True}}},
    ]))
    assert result["status"] == "error" and "Nieznane filtry" in result["variants"][1]["error"]


def test_variant_config_is_merged_over_the_scenario_config_and_its_expect_replaces():
    result = runner.run_scenario(scenario_with(
        [{"id": "a", "label": "A", "config": {"filters": {"prompt_length": True}, "limits": {"maxPromptChars": 3}},
          "expect": {"outcome": "blocked", "stage": ["prompt_length"]}},
         {"id": "b", "label": "B"}],                                   # bez własnego expect: obowiązuje ogólny
        config={"limits": {"maxPromptChars": 10_000}}, expect={"outcome": "allowed"}))
    assert [v["status"] for v in result["variants"]] == ["passed", "passed"], result["checks"]


def test_a_mock_scenario_without_variants_is_a_single_isolated_run():
    scenario = {k: v for k, v in scenario_with([]).items() if k != "variants"}
    scenario["expect"] = {"outcome": "allowed", "contains": ["ok"]}
    result = runner.run_scenario(scenario)
    assert result["status"] == "passed" and "variants" not in result and result["mockModel"] is True


def test_live_scenario_with_variants_uses_the_real_chat_on_a_policy_copy(monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(kw.get("zone")) or SimpleNamespace(
        role="assistant", content="odpowiedź modelu", tool_calls=None))
    scenario = {**BASE, "id": "liv", "role": "basic_user", "prompt": "Cześć", "expect": {"outcome": "allowed"},
                "variants": [{"id": "a", "label": "A", "config": {"policy": {"controls.pii.threshold": 0.5}}},
                             {"id": "b", "label": "B", "config": {"policy": {"controls.pii.threshold": 0.2}}}]}
    result = runner.run_scenario(scenario)
    assert result["status"] == "passed" and seen.count("chatbot") == 2        # po jednym wywołaniu chatbota na wariant
    assert all(v["mockModel"] is False and v["mode"] == "live" for v in result["variants"])


def test_mock_run_is_visible_in_the_trail_as_a_scripted_model():
    result = runner.run_scenario(next(s for s in CATALOG if s["id"] == "demo-masking"))
    assert all(v["tokens"] == 0 and v["cost"] == 0 for v in result["variants"])        # żadnego kosztu modelu


# --- przebieg w tle i potrzeba klucza ----------------------------------------------------------------------------------

def test_background_run_handles_variants(offline):
    run = runner.start_run(["demo-masking"])
    for _ in range(100):
        state = runner.current_run()
        if state["status"] == "done":
            break
        threading.Event().wait(0.1)
    assert state["status"] == "done"
    assert state["results"]["demo-masking"]["status"] == "passed" and len(state["results"]["demo-masking"]["variants"]) == 2


def test_needs_live_model_only_for_live_scenarios():
    assert runner.needs_live_model(["demo-masking", "demo-output-leak"]) is False
    assert runner.needs_live_model(["demo-masking", "access-banker-client"]) is True
    assert runner.needs_live_model(None) is True                          # wszystkie scenariusze obejmują live
    assert runner.needs_live_model([]) is True
