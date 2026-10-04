"""Mechanika testów na żywym modelu (live_tests/runner.py) — bez modelu: ocena wyniku, przywracanie
konfiguracji po scenariuszu i poprawność pliku scenariuszy. Same scenariusze na modelu: tests/test_live.py."""
from types import SimpleNamespace

import pytest

import pipeline
from config import DATA_ACCESS, ROLES, SETTINGS
from live_tests import runner


def _result(reply="", blocked=False, verdicts=(), tool_calls=(), masked=(), error=None):
    verdicts = list(verdicts)
    return SimpleNamespace(reply=reply, blocked=blocked, verdicts=verdicts, verdict=verdicts[0] if verdicts else None,
                           tool_calls=list(tool_calls), masked_for_model=list(masked), error=error)


def _failed(checks):
    return [c["name"] for c in checks if not c["ok"]]


def test_catalog_is_valid():
    catalog = runner.load_catalog()
    groups = {g["id"] for g in catalog["groups"]}
    ids = [s["id"] for s in catalog["scenarios"]]
    assert len(ids) == len(set(ids))
    for s in catalog["scenarios"]:
        # Scenariusz z wariantami może mieć oczekiwania w wariantach (wariant bez własnych bierze ogólne).
        variants = s.get("variants") or []
        expects = [v.get("expect", s.get("expect")) for v in variants] or [s.get("expect")]
        configs = [s.get("config", {})] + [v.get("config", {}) for v in variants]
        assert s["group"] in groups and s["prompt"] and all(expects), s["id"]
        for expect in expects:
            outcome = expect.get("outcome", [])
            assert set(outcome if isinstance(outcome, list) else [outcome]) <= set(runner.OUTCOMES), s["id"]
        for config in configs:
            assert set(config) <= {"guardMode", "maskPii", "filters", "roles", "limits", "policy"}, s["id"]
            assert set(config.get("filters", {})) <= set(SETTINGS.filters), s["id"]
            assert set(config.get("limits", {})) <= set(runner.LIMITS), s["id"]
            for areas in config.get("roles", {}).values():
                assert set(areas) <= set(DATA_ACCESS), s["id"]


@pytest.mark.parametrize("result, outcome", [
    (_result("ok"), "allowed"),
    (_result(blocked=True, verdicts=[{"decision": "block", "stage": "prompt_guard", "reason": ""}]), "blocked"),
    (_result("brak", tool_calls=[{"tool": "read_client_records", "allowed": False, "stage": "tool_whitelist"}]), "denied"),
    (_result("nie", verdicts=[{"decision": "refuse", "stage": "chatbot_refusal", "reason": ""}]), "denied"),
    (_result("[NAME]", verdicts=[{"decision": "redact", "stage": "pii_policy", "reason": ""}]), "redacted"),
    (_result(error="timeout"), "error"),
])
def test_outcome(result, outcome):
    assert runner.outcome_of(result) == outcome


def test_numbers_match_with_any_separators():
    for text in ("6959.17", "6 959,17 zł", "6,959.17", "6 959"):
        assert runner._appears("6959", text), text
    assert not runner._appears("6959", "6 958")
    assert runner._appears("France", "Kraj: france")


def test_evaluate_reports_each_failed_check():
    expect = {"outcome": "allowed", "stage": ["prompt_guard"], "contains": ["619", ["France", "Francja"]],
              "excludes": ["15634602"], "masked": ["EMAIL"],
              "tool": {"name": "read_client_records", "allowed": True}}
    good = _result("Score 619, Francja", verdicts=[{"decision": "warn", "stage": "prompt_guard", "reason": ""}],
                   tool_calls=[{"tool": "read_client_records", "allowed": True}], masked=["EMAIL"])
    assert _failed(runner.evaluate(expect, good)) == []

    bad = _result("Klient 15634602", blocked=True, verdicts=[{"decision": "block", "stage": "pii_policy", "reason": ""}])
    assert _failed(runner.evaluate(expect, bad)) == [
        "outcome", "control", "tool call", "reply contains", "reply contains", "reply excludes", "hidden from model"]


def test_masked_empty_list_means_nothing_hidden():
    assert _failed(runner.evaluate({"masked": []}, _result())) == []
    assert _failed(runner.evaluate({"masked": []}, _result(masked=["EMAIL"]))) == ["hidden from model"]


def test_config_is_applied_and_restored():
    before = (SETTINGS.guard_mode, SETTINGS.mask_pii, dict(SETTINGS.filters),
              list(ROLES["kadry"]["allowed_tools"]), pipeline.MAX_PROMPT_CHARS)
    config = {"guardMode": "warn" if before[0] == "block" else "block", "maskPii": not before[1],
              "filters": {"tool_whitelist": False}, "roles": {"hr": ["clients"]}, "limits": {"maxPromptChars": 7}}

    with runner.applied(config):
        assert SETTINGS.guard_mode == config["guardMode"] and SETTINGS.mask_pii is config["maskPii"]
        assert SETTINGS.filters["tool_whitelist"] is False and pipeline.MAX_PROMPT_CHARS == 7
        assert "read_client_records" in ROLES["kadry"]["allowed_tools"]
        assert "read_employee_records" not in ROLES["kadry"]["allowed_tools"]

    assert (SETTINGS.guard_mode, SETTINGS.mask_pii, dict(SETTINGS.filters),
            list(ROLES["kadry"]["allowed_tools"]), pipeline.MAX_PROMPT_CHARS) == before


def test_config_is_restored_after_an_error():
    before = dict(SETTINGS.filters)
    with pytest.raises(ValueError):
        with runner.applied({"filters": {"tool_whitelist": False, "no_such_filter": True}}):
            pass
    assert SETTINGS.filters == before
