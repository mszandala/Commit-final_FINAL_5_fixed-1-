"""API scenariuszy: katalog z trybem mock i wariantami oraz uruchamianie bez klucza dostawcy.

Fixtury (`env`) są z test_api.py: ten sam czysty stan serwera i ta sama izolacja plików.
"""
import time

from test_api import API, client, env, llm  # noqa: F401 - fixtury pytest

from config import SETTINGS


def wait_for_run():
    for _ in range(200):
        run = client.get(f"{API}/tests/runs/current").json()
        if run and run["status"] == "done":
            return run
        time.sleep(0.05)
    raise AssertionError("przebieg testów nie skończył się w czasie")


def test_catalog_lists_the_demo_group_with_mode_variants_and_notes():
    body = client.get(f"{API}/tests").json()
    assert "demo" in [g["id"] for g in body["groups"]]
    demo = {s["id"]: s for s in body["scenarios"] if s["group"] == "demo"}
    assert len(demo) == 4
    leak = demo["demo-output-leak"]
    assert leak["mode"] == "mock" and leak["standard"] and leak["roleLabel"] == "Employee"
    assert [v["label"] for v in leak["variants"]] == ["Reply filter ON", "Reply filter OFF"]
    assert "second layer" in demo["demo-malicious-code"]["note"]


def test_mock_scenarios_run_without_a_provider_key(monkeypatch):
    monkeypatch.setattr(SETTINGS, "openrouter_api_key", "")
    started = client.post(f"{API}/tests/runs", json={"ids": ["demo-masking", "demo-output-leak"]})
    assert started.status_code == 200
    run = wait_for_run()
    assert [run["results"][i]["status"] for i in ("demo-masking", "demo-output-leak")] == ["passed", "passed"]
    masking = run["results"]["demo-masking"]
    assert [v["label"] for v in masking["variants"]] == ["Masking ON", "Masking OFF"]
    assert "<PESEL_1>" in masking["variants"][0]["modelSaw"] and "89010212345" in masking["variants"][1]["modelSaw"]


def test_live_scenarios_still_need_the_provider_key(monkeypatch):
    monkeypatch.setattr(SETTINGS, "openrouter_api_key", "")
    assert client.post(f"{API}/tests/runs", json={"ids": ["access-banker-client"]}).status_code == 503
    assert client.post(f"{API}/tests/runs", json={"ids": ["demo-masking", "access-banker-client"]}).status_code == 503
    assert client.post(f"{API}/tests/runs").status_code == 503                    # wszystkie scenariusze obejmują live


def test_every_variant_turn_lands_in_the_log_like_a_normal_conversation():
    client.post(f"{API}/tests/runs", json={"ids": ["demo-data-exfiltration"]})
    run = wait_for_run()
    events = client.get(f"{API}/events", params={"steps": True}).json()
    assert len(events) == 2                                                        # po jednej turze na wariant
    blocked, allowed = events
    assert blocked["decision"] == "Blocked" and blocked["control"] == "Company policy"
    assert allowed["decision"] == "Allowed"
    assert any(s["kind"] == "model_call" and "mock" in s["summary"] for s in allowed["steps"])   # widać, że model był atrapą
    assert run["results"]["demo-data-exfiltration"]["variants"][0]["eventId"] == blocked["id"]


def test_unknown_scenario_id_is_still_a_422():
    assert client.post(f"{API}/tests/runs", json={"ids": ["nie-ma-takiego"]}).status_code in (422, 503)
