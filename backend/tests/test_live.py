"""Scenariusze z live_tests/scenarios.json na prawdziwym modelu, jako testy pytest.

Wywołują dostawcę modelu z .env i kosztują, więc domyślnie są pomijane. Uruchomienie (z backend/):

    RUN_LIVE_TESTS=1 python -m pytest tests/test_live.py -v          (PowerShell: $env:RUN_LIVE_TESTS=1)

Te same scenariusze uruchamia zakładka Tests w interfejsie i `python -m live_tests`.
"""
import os

import pytest

from live_tests.runner import load_catalog, run_scenario

pytestmark = pytest.mark.skipif(os.getenv("RUN_LIVE_TESTS") != "1",
                                reason="testy na żywym modelu: ustaw RUN_LIVE_TESTS=1")

SCENARIOS = load_catalog()["scenarios"]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_live_scenario(scenario):
    result = run_scenario(scenario)
    failed = [f"{c['name']}: {c['detail']}" for c in result["checks"] if not c["ok"]]
    assert result["status"] == "passed", (
        f"{scenario['title']}\n  " + "\n  ".join(failed or [result.get("error") or "error"])
        + f"\n  outcome: {result.get('outcome')}, reply: {result.get('reply', '')[:300]!r}")
