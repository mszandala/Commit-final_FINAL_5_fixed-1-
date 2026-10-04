import csv
import io
import json
from datetime import datetime, timedelta, timezone

from api import metrics

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def step(kind, zone, duration, level="info", **details):
    return {"kind": kind, "zone": zone, "duration_ms": duration, "level": level, "details": details}


def row(decision="Allowed", latency=100, steps=(), role="HR", control="", tokens=0, cost=0.0, security_cost=0.0,
        security_tokens=0, minutes_ago=0, **extra):
    return {
        "id": 1, "time": NOW - timedelta(minutes=minutes_ago), "role": role, "role_id": "hr", "conversation_id": "c",
        "decision": decision, "stage": None, "control": control, "reason": "", "level": "info", "model": "m",
        "tokens": tokens, "latency_ms": latency, "step_count": len(steps), "masked_for_model": [],
        "leaks_to_chatbot": 0, "steps": list(steps),
        "trail": [{"type": "turn", "cost": cost, "security_cost": security_cost, "security_tokens": security_tokens}],
        **extra,
    }


def test_percentiles_use_nearest_rank():
    assert metrics.percentile([10, 20, 30, 40, 50], 50) == 30
    assert metrics.percentile([10, 20, 30, 40, 50], 95) == 50
    assert metrics.percentile([], 99) == 0
    assert metrics.latency_stats([10, 20, 30, 40, 50]) == {"avg": 30, "p50": 30, "p95": 50, "p99": 50, "max": 50}
    assert metrics.latency_stats([]) == {"avg": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0}


def test_empty_log_gives_zeros_not_errors():
    result = metrics.compute_metrics([])
    assert result["total"] == 0 and result["blocked_rate"] == 0.0 and result["intervention_rate"] == 0.0
    assert result["window"] == {"from": None, "to": None} and result["step_timings_ms"] == {}


def test_metrics_summarize_decisions_costs_and_timings():
    rows = [
        row("Allowed", 100, [step("prompt_guard", "security", 5), step("model_call", "chatbot", 80)],
            tokens=100, cost=0.01, security_cost=0.002, security_tokens=40),
        row("Blocked", 20, [step("prompt_guard", "security", 15, "block", details={"attack_type": "Prompt_Injection"})],
            control="Prompt guard"),
        row("Redacted", 300, [step("output_filter", "security", 10, "warn"), step("tool_call", "local", 50),
                              step("tool_call", "security", 3, "block", attack_type="Sandbox_Escape")],
            control="PII policy", tokens=50, cost=0.02, role="Admin", minutes_ago=10),
    ]
    result = metrics.compute_metrics(rows)
    assert result["total"] == 3 and result["by_decision"] == {"Allowed": 1, "Blocked": 1, "Redacted": 1}
    assert result["blocked_rate"] == 0.3333 and result["intervention_rate"] == 0.6667
    assert result["by_control"] == {"Prompt guard": 1, "PII policy": 1} and result["by_role"] == {"HR": 2, "Admin": 1}
    assert result["tokens"] == 150 and result["cost_usd"] == 0.03
    assert result["security_tokens"] == 40 and result["security_cost_usd"] == 0.002
    assert result["latency_ms"]["max"] == 300 and result["latency_ms"]["p50"] == 100
    assert result["step_timings_ms"]["prompt_guard"] == {"count": 2, "avg": 10, "p50": 5, "p95": 15, "p99": 15, "max": 15}
    assert result["blocked_by_step"] == {"prompt_guard": 1, "tool_call": 1}
    assert result["warned_by_step"] == {"output_filter": 1}
    assert result["by_attack_type"] == {"Prompt_Injection": 1, "Sandbox_Escape": 1}
    # średnio na turę: security (5 + 15 + 13) / 3, chatbot 80 / 3, local 50 / 3
    assert result["zone_avg_ms"] == {"security": 11, "chatbot": 26, "local": 16}
    assert result["window"] == {"from": NOW - timedelta(minutes=10), "to": NOW}


def test_attack_type_counts_only_steps_that_reacted():
    quiet = row(steps=[step("prompt_guard", "security", 1, "info", details={"attack_type": "Prompt_Injection"})])
    assert metrics.compute_metrics([quiet])["by_attack_type"] == {}


def test_filter_since_keeps_only_recent_rows():
    rows = [row(minutes_ago=120), row(minutes_ago=5)]
    assert len(metrics.filter_since(rows, NOW - timedelta(minutes=30))) == 1
    assert metrics.filter_since(rows, None) == rows


def test_jsonl_export_keeps_the_trail_and_drops_duplicated_steps():
    lines = list(metrics.export_jsonl([row(steps=[step("prompt_guard", "security", 5)], tokens=7)]))
    assert len(lines) == 1 and lines[0].endswith("\n")
    data = json.loads(lines[0])
    assert "steps" not in data and data["trail"][0]["type"] == "turn" and data["tokens"] == 7
    assert data["time"] == NOW.isoformat()


def test_csv_export_has_fixed_columns_and_neutralizes_formulas():
    risky = row(control="Prompt guard", reason='=HYPERLINK("http://zlosliwa.example")', masked_for_model=["EMAIL", "NAME"])
    parsed = list(csv.reader(io.StringIO(metrics.export_csv([risky, row()]))))
    assert parsed[0] == metrics.CSV_COLUMNS and len(parsed) == 3
    record = dict(zip(parsed[0], parsed[1]))
    assert record["reason"].startswith("'=") and record["masked_for_model"] == "EMAIL;NAME"
    assert record["time"] == NOW.isoformat() and record["tokens"] == "0"
    assert dict(zip(parsed[0], parsed[2]))["reason"] == ""
