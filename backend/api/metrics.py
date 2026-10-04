"""Metryki i eksport logu audytu dla zespołu bezpieczeństwa i zarządu.

Wejściem są wiersze logu (`state.list_events`), czyli to samo, co widzi zakładka Dashboard. Surowe wartości
wrażliwe nie trafiają ani do metryk, ani do eksportu: log zawiera tylko zamaskowane prompty i etykiety typów.
"""
import csv
import io
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Iterable, Iterator, Optional

# Kolumny płaskiego eksportu CSV (pełny ślad tury jest w eksporcie JSONL).
CSV_COLUMNS = ["id", "time", "role", "role_id", "conversation_id", "decision", "stage", "control", "reason",
               "level", "model", "tokens", "latency_ms", "step_count", "masked_for_model", "leaks_to_chatbot"]


def percentile(sorted_values: list, q: float):
    """Percentyl metodą najbliższej pozycji (bez interpolacji); 0 dla pustej listy."""
    if not sorted_values:
        return 0
    rank = max(1, math.ceil(q / 100 * len(sorted_values)))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def latency_stats(values: Iterable[float]) -> dict:
    ordered = sorted(values)
    return {
        "avg": int(sum(ordered) / len(ordered)) if ordered else 0,
        "p50": int(percentile(ordered, 50)), "p95": int(percentile(ordered, 95)),
        "p99": int(percentile(ordered, 99)), "max": int(ordered[-1]) if ordered else 0,
    }


def _attack_type(details: dict) -> Optional[str]:
    return details.get("attack_type") or (details.get("details") or {}).get("attack_type")


def compute_metrics(rows: list[dict]) -> dict:
    """Podsumowanie logu: decyzje, blokady, koszty, opóźnienia całych tur i poszczególnych kontroli."""
    by_decision = Counter(r["decision"] for r in rows)
    kind_ms: dict[str, list] = defaultdict(list)
    zone_ms = {"security": [], "chatbot": [], "local": []}
    blocked_by_kind, warned_by_kind, attack_types = Counter(), Counter(), Counter()
    cost = security_cost = 0.0
    security_tokens = 0

    for row in rows:
        zones = Counter()
        for step in row.get("steps") or []:
            kind_ms[step["kind"]].append(step["duration_ms"])
            zones[step["zone"]] += step["duration_ms"]
            if step["level"] == "block":
                blocked_by_kind[step["kind"]] += 1
            elif step["level"] == "warn":
                warned_by_kind[step["kind"]] += 1
            attack = _attack_type(step.get("details") or {})
            if attack and step["level"] in ("warn", "block"):
                attack_types[attack] += 1
        for zone, bucket in zone_ms.items():
            bucket.append(zones.get(zone, 0))
        turn = next((e for e in row.get("trail") or [] if e.get("type") == "turn"), {})
        cost += turn.get("cost", 0) or 0
        security_cost += turn.get("security_cost", 0) or 0
        security_tokens += turn.get("security_tokens", 0) or 0

    total = len(rows)
    times = [r["time"] for r in rows if r.get("time")]
    return {
        "total": total,
        "window": {"from": min(times) if times else None, "to": max(times) if times else None},
        "by_decision": dict(by_decision),
        "by_control": dict(Counter(r["control"] for r in rows if r.get("control"))),
        "by_role": dict(Counter(r["role"] for r in rows)),
        "by_level": dict(Counter(r["level"] for r in rows)),
        "blocked_rate": round(by_decision.get("Blocked", 0) / total, 4) if total else 0.0,
        "intervention_rate": round(sum(n for d, n in by_decision.items() if d != "Allowed") / total, 4) if total else 0.0,
        "tokens": sum(r["tokens"] for r in rows),
        "cost_usd": round(cost, 6),
        "security_tokens": security_tokens,
        "security_cost_usd": round(security_cost, 6),
        "latency_ms": latency_stats(r["latency_ms"] for r in rows),
        "step_timings_ms": {kind: {"count": len(v), **latency_stats(v)} for kind, v in sorted(kind_ms.items())},
        "zone_avg_ms": {zone: (int(sum(v) / len(v)) if v else 0) for zone, v in zone_ms.items()},
        "blocked_by_step": dict(blocked_by_kind),
        "warned_by_step": dict(warned_by_kind),
        "by_attack_type": dict(attack_types),
    }


def filter_since(rows: list[dict], since: Optional[datetime]) -> list[dict]:
    return rows if since is None else [r for r in rows if r["time"] >= since]


# --- eksport ----------------------------------------------------------------------------------------

def _plain(value):
    return value.isoformat() if isinstance(value, datetime) else value


def exportable(row: dict) -> dict:
    """Wiersz do eksportu JSONL: pełny ślad audytu tury (`trail`), bez zduplikowanych kroków dla interfejsu."""
    return {key: _plain(value) for key, value in row.items() if key != "steps"}


def export_jsonl(rows: Iterable[dict]) -> Iterator[str]:
    for row in rows:
        yield json.dumps(exportable(row), ensure_ascii=False, default=str) + "\n"


def _csv_safe(value) -> str:
    """Komórka nie może zaczynać się od znaku, który arkusz wykona jako formułę."""
    text = ";".join(map(str, value)) if isinstance(value, list) else "" if value is None else str(_plain(value))
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def export_csv(rows: Iterable[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow([_csv_safe(row.get(column)) for column in CSV_COLUMNS])
    return out.getvalue()
