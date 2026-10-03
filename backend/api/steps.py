"""Kroki tury dla interfejsu: zdarzenia śladu audytu z poziomem (info / warn / block) i opisem.

Poziom i opis powstają tutaj, żeby interfejs nie musiał znać reguł warstwy bezpieczeństwa.
Opisy są po angielsku, jak reszta interfejsu; powody decyzji strażników zostają w oryginale.
"""
from collections import Counter
from typing import Optional

from config import CONTROLS

LEVELS = ["info", "warn", "block"]

# Rodzaje kroków (pole `kind`) i ich nazwy dla ludzi.
STEP_KINDS = {
    "prompt_guard":   "Prompt guard",
    "company_policy": "Company policy",
    "prompt_masking": "Prompt masking",
    "pii_judge":      "PII judge",
    "model_call":     "Model call",
    "tool_call":      "Tool call",
    "output_filter":  "Reply filter",
    "budget":         "Budget",
    "error":          "Error",
}

ZONES = {
    "security": "Security zone",
    "chatbot":  "Chatbot zone",
    "local":    "Local",
}

_KIND_OF = {"llm_call": "model_call"}
_POLICY_POINTS = {"input": "Prompt", "tool": "Tool arguments", "retrieval": "Tool result", "output": "Reply"}
_PURPOSES = {"chat": "chatbot", "pii_judge": "PII judge", "company_policy_classifier": "policy classifier"}


def _counted(types: list) -> str:
    """["NAME", "NAME", "EMAIL"] -> "EMAIL, NAME ×2"."""
    return ", ".join(t if n == 1 else f"{t} ×{n}" for t, n in sorted(Counter(types).items()))


def _args(args: dict) -> str:
    text = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items())
    return text if len(text) <= 80 else text[:77] + "..."


def _prompt_guard(e: dict) -> tuple[str, str]:
    if e.get("blocked"):
        return "block", e.get("reason") or "Prompt blocked"
    if e.get("decision") == "warn":
        return "warn", e.get("reason") or "Prompt flagged"
    return "info", "Prompt matches the role"


def _company_policy(e: dict) -> tuple[str, str]:
    point = _POLICY_POINTS.get(e.get("point"), e.get("point"))
    decision = e.get("decision")
    if decision == "pass" and not e.get("detector_error"):
        text = f"{point}: no rule violated"
    else:
        rule = " ".join(filter(None, [e.get("rule_id"), f"({e['section']})" if e.get("section") else None]))
        text = f"{point}: {decision}" + (f", rule {rule}" if rule else "")
        if e.get("softened"):
            text += ", downgraded from block (weak evidence)"
        if e.get("reason"):
            text += f". {e['reason']}"
    classifier = e.get("classifier")
    if classifier and classifier.get("category") is not None:
        text += f" [classifier: {classifier['category']}, confidence {classifier.get('confidence')}]"
    if e.get("detector_error"):
        text += " [classifier unavailable]"
    level = "block" if decision == "block" else "warn" if decision != "pass" or e.get("detector_error") else "info"
    return level, text


def _prompt_masking(e: dict) -> tuple[str, str]:
    by = {"mask": [], "send": [], "block": []}
    for d in e.get("decisions", []):
        by.setdefault(d["decision"], []).append(d["type"])
    if by["block"]:
        return "block", f"Not allowed to reach the model: {_counted(by['block'])}"
    if by["mask"]:
        sent = f"; sent as typed: {_counted(by['send'])}" if by["send"] else ""
        return "warn", f"Hidden from the model: {_counted(by['mask'])}{sent}"
    if by["send"]:
        return "info", f"Sent as typed: {_counted(by['send'])}"
    return "info", "No sensitive data in the prompt"


def _pii_judge(e: dict) -> tuple[str, str]:
    parts = [f"{d['type']} → {d['decision']}" + (f" ({d['reason']})" if d.get("reason") else "")
             for d in e.get("decisions", [])]
    text = "; ".join(parts) or "Nothing to decide"
    if e.get("error"):
        return "warn", f"Judge unavailable ({e['error']}), everything masked. {text}"
    return ("warn" if any(d["decision"] == "mask" for d in e.get("decisions", [])) else "info"), text


def _model_call(e: dict) -> tuple[str, str]:
    purpose = _PURPOSES.get(e.get("purpose"), e.get("purpose"))
    cost = f", ${e['cost']:.5f}" if e.get("cost") else ""
    return "info", f"{purpose} · {e.get('model')} · {e.get('tokens', 0)} tokens{cost}"


def _tool_call(e: dict) -> tuple[str, str]:
    call = f"{e.get('tool')}({_args(e.get('args'))})"
    if not e.get("allowed"):
        control = CONTROLS.get(e.get("stage"), e.get("stage") or "security layer")
        reason = f": {e['reason']}" if e.get("reason") else ""
        return "block", f"{call} rejected by {control}{reason}"
    stats = {k: v for k, v in (e.get("masked") or {}).items() if v}
    if stats:
        hidden = ", ".join(f"{v} {k}" for k, v in stats.items())
        return "warn", f"{call} ran; before reaching the model: {hidden}"
    return "info", f"{call} ran; nothing to hide in the result"


def _output_filter(e: dict) -> tuple[str, str]:
    if e.get("blocked"):
        return "block", f"Reply blocked: {_counted(e['blocked'])}"
    parts = []
    if e.get("redacted"):
        parts.append(f"hidden in the reply: {_counted(e['redacted'])}")
    if e.get("found"):
        parts.append(f"found but left visible (masking is off): {_counted(e['found'])}")
    if e.get("restored"):
        parts.append(f"restored for the user: {_counted(e['restored'])}")
    if e.get("exempt"):
        parts.append(f"public or typed by the user: {_counted(e['exempt'])}")
    level = "warn" if e.get("redacted") or e.get("found") else "info"
    text = "; ".join(parts)
    return level, (text[0].upper() + text[1:]) if text else "Nothing to hide in the reply"


_DESCRIBE = {
    "prompt_guard": _prompt_guard,
    "company_policy": _company_policy,
    "prompt_masking": _prompt_masking,
    "pii_judge": _pii_judge,
    "model_call": _model_call,
    "tool_call": _tool_call,
    "output_filter": _output_filter,
    "budget": lambda e: ("block", e.get("reason") or "Budget exhausted"),
    "error": lambda e: ("block", f"Model call failed: {e.get('error')}"),
}


def build_steps(trail: list[dict]) -> list[dict]:
    """Ślad audytu tury -> kroki dla interfejsu (bez zdarzenia podsumowującego `turn`)."""
    steps = []
    for event in trail:
        kind = _KIND_OF.get(event["type"], event["type"])
        if kind not in _DESCRIBE:
            continue
        level, summary = _DESCRIBE[kind](event)
        steps.append({
            "index": len(steps) + 1,
            "kind": kind,
            "label": STEP_KINDS[kind],
            "zone": event.get("zone", "security"),
            "level": level,
            "summary": summary,
            "at_ms": event.get("at_ms", 0),
            "duration_ms": event.get("ms", 0),
            "details": {k: v for k, v in event.items() if k not in ("ts", "at_ms", "ms", "type", "zone")},
        })
    return steps


def turn_level(steps: list[dict], decision: Optional[str] = None) -> str:
    """Najwyższy poziom spośród kroków tury; tura zakończona błędem albo blokadą jest zawsze `block`."""
    level = max((s["level"] for s in steps), key=LEVELS.index, default="info")
    return "block" if decision in ("Blocked", "Error") else level
