import json
import re
from pathlib import Path

from audit import logger as audit
from chatbot import llm_client
from config import ROLES

_PROMPT = (Path(__file__).parent / "prompts" / "pii_judge.txt").read_text(encoding="utf-8")
_REPLY_PROMPT = (Path(__file__).parent / "prompts" / "pii_reply_judge.txt").read_text(encoding="utf-8")


def judge_entities(role: str, prompt: str, entities: list[dict]) -> list[str]:
    """Rozstrzyga dla każdej encji z promptu: "send" (chatbot zobaczy wartość) albo "mask".

    Sędzia działa w strefie bezpieczeństwa i widzi dane surowe. Każda wątpliwość — błąd wywołania,
    nieczytelna odpowiedź, brak decyzji dla encji — kończy się maskowaniem.
    """
    if not entities:
        return []
    listing = "\n".join(f'{i}. {e["type"]}: "{e["text"]}"' for i, e in enumerate(entities, 1))
    message = _PROMPT.format(
        role=role,
        role_description=ROLES.get(role, {}).get("description", ""),
        prompt=prompt,
        entities=listing,
    )
    decisions = ["mask"] * len(entities)
    reasons = [""] * len(entities)
    try:
        reply = llm_client.chat([{"role": "user", "content": message}], zone="security", purpose="pii_judge")
        match = re.search(r"\{.*\}", reply.content or "", re.DOTALL)
        parsed = json.loads(match.group(0)) if match else {}
        for i in range(len(entities)):
            # Sędzia odpowiada {"decision", "reason"}; sam napis "send"/"mask" też jest przyjmowany.
            answer = parsed.get(str(i + 1), "")
            if isinstance(answer, dict):
                reasons[i] = str(answer.get("reason", ""))[:200]
                answer = answer.get("decision", "")
            if str(answer).strip().lower() == "send":
                decisions[i] = "send"
        error = None
    except Exception as exc:
        error = type(exc).__name__
    # Uzasadnienie może powtarzać ocenianą wartość, więc przed zapisem do logu zamieniamy ją na typ.
    for e in entities:
        reasons = [r.replace(e["text"], f"[{e['type']}]") for r in reasons]
    audit.record(
        "pii_judge", "security",
        decisions=[{"type": e["type"], "decision": d, "reason": r} for e, d, r in zip(entities, decisions, reasons)],
        error=error,
    )
    return decisions


def judge_reply_entities(role: str, reply: str, entities: list[dict]) -> list[str]:
    """Dla każdej encji z odpowiedzi chatbota: "hide" (dane osobowe konkretnej osoby) albo "keep".

    Detektor oznacza jako osoby i kwoty także zwykłe wyrażenia ("Masa Księżyca", nazwę stanowiska,
    liczbę w obliczeniach). Sędzia odsiewa takie pomyłki; każda wątpliwość i każdy błąd to "hide".
    """
    if not entities:
        return []
    listing = "\n".join(f'{i}. {e["type"]}: "{e["text"]}"' for i, e in enumerate(entities, 1))
    message = _REPLY_PROMPT.format(role=role, role_description=ROLES.get(role, {}).get("description", ""),
                                   reply=reply, entities=listing)
    decisions = ["hide"] * len(entities)
    reasons = [""] * len(entities)
    try:
        answer = llm_client.chat([{"role": "user", "content": message}], zone="security", purpose="pii_reply_judge")
        match = re.search(r"\{.*\}", answer.content or "", re.DOTALL)
        parsed = json.loads(match.group(0)) if match else {}
        for i in range(len(entities)):
            item = parsed.get(str(i + 1), "")
            if isinstance(item, dict):
                reasons[i] = str(item.get("reason", ""))[:200]
                item = item.get("decision", "")
            if str(item).strip().lower() == "keep":
                decisions[i] = "keep"
        error = None
    except Exception as exc:
        error = type(exc).__name__
    for e in entities:
        reasons = [r.replace(e["text"], f"[{e['type']}]") for r in reasons]
    audit.record(
        "pii_judge", "security", target="reply",
        decisions=[{"type": e["type"], "decision": d, "reason": r} for e, d, r in zip(entities, decisions, reasons)],
        error=error,
    )
    return decisions
