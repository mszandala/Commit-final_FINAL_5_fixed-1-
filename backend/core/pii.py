"""Wykrywanie, maskowanie i filtrowanie danych osobowych (PII) na granicach stref zaufania.

Funkcje są czyste względem konfiguracji: politykę i detektor dostają jako argumenty.
"""
import re
from typing import Optional

from audit import logger as audit
from security.masking import Vault, label_for
from security.pii.regex_detector import _luhn_ok, in_decimal, is_date_like
from security.pii_judge import judge_entities, judge_reply_entities

from .context import Detect, TurnContext
from .models import Policy
from .session import Conversation

_CURRENCY = re.compile(r"zł|pln|usd|eur|gbp|chf|[$€£]|dolar|euro|złot", re.IGNORECASE)


def well_formed(entity: dict, source: str) -> bool:
    """Odrzuca wykrycia, które nie mają budowy swojego typu.

    Detektor oparty na modelu bierze za numery części ułamkowe liczb ("22.459157718"), za numer
    karty słowo "rachunku", a za wynagrodzenie każdą liczbę — bez tych reguł wynik obliczeń
    blokuje całą odpowiedź.
    """
    text = entity["text"]
    digits = re.sub(r"\D", "", text)
    kind = entity["type"]
    if kind in ("PHONE-NO", "CREDIT-CARD-NO") and in_decimal(source, entity["start"]):
        return False
    if kind == "CREDIT-CARD-NO":
        return 13 <= len(digits) <= 19 and _luhn_ok(digits)
    if kind == "PHONE-NO":
        return 7 <= len(digits) <= 15 and not is_date_like(text)
    if kind == "EMAIL":
        return "@" in text
    if kind == "SALARY":
        # Kwota to liczba z walutą w samej encji albo tuż obok niej.
        around = source[max(0, entity["start"] - 12): entity["end"] + 12]
        return bool(digits) and bool(_CURRENCY.search(around))
    return True


def plausible(entity: dict) -> bool:
    """Odsiewa oczywiste pomyłki detektora, zanim nieodwracalnie ukryjemy coś w odpowiedzi.

    GLiNER na polskim tekście oznacza zwykłe słowa ("Kobieta", "Wiek") jako osoby.
    """
    words = entity["text"].split()
    if entity["type"] == "NAME":
        return len(words) >= 2 and all(w[0].isupper() for w in words)
    # Także zwykłe słowa ("city", "demo environment") jako miejsca; krótkie łączniki ("Isle of Man") zostają.
    if entity["type"] == "LOCATION":
        return bool(words) and words[0][0].isupper() and all(w[0].isupper() or len(w) <= 3 for w in words)
    return True


def replace_spans(text: str, entities: list[dict], replacement) -> str:
    for e in sorted(entities, key=lambda e: e["start"], reverse=True):
        text = text[: e["start"]] + replacement(e) + text[e["end"]:]
    return text


def label_sensitive(text: str, entities: list[dict], policy: Policy) -> str:
    """Wersja do logu: każda encja wrażliwa w kanale chatbota zamieniona na etykietę typu."""
    return replace_spans(text, [e for e in entities if policy.chatbot_action(e["type"]) != "allow"],
                         lambda e: label_for(e["type"]))


def logged_prompt(ctx: TurnContext, prompt: str) -> str:
    """Prompt tury zatrzymanej przed modelem, w postaci nadającej się do logu.

    Taka tura nie dochodzi do maskowania, a bez treści promptu nie da się potem ustalić, co zostało
    zablokowane. Wartości wrażliwe są zamieniane na etykiety typu, jak w reszcie logu.
    """
    return label_sensitive(prompt, ctx.detect(prompt, ctx.threshold), ctx.policy)


def mask_prompt(conv: Conversation, prompt: str, *, policy: Policy, detect: Detect,
                threshold: Optional[float] = None) -> tuple[str, list, bool]:
    """Maskuje prompt przed wysłaniem do chatbota. Zwraca (prompt, encje z decyzjami, czy blokada)."""
    mask_on = policy.controls.pii.mask_in_chatbot_channel
    entities = detect(prompt, threshold)
    pending = []
    for e in entities:
        action = policy.chatbot_action(e["type"]) if mask_on else "allow"
        e["decision"] = {"allow": "send", "redact": "mask", "block": "block"}.get(action, "mask")
        if action == "judge":
            pending.append(e)
    if pending and policy.controls.pii.judge_enabled:
        for e, decision in zip(pending, judge_entities(conv.role, prompt, pending, policy=policy)):
            e["decision"] = decision

    blocked = any(e["decision"] == "block" for e in entities)
    masked = conv.vault.mask_entities(prompt, [e for e in entities if e["decision"] == "mask"])
    if mask_on:
        masked = conv.vault.mask_known(masked)
    audit.record(
        "prompt_masking", "security",
        decisions=[{"type": e["type"], "decision": e["decision"]} for e in entities],
        prompt=label_sensitive(prompt, entities, policy),
    )
    return masked, entities, blocked


def pseudonymize_known_ids(text: str, vault: Vault, role_policy: dict, own: str) -> str:
    """Identyfikator z sejfu wypisany wprost (np. model zna publiczny zbiór danych z treningu) wraca do
    pseudonimu, gdy rola ma widzieć identyfikatory tylko jako pseudonimy."""
    for token, entity_type, value in vault.entries():
        if role_policy.get(entity_type) == "pseudonymize" and value and value not in own:
            text = re.sub(rf"(?<!\d){re.escape(value)}(?!\d)", token, text)
    return text


class _AllowAll(dict):
    """Polityka PII roli, która niczego nie ukrywa ani nie blokuje (wyłączony filtr odpowiedzi)."""

    def get(self, key, default=None):
        return "allow"


def filter_output(role: str, text: str, vault: Optional[Vault] = None, own_texts=(), public_texts=(),
                  threshold: Optional[float] = None, redact: bool = True, judge: bool = False,
                  enforce: bool = True, *, policy: Policy, detect: Detect) -> tuple[str, str, dict]:
    """Filtr odpowiedzi w kanale użytkownika.

    Nie ukrywa wartości, które użytkownik sam wpisał (`own_texts`) ani pochodzących ze źródeł
    publicznych (`public_texts`). Zwraca (tekst dla użytkownika, tekst do logu, statystyki);
    statystyki zawierają klucz "blocked" z typami, które wymuszają blokadę całej odpowiedzi.
    Przy `redact=False` nic nie jest ukrywane (typy trafiają do "found"), ale blokady nadal działają.
    Przy `judge=True` imiona i kwoty przed ukryciem ocenia sędzia LLM: "Masa Księżyca" albo nazwa
    stanowiska to nie dane osobowe, choć detektor tak je oznacza.
    Przy `enforce=False` (filtr wyłączony w konfiguracji) niczego nie ukrywamy ani nie blokujemy; znaczniki
    z sejfu wracają do wartości, a log nadal dostaje wersję z etykietami.
    """
    vault = vault or Vault()
    role_policy = policy.pii_policy_for(role) if enforce else _AllowAll()
    own = "\n".join(own_texts)
    exempt = own + "\n" + "\n".join(public_texts)
    text = pseudonymize_known_ids(text, vault, role_policy, own)
    spans = vault.token_spans(text)

    entities = [
        e for e in detect(text, threshold)
        if plausible(e) and not any(e["start"] < end and start < e["end"] for start, end in spans)
    ]
    to_replace, exempted, found = [], [], []
    for e in entities:
        action = role_policy.get(e["type"], "redact")
        e["action"] = action
        if action == "allow":
            continue
        if e["text"] in exempt:
            e["action"] = "exempt"
            exempted.append(e["type"])
        elif action == "redact" and not redact:
            e["action"] = "found"
            found.append(e["type"])
        else:
            to_replace.append(e)

    # Typy, które w kanale chatbota rozstrzyga sędzia (imię i nazwisko, kwota), ocenia on także tutaj.
    doubtful = [e for e in to_replace if e["action"] == "redact" and policy.chatbot_action(e["type"]) == "judge"]
    if judge and doubtful:
        for e, decision in zip(doubtful, judge_reply_entities(role, text, doubtful, policy=policy)):
            if decision == "keep":
                e["action"] = "exempt"
                exempted.append(e["type"])
        to_replace = [e for e in to_replace if e["action"] != "exempt"]

    def visible(e):
        return vault.token_for(e["type"], e["text"]) if e["action"] == "pseudonymize" else label_for(e["type"])

    shown, stats = vault.render(replace_spans(text, to_replace, visible), role_policy, own)
    stats["redacted"] += [e["type"] for e in to_replace if e["action"] == "redact"]
    stats["blocked"] += [e["type"] for e in to_replace if e["action"] == "block"]
    stats["exempt"] = exempted
    stats["found"] = found
    stats["entities"] = entities
    return shown, label_sensitive(text, entities, policy), stats
