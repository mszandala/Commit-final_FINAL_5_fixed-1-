"""Izolowane uruchamianie scenariuszy: kopia polityki zamiast zmiany globalnej konfiguracji i wstrzykiwany czat.

Scenariusz w trybie mock albo z wariantami nie dotyka stanu serwera: konfiguracja scenariusza jest
tłumaczona na kopię `Policy` obowiązującą tylko w jego turze, a odpowiedzi modelu chatbota podaje skrypt
(mock) albo prawdziwy model (live). Dzięki temu scenariusze ON/OFF mogą działać obok zwykłego czatu.
"""
import copy
from types import SimpleNamespace
from typing import Optional

from audit import logger as audit
from chatbot import llm_client
from core import Policy
from core.models import FILTER_IDS

NOTICE_END = "[End of notice]"

# Tryb mock uruchamia tylko kontrole deterministyczne: sędziowie i klasyfikatory LLM wołałyby model, więc
# kosztowałyby i nie byłyby powtarzalne. Scenariusz włącza je jawnie w `config`, ale wtedy przestaje być
# w pełni deterministyczny.
MOCK_BASELINE = {
    "filters": {"intent_classifier": False, "company_policies": False},
    "policy": {"controls.pii.judge_enabled": False, "controls.refusal_detection.judge_enabled": False,
               "controls.refusal_detection.embeddings_enabled": False},
}


def merge_config(base: dict, extra: dict) -> dict:
    """Słowniki scalane rekurencyjnie (filters, limits, roles, policy), reszta nadpisywana."""
    out = copy.deepcopy(base)
    for key, value in (extra or {}).items():
        out[key] = merge_config(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) \
            else copy.deepcopy(value)
    return out


def _set_path(data: dict, dotted: str, value) -> None:
    *parents, leaf = dotted.split(".")
    node = data
    for part in parents:
        if not isinstance(node.get(part), dict):
            raise ValueError(f"Polityka nie ma sekcji „{part}” (ścieżka {dotted})")
        node = node[part]
    if leaf not in node:
        raise ValueError(f"Polityka nie ma klucza „{leaf}” (ścieżka {dotted})")
    node[leaf] = value


def policy_with(config: dict, base: Policy, role_by_id: dict) -> Policy:
    """Kopia `base` ze zmianami z konfiguracji scenariusza; `base` pozostaje nietknięta.

    Klucze jak w starej ścieżce (guardMode, maskPii, filters, roles, limits) plus `policy`: słownik
    ścieżek (np. {"controls.pii.threshold": 0.85}) do zmiany dowolnego klucza polityki."""
    data = base.model_dump()
    controls, per_turn = data["controls"], data["budgets"]["per_turn"]
    if "guardMode" in config:
        controls["prompt_guard"]["mode"] = config["guardMode"]
    if "maskPii" in config:
        controls["pii"]["mask_in_chatbot_channel"] = config["maskPii"]
    unknown = [f for f in config.get("filters", {}) if f not in FILTER_IDS]
    if unknown:
        raise ValueError(f"Nieznane filtry: {unknown}")
    for name, enabled in config.get("filters", {}).items():
        controls[name]["enabled"] = enabled
    area_tools = {t for area in data["areas"].values() for t in area["tools"]}
    for role_id, areas in config.get("roles", {}).items():
        missing = [a for a in areas if a not in data["areas"]]
        if missing:
            raise ValueError(f"Nieznane obszary danych: {missing}")
        role = data["roles"][role_by_id[role_id]]
        kept = [t for t in role["allowed_tools"] if t not in area_tools]
        role["allowed_tools"] = [t for a in areas for t in data["areas"][a]["tools"]] + kept
    limits = {"maxPromptChars": (controls["prompt_length"], "max_chars"),
              "maxTurnTokens": (per_turn, "max_tokens"), "maxTurnCost": (per_turn, "max_cost_usd")}
    for key, value in config.get("limits", {}).items():
        target, field = limits[key]
        target[field] = value
    for dotted, value in config.get("policy", {}).items():
        _set_path(data, dotted, value)
    return Policy.model_validate(data)


def strip_notice(content: str) -> str:
    """Treść wiadomości bez informacji warstwy dołączanej do pierwszej wiadomości rozmowy."""
    return content.split(NOTICE_END, 1)[1].lstrip() if NOTICE_END in content else content


def _role_and_content(message) -> tuple:
    if isinstance(message, dict):
        return message.get("role"), message.get("content") or ""
    return getattr(message, "role", None), getattr(message, "content", None) or ""


class ScenarioChat:
    """Czat chatbota dla jednego scenariusza: odpowiada wg skryptu (mock) albo wywołuje prawdziwy model,
    i w obu przypadkach zapisuje, co dostał model. Podstawiany za `llm_client.chat` tylko w tej turze.

    Krok skryptu to {"reply": "tekst"} albo {"tool_calls": [{"name", "args"}]}. W tekście odpowiedzi:
    {prompt} = zapytanie użytkownika w wersji, którą dostał model (po maskowaniu, bez informacji warstwy),
    {tool_result} = ostatni wynik narzędzia, który dostał model."""

    def __init__(self, script: Optional[list] = None):
        self.script = copy.deepcopy(script) if script is not None else None
        self.calls: list[list[tuple]] = []        # dla każdego wywołania: [(rola, treść), ...]

    @property
    def is_mock(self) -> bool:
        return self.script is not None

    def __call__(self, messages, tools=None, provider=None, model=None, zone="chatbot", purpose="chat"):
        self.calls.append([_role_and_content(m) for m in messages])
        if not self.is_mock:
            return llm_client.chat(messages, tools=tools, provider=provider, model=model, zone=zone, purpose=purpose)
        audit.record("llm_call", zone, purpose=purpose, provider="mock", model="mock (scripted)",
                     messages=len(messages), tokens=0, cost=0.0)
        if not self.script:
            raise RuntimeError("Skrypt atrapy modelu się skończył: model wywołano częściej, niż opisuje scenariusz")
        step = self.script.pop(0)
        if "tool_calls" in step:
            calls = [SimpleNamespace(id=f"call_{i}", type="function",
                                     function=SimpleNamespace(name=c["name"], arguments=dict(c.get("args", {}))))
                     for i, c in enumerate(step["tool_calls"])]
            return SimpleNamespace(role="assistant", content="", tool_calls=calls)
        return SimpleNamespace(role="assistant", content=self._fill(step["reply"]), tool_calls=None)

    def _fill(self, template: str) -> str:
        messages = self.calls[-1]
        prompt = next((strip_notice(c) for r, c in reversed(messages) if r == "user"), "")
        tool_result = next((c for r, c in reversed(messages) if r == "tool"), "")
        return template.replace("{prompt}", prompt).replace("{tool_result}", tool_result)

    def received(self) -> str:
        """Wszystko, co model dostał w całej turze (zapytanie użytkownika i wyniki narzędzi), bez informacji
        warstwy: do sprawdzeń „model to widział / nie widział”."""
        seen = [strip_notice(c) for call in self.calls for r, c in call if r in ("user", "tool") and c]
        return "\n".join(dict.fromkeys(seen))

    def last_user_view(self) -> str:
        """To, co model dostał jako zapytanie w ostatnim wywołaniu (do pokazania w interfejsie)."""
        if not self.calls:
            return ""
        return "\n".join(strip_notice(c) for r, c in self.calls[-1] if r in ("user", "tool") and c)


def tool_call_step(name: str, **args) -> dict:
    """Pomocnik do tworzenia kroków skryptu w testach: {"tool_calls": [{"name", "args"}]}."""
    return {"tool_calls": [{"name": name, "args": args}]}
