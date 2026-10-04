"""Dowód, że etapy `core` i strażnicy decydują wyłącznie na podstawie polityki, a nie `config.py`.

Konfiguracja jest tu celowo zatruta: role, zasoby, polityki PII i typy identyfikatorów są puste, progi
wykrywania odmów absurdalne. Polityka z pliku opisuje rolę, typ identyfikatora i narzędzie, których
w config.py nie ma, więc jeśli jakikolwiek etap sięgnie po konfigurację, test się wysypie.
"""
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import config
from chatbot import llm_client
from core import PolicyStore
from core.context import TurnContext
from core.pii import well_formed
from core.session import Conversation
from core.stages import check_request, check_response
from core.tool_guard import ToolGuard
from security import budget as budget_module
from security import refusal_detector
from security.budget import Budget
from security.company_policies.policy import PolicyError, parse_policy
from security.intent_classifier import classify_intent
from security.masking import Vault
from security.pii.regex_detector import detect_regex_pii
from security.pii_judge import judge_entities, judge_reply_entities
from security.prompt_guard import check_prompt

SAMPLE = Path(__file__).resolve().parents[2] / "policy" / "policy.yaml"
RULES = Path(config.__file__).parent / "security" / "company_policies" / "rules.txt"

# Struktury z config.py, z których czyta stary kod (zmieniane na miejscu, bo moduły trzymają referencje).
_POISONED = ["ROLES", "RESOURCE_TOOLS", "DATA_ACCESS", "CHATBOT_PII_POLICY", "DEFAULT_ROLE_PII_POLICY",
             "COLUMN_TYPES", "TOOL_RESULT_SCAN", "GLOBAL_BLOCKED_PII", "GLOBAL_REDACTED_PII", "ID_TYPES",
             "PUBLIC_SOURCE_TOOLS", "CHATBOT_ZONE_TOOLS", "MODEL_PRESETS"]


@pytest.fixture(autouse=True)
def poisoned_config(monkeypatch):
    saved = {name: copy.deepcopy(getattr(config, name)) for name in _POISONED}
    for name in _POISONED:
        getattr(config, name).clear()
    monkeypatch.setattr(budget_module, "MAX_SPENDING", 1e-9)
    monkeypatch.setattr(config, "MAX_SPENDING", 1e-9)
    monkeypatch.setattr(refusal_detector, "REFUSAL_THRESHOLD", 99.0)
    monkeypatch.setattr(refusal_detector, "REFUSAL_TRIGGER_THRESHOLD", 99.0)
    monkeypatch.setattr(refusal_detector, "REFUSAL_EMBEDDINGS_ENABLED", True)
    yield
    for name, value in saved.items():
        target = getattr(config, name)
        target.clear()
        target.update(value) if isinstance(target, dict) else target.extend(value)


@pytest.fixture
def store(tmp_path):
    data = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    for control in ("intent_classifier", "company_policies"):
        data["controls"][control] = {"enabled": False}
    data["controls"]["pii"]["judge_enabled"] = False
    data["controls"]["refusal_detection"] = {"embeddings_enabled": False, "judge_enabled": False}
    data["roles"]["audytor"] = {
        "id": "auditor", "description": "Audytor wewnętrzny; przegląda projekty i dzienniki audytu.",
        "allowed_tools": ["list_projects", "read_project", "read_employee_records", "read_audit_log"],
        "allowed_pii": ["PROJECT", "ORGANIZATION"], "pii_policy": {"NAME": "block"}, "daily_tokens": 1000}
    data["roles"]["gość"] = {"id": "guest", "description": "Gość.", "allowed_tools": ["list_projects"],
                             "allowed_pii": ["PROJECT"], "daily_tokens": 10}
    data["pii"]["id_types"].append("AUDIT-ID")
    data["pii"]["chatbot_policy"]["AUDIT-ID"] = "redact"
    data["pii"]["default_role_policy"]["AUDIT-ID"] = "allow"
    data["tools"]["read_audit_log"] = {"scan": "columns", "column_types": {"user_ref": "AUDIT-ID", "email": "EMAIL"}}
    data["areas"]["audit"] = {"label": "Audit logs", "tools": ["read_audit_log"]}
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return PolicyStore(path)


def find_names(text, threshold=None):
    """Detektor imion w stylu GLiNER: regex dla reszty plus imię i nazwisko Jan Kowalski."""
    entities = [e for e in detect_regex_pid(text) if well_formed(e, text)]
    at = text.find("Jan Kowalski")
    if at >= 0:
        entities.append({"type": "NAME", "text": "Jan Kowalski", "start": at, "end": at + len("Jan Kowalski")})
    return entities


def detect_regex_pid(text):
    return detect_regex_pii(text)


def ctx_for(store, role="audytor"):
    return TurnContext(Conversation(role), store.get(), find_names)


def test_the_config_really_is_poisoned():
    assert config.ROLES == {} and config.RESOURCE_TOOLS == {} and config.ID_TYPES == []
    assert Budget().spending_limit() == 1e-9


# --- strażnik promptu, klasyfikator intencji, sędzia ---------------------------------------------------

def test_prompt_guard_reads_roles_and_resources_from_the_policy(store):
    policy = store.get()
    assert check_prompt("audytor", "Pokaż pensje pracowników", policy=policy).decision == "pass"
    guest = check_prompt("gość", "Pokaż pensje pracowników", policy=policy)
    assert guest.decision == "warn" and guest.details["requested_resource"] == "employee_data"
    store.set_override("resources.employee_data", ["narzedzie_tylko_dla_hr"])
    assert check_prompt("audytor", "Pokaż pensje pracowników", policy=store.get()).decision == "warn"


def test_intent_classifier_describes_the_role_and_areas_from_the_policy(store, monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(messages[0]["content"])
                        or SimpleNamespace(content='{"category": "in_scope", "reason": ""}'))
    result = classify_intent("audytor", "Pokaż projekty", policy=store.get())
    assert result["category"] == "in_scope"
    message = seen[0]
    assert "Audytor wewnętrzny" in message and "Audit logs" in message and "HR data" in message


def test_pii_judges_use_the_role_description_from_the_policy(store, monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(messages[0]["content"])
                        or SimpleNamespace(content="{}"))
    entity = [{"type": "NAME", "text": "Jan Kowalski", "start": 0, "end": 12}]
    assert judge_entities("audytor", "Jan Kowalski", entity, policy=store.get()) == ["mask"]
    assert judge_reply_entities("audytor", "Jan Kowalski", entity, policy=store.get()) == ["hide"]
    assert all("Audytor wewnętrzny" in message for message in seen) and len(seen) == 2


def test_refusal_settings_come_from_the_policy_not_the_module(monkeypatch):
    calls = []
    monkeypatch.setattr(refusal_detector, "_embedder", lambda name=None: calls.append(name))
    off = SimpleNamespace(embeddings_enabled=False, model="x/off", threshold=0.5, trigger_threshold=0.3)
    on = SimpleNamespace(embeddings_enabled=True, model="x/on", threshold=0.5, trigger_threshold=0.3)
    refusal_detector.assess_refusal("pytanie", "Zwykła odpowiedź.", judge=False, settings=off)
    assert calls == []                                   # moduł mówi True, polityka False: wygrywa polityka
    refusal_detector.assess_refusal("pytanie", "Zwykła odpowiedź.", judge=False, settings=on)
    assert calls == ["x/on"]                             # model z polityki, nie z REFUSAL_MODEL


# --- regulaminy i budżet ----------------------------------------------------------------------------------

def test_company_rules_validate_roles_against_the_given_list():
    text = RULES.read_text(encoding="utf-8")
    documents, fixtures = config.COMPANY_DOCUMENTS_DIR, config.COMPANY_FIXTURES_DIR
    everybody = ["podstawowy użytkownik", "kadry", "bankier", "analityk", "prawnik", "Portfolio Manager", "IT",
                 "administrator"]
    assert parse_policy(text, documents, fixtures, known_roles=lambda: everybody).active_rules
    with pytest.raises(PolicyError, match="nieznana rola"):
        parse_policy(text, documents, fixtures, known_roles=lambda: ["audytor"])


def test_budget_limits_and_role_ids_come_from_the_policy(store, tmp_path):
    budget = Budget(tmp_path / "spending.db", policy=store.get)
    assert budget.token_limit("audytor") == 1000 and budget.token_limit("gość") == 10
    assert budget.spending_limit() == 0.5
    assert budget.check("gość", "x" * 100) is not None            # 25 tokenów przy limicie 10
    assert budget.check("audytor", "krótko") is None
    budget.add("audytor", 995, cost=0.6, model="m")
    assert budget.tokens_used("audytor") == 995 and budget.spent("audytor") == 0.6
    assert budget.check("audytor", "krótko")["reason"].startswith("Przekroczono limit wydatków")
    assert budget.tokens_used("gość") == 0                          # identyfikator roli z polityki, osobne liczniki
    budget.reset("audytor")
    assert budget.spent("audytor") == 0
    with pytest.raises(KeyError):
        budget.token_limit("nieznana")


def test_budget_follows_policy_changes_immediately(store, tmp_path):
    budget = Budget(tmp_path / "spending.db", policy=store.get)
    store.set_override("roles.audytor.daily_tokens", 5)
    assert budget.token_limit("audytor") == 5
    store.set_override("budgets.spending_limit_usd", 2.0)
    assert budget.spending_limit() == 2.0


# --- sejf, bramka narzędzi, etapy ----------------------------------------------------------------------

def test_vault_pseudonymizes_exactly_the_policy_id_types(store):
    ctx = ctx_for(store)
    assert ctx.conv.vault.token_for("AUDIT-ID", "u-1").startswith("ID-")
    assert ctx.conv.vault.token_for("EMAIL", "jan@firma.pl") == "<EMAIL_1>"    # nie jest identyfikatorem: zwykły znacznik
    store.set_override("pii.id_types", ["AUDIT-ID"])                            # CLIENT-ID przestaje być identyfikatorem
    later = ctx_for(store)
    assert later.conv.vault.token_for("CLIENT-ID", "42") == "<CLIENT_ID_1>"
    assert Vault().is_id_type("CLIENT-ID") is False                            # tryb zgodności czyta zatrutą konfigurację


def test_tool_guard_allows_denies_and_masks_by_the_policy(store):
    ctx = ctx_for(store)
    guard = ToolGuard(ctx, lambda: (0, 0.0))
    assert not guard.before("read_client_records", {}).allowed          # poza rolą audytora
    decision = guard.before("read_audit_log", {})
    assert decision.allowed
    outcome = guard.after("read_audit_log", decision.call, "user_ref,email\nu-1,jan@firma.pl\nu-2,ewa@firma.pl\n")
    rows = outcome.text.split("\n")
    assert outcome.scan == "columns" and rows[1].startswith("ID-") and rows[1].endswith("[REDACTED]")
    assert "u-1" not in outcome.text and "jan@firma.pl" not in outcome.text


def test_request_and_response_stages_follow_the_policy(store):
    ctx = ctx_for(store)
    request = check_request(ctx, "Napisz do jan.kowalski@firma.pl", model="google/gemma-4-26b-a4b-it")
    assert not request.blocked and request.masked_prompt == "Napisz do <EMAIL_1>"
    blocked = check_response(ctx, "Odpowiedzialny jest Jan Kowalski.", "Kto?", request,
                             denied_tools=[], tool_names=[])
    assert blocked.blocked and blocked.verdict["stage"] == "pii_policy"      # NAME: block tylko dla audytora
    other = ctx_for(store, "gość")
    shown = check_response(other, "Odpowiedzialny jest Jan Kowalski.", "Kto?", check_request(other, "Kto?"),
                           denied_tools=[], tool_names=[])
    assert not shown.blocked and shown.reply == "Odpowiedzialny jest [NAME]."


def test_policy_change_reaches_the_stages_without_restart(store):
    store.set_override("models.allowed", ["google/gemma-*", "meta/llama"])
    assert check_request(ctx_for(store), "Cześć", model="meta/llama").blocked is False
    store.set_override("models.allowed", ["google/gemma-*"])
    assert check_request(ctx_for(store), "Cześć", model="meta/llama").blocked


# --- przekazanie polityki w etapach (nie tylko w strażnikach wywoływanych bezpośrednio) -------------------

def test_request_stage_applies_the_role_scope_from_the_policy(store):
    store.set_override("controls.prompt_guard.mode", "block")
    blocked = check_request(ctx_for(store, "gość"), "Pokaż pensje pracowników")
    assert blocked.blocked and blocked.verdict["stage"] == "prompt_guard"
    assert not check_request(ctx_for(store, "audytor"), "Pokaż pensje pracowników").blocked


def test_request_stage_gives_the_intent_classifier_the_policy(store, monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(messages[0]["content"])
                        or SimpleNamespace(content='{"category": "in_scope", "reason": ""}'))
    store.set_override("controls.intent_classifier.enabled", True)
    assert not check_request(ctx_for(store), "Pokaż projekty").blocked
    assert len(seen) == 1 and "Audytor wewnętrzny" in seen[0]


def test_request_stage_gives_the_pii_judge_the_policy(store, monkeypatch):
    seen = []
    monkeypatch.setattr(llm_client, "chat", lambda messages, **kw: seen.append(messages[0]["content"])
                        or SimpleNamespace(content="{}"))
    store.set_override("controls.pii.judge_enabled", True)
    decision = check_request(ctx_for(store), "Zadzwoń do Jan Kowalski")
    assert decision.masked_prompt == "Zadzwoń do <NAME_1>"                    # wątpliwość sędziego = maskowanie
    assert len(seen) == 1 and "Audytor wewnętrzny" in seen[0]


def test_response_stage_uses_the_refusal_settings_of_the_policy(store, monkeypatch):
    def forbidden(name=None):
        raise AssertionError("embeddingi są wyłączone w polityce, więc nie wolno ich ładować")

    monkeypatch.setattr(refusal_detector, "_embedder", forbidden)              # moduł mówi True, polityka False
    ctx = ctx_for(store)
    decision = check_response(ctx, "Zwykła odpowiedź.", "Pytanie", check_request(ctx, "Pytanie"),
                              denied_tools=[], tool_names=[])
    assert not decision.blocked and decision.refusal is None
