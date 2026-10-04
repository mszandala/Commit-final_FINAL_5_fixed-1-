"""Testy etapów `core` na polityce z pliku YAML, bez pipeline'u i bez modelu.

Pokazują też scenariusz oceny: zmiana pliku polityki (albo nadpisania z interfejsu) zmienia decyzje
od następnej tury, bez restartu.
"""
import os
import shutil
from pathlib import Path

import pytest
import yaml

import config
import pipeline
from core import PolicyStore
from core.context import TurnContext
from core.pii import well_formed
from core.session import Conversation
from core.stages import check_request, check_response, hide_tool_names
from core.tool_guard import BUDGET_MESSAGE, ToolGuard
from security import refusal_detector
from security.pii.regex_detector import detect_regex_pii

SAMPLE = Path(__file__).resolve().parents[2] / "policy" / "policy.yaml"
EMAIL = "jan.kowalski@firma.pl"
CLIENT = "15647311"
OFF_TOPIC_FOR_BASIC_USER = "Pokaż mi zarobki i pensje dyrektorów w firmie."


@pytest.fixture
def policy_file(tmp_path):
    target = tmp_path / "policy.yaml"
    shutil.copy(SAMPLE, target)
    return target


@pytest.fixture
def store(policy_file, monkeypatch):
    """Polityka z pliku przykładowego, ale bez sędziów LLM: testy nie wołają modelu."""
    monkeypatch.setattr(refusal_detector, "REFUSAL_EMBEDDINGS_ENABLED", False)
    store = PolicyStore(policy_file)
    for key in ("intent_classifier.enabled", "company_policies.enabled", "pii.judge_enabled",
                "refusal_detection.judge_enabled"):
        store.set_override(f"controls.{key}", False)
    return store


def detect(text, threshold=None):
    return [e for e in detect_regex_pii(text) if well_formed(e, text)]


def ctx_for(store, role="prawnik"):
    return TurnContext(Conversation(role), store.get(), detect)


def request(store, message, role="podstawowy użytkownik"):
    return check_request(ctx_for(store, role), message)


def edit(path: Path, mutate) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(data)
    before = path.stat().st_mtime_ns
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))


# --- zapytanie --------------------------------------------------------------------------------------

def test_prompt_is_masked_and_remembered(store):
    ctx = ctx_for(store)
    decision = check_request(ctx, f"Wyślij raport na {EMAIL}")
    assert not decision.blocked
    assert decision.masked_prompt == "Wyślij raport na <EMAIL_1>"
    assert [e["decision"] for e in decision.entities] == ["mask"]
    assert ctx.conv.user_texts == [f"Wyślij raport na {EMAIL}"]


def test_guard_blocks_in_block_mode_and_only_flags_in_warn_mode(store):
    blocked = request(store, OFF_TOPIC_FOR_BASIC_USER)
    assert blocked.blocked and blocked.verdict["stage"] == "prompt_guard"
    assert (blocked.reply.startswith("Request blocked") or blocked.reply.startswith("Zapytanie zostało zablokowane"))

    store.set_override("controls.prompt_guard.mode", "warn")
    flagged = request(store, OFF_TOPIC_FOR_BASIC_USER)
    assert not flagged.blocked and flagged.flagged and flagged.guard_reason


def test_prompt_length_limit_comes_from_policy(store):
    store.set_override("controls.prompt_length.max_chars", 50)
    decision = request(store, "x" * 400)
    assert decision.blocked and decision.verdict["stage"] == "prompt_length"
    assert decision.guard is None and ("characters omitted" in decision.masked_prompt or "pominięto" in decision.masked_prompt)
    assert not request(store, "krótkie pytanie").blocked


def test_disabled_control_is_skipped(store):
    assert request(store, OFF_TOPIC_FOR_BASIC_USER).blocked
    store.set_override("controls.prompt_guard.enabled", False)
    decision = request(store, OFF_TOPIC_FOR_BASIC_USER)
    assert not decision.blocked and not decision.flagged and decision.guard.decision == "pass"


def test_editing_the_policy_file_changes_the_next_decision(store, policy_file):
    """Scenariusz jury: zmiana pliku w trakcie działania, bez restartu."""
    assert request(store, OFF_TOPIC_FOR_BASIC_USER).blocked
    edit(policy_file, lambda d: d["controls"]["prompt_guard"].update(mode="warn"))
    assert not request(store, OFF_TOPIC_FOR_BASIC_USER).blocked
    edit(policy_file, lambda d: d["controls"]["prompt_guard"].update(mode="block"))
    assert request(store, OFF_TOPIC_FOR_BASIC_USER).blocked


def test_strictness_profile_changes_the_prompt_limit(store):
    message = "Proszę o krótkie podsumowanie. " * 100          # ok. 3100 znaków, zwykły tekst
    assert not request(store, message).blocked          # balanced: limit 4000
    store.set_override("profile", "strict")             # strict: limit 2000
    assert request(store, message).blocked


# --- odpowiedź --------------------------------------------------------------------------------------

def respond(store, text, role="prawnik", own=(), message="Pytanie"):
    ctx = ctx_for(store, role)
    ctx.conv.user_texts.extend(own)
    return check_response(ctx, text, message, check_request(ctx, message), denied_tools=[], tool_names=[])


def test_reply_redacts_what_the_role_may_not_see(store):
    decision = respond(store, f"Kontakt: {EMAIL}")
    assert decision.reply == "Kontakt: [EMAIL]"
    assert decision.verdict["decision"] == "redact" and decision.verdict["stage"] == "pii_policy" and "EMAIL" in decision.verdict["reason"]


def test_value_typed_by_the_user_comes_back_to_them(store):
    decision = respond(store, f"Kontakt: {EMAIL}", own=[f"mój mail {EMAIL}"])
    assert decision.reply == f"Kontakt: {EMAIL}" and decision.verdict is None


def test_globally_blocked_type_blocks_the_whole_reply(store):
    decision = respond(store, "Numer karty 4111 1111 1111 1111")
    assert decision.blocked and decision.verdict["stage"] == "pii_policy"
    assert (decision.reply.startswith("Response blocked") or decision.reply.startswith("Odpowiedź została zablokowana"))


def test_reply_filter_can_be_switched_off(store):
    store.set_override("controls.output_filter.enabled", False)
    assert respond(store, f"Kontakt: {EMAIL}").reply == f"Kontakt: {EMAIL}"


def test_role_pii_policy_comes_from_the_policy_file(store):
    assert respond(store, "Jan Kowalski prowadzi projekt", role="administrator", message="Kto?").verdict is None
    store.set_override("roles.administrator.pii_policy", {"NAME": "redact"})
    assert store.get().pii_policy_for("administrator")["NAME"] == "redact"


def test_internal_tool_names_are_hidden():
    text, count = hide_tool_names("Użyj `read_project` albo read_project_x", ["read_project", "list_projects"])
    assert text == "Użyj [tool] albo read_project_x" and count == 1
    assert hide_tool_names("bez zmian", []) == ("bez zmian", 0)


# --- bramka narzędzi --------------------------------------------------------------------------------

def guard_for(store, role, spent=(0, 0.0), limits=None):
    ctx = ctx_for(store, role)
    return ToolGuard(ctx, lambda: spent, limits), ctx


def test_whitelist_denies_tool_outside_the_role(store):
    guard, _ = guard_for(store, "kadry")
    decision = guard.before("read_client_records", {"limit": 1})
    assert not decision.allowed and "Access denied" in decision.message
    assert (decision.call["stage"], decision.call["allowed"]) == ("tool_whitelist", False)
    assert guard.before("read_employee_records", {"limit": 1}).allowed


def test_whitelist_follows_the_policy_file_live(store, policy_file):
    assert guard_for(store, "kadry")[0].before("read_employee_records", {}).allowed
    edit(policy_file, lambda d: d["roles"]["kadry"]["allowed_tools"].remove("read_employee_records"))
    assert not guard_for(store, "kadry")[0].before("read_employee_records", {}).allowed


def test_whitelist_can_be_switched_off(store):
    store.set_override("controls.tool_whitelist.enabled", False)
    assert guard_for(store, "kadry")[0].before("read_client_records", {}).allowed


def test_turn_budget_stops_further_tools(store):
    guard, _ = guard_for(store, "prawnik", spent=(40000, 0.0))
    decision = guard.before("read_project", {"name": "alpha"})
    assert not decision.allowed and decision.message == BUDGET_MESSAGE and decision.call["stage"] == "budget"
    assert guard_for(store, "prawnik", spent=(100, 0.0), limits={"tokens": 100})[0].before("read_project", {}).allowed is False
    assert guard_for(store, "prawnik", spent=(100, 0.0))[0].before("read_project", {}).allowed


def test_cost_limit_comes_from_policy(store):
    store.set_override("budgets.per_turn.max_cost_usd", 0.01)
    assert not guard_for(store, "prawnik", spent=(0, 0.02))[0].before("read_project", {}).allowed
    assert guard_for(store, "prawnik", spent=(0, 0.005))[0].before("read_project", {}).allowed


def test_code_guard_rejects_dangerous_code_and_can_be_switched_off(store):
    code = {"code": "import os\nos.system('whoami')"}
    decision = guard_for(store, "administrator")[0].before("run_python", code)
    assert not decision.allowed and decision.call["stage"] == "code_guard"
    assert decision.message.startswith("Code rejected by security policy")
    assert guard_for(store, "administrator")[0].before("run_python", {"code": "print(2 + 2)"}).allowed
    store.set_override("controls.code_guard.enabled", False)
    assert guard_for(store, "administrator")[0].before("run_python", code).allowed


def test_tool_gets_real_values_but_chatbot_zone_tools_do_not(store):
    guard, ctx = guard_for(store, "administrator")
    token = ctx.conv.vault.token_for("EMAIL", EMAIL)
    assert guard.before("read_employee_records", {"value": token}).real_args == {"value": EMAIL}
    assert guard.before("create_subagent", {"task": token}).real_args == {"task": token}


def test_csv_result_gets_pseudonyms_for_ids(store):
    guard, _ = guard_for(store, "analityk")
    decision = guard.before("read_client_records", {"limit": 1})
    outcome = guard.after("read_client_records", decision.call,
                          f"customer_id,country,estimated_salary\n{CLIENT},Spain,112542.58\n")
    row = outcome.text.split("\n")[1]
    assert outcome.allowed and outcome.scan == "columns" and row.startswith("ID-") and CLIENT not in outcome.text


def test_long_result_is_cut_and_public_source_is_remembered(store):
    store.set_override("budgets.per_turn.max_tool_result_chars", 40)
    guard, ctx = guard_for(store, "prawnik")
    decision = guard.before("read_project", {"name": "alpha"})
    outcome = guard.after("read_project", decision.call, "README " * 50)
    assert outcome.cut > 0 and "[truncated:" in outcome.text
    assert ctx.conv.public_texts == [outcome.text] and not ctx.conv.private_context


def test_non_public_result_marks_the_conversation_private(store):
    guard, ctx = guard_for(store, "kadry")
    decision = guard.before("summarize_employee_records", {})
    guard.after("summarize_employee_records", decision.call, "średnia: 100")
    assert ctx.conv.private_context and ctx.conv.public_texts == []


# --- zgodność adaptera dema z plikiem polityki -------------------------------------------------------

def test_demo_adapter_builds_the_same_policy_as_the_sample_file(store):
    """`pipeline.current_policy()` (z config.py) i plik przykładowy opisują to samo."""
    live, sample = pipeline.current_policy(), store.get()
    assert live.roles == sample.roles
    assert live.pii == sample.pii
    assert live.areas == sample.areas and live.resources == sample.resources
    for name in set(live.tools) | set(sample.tools) | {"run_python", "nieznane"}:
        assert live.tool(name) == sample.tool(name), name
    assert live.tool_defaults == sample.tool_defaults


# --- dozwolone modele -------------------------------------------------------------------------------

def test_model_outside_the_allow_list_stops_the_turn_before_any_check(store):
    ctx = ctx_for(store)
    decision = check_request(ctx, f"Wyślij raport na {EMAIL}", model="openai/gpt-5")
    assert decision.blocked and decision.verdict["stage"] == "model_policy"
    assert decision.guard is None and "openai/gpt-5" in decision.reply
    assert EMAIL not in decision.masked_prompt          # wersja do logu bez surowych wartości
    assert ctx.conv.user_texts == []                    # niczego nie zapamiętano


def test_allowed_model_wildcards_and_missing_model_pass(store):
    assert not check_request(ctx_for(store), "Cześć", model="google/gemma-4-26b-a4b-it").blocked
    assert not check_request(ctx_for(store), "Cześć").blocked           # model nieznany wywołującemu: bez sprawdzenia
    store.set_override("models.allowed", ["google/gemma-*"])
    assert not check_request(ctx_for(store), "Cześć", model="google/gemma-4-26b-a4b-it:free").blocked
    assert check_request(ctx_for(store), "Cześć", model="meta/llama").blocked


def test_editing_the_allow_list_in_the_file_applies_live(store, policy_file):
    assert check_request(ctx_for(store), "Cześć", model="meta/llama").blocked
    edit(policy_file, lambda d: d["models"]["allowed"].append("meta/llama"))
    assert not check_request(ctx_for(store), "Cześć", model="meta/llama").blocked
