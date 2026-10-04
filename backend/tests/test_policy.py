import os
import shutil
import threading
from pathlib import Path

import pytest
import yaml

import config
from core import Policy, PolicyError, PolicyStore, default_policy_path
from core.store import build_policy, deep_merge, diff
from security import masking
from security.tool_whitelist import role_areas

SAMPLE = Path(__file__).resolve().parents[2] / "policy" / "policy.yaml"


@pytest.fixture
def policy_file(tmp_path):
    target = tmp_path / "policy.yaml"
    shutil.copy(SAMPLE, target)
    return target


def edit(path: Path, mutate) -> None:
    """Zmienia plik YAML i przesuwa jego czas modyfikacji, żeby zmiana na pewno była widoczna."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(data)
    before = path.stat().st_mtime_ns
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))


@pytest.fixture
def store(policy_file):
    return PolicyStore(policy_file)


# --- plik przykładowy ------------------------------------------------------------------------------

def test_default_path_points_to_sample():
    assert default_policy_path() == SAMPLE


def test_sample_loads_with_balanced_profile(store):
    policy = store.get()
    assert policy.profile == "balanced"
    assert policy.profile_names == ("strict", "balanced", "permissive")
    assert all(policy.filters().values())
    assert policy.controls.prompt_guard.mode == "block"


# --- zgodność z dzisiejszym config.py (do czasu przeniesienia konfiguracji do pliku) ---------------

def test_roles_match_config(store):
    policy = store.get()
    assert list(policy.roles) == list(config.ROLES)
    for name, cfg in config.ROLES.items():
        role = policy.roles[name]
        assert role.id == cfg["id"]
        assert role.description == cfg["description"]
        assert role.allowed_tools == cfg["allowed_tools"]
        assert role.allowed_pii == cfg["allowed_pii"]
        assert role.pii_policy == cfg.get("pii_policy", {})
        assert role.daily_tokens == cfg["daily_token_budget"]


def test_pii_sections_match_config(store):
    pii = store.get().pii
    assert pii.global_blocked == config.GLOBAL_BLOCKED_PII
    assert pii.global_redacted == config.GLOBAL_REDACTED_PII
    assert pii.chatbot_policy == config.CHATBOT_PII_POLICY
    assert pii.default_role_policy == config.DEFAULT_ROLE_PII_POLICY
    assert pii.id_types == config.ID_TYPES


@pytest.mark.parametrize("role", [*config.ROLES, "nieznana rola"])
def test_pii_policy_for_role_matches_masking(store, role):
    assert store.get().pii_policy_for(role) == masking.role_policy(role)


@pytest.mark.parametrize("entity_type", [*config.CHATBOT_PII_POLICY, "NIEZNANY"])
def test_chatbot_action_matches_masking(store, entity_type):
    assert store.get().chatbot_action(entity_type) == masking.chatbot_action(entity_type)


def test_tools_match_config(store):
    policy = store.get()
    names = set(config.TOOL_RESULT_SCAN) | set(config.PUBLIC_SOURCE_TOOLS) | set(config.CHATBOT_ZONE_TOOLS)
    for name in names | {"run_python", "list_files", "nieznane_narzedzie"}:
        meta = policy.tool(name)
        assert meta.scan == config.TOOL_RESULT_SCAN.get(name, config.DEFAULT_TOOL_RESULT_SCAN), name
        assert meta.public == (name in config.PUBLIC_SOURCE_TOOLS), name
        assert meta.chatbot_zone == (name in config.CHATBOT_ZONE_TOOLS), name
        assert meta.column_types == config.COLUMN_TYPES.get(name, {}), name


def test_areas_and_resources_match_config(store):
    policy = store.get()
    assert {k: (a.label, a.tools) for k, a in policy.areas.items()} == \
           {k: (a["label"], a["tools"]) for k, a in config.DATA_ACCESS.items()}
    assert policy.resources == config.RESOURCE_TOOLS


@pytest.mark.parametrize("role", [*config.ROLES, "nieznana rola"])
def test_role_areas_and_tool_access_match_whitelist(store, role):
    policy = store.get()
    assert policy.role_areas(role) == role_areas(role)
    for tool in ("read_employee_records", "run_python", "list_projects"):
        assert policy.is_tool_allowed(role, tool) == (tool in config.ROLES.get(role, {}).get("allowed_tools", []))


def test_limits_match_documented_defaults(store):
    budgets = store.get().budgets
    assert (budgets.per_turn.max_tokens, budgets.per_turn.max_cost_usd) == (40000, 0.05)
    assert (budgets.per_turn.max_tool_steps, budgets.per_turn.max_tool_result_chars) == (config.MAX_TOOL_STEPS, 24000)
    assert budgets.spending_limit_usd == config.MAX_SPENDING


# --- profile ścisłości -----------------------------------------------------------------------------

def test_profiles_change_strictness(policy_file):
    def values(profile):
        edit(policy_file, lambda d: d.update(profile=profile))
        p = PolicyStore(policy_file).get()
        return (p.controls.prompt_guard.mode, p.controls.prompt_length.max_chars, p.controls.pii.threshold,
                p.controls.company_policies.fail_closed, p.budgets.per_turn.max_tool_steps)

    assert values("strict") == ("block", 2000, 0.20, True, 6)
    assert values("balanced") == ("block", 4000, 0.35, False, 10)
    assert values("permissive") == ("warn", 8000, 0.50, False, 15)


def test_unknown_profile_is_rejected_with_available_names(policy_file):
    edit(policy_file, lambda d: d.update(profile="paranoid"))
    with pytest.raises(PolicyError) as exc:
        PolicyStore(policy_file)
    assert "paranoid" in str(exc.value) and "strict" in str(exc.value)


def test_error_in_inactive_profile_is_caught_immediately(policy_file):
    edit(policy_file, lambda d: d["profiles"]["strict"]["controls"]["prompt_guard"].update(mode="maybe"))
    with pytest.raises(PolicyError) as exc:
        PolicyStore(policy_file)
    assert any("prompt_guard" in p for p in exc.value.problems)


def test_profile_may_only_touch_controls_and_budgets(policy_file):
    edit(policy_file, lambda d: d["profiles"]["strict"].update(roles={}))
    with pytest.raises(PolicyError):
        PolicyStore(policy_file)


# --- walidacja -------------------------------------------------------------------------------------

def test_typo_in_key_is_rejected(policy_file):
    edit(policy_file, lambda d: d["controls"]["prompt_guard"].update(mod="warn"))
    with pytest.raises(PolicyError) as exc:
        PolicyStore(policy_file)
    assert any("controls.prompt_guard.mod" in p and "literówka" in p for p in exc.value.problems)


@pytest.mark.parametrize("mutate, where", [
    (lambda d: d["controls"]["prompt_guard"].update(mode="maybe"), "controls.prompt_guard.mode"),
    (lambda d: d["controls"]["pii"].update(threshold=1.5), "controls.pii.threshold"),
    (lambda d: d["controls"]["prompt_length"].update(max_chars=0), "controls.prompt_length.max_chars"),
    (lambda d: d["budgets"].update(spending_limit_usd=-1), "budgets.spending_limit_usd"),
    (lambda d: d["pii"]["chatbot_policy"].update(EMAIL="hide"), "pii.chatbot_policy.EMAIL"),
    (lambda d: d["roles"]["IT"].update(daily_tokens=0), "roles.IT.daily_tokens"),
])
def test_invalid_values_are_reported_with_path(policy_file, mutate, where):
    edit(policy_file, mutate)
    with pytest.raises(PolicyError) as exc:
        PolicyStore(policy_file)
    assert any(p.startswith(where) for p in exc.value.problems), exc.value.problems


def test_duplicate_role_ids_are_rejected(policy_file):
    edit(policy_file, lambda d: d["roles"]["IT"].update(id="admin"))
    with pytest.raises(PolicyError):
        PolicyStore(policy_file)


@pytest.mark.parametrize("content", ["", "- a\n- b\n", "controls: [unclosed", "version: 2\n"])
def test_unusable_file_fails_at_startup(tmp_path, content):
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyError):
        PolicyStore(path)


def test_missing_file_fails_at_startup(tmp_path):
    with pytest.raises(PolicyError, match="Nie znaleziono"):
        PolicyStore(tmp_path / "brak.yaml")


def test_removed_control_section_stays_enabled(policy_file):
    """Usunięcie sekcji nie wyłącza kontroli; wyłącza ją tylko jawne `enabled: false`."""
    edit(policy_file, lambda d: (d["controls"].pop("code_guard"), d["controls"].pop("prompt_guard")))
    policy = PolicyStore(policy_file).get()
    assert policy.filter_on("code_guard") and policy.controls.prompt_guard.mode == "block"
    edit(policy_file, lambda d: d["controls"].update(code_guard={"enabled": False}))
    assert not PolicyStore(policy_file).get().filter_on("code_guard")


def test_unknown_filter_counts_as_enabled(store):
    assert store.get().filter_on("nieistniejacy_filtr")


# --- przeładowanie na żywo -------------------------------------------------------------------------

def test_change_in_file_applies_without_restart(store, policy_file):
    first = store.get()
    edit(policy_file, lambda d: d["controls"]["prompt_guard"].update(mode="warn"))
    second = store.get()
    assert second.controls.prompt_guard.mode == "warn"
    assert first.controls.prompt_guard.mode == "block"      # stary obiekt jest niezmienny
    assert store.status()["version"] == 2
    assert store.status()["last_changes"] == [{"path": "controls.prompt_guard.mode", "old": "block", "new": "warn"}]


def test_disabling_control_and_removing_tool_from_role_applies(store, policy_file):
    def mutate(d):
        d["controls"]["output_filter"] = {"enabled": False}
        d["roles"]["kadry"]["allowed_tools"].remove("read_employee_records")

    edit(policy_file, mutate)
    policy = store.get()
    assert not policy.filter_on("output_filter")
    assert not policy.is_tool_allowed("kadry", "read_employee_records")
    assert policy.is_tool_allowed("kadry", "summarize_employee_records")


def test_unchanged_content_does_not_bump_version(store, policy_file):
    before = policy_file.stat().st_mtime_ns
    os.utime(policy_file, ns=(before + 5_000_000_000, before + 5_000_000_000))
    store.get()
    assert store.status()["version"] == 1


def test_broken_reload_keeps_last_good_policy_and_reports_error(store, policy_file):
    edit(policy_file, lambda d: d["controls"]["prompt_guard"].update(mode="warn"))
    assert store.get().controls.prompt_guard.mode == "warn"
    before = policy_file.stat().st_mtime_ns
    policy_file.write_text("controls: [unclosed", encoding="utf-8")
    os.utime(policy_file, ns=(before + 2_000_000_000, before + 2_000_000_000))
    assert store.get().controls.prompt_guard.mode == "warn"     # nadal ostatnia poprawna
    error = store.status()["error"]
    assert error and "YAML" in error["message"]
    shutil.copy(SAMPLE, policy_file)        # naprawa pliku: edit() nie odczyta zepsutego YAML-a
    os.utime(policy_file, ns=(before + 4_000_000_000, before + 4_000_000_000))
    assert store.get().controls.prompt_guard.mode == "block"
    assert store.status()["error"] is None


def test_invalid_values_on_reload_keep_last_good_policy(store, policy_file):
    edit(policy_file, lambda d: d["controls"]["pii"].update(threshold=7))
    assert store.get().controls.pii.threshold == 0.35
    assert store.status()["error"]["problems"][0].startswith("controls.pii.threshold")


def test_reload_callback_receives_policy_and_changes(policy_file):
    seen = []
    store = PolicyStore(policy_file, on_reload=lambda policy, changes: seen.append((policy, changes)))
    assert seen == []                                           # start nie jest przeładowaniem
    edit(policy_file, lambda d: d.update(profile="strict"))
    store.get()
    assert len(seen) == 1 and seen[0][0].profile == "strict"
    assert any(c["path"] == "controls.prompt_length.max_chars" for c in seen[0][1])


def test_concurrent_readers_never_see_a_broken_policy(store, policy_file):
    errors = []

    def reader():
        try:
            for _ in range(200):
                assert store.get().controls.prompt_guard.mode in ("block", "warn")
        except Exception as exc:       # noqa: BLE001 - zbieramy wszystko do asercji niżej
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for mode in ("warn", "block", "warn"):
        edit(policy_file, lambda d, mode=mode: d["controls"]["prompt_guard"].update(mode=mode))
    for t in threads:
        t.join()
    assert errors == []


# --- nadpisania z interfejsu (decyzja A) -----------------------------------------------------------

def test_override_wins_over_file_and_reset_restores_file_value(store):
    store.set_override("controls.prompt_guard.mode", "warn")
    assert store.get().controls.prompt_guard.mode == "warn"
    assert store.status()["overridden"] == ["controls.prompt_guard.mode"]
    store.clear_overrides()
    assert store.get().controls.prompt_guard.mode == "block"
    assert store.status()["overridden"] == []
    assert not store.overrides_path.exists()


def test_override_survives_edit_of_the_policy_file(store, policy_file):
    store.set_override("controls.code_guard.enabled", False)
    edit(policy_file, lambda d: d["controls"]["pii"].update(threshold=0.4))
    policy = store.get()
    assert policy.controls.pii.threshold == 0.4
    assert not policy.filter_on("code_guard")


def test_override_wins_over_active_profile(policy_file):
    edit(policy_file, lambda d: d.update(profile="permissive"))
    store = PolicyStore(policy_file)
    assert store.get().controls.prompt_guard.mode == "warn"
    store.set_override("controls.prompt_guard.mode", "block")
    assert store.get().controls.prompt_guard.mode == "block"
    assert store.get().controls.prompt_length.max_chars == 8000       # reszta profilu bez zmian


def test_profile_can_be_switched_by_override(store):
    store.set_override("profile", "strict")
    assert store.get().profile == "strict" and store.get().controls.prompt_length.max_chars == 2000
    store.clear_overrides("profile")
    assert store.get().profile == "balanced"


def test_invalid_override_is_rejected_and_not_saved(store):
    with pytest.raises(PolicyError):
        store.set_override("controls.prompt_guard.mode", "maybe")
    with pytest.raises(PolicyError):
        store.set_override("controls.prompt_guard.nieznany", True)
    assert not store.overrides_path.exists()
    assert store.get().controls.prompt_guard.mode == "block"


def test_clear_single_override_keeps_the_others(store):
    store.set_override("controls.prompt_guard.mode", "warn")
    store.set_override("controls.pii.threshold", 0.2)
    store.clear_overrides("controls.prompt_guard.mode")
    assert store.status()["overridden"] == ["controls.pii.threshold"]
    assert store.get().controls.prompt_guard.mode == "block"


def test_corrupt_overrides_file_keeps_last_good_policy(store):
    store.set_override("controls.prompt_guard.mode", "warn")
    before = store.overrides_path.stat().st_mtime_ns
    store.overrides_path.write_text("{nie json", encoding="utf-8")
    os.utime(store.overrides_path, ns=(before + 2_000_000_000, before + 2_000_000_000))
    assert store.get().controls.prompt_guard.mode == "warn"
    assert store.status()["error"]


# --- funkcje pomocnicze ----------------------------------------------------------------------------

def test_deep_merge_replaces_lists_and_merges_maps():
    assert deep_merge({"a": {"x": 1, "y": 2}, "l": [1, 2]}, {"a": {"y": 3}, "l": [9]}) == {"a": {"x": 1, "y": 3}, "l": [9]}


def test_diff_reports_leaf_changes_only():
    old = {"a": {"x": 1, "y": 2}, "l": [1]}
    new = {"a": {"x": 1, "y": 3}, "l": [1, 2], "n": True}
    assert diff(old, new) == [{"path": "a.y", "old": 2, "new": 3}, {"path": "l", "old": [1], "new": [1, 2]},
                              {"path": "n", "old": None, "new": True}]


def test_build_policy_without_profiles_uses_base_values():
    policy = build_policy({"controls": {"prompt_guard": {"mode": "warn"}}})
    assert isinstance(policy, Policy) and policy.controls.prompt_guard.mode == "warn"


# --- dozwolone modele ------------------------------------------------------------------------------

def test_model_allow_list_matches_names_and_wildcards(store):
    policy = store.get()
    assert policy.is_model_allowed("google/gemma-4-26b-a4b-it")
    assert not policy.is_model_allowed("openai/gpt-5")
    store.set_override("models.allowed", ["google/gemma-*", "mistralai/mistral-small"])
    policy = store.get()
    assert policy.is_model_allowed("google/gemma-4-26b-a4b-it:free") and policy.is_model_allowed("mistralai/mistral-small")
    assert not policy.is_model_allowed("google/palm") and not policy.is_model_allowed("mistralai/mistral-large")


def test_model_control_can_be_switched_off_and_empty_list_means_no_limit(store):
    store.set_override("models.enabled", False)
    assert store.get().is_model_allowed("cokolwiek/model")
    store.clear_overrides()
    store.set_override("models.allowed", [])
    assert store.get().is_model_allowed("cokolwiek/model")


def test_sample_allowed_models_match_the_models_offered_in_the_ui(store):
    assert store.get().models.allowed == [m["id"] for m in config.MODEL_PRESETS]
