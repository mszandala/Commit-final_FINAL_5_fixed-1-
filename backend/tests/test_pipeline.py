import json
from types import SimpleNamespace

import pytest

import pipeline
from audit import logger as audit_logger
from chatbot import llm_client
from config import ROLES
from security.pii.regex_detector import detect_regex_pii
from tools import domain_helpers

EMAIL = "jan.kowalski@firma.pl"
CLIENT = "15647311"
SALARY = "112542.58"


def _tool_call(tool, **args):
    return SimpleNamespace(function=SimpleNamespace(name=tool, arguments=args))


def _reply(content="", tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls)


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    """Dane w katalogu tymczasowym, detektor bez modelu GLiNER, log audytu w pliku tymczasowym."""
    monkeypatch.setattr(domain_helpers, "BASE_DIR", tmp_path)
    monkeypatch.setattr(audit_logger, "AUDIT_LOG", tmp_path / "events.jsonl")
    monkeypatch.setattr(pipeline, "detect_pii", lambda text, threshold=None: detect_regex_pii(text))
    monkeypatch.setattr(pipeline, "PII_JUDGE_ENABLED", True)
    pipeline._detect_cached.cache_clear()
    (tmp_path / "clients_data").mkdir()
    (tmp_path / "clients_data" / "Bank Customer Churn Prediction.csv").write_text(
        f"customer_id,country,estimated_salary\n{CLIENT},Spain,{SALARY}\n15634602,France,101348.88\n",
        encoding="utf-8")
    (tmp_path / "projects").mkdir()
    (tmp_path / "projects" / "alpha_README.md").write_text(f"Kontakt: {EMAIL}", encoding="utf-8")
    return tmp_path


@pytest.fixture
def llm(monkeypatch):
    """Kolejka odpowiedzi chatbota; zapisuje wszystko, co do niego wysłano. Odpowiedź może być
    funkcją (messages) -> reply, żeby test mógł użyć znaczników z otrzymanego promptu."""
    state = SimpleNamespace(chatbot=[], security=[], queue=[], judge="{}")

    def chat(messages, tools=None, provider=None, model=None, zone="chatbot", purpose="chat"):
        if zone == "security":
            state.security.append(messages)
            if isinstance(state.judge, Exception):
                raise state.judge
            return _reply(state.judge)
        state.chatbot.append([m if isinstance(m, dict) else {"role": "assistant"} for m in messages])
        reply = state.queue.pop(0)
        return reply(messages) if callable(reply) else reply

    monkeypatch.setattr(llm_client, "chat", chat)
    return state


def _sent_to_chatbot(llm) -> str:
    return json.dumps(llm.chatbot, ensure_ascii=False)


def _audit(tmp_path) -> str:
    return (tmp_path / "events.jsonl").read_text(encoding="utf-8")


def test_prompt_is_masked_and_restored_by_role(llm, env):
    for role, expected in [("bankier", f"Wysłano na {EMAIL}."), ("prawnik", f"Wysłano na {EMAIL}.")]:
        llm.queue = [_reply("Wysłano na <EMAIL_1>.")]
        result = pipeline.run_turn(pipeline.Conversation(role), f"Wyślij raport na {EMAIL}")
        assert result.masked_prompt == "Wyślij raport na <EMAIL_1>"
        assert result.reply == expected          # użytkownik sam podał adres, więc go odzyskuje
        assert result.leaks_to_chatbot == 0
    assert EMAIL not in _sent_to_chatbot(llm)
    assert EMAIL not in _audit(env)


def test_tool_gets_real_value_and_result_is_masked(llm, env):
    def call_tool(messages):
        token = messages[-1]["content"].split()[-1]
        assert token.startswith("ID-")
        return _reply(tool_calls=[_tool_call("read_client_records", column="customer_id", value=token)])

    llm.queue = [call_tool, lambda messages: _reply("Klient " + messages[-1]["content"].split("\n")[1])]
    result = pipeline.run_turn(pipeline.Conversation("bankier"), f"Podaj dane customer_id {CLIENT}")

    assert result.reply == f"Klient {CLIENT},Spain,{SALARY}"     # bankier: ID wraca, pensję wolno mu widzieć
    assert result.tool_calls[0]["allowed"] and CLIENT not in str(result.tool_calls[0]["args"])
    assert CLIENT not in _sent_to_chatbot(llm)
    assert CLIENT not in _audit(env)


def test_analyst_sees_only_pseudonyms(llm, env):
    llm.queue = [
        _reply(tool_calls=[_tool_call("read_client_records", limit=2)]),
        lambda messages: _reply(messages[-1]["content"]),
    ]
    result = pipeline.run_turn(pipeline.Conversation("analityk"), "Pokaż klientów")
    rows = result.reply.split("\n")[1:3]
    assert all(r.startswith("ID-") for r in rows)
    assert CLIENT not in result.reply and CLIENT not in _sent_to_chatbot(llm)


def test_whitelist_still_blocks_and_tool_is_not_run(llm, env):
    llm.queue = [_reply(tool_calls=[_tool_call("read_client_records", limit=1)]), _reply("Brak dostępu.")]
    result = pipeline.run_turn(pipeline.Conversation("kadry"), "Pokaż klientów")
    call = result.tool_calls[0]
    assert (call["tool"], call["args"], call["allowed"], call["stage"]) == (
        "read_client_records", {"limit": 1}, False, "tool_whitelist")
    assert "Access denied" in llm.chatbot[-1][-1]["content"]
    assert SALARY not in _sent_to_chatbot(llm)


def test_text_tool_result_is_scanned(llm, env):
    llm.queue = [
        _reply(tool_calls=[_tool_call("read_project", name="alpha")]),
        lambda messages: _reply(messages[-1]["content"]),
    ]
    result = pipeline.run_turn(pipeline.Conversation("podstawowy użytkownik"), "Co jest w projekcie alpha?")
    assert result.reply == "Kontakt: [EMAIL]"
    assert EMAIL not in _sent_to_chatbot(llm)


def test_judge_decides_only_judge_types(llm, env, monkeypatch):
    def detector(text, threshold=None):
        found = detect_regex_pii(text)
        start = text.find("Tim Cook")
        if start >= 0:
            found.append({"type": "NAME", "text": "Tim Cook", "start": start, "end": start + 8})
        return found

    monkeypatch.setattr(pipeline, "detect_pii", detector)
    prompt = f"Co mówił Tim Cook? Odpowiedz na {EMAIL}"

    llm.judge = '{"1": "send", "2": "send"}'          # sędzia nie dostaje e-maila, więc go nie odblokuje
    llm.queue = [_reply("ok")]
    result = pipeline.run_turn(pipeline.Conversation("prawnik"), prompt)
    assert result.masked_prompt == "Co mówił Tim Cook? Odpowiedz na <EMAIL_1>"
    assert EMAIL not in json.dumps(llm.security[-1], ensure_ascii=False).split("Detected values:")[1]

    for judge in ('{"1": "mask"}', "nie wiem", RuntimeError("brak modelu")):
        llm.judge = judge
        llm.queue = [_reply("ok")]
        result = pipeline.run_turn(pipeline.Conversation("prawnik"), prompt)
        assert result.masked_prompt == "Co mówił <NAME_1>? Odpowiedz na <EMAIL_1>"

    monkeypatch.setattr(pipeline, "PII_JUDGE_ENABLED", False)
    calls = len(llm.security)
    llm.queue = [_reply("ok")]
    result = pipeline.run_turn(pipeline.Conversation("prawnik"), prompt)
    assert "<NAME_1>" in result.masked_prompt and len(llm.security) == calls


def test_output_redact_and_block(llm, env, monkeypatch):
    llm.queue = [_reply(f"Napisz do {EMAIL}")]
    result = pipeline.run_turn(pipeline.Conversation("podstawowy użytkownik"), "Kto prowadzi projekt?")
    assert result.reply == "Napisz do [EMAIL]" and not result.blocked
    assert EMAIL not in _audit(env)

    monkeypatch.setitem(ROLES["podstawowy użytkownik"], "pii_policy", {"EMAIL": "block"})
    llm.queue = [_reply(f"Napisz do {EMAIL}")]
    result = pipeline.run_turn(pipeline.Conversation("podstawowy użytkownik"), "Kto prowadzi projekt?")
    assert result.blocked and result.block_reason == "pii_policy" and EMAIL not in result.reply


def test_public_and_own_values_are_not_redacted():
    text = f"Kontakt {EMAIL}"
    assert pipeline.filter_output("prawnik", text)[0] == "Kontakt [EMAIL]"
    assert pipeline.filter_output("prawnik", text, public_texts=[f"README: {EMAIL}"])[0] == text
    assert pipeline.filter_output("prawnik", text, own_texts=[f"mój mail {EMAIL}"])[0] == text


def test_history_carries_masked_values_across_turns(llm, env):
    conv = pipeline.Conversation("prawnik")
    llm.queue = [_reply("Zapisane."), _reply("To <EMAIL_1>.")]
    pipeline.run_turn(conv, f"Zapamiętaj adres {EMAIL}")
    result = pipeline.run_turn(conv, f"Jaki adres podałem? ({EMAIL})")
    assert result.masked_prompt == "Jaki adres podałem? (<EMAIL_1>)"
    assert result.reply == f"To {EMAIL}."
    assert EMAIL not in _sent_to_chatbot(llm)


def test_audit_events_are_tagged_with_zone(llm, env):
    llm.queue = [_reply("ok")]
    result = pipeline.run_turn(pipeline.Conversation("prawnik"), "Dzień dobry")
    assert [(e["type"], e["zone"]) for e in result.events] == [
        ("prompt_guard", "security"), ("prompt_masking", "security"),
        ("output_filter", "security"), ("turn", "security"),
    ]
    lines = [json.loads(line) for line in _audit(env).splitlines()]
    assert len(lines) == 4 and all(l["role"] == "prawnik" and l["turn"] == 1 for l in lines)


def test_output_filter_ignores_implausible_detections(monkeypatch):
    def detector(text, threshold=None):
        return [
            {"type": "NAME", "text": "Kobieta", "start": 0, "end": 7},
            {"type": "SALARY", "text": "saldo", "start": 9, "end": 14},
            {"type": "NAME", "text": "Jan Kowalski", "start": 16, "end": 28},
            {"type": "SALARY", "text": "5 000 zł", "start": 30, "end": 38},
        ]

    monkeypatch.setattr(pipeline, "detect_pii", detector)
    shown, logged, stats = pipeline.filter_output("IT", "Kobieta, saldo, Jan Kowalski, 5 000 zł")
    assert shown == "Kobieta, saldo, [NAME], [SALARY]"
    assert stats["redacted"] == ["NAME", "SALARY"] and "Jan Kowalski" not in logged


def test_malformed_detections_never_mask_the_prompt(llm, env, monkeypatch):
    monkeypatch.setattr(pipeline, "detect_pii", lambda text, threshold=None: [
        {"type": "CREDIT-CARD-NO", "text": "rachunku", "start": 15, "end": 23}])
    llm.queue = [_reply("ok")]
    result = pipeline.run_turn(pipeline.Conversation("bankier"), "A jaki ma numer rachunku?")
    assert result.masked_prompt == "A jaki ma numer rachunku?"


def test_account_number_is_pseudonymized(llm, env):
    path = env / "clients_data" / "Bank Customer Churn Prediction.csv"
    path.write_text(f"customer_id,account_number,country\n{CLIENT},9999{CLIENT},Spain\n", encoding="utf-8")
    llm.queue = [
        _reply(tool_calls=[_tool_call("read_client_records", limit=1)]),
        lambda messages: _reply(messages[-1]["content"]),
    ]
    result = pipeline.run_turn(pipeline.Conversation("analityk"), "Pokaż klienta")
    assert CLIENT not in result.reply and CLIENT not in _sent_to_chatbot(llm)

    llm.queue = [
        _reply(tool_calls=[_tool_call("read_client_records", limit=1)]),
        lambda messages: _reply(messages[-1]["content"]),
    ]
    result = pipeline.run_turn(pipeline.Conversation("bankier"), "Pokaż klienta")
    assert result.reply.split("\n")[1] == f"{CLIENT},9999{CLIENT},Spain"
    assert CLIENT not in _sent_to_chatbot(llm)
