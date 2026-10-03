from types import SimpleNamespace

import pytest

from chatbot import agent, llm_client
from tools import _files


def _tool_call(name, **args):
    return SimpleNamespace(function=SimpleNamespace(name=name, arguments=args))


def _reply(content="", tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls)


@pytest.fixture
def fake_llm(monkeypatch):
    """Podmienia model na kolejkę gotowych odpowiedzi."""
    def install(replies):
        queue = list(replies)
        monkeypatch.setattr(llm_client, "chat", lambda messages, tools=None: queue.pop(0))
    return install


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_files, "BASE_DIR", tmp_path)
    (tmp_path / "faq.txt").write_text("pierwsza\ndruga\n", encoding="utf-8")
    return tmp_path


def test_answer_without_tools(fake_llm):
    fake_llm([_reply("Cześć")])
    answer, history = agent.run_agent("hej")
    assert answer == "Cześć"
    assert [m["role"] for m in history] == ["system", "user", "assistant"]


def test_tool_result_reaches_model(fake_llm, data_dir):
    fake_llm([_reply(tool_calls=[_tool_call("read_file", filename="faq.txt")]), _reply("gotowe")])
    answer, history = agent.run_agent("co jest w faq?")
    assert answer == "gotowe"
    assert history[3] == {"role": "tool", "content": "pierwsza\ndruga\n"}


def test_gate_refusal_replaces_tool_result(fake_llm, data_dir):
    fake_llm([_reply(tool_calls=[_tool_call("read_file", filename="faq.txt")]), _reply("bez narzędzia")])
    answer, history = agent.run_agent("x", tool_gate=lambda name, args: "Tool not available.")
    assert answer == "bez narzędzia"
    assert history[3] == {"role": "tool", "content": "Tool not available."}


def test_gate_can_block_response(fake_llm, data_dir):
    def gate(name, args):
        raise agent.ResponseBlocked("poza rolą")

    previous = agent.new_history()
    fake_llm([_reply(tool_calls=[_tool_call("read_file", filename="faq.txt")])])
    with pytest.raises(agent.ResponseBlocked):
        agent.run_agent("x", history=previous, tool_gate=gate)
    assert len(previous) == 1


def test_path_outside_data_is_rejected(data_dir):
    sibling = data_dir.parent / (data_dir.name + "_backup")
    sibling.mkdir()
    (sibling / "secret.txt").write_text("tajne", encoding="utf-8")
    with pytest.raises(ValueError):
        _files.read_file(f"../{sibling.name}/secret.txt")
