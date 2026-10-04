import json
import threading

import pytest

from audit import logger


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    path = tmp_path / "audit" / "events.jsonl"
    monkeypatch.setattr(logger, "AUDIT_LOG", path)
    monkeypatch.setattr(logger, "_warned", False)
    return path


def turn(**fields):
    events = logger.start_turn()
    logger.record("prompt_guard", "security", decision="pass", **fields)
    return events


def test_file_sink_writes_one_json_line_per_event(log_file, monkeypatch):
    monkeypatch.setattr(logger, "AUDIT_SINK", "file")
    logger.flush(turn(), conversation="c1", role="kadry", turn=1)
    rows = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["conversation"] == "c1" and rows[0]["type"] == "prompt_guard"


def test_stdout_sink_writes_json_lines_and_no_file(log_file, monkeypatch, capsys):
    monkeypatch.setattr(logger, "AUDIT_SINK", "stdout")
    logger.flush(turn(), conversation="c2", role="IT", turn=1)
    assert json.loads(capsys.readouterr().out)["conversation"] == "c2"
    assert not log_file.exists()


def test_both_sink_writes_everywhere(log_file, monkeypatch, capsys):
    monkeypatch.setattr(logger, "AUDIT_SINK", "both")
    logger.flush(turn(), conversation="c3", role="IT", turn=1)
    assert "c3" in capsys.readouterr().out and "c3" in log_file.read_text(encoding="utf-8")


def test_none_sink_writes_nothing(log_file, monkeypatch, capsys):
    monkeypatch.setattr(logger, "AUDIT_SINK", "none")
    logger.flush(turn(), conversation="c4", role="IT", turn=1)
    assert capsys.readouterr().out == "" and not log_file.exists()


def test_unwritable_log_does_not_break_the_turn_and_warns_once(tmp_path, monkeypatch, caplog):
    blocker = tmp_path / "plik"
    blocker.write_text("to jest plik, nie katalog", encoding="utf-8")
    monkeypatch.setattr(logger, "AUDIT_LOG", blocker / "audit" / "events.jsonl")   # mkdir musi się nie udać
    monkeypatch.setattr(logger, "AUDIT_SINK", "file")
    monkeypatch.setattr(logger, "_warned", False)
    with caplog.at_level("WARNING", logger="control_layer.audit"):
        logger.flush(turn(), conversation="c5", role="IT", turn=1)      # nie rzuca
        logger.flush(turn(), conversation="c6", role="IT", turn=2)
    warnings = [r for r in caplog.records if "STATE_DIR" in r.getMessage()]
    assert len(warnings) == 1


def test_parallel_turns_never_interleave_their_lines(log_file, monkeypatch):
    monkeypatch.setattr(logger, "AUDIT_SINK", "file")

    def worker(n):
        for i in range(25):
            events = logger.start_turn()
            for step in range(4):
                logger.record("step", "security", n=n, i=i, step=step, padding="x" * 200)
            logger.flush(events, conversation=f"c{n}", role="IT", turn=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = log_file.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines]       # każda linia jest poprawnym JSON-em
    assert len(rows) == 6 * 25 * 4
    # bloki jednej tury leżą obok siebie, a nie przemieszane z blokami innych
    for start in range(0, len(rows), 4):
        block = rows[start:start + 4]
        assert len({(r["n"], r["i"]) for r in block}) == 1
