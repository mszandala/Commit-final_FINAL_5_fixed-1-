"""Executor kodu Pythona i jego klient w tools/_code.py.

Executor działa tylko na Linuksie (limity zasobów, fork), więc jego testy są pomijane na Windows; pełny zestaw
uruchamia `docker compose run --rm tests`. Klient bez skonfigurowanego executora działa wszędzie.
"""
import os
import sys
import threading

import pytest

from tools import _code

linux_only = pytest.mark.skipif(sys.platform == "win32", reason="executor wymaga Linuksa (resource, fork)")


# --- klient bez executora: zachowanie jak dotąd --------------------------------------------------------------------

def test_without_an_executor_code_runs_in_process(monkeypatch):
    monkeypatch.delenv("PYTHON_EXECUTOR_SOCKET", raising=False)
    assert _code.run_python("print(6 * 7)") == "42\n"
    assert _code.run_python("import os").startswith("Code rejected by security policy")


def test_client_reports_an_unreachable_executor_as_a_message_not_an_exception(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTHON_EXECUTOR_SOCKET", str(tmp_path / "brak.sock"))
    if sys.platform == "win32":
        pytest.skip("gniazda Unix wymagają Linuksa")
    assert _code.run_python("print(1)").startswith("Python executor error:")


def test_client_still_checks_the_code_before_sending_it(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTHON_EXECUTOR_SOCKET", str(tmp_path / "brak.sock"))
    assert _code.run_python("import pickle").startswith("Code rejected by security policy")        # nie dochodzi do gniazda
    assert _code.run_python("x = 1\n" * 5000) == "Code rejected by security policy: code is too large"


# --- sam executor ----------------------------------------------------------------------------------------------------

@pytest.fixture
def executor():
    if sys.platform == "win32":
        pytest.skip("executor wymaga Linuksa")
    import executor as module
    return module


@linux_only
def test_executor_returns_the_output(executor):
    assert executor.run("print(sum(range(10)))") == "45\n"
    assert executor.run("print(1/0)") == "ZeroDivisionError: division by zero"


@linux_only
def test_executor_rechecks_the_code_itself(executor):
    assert executor.run("import subprocess").startswith("Code rejected by security policy")
    assert executor.run("import operator\nprint(operator.attrgetter('__class__')(1))").startswith("Code rejected")


@linux_only
def test_endless_loop_is_killed_instead_of_hanging(executor, monkeypatch):
    monkeypatch.setattr(executor, "WALL_SECONDS", 1)
    assert executor.run("while True:\n    pass") == "Python executor timed out"
    assert executor.run("print('dalej działa')") == "dalej działa\n"        # serwer nie został zawieszony


@linux_only
def test_memory_hog_is_stopped(executor):
    result = executor.run("data = [0] * (10 ** 9)\nprint(len(data))")
    assert "MemoryError" in result or "resource limits" in result


@linux_only
def test_output_is_limited(executor):
    result = executor.run("print('x' * 20000)")
    assert len(result.encode()) <= executor.MAX_OUTPUT_BYTES + 100 and "Output limit exceeded" in result


# --- klient i serwer razem, przez prawdziwe gniazdo ----------------------------------------------------------------

@pytest.fixture
def server(executor, tmp_path, monkeypatch):
    import socketserver
    path = tmp_path / "run" / "executor.sock"
    path.parent.mkdir(mode=0o700)
    os.umask(0o077)
    srv = socketserver.UnixStreamServer(str(path), executor.Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("PYTHON_EXECUTOR_SOCKET", str(path))
    yield path
    srv.shutdown()
    srv.server_close()


@linux_only
def test_run_python_goes_through_the_socket_when_an_executor_is_configured(server):
    assert _code.run_python("print(2 ** 10)") == "1024\n"
    assert _code.run_python("print(1/0)") == "ZeroDivisionError: division by zero"


@linux_only
def test_code_does_not_run_in_the_calling_process_when_an_executor_is_configured(server, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("kod został wykonany w procesie backendu")

    monkeypatch.setattr(_code, "exec", forbidden, raising=False)      # przesłania wbudowane exec w tym module
    assert _code.run_python("print(3 + 4)") == "7\n"


@linux_only
def test_malformed_requests_get_an_error_not_a_crash(server, executor):
    import json
    import socket
    for payload in (b"to nie jest json", json.dumps({"code": 123}).encode(), json.dumps(["lista"]).encode()):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(server))
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            answer = json.loads(connection.recv(4096))
        assert answer["result"].startswith("Python executor error:")
    assert _code.run_python("print('żyje')") == "żyje\n"


@linux_only
def test_executor_refuses_a_group_readable_socket_directory(executor, tmp_path):
    folder = tmp_path / "otwarty"
    folder.mkdir()
    folder.chmod(0o755)
    with pytest.raises(SystemExit, match="private"):
        executor.prepare_socket(folder / "executor.sock")
