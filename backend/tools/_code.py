import contextlib
import io
import json
import os
import socket

from security.code_guard import SAFE_BUILTINS, check_code

MAX_CODE_BYTES = 8192
MAX_RESPONSE_BYTES = 16384
EXECUTOR_TIMEOUT = 8        # sekundy na całą rozmowę z executorem (jego własny limit obliczeń to 3 s)


def run_python(code: str) -> str:
    """Execute Python code for calculations. Only pure computation is allowed:
    no file, network or system access, and only modules such as math, statistics,
    json, datetime, re, collections, itertools, random, decimal.

    Args:
        code: Python source code to execute.

    Returns:
        Captured stdout, or an error message.
    """
    verdict = check_code(code)
    if verdict.is_blocked:
        return f"Code rejected by security policy: {verdict.reason}"

    # Gdy skonfigurowano osobny executor (w Dockerze: kontener bez sieci i danych, z limitami czasu i pamięci),
    # kod nie jest wykonywany w tym procesie. Bez niego (uruchomienie lokalne) działa jak dotąd.
    path = os.environ.get("PYTHON_EXECUTOR_SOCKET")
    if path:
        return _run_in_executor(code, path)

    stdout = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout):
            exec(code, {"__builtins__": SAFE_BUILTINS})
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"

    return stdout.getvalue()


def _run_in_executor(code: str, path: str) -> str:
    """Wysyła kod do executora przez gniazdo Unix. Błąd łączności to komunikat dla modelu, nie wyjątek."""
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return "Code rejected by security policy: code is too large"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(EXECUTOR_TIMEOUT)
            connection.connect(path)
            connection.sendall(json.dumps({"code": code}).encode("utf-8"))
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)
                if len(response) > MAX_RESPONSE_BYTES:
                    return "Python executor error: the response is too large"
        message = json.loads(response)
    except (OSError, ValueError) as exc:
        return f"Python executor error: {type(exc).__name__}"
    if not isinstance(message, dict) or not isinstance(message.get("result"), str):
        return "Python executor error: invalid response"
    return message["result"]
