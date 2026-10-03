"""Client for the isolated Python executor. No user code runs in this process."""

import json
import os
import socket

from security.code_guard import check_code

MAX_CODE_BYTES = 8192
MAX_RESPONSE_BYTES = 16384


def run_python(code: str) -> str:
    """Run a bounded calculation through the separate Python executor."""
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return "Code rejected by security policy: code is too large"
    verdict = check_code(code)
    if verdict.is_blocked:
        return f"Code rejected by security policy: {verdict.reason}"

    path = os.environ.get("PYTHON_EXECUTOR_SOCKET")
    if not path:
        raise RuntimeError("Python executor is not configured (PYTHON_EXECUTOR_SOCKET)")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(path)
        connection.sendall(json.dumps({"code": code}).encode("utf-8"))
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while chunk := connection.recv(4096):
            response.extend(chunk)
            if len(response) > MAX_RESPONSE_BYTES:
                raise ValueError("Python executor response is too large")
    message = json.loads(response)
    if not isinstance(message, dict) or not isinstance(message.get("result"), str):
        raise ValueError("Invalid Python executor response")
    return message["result"]
