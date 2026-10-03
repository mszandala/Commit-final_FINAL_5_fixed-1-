"""Local Unix-socket Python executor; run separately from the proxy process."""

import argparse
import contextlib
import io
import json
import multiprocessing
import os
import resource
import signal
import socket
import socketserver
import stat
from pathlib import Path

from security.code_guard import SAFE_BUILTINS, check_code

MAX_REQUEST_BYTES = 32768
MAX_CODE_BYTES = 8192
MAX_OUTPUT_BYTES = 8192
WALL_SECONDS = 3
MEMORY_BYTES = 256 * 1024 * 1024


class LimitedOutput(io.StringIO):
    def write(self, text):
        if len((self.getvalue() + text).encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("Output limit exceeded")
        return super().write(text)


def execute(code, sender):
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        os.environ.clear()
        output = LimitedOutput()
        try:
            with contextlib.redirect_stdout(output):
                exec(code, {"__builtins__": SAFE_BUILTINS})
            result = output.getvalue()
        except Exception as exc:
            result = f"{type(exc).__name__}: {exc}"
        sender.send(result[:MAX_OUTPUT_BYTES])
    finally:
        sender.close()


def run(code):
    verdict = check_code(code)
    if verdict.is_blocked:
        return f"Code rejected by security policy: {verdict.reason}"
    receiver, sender = multiprocessing.Pipe(duplex=False)
    child = multiprocessing.get_context("fork").Process(target=execute, args=(code, sender))
    child.start()
    sender.close()
    try:
        if not receiver.poll(WALL_SECONDS):
            return "Python executor timed out"
        return receiver.recv()
    except EOFError:
        child.join()
        if child.exitcode in (-signal.SIGXCPU, -signal.SIGKILL):
            return "Python executor exceeded resource limits"
        return "Python executor failed"
    finally:
        if child.is_alive():
            child.kill()
        child.join()
        receiver.close()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            request = bytearray()
            while chunk := self.request.recv(4096):
                request.extend(chunk)
                if len(request) > MAX_REQUEST_BYTES:
                    raise ValueError("Request too large")
            message = json.loads(request)
            code = message.get("code") if isinstance(message, dict) else None
            if not isinstance(code, str) or len(code.encode("utf-8")) > MAX_CODE_BYTES:
                raise ValueError("Invalid code")
            result = run(code)
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            result = f"Python executor error: {exc}"
        try:
            self.request.sendall(json.dumps({"result": result}).encode("utf-8"))
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    path = parser.parse_args().socket
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = path.parent.stat()
    if folder.st_uid != os.getuid() or stat.S_IMODE(folder.st_mode) & 0o077:
        parser.error("Socket directory must be private and owned by the executor user")
    os.umask(0o077)
    try:
        previous = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(previous.st_mode):
            parser.error("Socket path is not a Unix socket")
        with socket.socket(socket.AF_UNIX) as probe:
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()  # Stale socket after container SIGTERM; private directory and socket type verified.
            else:
                parser.error("Executor already running on this socket")
    # ponytail: one request at a time; add isolated workers if concurrent calculations become necessary.
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        try:
            server.serve_forever()
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
