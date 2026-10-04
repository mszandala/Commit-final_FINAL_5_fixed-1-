"""Executor kodu Pythona: osobny proces (w Dockerze osobny kontener bez sieci i bez danych), który wykonuje
obliczenia z narzędzia run_python i komunikuje się z backendem przez prywatny gniazdo Unix.

Pomysł i ochrona gniazda pochodzą z brancha `docker`. Tylko Linux (limity zasobów przez `resource`, fork).
Każdy kod jest sprawdzany jeszcze raz (security.code_guard), niezależnie od kontroli po stronie backendu, a jego
wykonanie ma limity: czas na ścianie, czas procesora, pamięć i rozmiar wyjścia. Executor obsługuje jedno żądanie
naraz; nieskończona pętla kończy się po `WALL_SECONDS` zabiciem procesu potomnego, a nie zawieszeniem serwera.

Uruchomienie: python -m executor --socket /run/executor/executor.sock
"""
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
CPU_SECONDS = 2
MEMORY_BYTES = 256 * 1024 * 1024


class LimitedOutput(io.StringIO):
    def write(self, text):
        if len((self.getvalue() + text).encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("Output limit exceeded")
        return super().write(text)


def execute(code, sender):
    """Wykonanie w procesie potomnym, z limitami zasobów i pustym środowiskiem."""
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
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
    """Sprawdza kod i wykonuje go w osobnym procesie; zwraca tekst wyniku albo komunikat o odrzuceniu."""
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


def prepare_socket(path: Path) -> None:
    """Prywatny katalog gniazda, właściciel i uprawnienia sprawdzone; stare gniazdo po SIGTERM usunięte."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = path.parent.stat()
    if folder.st_uid != os.getuid() or stat.S_IMODE(folder.st_mode) & 0o077:
        raise SystemExit("Socket directory must be private and owned by the executor user")
    try:
        previous = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(previous.st_mode):
        raise SystemExit("Socket path is not a Unix socket")
    with socket.socket(socket.AF_UNIX) as probe:
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            path.unlink()       # nieaktualne gniazdo po zatrzymaniu kontenera; katalog prywatny, typ sprawdzony
        else:
            raise SystemExit("Executor already running on this socket")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    path = parser.parse_args().socket
    os.umask(0o077)
    prepare_socket(path)
    # Jedno żądanie naraz; równoległe obliczenia wymagałyby izolowanych procesów roboczych.
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        try:
            server.serve_forever()
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
