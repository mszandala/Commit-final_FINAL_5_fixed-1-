import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from security.code_guard import check_code
from tools._code import run_python


class ExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.socket_path = Path(cls.directory.name) / "executor.sock"
        cls.process = subprocess.Popen([
            sys.executable, str(Path(__file__).resolve().parents[1] / "executor.py"),
            "--socket", str(cls.socket_path),
        ])
        deadline = time.monotonic() + 5
        while not cls.socket_path.exists() and cls.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not cls.socket_path.exists() or cls.process.poll() is not None:
            cls.process.terminate()
            cls.process.wait(timeout=5)
            cls.directory.cleanup()
            raise RuntimeError("Python executor did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.directory.cleanup()

    def call(self, code):
        with patch.dict(os.environ, {"PYTHON_EXECUTOR_SOCKET": str(self.socket_path)}):
            return run_python(code)

    def test_calculation_and_recovery_after_runtime_error(self):
        self.assertEqual(self.call("import statistics\nprint(statistics.mean([1, 2, 3]))"), "2\n")
        self.assertEqual(self.call("print(1 / 0)"), "ZeroDivisionError: division by zero")
        self.assertEqual(self.call("print(7)"), "7\n")

    def test_rejection_precedes_connection_and_server_rechecks(self):
        with patch.dict(os.environ, {"PYTHON_EXECUTOR_SOCKET": str(self.socket_path) + ".missing"}):
            self.assertTrue(run_python("import os").startswith("Code rejected by security policy:"))
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps({"code": "import os"}).encode())
            connection.shutdown(socket.SHUT_WR)
            reply = json.loads(connection.recv(2048))
        self.assertTrue(reply["result"].startswith("Code rejected by security policy:"))
        self.assertTrue(check_code("def (").is_blocked)

    def test_missing_executor_never_runs_code_locally(self):
        with patch.dict(os.environ, {"PYTHON_EXECUTOR_SOCKET": str(self.socket_path) + ".missing"}):
            with self.assertRaises(OSError):
                run_python("print(123)")

    def test_runaway_and_large_output_are_limited(self):
        self.assertEqual(self.call("while True: pass"), "Python executor exceeded resource limits")
        self.assertEqual(self.call("print('x' * 9000)"), "ValueError: Output limit exceeded")
        self.assertEqual(self.call("print(3)"), "3\n")


    def test_restart_replaces_only_a_stale_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "executor.sock"
            with socket.socket(socket.AF_UNIX) as stale:
                stale.bind(str(path))
            process = subprocess.Popen([
                sys.executable, str(Path(__file__).resolve().parents[1] / "executor.py"), "--socket", str(path),
            ])
            try:
                deadline = time.monotonic() + 5
                while process.poll() is None and time.monotonic() < deadline:
                    with patch.dict(os.environ, {"PYTHON_EXECUTOR_SOCKET": str(path)}):
                        try:
                            if run_python("print(11)") == "11\n":
                                break
                        except (ConnectionRefusedError, FileNotFoundError):
                            pass
                    time.sleep(0.01)
                else:
                    self.fail("Executor failed to replace a stale socket")
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
