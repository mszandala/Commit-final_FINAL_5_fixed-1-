import pytest

from security.code_guard import check_code
from tools.registry import run_tool

ALLOWED_CODE = [
    "print(sum([1, 2, 3]))",
    "import statistics\nprint(statistics.mean([1, 2, 3]))",
    "from collections import Counter\nprint(Counter('aab')['a'])",
    "import json\nprint(json.dumps({'a': 1}))",
]

BLOCKED_CODE = [
    ("import os\nprint(os.listdir('.'))", "systemu operacyjnego"),
    ("import subprocess\nsubprocess.run(['whoami'])", "uruchamianie procesów"),
    ("import pickle\npickle.loads(b'x')", "deserializacja"),
    ("from yaml import load", "deserializacja"),
    ("import socket", "sieciowe"),
    ("import requests", "sieciowe"),
    ("import numpy", "spoza listy"),
    ("print(open('data/employee_data/x.csv').read())", "'open'"),
    ("eval('1+1')", "'eval'"),
    ("__import__('os')", "'__import__'"),
    ("getattr(print, 'x')", "'getattr'"),
    ("().__class__.__base__.__subclasses__()", "__subclasses__"),
    ("from . import x", "względny"),
]


@pytest.mark.parametrize("code", ALLOWED_CODE)
def test_computation_is_allowed(code):
    assert check_code(code).decision == "pass"
    assert not run_tool("run_python", {"code": code}).startswith("Code rejected")


@pytest.mark.parametrize("code, reason", BLOCKED_CODE)
def test_dangerous_code_is_rejected(code, reason):
    verdict = check_code(code)
    assert verdict.is_blocked
    assert reason in verdict.reason
    assert run_tool("run_python", {"code": code}).startswith("Code rejected by security policy")


def test_runtime_import_is_also_restricted():
    # Gdyby analiza statyczna coś przepuściła, exec ma ograniczone builtins.
    from tools._code import SAFE_BUILTINS
    assert "open" not in SAFE_BUILTINS and "eval" not in SAFE_BUILTINS
    with pytest.raises(ImportError):
        SAFE_BUILTINS["__import__"]("os")


def test_syntax_error_is_blocked():
    assert check_code("def (").is_blocked
