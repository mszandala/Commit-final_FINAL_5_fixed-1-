"""Utwardzenie code_guard: obejścia blokady atrybutów specjalnych i nazwane typy ataków."""
import pytest

from security.code_guard import check_code
from tools.registry import run_tool

# Czytają atrybuty po nazwie z napisu, więc w drzewie składni nie ma węzła Attribute z __dunder__.
SANDBOX_ESCAPES = {
    "attrgetter": "import operator\nprint(operator.attrgetter('__class__')(1))",
    "attrgetter z napisu składanego": "import operator\nn = '__cla' + 'ss__'\nprint(operator.attrgetter(n)(1))",
    "attrgetter przez from-import": "from operator import attrgetter\nprint(attrgetter('real')(1))",
    "methodcaller": "import operator\nprint(operator.methodcaller('__repr__')(1))",
    "format z atrybutem specjalnym": "print('{0.__class__}'.format(1))",
    "Formatter.get_field": "import string\nstring.Formatter().get_field('0.real', [1], {})",
    "nazwa specjalna": "print(__builtins__)",
}


@pytest.mark.parametrize("code", SANDBOX_ESCAPES.values(), ids=SANDBOX_ESCAPES.keys())
def test_sandbox_escape_is_blocked_and_named(code):
    verdict = check_code(code)
    assert verdict.is_blocked and verdict.details["attack_type"] == "Sandbox_Escape"
    assert run_tool("run_python", {"code": code}).startswith("Code rejected by security policy")


@pytest.mark.parametrize("module, attack_type", [
    ("pickle", "Deserialization"), ("marshal", "Deserialization"), ("yaml", "Deserialization"),
    ("torch", "Deserialization"), ("cloudpickle", "Deserialization"),
    ("transformers", "Supply_Chain"), ("huggingface_hub", "Supply_Chain"), ("pip", "Supply_Chain"),
    ("socket", "Network_Access"), ("requests", "Network_Access"),
    ("os", "Code_Execution"), ("subprocess", "Code_Execution"),
    ("shutil", "File_Access"), ("pathlib", "File_Access"),
    ("ctypes", "Sandbox_Escape"), ("importlib", "Sandbox_Escape"), ("gc", "Sandbox_Escape"),
])
def test_known_attack_vectors_are_named_by_type(module, attack_type):
    verdict = check_code(f"import {module}")
    assert verdict.is_blocked and verdict.details["attack_type"] == attack_type
    assert verdict.details["line"] == 1


def test_from_import_of_a_dangerous_module_is_named_too():
    verdict = check_code("from transformers import AutoModel")
    assert verdict.details["attack_type"] == "Supply_Chain" and "trust_remote_code" in verdict.reason


def test_unknown_module_is_blocked_as_generic_code_execution():
    verdict = check_code("import antigravity")
    assert verdict.is_blocked and verdict.details["attack_type"] == "Code_Execution"
    assert "spoza listy" in verdict.reason


@pytest.mark.parametrize("code", [
    "import math\nprint(math.sqrt(16))",
    "print('{:.2f}'.format(3.14159))",
    "import operator\nprint(operator.add(1, 2), operator.itemgetter(0)([5]))",
    "import json\nprint(json.dumps({'a': 1}))",
    "import collections\nprint(collections.Counter('aab'))",
])
def test_ordinary_computation_still_passes(code):
    assert check_code(code).decision == "pass"
    assert not run_tool("run_python", {"code": code}).startswith("Code rejected")
