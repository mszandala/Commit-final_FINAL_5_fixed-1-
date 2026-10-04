import ast
import builtins
import re

from security.common.verdicts import Verdict

# Pure computational modules — no file, network, or OS process access.
ALLOWED_MODULES = {
    "math", "statistics", "json", "datetime", "re", "collections", "itertools",
    "functools", "random", "decimal", "fractions", "string", "textwrap", "operator",
}

# Known attack vectors: designated attack type and reason are sent to audit telemetry.
_DANGEROUS = {
    # module: (attack_type, reason)
    "os": ("Code_Execution", "dostęp do systemu operacyjnego"),
    "sys": ("Sandbox_Escape", "dostęp do interpretera"),
    "subprocess": ("Code_Execution", "uruchamianie procesów"),
    "multiprocessing": ("Code_Execution", "uruchamianie procesów"),
    "pty": ("Code_Execution", "uruchamianie procesów"),
    "shutil": ("File_Access", "operacje na plikach"),
    "pathlib": ("File_Access", "operacje na plikach"),
    "io": ("File_Access", "operacje na plikach"),
    "glob": ("File_Access", "operacje na plikach"),
    "tempfile": ("File_Access", "operacje na plikach"),
    "zipfile": ("File_Access", "operacje na plikach"),
    "tarfile": ("File_Access", "operacje na plikach"),
    "socket": ("Network_Access", "połączenia sieciowe"),
    "urllib": ("Network_Access", "połączenia sieciowe"),
    "requests": ("Network_Access", "połączenia sieciowe"),
    "http": ("Network_Access", "połączenia sieciowe"),
    "ftplib": ("Network_Access", "połączenia sieciowe"),
    "smtplib": ("Network_Access", "połączenia sieciowe"),
    "pickle": ("Deserialization", "niebezpieczna deserializacja"),
    "cloudpickle": ("Deserialization", "niebezpieczna deserializacja"),
    "jsonpickle": ("Deserialization", "niebezpieczna deserializacja"),
    "marshal": ("Deserialization", "niebezpieczna deserializacja"),
    "shelve": ("Deserialization", "niebezpieczna deserializacja"),
    "dill": ("Deserialization", "niebezpieczna deserializacja"),
    "joblib": ("Deserialization", "niebezpieczna deserializacja"),
    "torch": ("Deserialization", "niebezpieczna deserializacja (torch.load)"),
    "yaml": ("Deserialization", "niebezpieczna deserializacja (yaml.load)"),
    "transformers": ("Supply_Chain", "ładowanie modeli z zewnętrznych repozytoriów (trust_remote_code)"),
    "huggingface_hub": ("Supply_Chain", "pobieranie modeli z zewnętrznych repozytoriów"),
    "datasets": ("Supply_Chain", "pobieranie danych z zewnętrznych repozytoriów"),
    "pip": ("Supply_Chain", "instalowanie pakietów"),
    "ensurepip": ("Supply_Chain", "instalowanie pakietów"),
    "setuptools": ("Supply_Chain", "instalowanie pakietów"),
    "pkg_resources": ("Supply_Chain", "instalowanie pakietów"),
    "venv": ("Supply_Chain", "instalowanie pakietów"),
    "ctypes": ("Sandbox_Escape", "dostęp do pamięci natywnej"),
    "importlib": ("Sandbox_Escape", "dynamiczne importy"),
    "runpy": ("Sandbox_Escape", "dynamiczne importy"),
    "pkgutil": ("Sandbox_Escape", "dynamiczne importy"),
    "zipimport": ("Sandbox_Escape", "dynamiczne importy"),
    "builtins": ("Sandbox_Escape", "nadpisanie wbudowanych funkcji"),
    "gc": ("Sandbox_Escape", "dostęp do obiektów interpretera"),
    "inspect": ("Sandbox_Escape", "dostęp do ramek i obiektów interpretera"),
    "types": ("Sandbox_Escape", "tworzenie obiektów niskiego poziomu"),
    "code": ("Sandbox_Escape", "uruchamianie kodu z napisu"),
    "codeop": ("Sandbox_Escape", "uruchamianie kodu z napisu"),
}
DANGEROUS_MODULES = {module: reason for module, (_, reason) in _DANGEROUS.items()}

# Helpers reading attributes dynamically by string name: bypass __dunder__ attribute AST inspection.
INTROSPECTION_HELPERS = {"attrgetter", "methodcaller", "Formatter", "vformat", "get_field"}

# String containing special dunder attribute names.
_DUNDER_STRING = re.compile(r"__[A-Za-z0-9_]+__")

FORBIDDEN_CALLS = {
    "open", "exec", "eval", "compile", "__import__", "input", "breakpoint",
    "globals", "locals", "vars", "getattr", "setattr", "delattr", "help", "exit", "quit",
}

SAFE_BUILTINS = {
    name: getattr(builtins, name) for name in dir(builtins)
    if not name.startswith("_") and name not in FORBIDDEN_CALLS
}


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level or name.split(".")[0] not in ALLOWED_MODULES:
        raise ImportError(f"Import of '{name}' is not allowed")
    return __import__(name, globals, locals, fromlist, level)


SAFE_BUILTINS["__import__"] = _safe_import


def check_code(code: str) -> Verdict:
    """Static Python AST inspection prior to execution in run_python: imports, calls, dunder attributes."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return Verdict("block", f"Syntax error: {e.msg}", "code_guard", is_blocked=True)

    for node in ast.walk(tree):
        problem = _inspect(node)
        if problem:
            reason, attack_type = problem
            return Verdict("block", reason, "code_guard",
                           {"line": getattr(node, "lineno", None), "attack_type": attack_type},
                           is_blocked=True)
    return Verdict("pass", "Code verified safe", "code_guard")



def _inspect(node: ast.AST):
    """Returns (reason, attack_type) of first violation in node, or None."""
    if isinstance(node, ast.Import):
        modules = [a.name for a in node.names]
    elif isinstance(node, ast.ImportFrom):
        if node.level:
            return "Import względny jest niedozwolony", "Code_Execution"
        modules = [node.module or ""]
        for alias in node.names:
            if alias.name in INTROSPECTION_HELPERS:
                return _helper_problem(alias.name)
    else:
        modules = []
    for module in modules:
        root = module.split(".")[0]
        if root in _DANGEROUS:
            attack_type, reason = _DANGEROUS[root]
            return f"Import '{module}': {reason}", attack_type
        if root not in ALLOWED_MODULES:
            return f"Import '{module}' spoza listy dozwolonych modułów", "Code_Execution"

    if isinstance(node, ast.Name) and node.id in FORBIDDEN_CALLS:
        return f"Użycie '{node.id}' jest niedozwolone", "Code_Execution"
    if isinstance(node, ast.Name) and node.id.startswith("__"):
        return f"Użycie nazwy specjalnej '{node.id}' jest niedozwolone", "Sandbox_Escape"
    # __class__, __subclasses__, __globals__ etc. are classic sandbox escape vectors.
    if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
        return f"Dostęp do atrybutu '{node.attr}' jest niedozwolony", "Sandbox_Escape"
    if isinstance(node, ast.Attribute) and node.attr in INTROSPECTION_HELPERS:
        return _helper_problem(node.attr)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        match = _DUNDER_STRING.search(node.value)
        if match:
            return f"Napis z nazwą atrybutu specjalnego '{match.group()}' jest niedozwolony", "Sandbox_Escape"
    return None


def _helper_problem(name: str):
    return f"'{name}' czyta atrybuty po nazwie z napisu i omija blokadę atrybutów specjalnych", "Sandbox_Escape"

