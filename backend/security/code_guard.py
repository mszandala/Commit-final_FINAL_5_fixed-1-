import ast
import builtins

from security.verdicts import Verdict

# Moduły czysto obliczeniowe — bez dostępu do plików, sieci i procesów.
ALLOWED_MODULES = {
    "math", "statistics", "json", "datetime", "re", "collections", "itertools",
    "functools", "random", "decimal", "fractions", "string", "textwrap", "operator",
}

# Znane wektory ataków: nazwany powód trafia do audytu zamiast ogólnego „moduł spoza listy”.
DANGEROUS_MODULES = {
    "os": "dostęp do systemu operacyjnego",
    "sys": "dostęp do interpretera",
    "subprocess": "uruchamianie procesów",
    "shutil": "operacje na plikach",
    "pathlib": "operacje na plikach",
    "io": "operacje na plikach",
    "socket": "połączenia sieciowe",
    "urllib": "połączenia sieciowe",
    "requests": "połączenia sieciowe",
    "http": "połączenia sieciowe",
    "pickle": "niebezpieczna deserializacja",
    "marshal": "niebezpieczna deserializacja",
    "shelve": "niebezpieczna deserializacja",
    "dill": "niebezpieczna deserializacja",
    "joblib": "niebezpieczna deserializacja",
    "torch": "niebezpieczna deserializacja (torch.load)",
    "yaml": "niebezpieczna deserializacja (yaml.load)",
    "ctypes": "dostęp do pamięci natywnej",
    "importlib": "dynamiczne importy",
    "builtins": "nadpisanie wbudowanych funkcji",
}

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
    """Statyczna analiza kodu przed wykonaniem w run_python: importy, wywołania, atrybuty dunder."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return Verdict("block", f"Błąd składni: {e.msg}", "code_guard", is_blocked=True)

    for node in ast.walk(tree):
        problem = _inspect(node)
        if problem:
            return Verdict("block", problem, "code_guard",
                           {"line": getattr(node, "lineno", None), "attack_type": "Code_Execution"},
                           is_blocked=True)
    return Verdict("pass", "Kod bez niebezpiecznych konstrukcji", "code_guard")


def _inspect(node: ast.AST):
    if isinstance(node, ast.Import):
        modules = [a.name for a in node.names]
    elif isinstance(node, ast.ImportFrom):
        if node.level:
            return "Import względny jest niedozwolony"
        modules = [node.module or ""]
    else:
        modules = []
    for module in modules:
        root = module.split(".")[0]
        if root in DANGEROUS_MODULES:
            return f"Import '{module}': {DANGEROUS_MODULES[root]}"
        if root not in ALLOWED_MODULES:
            return f"Import '{module}' spoza listy dozwolonych modułów"

    if isinstance(node, ast.Name) and node.id in FORBIDDEN_CALLS:
        return f"Użycie '{node.id}' jest niedozwolone"
    # __class__, __subclasses__, __globals__ itp. to klasyczna droga ucieczki z piaskownicy.
    if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
        return f"Dostęp do atrybutu '{node.attr}' jest niedozwolony"
    return None
