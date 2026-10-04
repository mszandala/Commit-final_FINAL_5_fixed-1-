import ast
import builtins
import re

from security.common.verdicts import Verdict

# Moduły czysto obliczeniowe — bez dostępu do plików, sieci i procesów.
ALLOWED_MODULES = {
    "math", "statistics", "json", "datetime", "re", "collections", "itertools",
    "functools", "random", "decimal", "fractions", "string", "textwrap", "operator",
}

# Znane wektory ataków: nazwany powód i typ ataku trafiają do audytu zamiast ogólnego „moduł spoza listy”.
# Wszystko spoza ALLOWED_MODULES i tak jest blokowane; ta tabela nadaje blokadzie nazwę (raport dla zespołu
# bezpieczeństwa, statystyki po typach ataków).
_DANGEROUS = {
    # moduł: (typ ataku, powód)
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

# Pomocniki czytające atrybuty po nazwie podanej jako napis: omijają blokadę atrybutów __dunder__,
# bo w drzewie składni nie ma wtedy węzła Attribute (np. operator.attrgetter('__class__')(x)).
INTROSPECTION_HELPERS = {"attrgetter", "methodcaller", "Formatter", "vformat", "get_field"}

# Napis z nazwą atrybutu specjalnego ('__class__', '{0.__globals__}'.format(...)) służy do tego samego.
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
    """Statyczna analiza kodu przed wykonaniem w run_python: importy, wywołania, atrybuty dunder.

    To kontrola statyczna, a nie piaskownica: kod i tak działa w procesie wywołującego, więc prawdziwą
    izolację (osobny kontener, limity czasu i pamięci) zapewnia dopiero wydzielony executor.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return Verdict("block", f"Błąd składni: {e.msg}", "code_guard", is_blocked=True)

    for node in ast.walk(tree):
        problem = _inspect(node)
        if problem:
            reason, attack_type = problem
            return Verdict("block", reason, "code_guard",
                           {"line": getattr(node, "lineno", None), "attack_type": attack_type},
                           is_blocked=True)
    return Verdict("pass", "Kod bez niebezpiecznych konstrukcji", "code_guard")


def _inspect(node: ast.AST):
    """Zwraca (powód, typ ataku) pierwszego naruszenia w węźle albo None."""
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
    # __class__, __subclasses__, __globals__ itp. to klasyczna droga ucieczki z piaskownicy.
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
