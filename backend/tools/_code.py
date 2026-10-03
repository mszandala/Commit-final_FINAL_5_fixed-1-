import contextlib
import io

from security.code_guard import SAFE_BUILTINS, check_code


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

    stdout = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout):
            exec(code, {"__builtins__": SAFE_BUILTINS})
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"

    return stdout.getvalue()
