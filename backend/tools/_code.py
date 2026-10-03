import contextlib
import io

def run_python(code: str) -> str:
    """Execute Python code provided as an argument.

    Args:
        code: Python source code to execute.

    Returns:
        Captured stdout, or an error message.
    """

    stdout = io.StringIO()

    try:
        with contextlib.redirect_stdout(stdout):
            exec(code, {})
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"

    return stdout.getvalue()