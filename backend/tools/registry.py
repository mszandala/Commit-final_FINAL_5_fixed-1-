from tools._files import list_files, read_file
from tools._code import run_python
from tools._subagent import create_subagent

# Wszystkie narzędzia — model widzi komplet, niezależnie od roli użytkownika.
TOOLS = [read_file, list_files, run_python, create_subagent]

TOOL_MAP = {fn.__name__: fn for fn in TOOLS}


def run_tool(name: str, args: dict) -> str:
    fn = TOOL_MAP.get(name)
    if fn is None:
        return f"Unknown tool: {name}"
    try:
        result = fn(**args)
        return str(result)
    except Exception as e:
        return f"Tool error: {e}"
