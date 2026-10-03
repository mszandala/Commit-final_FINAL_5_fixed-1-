from tools._files import list_files, read_file
from tools._code import run_python
def create_subagent(user_message: str) -> str:
    from tools._subagent import create_subagent as _subagent_impl
    return _subagent_impl(user_message)
from tools.banking_tools import read_bank_campaigns, read_client_records
from tools.hr_tools import read_employee_records
from tools.market_tools import list_earnings_calls, read_earnings_call, read_stock_prices
from tools.projects_tools import list_projects, read_project

# Wszystkie narzędzia — model widzi komplet, niezależnie od roli użytkownika.
TOOLS = [
    list_projects,
    read_project,
    read_employee_records,
    read_client_records,
    read_bank_campaigns,
    read_stock_prices,
    list_earnings_calls,
    read_earnings_call,
    run_python,
    create_subagent,
    read_file,
    list_files,
]

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
