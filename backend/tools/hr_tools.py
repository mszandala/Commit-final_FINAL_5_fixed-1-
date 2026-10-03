from tools.domain_helpers import read_csv_rows, safe_path

EMPLOYEES = "employee_data/WA_Fn-UseC_-HR-Employee-Attrition.csv"


def read_employee_records(column: str = "", value: str = "", start_row: int = 0, limit: int = 20) -> str:
    """Read HR employee records: age, department, job role, monthly income, performance, attrition.

    Args:
        column: Optional column to filter on, e.g. Department, JobRole, EmployeeNumber.
        value: Value the column must equal (used only when column is given).
        start_row: Number of matching rows to skip (default 0).
        limit: Maximum number of rows to return (default 20, max 50).

    Returns:
        CSV text with a header line, or an error message.
    """
    return read_csv_rows(safe_path(EMPLOYEES), ",", column, value, start_row, limit)
