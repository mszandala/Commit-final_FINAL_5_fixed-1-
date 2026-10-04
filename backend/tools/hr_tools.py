from config import COLUMN_TYPES
from tools.domain_helpers import aggregate_csv, read_csv_rows, safe_path

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


def summarize_employee_records(operation: str = "count", column: str = "", group_by: str = "",
                               filter_column: str = "", filter_value: str = "") -> str:
    """Compute a statistic over ALL HR employee records (the row-reading tool returns at most 50 rows).

    Use this for totals, counts, averages, minimums and maximums instead of calculating from rows.

    Args:
        operation: One of count, sum, avg, min, max.
        column: Numeric column for sum/avg/min/max, e.g. MonthlyIncome, Age. Not needed for count.
        group_by: Optional column to split the result by, e.g. Department, JobRole.
        filter_column: Optional column to filter on before computing.
        filter_value: Value filter_column must equal.

    Returns:
        CSV text: group, number of rows, result. Statistics of groups under 5 rows are hidden.
    """
    return aggregate_csv(safe_path(EMPLOYEES), ",", operation, column, group_by, filter_column, filter_value,
                         sensitive_columns=COLUMN_TYPES["read_employee_records"])
