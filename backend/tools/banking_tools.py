from config import COLUMN_TYPES
from tools.domain_helpers import aggregate_csv, read_csv_rows, safe_path

CLIENTS = "clients_data/Bank Customer Churn Prediction.csv"
CAMPAIGNS = {"sample": "bank_data/bank.csv", "full": "bank_data/bank-full.csv"}


def read_client_records(column: str = "", value: str = "", start_row: int = 0, limit: int = 20) -> str:
    """Read bank client records: customer id, credit score, country, balance, estimated salary, churn.

    Args:
        column: Optional column to filter on, e.g. customer_id, country, churn.
        value: Value the column must equal (used only when column is given).
        start_row: Number of matching rows to skip (default 0).
        limit: Maximum number of rows to return (default 20, max 50).

    Returns:
        CSV text with a header line, or an error message.
    """
    return read_csv_rows(safe_path(CLIENTS), ",", column, value, start_row, limit)


def summarize_client_records(operation: str = "count", column: str = "", group_by: str = "",
                             filter_column: str = "", filter_value: str = "") -> str:
    """Compute a statistic over ALL bank client records (the row-reading tool returns at most 50 rows).

    Use this for totals, counts, averages, minimums and maximums instead of calculating from rows.

    Args:
        operation: One of count, sum, avg, min, max.
        column: Numeric column for sum/avg/min/max, e.g. balance, credit_score. Not needed for count.
        group_by: Optional column to split the result by, e.g. country, churn.
        filter_column: Leave empty to use all records. Set it only to restrict the records to one value.
        filter_value: Exact value filter_column must equal (only with filter_column).

    Returns:
        CSV text: group, number of rows, result. Statistics of groups under 5 rows are hidden.
    """
    return aggregate_csv(safe_path(CLIENTS), ",", operation, column, group_by, filter_column, filter_value,
                         sensitive_columns=COLUMN_TYPES["read_client_records"])


def read_bank_campaigns(dataset: str = "sample", column: str = "", value: str = "",
                        start_row: int = 0, limit: int = 20) -> str:
    """Read anonymous results of the bank's term-deposit marketing campaign (one row per contact).

    Args:
        dataset: 'sample' (4.5k rows) or 'full' (45k rows).
        column: Optional column to filter on, e.g. job, marital, education, y.
        value: Value the column must equal (used only when column is given).
        start_row: Number of matching rows to skip (default 0).
        limit: Maximum number of rows to return (default 20, max 50).

    Returns:
        CSV text with a header line, or an error message.
    """
    if dataset not in CAMPAIGNS:
        return f"Unknown dataset '{dataset}'. Use 'sample' or 'full'."
    return read_csv_rows(safe_path(CAMPAIGNS[dataset]), ";", column, value, start_row, limit)
