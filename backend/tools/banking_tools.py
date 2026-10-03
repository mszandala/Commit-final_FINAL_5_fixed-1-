from tools.domain_helpers import read_csv_rows, safe_path

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
