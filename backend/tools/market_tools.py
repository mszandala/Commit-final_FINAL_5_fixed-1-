from tools.domain_helpers import MAX_ROWS, read_text_window, safe_path

SUBDIR = "stock_market"
CALLS_SUBDIR = "stock_market/cleaned_ECTs_dataset"
PRICES = {
    "NASDAQ": "NASDAQ 1962-2024.csv",
    "NYSE":   "NYSE 1962-2024.csv",
    "NYSE A": "NYSE A 1973-2024.csv",
    "OTC":    "OTC 1972-2024.csv",
}


def read_stock_prices(exchange: str, ticker: str, start_date: str = "", end_date: str = "",
                      limit: int = 30) -> str:
    """Read daily stock prices (open, high, low, close, volume) for one ticker.

    Args:
        exchange: One of 'NASDAQ', 'NYSE', 'NYSE A', 'OTC'.
        ticker: Ticker symbol, e.g. AAPL.
        start_date: Optional first date to include, YYYY-MM-DD.
        end_date: Optional last date to include, YYYY-MM-DD.
        limit: Maximum number of rows to return (default 30, max 50).

    Returns:
        CSV text with a header line, or an error message.
    """
    exchange = exchange.upper().strip()
    if exchange not in PRICES:
        return f"Unknown exchange '{exchange}'. Use one of: {', '.join(PRICES)}."
    path = safe_path(PRICES[exchange], SUBDIR)
    if not path.exists():
        return f"File not found: {path.name}"
    ticker = ticker.upper().strip()
    limit = max(1, min(int(limit), MAX_ROWS))

    # Pliki mają miliony wierszy; wiersze jednego tickera leżą obok siebie, więc po nich kończymy.
    rows = []
    found = False
    with open(path, encoding="utf-8-sig") as f:
        header = next(f, "")
        for line in f:
            parts = line.split(",", 2)
            if len(parts) < 3 or parts[1] != ticker:
                if found:
                    break
                continue
            found = True
            date = parts[0]
            if (start_date and date < start_date) or (end_date and date > end_date):
                continue
            rows.append(line)
            if len(rows) == limit:
                break

    if not found:
        return f"Ticker '{ticker}' not found on {exchange}."
    if not rows:
        return header + "(no rows in this date range)"
    return header + "".join(rows)


def list_earnings_calls(company: str = "") -> str:
    """List available earnings call transcripts.

    Args:
        company: Company name as returned by this tool. Leave empty to list all companies.

    Returns:
        Company names, or the transcripts (year and quarter) available for one company.
    """
    folder = safe_path(company, CALLS_SUBDIR)
    if not folder.is_dir():
        return f"Unknown company: {company}"
    if not company:
        return "\n".join(sorted(p.name for p in folder.iterdir() if p.is_dir()))
    return "\n".join(sorted("_".join(p.name.split("_")[:2]) for p in folder.glob("*.txt")))


def read_earnings_call(company: str, year: int, quarter: int, offset: int = 0,
                       max_chars: int = 6000) -> str:
    """Read the transcript of one quarterly earnings call.

    Args:
        company: Company name exactly as returned by list_earnings_calls.
        year: Year of the call, e.g. 2023.
        quarter: Quarter of the call, 1-4.
        offset: Character position to start reading from (default 0).
        max_chars: Maximum number of characters to return (default 6000).

    Returns:
        The requested part of the transcript, or an error message.
    """
    folder = safe_path(company, CALLS_SUBDIR)
    matches = sorted(folder.glob(f"{int(year)}_Q{int(quarter)}_*.txt")) if folder.is_dir() else []
    if not company or not matches:
        return f"No transcript for {company} {year} Q{quarter}."
    return read_text_window(matches[0], offset, max_chars)
