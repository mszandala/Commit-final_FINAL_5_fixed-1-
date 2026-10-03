import pytest

from security.tool_whitelist import ToolGate, is_allowed
from config import ROLES
from tools import _files, domain_helpers
from tools.registry import TOOL_MAP, run_tool


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(_files, "BASE_DIR", tmp_path)
    monkeypatch.setattr(domain_helpers, "BASE_DIR", tmp_path)
    (tmp_path / "projects").mkdir()
    (tmp_path / "projects" / "alpha_README.md").write_text("0123456789", encoding="utf-8")
    (tmp_path / "employee_data").mkdir()
    (tmp_path / "employee_data" / "WA_Fn-UseC_-HR-Employee-Attrition.csv").write_text(
        "﻿Age,Department,MonthlyIncome\n41,Sales,5993\n49,R&D,5130\n33,Sales,2909\n", encoding="utf-8")
    (tmp_path / "bank_data").mkdir()
    (tmp_path / "bank_data" / "bank.csv").write_text(
        '"age";"job";"y"\n30;"unemployed";"no"\n33;"services";"yes"\n', encoding="utf-8")
    market = tmp_path / "stock_market"
    (market / "cleaned_ECTs_dataset" / "Apple").mkdir(parents=True)
    (market / "cleaned_ECTs_dataset" / "Apple" / "2018_Q1_aapl_processed.txt").write_text("Good day.", encoding="utf-8")
    (market / "OTC 1972-2024.csv").write_text(
        "Date,Ticker,Exchange,Open,High,Low,Close,Adj Close,Volume\n"
        "1995-05-05,AATC,OTC,1,1,1,1,1,10\n1995-05-08,AATC,OTC,2,2,2,2,2,20\n1995-05-05,ABCD,OTC,3,3,3,3,3,30\n",
        encoding="utf-8")
    return tmp_path


def test_every_whitelisted_tool_exists():
    for role, cfg in ROLES.items():
        assert cfg["allowed_tools"], role
        assert set(cfg["allowed_tools"]) <= set(TOOL_MAP), role


def test_projects(data_dir):
    assert run_tool("list_projects", {}) == "alpha"
    assert run_tool("list_projects", {"search": "zzz"}) == "(no matching projects)"
    assert run_tool("read_project", {"name": "alpha", "offset": 2, "max_chars": 3}).startswith("234\n[5 more")
    assert run_tool("read_project", {"name": "../employee_data/x"}).startswith("Tool error: Unsafe path")


def test_csv_filter_and_paging(data_dir):
    out = run_tool("read_employee_records", {"column": "Department", "value": "Sales", "start_row": 1})
    assert out == "Age,Department,MonthlyIncome\n33,Sales,2909\n"
    assert run_tool("read_employee_records", {"column": "Nope", "value": "x"}).startswith("Unknown column")
    assert run_tool("read_bank_campaigns", {"column": "y", "value": "yes"}) == "age,job,y\n33,services,yes\n"
    assert run_tool("read_client_records", {}).startswith("File not found")


def test_stock_prices(data_dir):
    out = run_tool("read_stock_prices", {"exchange": "otc", "ticker": "aatc", "start_date": "1995-05-08"})
    assert out.splitlines()[1:] == ["1995-05-08,AATC,OTC,2,2,2,2,2,20"]
    assert "not found" in run_tool("read_stock_prices", {"exchange": "OTC", "ticker": "ZZZ"})
    assert run_tool("read_stock_prices", {"exchange": "NYSE", "ticker": "X"}).startswith("File not found")


def test_earnings_calls(data_dir):
    assert run_tool("list_earnings_calls", {}) == "Apple"
    assert run_tool("list_earnings_calls", {"company": "Apple"}) == "2018_Q1"
    assert run_tool("read_earnings_call", {"company": "Apple", "year": 2018, "quarter": 1}) == "Good day."
    assert run_tool("read_earnings_call", {"company": "Apple", "year": 2019, "quarter": 1}).startswith("No transcript")
    assert run_tool("list_earnings_calls", {"company": "../.."}).startswith("Tool error: Unsafe path")


def test_gate_allows_whitelisted_and_records_violations():
    gate = ToolGate("kadry")
    assert gate("read_employee_records", {}) is None
    refusal = gate("read_client_records", {"column": "customer_id"})
    assert "read_client_records" in refusal
    assert gate.violations == [{"tool": "read_client_records", "args": {"column": "customer_id"}, "allowed": False}]
    assert len(gate.calls) == 2


def test_unknown_role_has_no_tools():
    assert not is_allowed("nieznana", "list_projects")
    assert is_allowed("administrator", "read_stock_prices")
