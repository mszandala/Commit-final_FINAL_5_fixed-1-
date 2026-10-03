from pathlib import Path

MODEL = "gemma4:12b"
PII_MODEL = "AI-Enthusiast11/pii-entity-extractor"

BASE_DIR       = Path(__file__).parent / "data"
MAX_HISTORY    = 12
MAX_TOOL_STEPS = 10

# Tymczasowo: dopóki nie ma narzędzi domenowych, każda rola ma oba narzędzia ogólne.
# Docelowe whitelisty, opisy i allowed_pii — po ustaleniu faktycznych danych (ARCHITECTURE.md).
_GENERIC_TOOLS = ["list_files", "read_file"]

ROLES = {
    "podstawowy użytkownik": {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "kadry":                 {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "administrator":         {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "bankier":               {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "IT":                    {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "analityk":              {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "prawnik":               {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "Portfolio Manager":     {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
}
