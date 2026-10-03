import os
from pathlib import Path
from dotenv import load_dotenv

# Wczytanie zmiennych środowiskowych (.env z folderu backend lub nadrzędnego)
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")

# Provider LLM: "openrouter" (domyślny) lub "ollama"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter")

# Konfiguracja OpenRouter
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemma-4-26b-a4b-it:free")

# Konfiguracja Ollama
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:12b")

# Aktywny model przypisany do providera
MODEL = OPENROUTER_MODEL if LLM_PROVIDER == "openrouter" else OLLAMA_MODEL

# Model wykrywania PII / danych poufnych (GLiNER zero-shot NER)
PII_MODEL = os.getenv("PII_MODEL", "urchade/gliner_small-v2.1")
PII_THRESHOLD = float(os.getenv("PII_THRESHOLD", "0.35"))

BASE_DIR       = Path(__file__).parent / "data"
CONTEXT_FOLDERS = ["bank_data", "clients_data", "employee_data", "projects", "stock_market"]
MAX_HISTORY    = 12
MAX_TOOL_STEPS = 10

# Tymczasowo: dopóki nie ma narzędzi domenowych, każda rola ma oba narzędzia ogólne.
# Docelowe whitelisty, opisy i allowed_pii — po ustaleniu faktycznych danych (ARCHITECTURE.md).
_GENERIC_TOOLS = ["list_files", "read_file"]

ROLES = {
    "podstawowy użytkownik": {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "kadry":                 {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "administrator":         {"description": "", "allowed_tools": _GENERIC_TOOLS + ["run_python", "create_subagent"], "allowed_pii": []},
    "bankier":               {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "IT":                    {"description": "", "allowed_tools": _GENERIC_TOOLS + ["run_python", "create_subagent"], "allowed_pii": []},
    "analityk":              {"description": "", "allowed_tools": _GENERIC_TOOLS + ["create_subagent"], "allowed_pii": []},
    "prawnik":               {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
    "Portfolio Manager":     {"description": "", "allowed_tools": _GENERIC_TOOLS, "allowed_pii": []},
}
