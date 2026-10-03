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

# Narzędzia pogrupowane po domenach danych (podfoldery data/).
_GENERIC_TOOLS = ["list_files", "read_file"]
_PROJECTS  = ["list_projects", "read_project"]
_HR        = ["read_employee_records"]
_CLIENTS   = ["read_client_records"]
_CAMPAIGNS = ["read_bank_campaigns"]
_MARKET    = ["read_stock_prices", "list_earnings_calls", "read_earnings_call"]
_CODE      = ["run_python"]
_SUBAGENT  = ["create_subagent"]

ROLES = {
    "podstawowy użytkownik": {
        "description": "Pracownik bez specjalnych uprawnień; korzysta z ogólnej bazy wiedzy o projektach.",
        "allowed_tools": _PROJECTS,
        "allowed_pii": [],
    },
    "kadry": {
        "description": "Dział kadr; pracuje na danych pracowników: stanowiska, wynagrodzenia, oceny, rotacja.",
        "allowed_tools": _PROJECTS + _HR,
        "allowed_pii": ["SALARY", "NAME"],
    },
    "administrator": {
        "description": "Administrator systemu z pełnym dostępem do wszystkich danych.",
        "allowed_tools": _PROJECTS + _HR + _CLIENTS + _CAMPAIGNS + _MARKET + _CODE + _GENERIC_TOOLS + _SUBAGENT,
        "allowed_pii": ["NAME", "SALARY", "ORGANIZATION", "LOCATION", "PASSWORD", "PROJECT", "PHONE-NO", "EMAIL", "CREDIT-CARD-NO"],
    },
    "bankier": {
        "description": "Doradca bankowy; obsługuje klientów banku i kampanie sprzedaży lokat.",
        "allowed_tools": _PROJECTS + _CLIENTS + _CAMPAIGNS,
        "allowed_pii": ["NAME", "PHONE-NO", "EMAIL"],
    },
    "IT": {
        "description": "Dział IT; korzysta z dokumentacji technicznej projektów.",
        "allowed_tools": _PROJECTS + _CODE + _SUBAGENT,
        "allowed_pii": ["PASSWORD", "PROJECT"],
    },
    "analityk": {
        "description": "Analityk danych; pracuje na anonimowych danych kampanii oraz danych rynkowych.",
        "allowed_tools": _PROJECTS + _CAMPAIGNS + _MARKET + _SUBAGENT,
        "allowed_pii": [],
    },
    "prawnik": {
        "description": "Dział prawny; analizuje publiczne wypowiedzi spółek z telekonferencji wynikowych.",
        "allowed_tools": _PROJECTS + ["list_earnings_calls", "read_earnings_call"],
        "allowed_pii": [],
    },
    "Portfolio Manager": {
        "description": "Zarządzający portfelem; analizuje notowania i telekonferencje wynikowe spółek.",
        "allowed_tools": _PROJECTS + _MARKET,
        "allowed_pii": [],
    },
}
