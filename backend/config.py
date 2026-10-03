import os
from dataclasses import dataclass
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
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemma-4-26b-a4b-it")

# Konfiguracja Ollama
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:12b")

# Aktywny model przypisany do providera
MODEL = OPENROUTER_MODEL if LLM_PROVIDER == "openrouter" else OLLAMA_MODEL

# Model wykrywania PII / danych poufnych (GLiNER zero-shot NER)
PII_MODEL = os.getenv("PII_MODEL", "urchade/gliner_small-v2.1")
PII_THRESHOLD = float(os.getenv("PII_THRESHOLD", "0.35"))

# Strefa bezpieczeństwa (strażnicy, sędziowie): widzi dane surowe i docelowo działa na lokalnej
# infrastrukturze. Dziś idzie tym samym providerem co chatbot; zmiana to dwie zmienne w .env.
# Puste = strefa bezpieczeństwa używa bieżącego providera i modelu chatbota (SETTINGS).
SECURITY_PROVIDER = os.getenv("SECURITY_PROVIDER", "")
SECURITY_MODEL = os.getenv("SECURITY_MODEL", "")

# Maskowanie danych wrażliwych w strefie chatbota (prompt, historia, wyniki narzędzi)
MASKING_ENABLED = os.getenv("MASKING_ENABLED", "true").lower() == "true"
# Sędzia LLM dla typów oznaczonych "judge" w CHATBOT_PII_POLICY; wyłączony = zawsze maskuj
PII_JUDGE_ENABLED = os.getenv("PII_JUDGE_ENABLED", "true").lower() == "true"
# Klucz HMAC do pseudonimizacji identyfikatorów; pusty = losowy na czas działania procesu
PSEUDONYM_KEY = os.getenv("PSEUDONYM_KEY", "")

# Tryb strażnika promptu: "warn" (ostrzega i przepuszcza) albo "block" (zatrzymuje zapytanie)
PROMPT_GUARD_MODE = os.getenv("PROMPT_GUARD_MODE", "block")
# Klasyfikator intencji (LLM, strefa bezpieczeństwa): czy zapytanie mieści się w pracy roli.
# Włączony rozstrzyga zamiast słów kluczowych strażnika; wyłączony = decyduje sam strażnik regex.
INTENT_CLASSIFIER_ENABLED = os.getenv("INTENT_CLASSIFIER_ENABLED", "true").lower() == "true"

AUDIT_LOG = Path(__file__).parent / "audit" / "events.jsonl"


@dataclass
class Settings:
    """Ustawienia zmienialne w trakcie działania (formularz konfiguracji w interfejsie).

    Moduły czytają je w chwili użycia, więc zmiana przez API działa od następnej wiadomości.
    Wartości startowe pochodzą z .env; po restarcie serwera wracają do nich.
    """
    provider: str             # "openrouter" | "ollama"
    model: str
    openrouter_api_key: str
    pii_threshold: float
    guard_mode: str           # "warn" | "block"
    mask_pii: bool            # maskowanie w strefie chatbota i ukrywanie PII w odpowiedzi


SETTINGS = Settings(
    provider=LLM_PROVIDER,
    model=MODEL,
    openrouter_api_key=OPENROUTER_API_KEY,
    pii_threshold=PII_THRESHOLD,
    guard_mode=PROMPT_GUARD_MODE,
    mask_pii=MASKING_ENABLED,
)

# Modele do wyboru w formularzu konfiguracji.
MODEL_PRESETS = [
    {"id": "google/gemma-4-26b-a4b-it",      "label": "Gemma 4 26B",            "provider": "openrouter"},
    {"id": "google/gemma-4-26b-a4b-it:free", "label": "Gemma 4 26B, free tier", "provider": "openrouter"},
    {"id": "gemma4:12b",                     "label": "Gemma 4 12B",            "provider": "ollama"},
]

# Poziomy czułości detektora PII (próg GLiNER): im niższy próg, tym więcej wykryć.
PII_SENSITIVITY_LEVELS = [
    {"id": "low",      "label": "Low",      "threshold": 0.50},
    {"id": "balanced", "label": "Balanced", "threshold": 0.35},
    {"id": "high",     "label": "High",     "threshold": 0.20},
]

# Etapy kontroli (pole `stage` werdyktów i zdarzeń) i ich nazwy dla ludzi.
CONTROLS = {
    "prompt_guard":   "Prompt guard",
    "tool_whitelist": "Tool permissions",
    "pii_policy":     "PII policy",
    "code_guard":     "Code guard",
    "company_policies": "Company policy",
    "chatbot_refusal": "Chatbot refusal",
    "budget":         "Token budget",
}

BASE_DIR       = Path(__file__).parent / "data"
CONTEXT_FOLDERS = ["bank_data", "clients_data", "employee_data", "projects", "stock_market"]

# Dane modułu company_policies. Celowo poza CONTEXT_FOLDERS: agent nie czyta ich narzędziami plikowymi.
COMPANY_DOCUMENTS_DIR = BASE_DIR / "company_documents"  # regulaminy, NDA, polityki (.md ze znacznikami control:)
COMPANY_FIXTURES_DIR  = BASE_DIR / "company_fixtures"   # poufne materiały do fingerprintingu
MAX_HISTORY    = 12
MAX_TOOL_STEPS = 10
# Limit wydatków na rolę w dolarach (łącznie, bez dziennego zerowania) i baza, w której są zapisywane.
MAX_SPENDING = 0.5
SPENDING_DB = Path(__file__).parent / "spending.db"

# Moduł regulaminów firmowych (security/company_policies) w przebiegu tury.
COMPANY_POLICIES_ENABLED = os.getenv("COMPANY_POLICIES_ENABLED", "true").lower() == "true"
# Klasyfikator semantyczny modułu: "security" = strefa bezpieczeństwa (SECURITY_PROVIDER/SECURITY_MODEL),
# "policy" = provider i model z nagłówka rules.txt (docelowo lokalna Ollama).
COMPANY_POLICIES_CLASSIFIER = os.getenv("COMPANY_POLICIES_CLASSIFIER", "security")
# Samo słowo kluczowe w wyniku narzędzia albo w odpowiedzi to słaby dowód (np. „marża” w omówieniu
# wyników spółki), więc domyślnie daje ostrzeżenie zamiast blokady. W prompcie blokuje jak dotąd;
# znaczniki, wzorce, odciski plików i klasyfikator blokują wszędzie. true = blokuj także tutaj.
COMPANY_POLICIES_STRICT_KEYWORDS = os.getenv("COMPANY_POLICIES_STRICT_KEYWORDS", "false").lower() == "true"
# Ocena tematu przez klasyfikator bez twardego dowodu (klauzula, numer umowy, odcisk pliku) myli się
# zbyt często, żeby sama blokowała: w testach QA zatrzymywała zwykłe pytania jako „cenniki i marże".
# Domyślnie daje ostrzeżenie; true = blokuj jak w regułach.
COMPANY_POLICIES_SEMANTIC_BLOCKS = os.getenv("COMPANY_POLICIES_SEMANTIC_BLOCKS", "false").lower() == "true"
# Gdy klasyfikator jest niedostępny (brak klucza, błąd dostawcy): true = blokuj (fail-closed, jak
# w regułach), false = ostrzeżenie i sprawdzenie samymi regułami deterministycznymi.
COMPANY_POLICIES_FAIL_CLOSED = os.getenv("COMPANY_POLICIES_FAIL_CLOSED", "false").lower() == "true"

# Wykrywanie odmowy w odpowiedzi chatbota (security/refusal_detector.py): słowa kluczowe, a gdy nic
# nie znajdą — podobieństwo zdań do wzorcowych odmów liczone lokalnym modelem embeddingów.
REFUSAL_DETECTION_ENABLED = os.getenv("REFUSAL_DETECTION_ENABLED", "true").lower() == "true"
REFUSAL_EMBEDDINGS_ENABLED = os.getenv("REFUSAL_EMBEDDINGS_ENABLED", "true").lower() == "true"
REFUSAL_MODEL = os.getenv("REFUSAL_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
REFUSAL_THRESHOLD = float(os.getenv("REFUSAL_THRESHOLD", "0.5"))
# Sędzia LLM potwierdza odmowę; słowa kluczowe i podobieństwo (od niższego progu) tylko wskazują kandydata.
REFUSAL_JUDGE_ENABLED = os.getenv("REFUSAL_JUDGE_ENABLED", "true").lower() == "true"
REFUSAL_TRIGGER_THRESHOLD = float(os.getenv("REFUSAL_TRIGGER_THRESHOLD", "0.35"))

# Ogólne reguły postępowania dla chatbota (decyzje kadrowe, dyskryminacja itp.). Warstwa nie zmienia
# promptu systemowego chronionego chatbota — reguły dołącza do pierwszej wiadomości rozmowy.
CONDUCT_RULES_FILE = Path(__file__).parent / "security" / "rules.txt"
# Narzędzia pogrupowane po domenach danych (podfoldery data/).
_GENERIC_TOOLS = ["list_files", "read_file"]
_PROJECTS  = ["list_projects", "read_project"]
_HR        = ["read_employee_records"]
_CLIENTS   = ["read_client_records"]
_CAMPAIGNS = ["read_bank_campaigns"]
_MARKET    = ["read_stock_prices", "list_earnings_calls", "read_earnings_call"]
_CODE      = ["run_python"]
_SUBAGENT  = ["create_subagent"]

# Obszary dostępu pokazywane w macierzy ról w interfejsie: id -> etykieta i narzędzia.
# Narzędzia spoza tych obszarów (_GENERIC_TOOLS) nie są edytowalne z interfejsu.
DATA_ACCESS = {
    "projects":  {"label": "Projects",       "tools": _PROJECTS},
    "hr":        {"label": "HR data",        "tools": _HR},
    "clients":   {"label": "Bank clients",   "tools": _CLIENTS},
    "campaigns": {"label": "Campaigns",      "tools": _CAMPAIGNS},
    "stocks":    {"label": "Stock prices",   "tools": ["read_stock_prices"]},
    "earnings":  {"label": "Earnings calls", "tools": ["list_earnings_calls", "read_earnings_call"]},
    "code":      {"label": "Run code",       "tools": _CODE},
    "subagents": {"label": "Subagents",      "tools": _SUBAGENT},
}

# Zasób danych → narzędzia, które go czytają. Z tego prompt_guard wylicza, czy rola ma dostęp
# do zasobu, o który pyta użytkownik — zmiana allowed_tools od razu zmienia jego decyzje.
RESOURCE_TOOLS = {
    "employee_data":  _HR,
    "client_data":    _CLIENTS,
    "bank_campaigns": _CAMPAIGNS,
    "stock_prices":   ["read_stock_prices"],
    "earnings_calls": ["list_earnings_calls", "read_earnings_call"],
}

# Kategorie PII obsługiwane globalnie, niezależnie od allowed_pii roli:
# - BLOCKED: odpowiedź się nie wyświetla (w danych ich nie ma, więc wykrycie = wyciek lub injection),
# - REDACTED: fragment zastępowany znacznikiem [TYP], reszta odpowiedzi zostaje.
GLOBAL_BLOCKED_PII  = ["PASSWORD", "CREDIT-CARD-NO"]
GLOBAL_REDACTED_PII = ["EMAIL", "PHONE-NO"]

# Nazwy typów dla interfejsu: znaczniki [TYP] w odpowiedzi; REDACTED to komórka tabeli ukryta u źródła.
PII_LABELS = {
    "NAME":           "Name",
    "SALARY":         "Salary",
    "ORGANIZATION":   "Organization",
    "LOCATION":       "Location",
    "PROJECT":        "Project",
    "EMAIL":          "Email",
    "PHONE-NO":       "Phone",
    "PASSWORD":       "Password",
    "CREDIT-CARD-NO": "Card number",
    "CLIENT-ID":      "Client ID",
    "ACCOUNT-NO":     "Account number",
    "EMPLOYEE-ID":    "Employee ID",
    "PESEL":          "PESEL",
    "REDACTED":       "Hidden",
}

ROLES = {
    "podstawowy użytkownik": {
        "description": "Pracownik bez specjalnych uprawnień; korzysta z ogólnej bazy wiedzy o projektach.",
        "allowed_tools": _PROJECTS,
        "allowed_pii": ["PROJECT", "ORGANIZATION"],
    },
    "kadry": {
        "description": "Dział kadr; pracuje na danych pracowników: stanowiska, wynagrodzenia, oceny, rotacja.",
        "allowed_tools": _PROJECTS + _HR,
        "allowed_pii": ["SALARY", "PROJECT", "ORGANIZATION"],
    },
    "administrator": {
        "description": "Administrator systemu z pełnym dostępem do wszystkich danych.",
        "allowed_tools": _PROJECTS + _HR + _CLIENTS + _CAMPAIGNS + _MARKET + _CODE + _GENERIC_TOOLS + _SUBAGENT,
        "allowed_pii": ["NAME", "SALARY", "ORGANIZATION", "LOCATION", "PROJECT"],
    },
    "bankier": {
        "description": "Doradca bankowy; obsługuje klientów banku (saldo, scoring, ryzyko odejścia) i kampanie sprzedaży lokat.",
        "allowed_tools": _PROJECTS + _CLIENTS + _CAMPAIGNS,
        "allowed_pii": ["SALARY", "LOCATION", "PROJECT", "ORGANIZATION"],
    },
    "IT": {
        "description": "Dział IT; korzysta z dokumentacji technicznej projektów.",
        "allowed_tools": _PROJECTS + _SUBAGENT,
        "allowed_pii": ["PROJECT", "ORGANIZATION"],
    },
    "analityk": {
        "description": "Analityk danych; pracuje na danych kampanii, spseudonimizowanych rekordach klientów oraz danych rynkowych.",
        "allowed_tools": _PROJECTS + _CLIENTS + _CAMPAIGNS + _MARKET + _SUBAGENT,
        "allowed_pii": ["SALARY", "ORGANIZATION", "LOCATION", "PROJECT"],
        # Widzi rekordy klientów, ale identyfikatory tylko jako stałe pseudonimy.
        "pii_policy": {"CLIENT-ID": "pseudonymize", "ACCOUNT-NO": "pseudonymize", "EMPLOYEE-ID": "pseudonymize"},
    },
    "prawnik": {
        "description": "Dział prawny; analizuje publiczne wypowiedzi spółek z telekonferencji wynikowych.",
        "allowed_tools": _PROJECTS + ["list_earnings_calls", "read_earnings_call"],
        "allowed_pii": ["ORGANIZATION", "NAME", "LOCATION", "PROJECT"],
    },
    "Portfolio Manager": {
        "description": "Zarządzający portfelem; analizuje notowania i telekonferencje wynikowe spółek.",
        "allowed_tools": _PROJECTS + _MARKET,
        "allowed_pii": ["SALARY", "ORGANIZATION", "NAME", "LOCATION", "PROJECT"],
    },
}

# Tożsamość roli w API i interfejsie: id (alias akceptowany przez prompt_guard), etykieta,
# przykładowy użytkownik i jego dzienny budżet tokenów.
_ROLE_PROFILES = {
    "podstawowy użytkownik": ("basic_user",        "Employee",          "Piotr Nowak",         20_000),
    "kadry":                 ("hr",                "HR",                "Anna Wiśniewska",     50_000),
    "bankier":               ("banker",            "Banker",            "Katarzyna Wójcik",    50_000),
    "analityk":              ("analyst",           "Analyst",           "Michał Kamiński",    100_000),
    "prawnik":               ("lawyer",            "Lawyer",            "Magdalena Kowalczyk", 50_000),
    "Portfolio Manager":     ("portfolio_manager", "Portfolio manager", "Jakub Szymański",    100_000),
    "IT":                    ("it",                "IT",                "Tomasz Lewandowski",  50_000),
    "administrator":         ("admin",             "Admin",             "Marek Zieliński",    200_000),
}
for _name, (_id, _label, _user, _budget) in _ROLE_PROFILES.items():
    ROLES[_name].update(id=_id, label=_label, user=_user, daily_token_budget=_budget)
# Kolejność ról w interfejsie: od najmniejszych uprawnień, administrator na końcu.
ROLES = {_name: ROLES[_name] for _name in _ROLE_PROFILES}


# --- Polityki danych wrażliwych -------------------------------------------------------------
# Działania: "allow" (pokaż), "redact" (zamaskuj), "block" (zablokuj całość),
#            "judge" (tylko kanał chatbota: decyduje sędzia LLM), "pseudonymize" (tylko identyfikatory).

# Kanał chatbota: co z promptu użytkownika może zobaczyć model w chmurze. Jedna polityka,
# niezależna od roli. Sędzia rozstrzyga wyłącznie typy "judge"; "redact" i "block" to twardy sufit.
CHATBOT_PII_POLICY = {
    "PASSWORD":       "redact",
    "EMAIL":          "redact",
    "PHONE-NO":       "redact",
    "CREDIT-CARD-NO": "redact",
    "CLIENT-ID":      "redact",
    "ACCOUNT-NO":     "redact",
    "EMPLOYEE-ID":    "redact",
    "PESEL":          "redact",
    "NAME":           "judge",
    "SALARY":         "judge",
    "ORGANIZATION":   "allow",
    "LOCATION":       "allow",
    "PROJECT":        "allow",
}

# Kanał użytkownika, w kolejności stosowania (security/masking.py: role_policy):
#   1. DEFAULT_ROLE_PII_POLICY - punkt wyjścia; typ spoza tej mapy jest ukrywany,
#   2. `allowed_pii` roli      - "allow",
#   3. `pii_policy` roli       - nadpisuje pojedyncze typy,
#   4. GLOBAL_BLOCKED_PII / GLOBAL_REDACTED_PII - obowiązują każdą rolę; `pii_policy` może je
#      tylko zaostrzyć, nigdy złagodzić.
# Typ spoza `allowed_pii` jest ukrywany, a nie blokuje całej odpowiedzi.
DEFAULT_ROLE_PII_POLICY = {
    "NAME":           "redact",
    "SALARY":         "redact",
    "PESEL":          "redact",
    # Nazwy miejsc, organizacji i projektów nie są danymi osobowymi: widzi je każda rola,
    # niezależnie od `allowed_pii` (ukrywanie ich psuło zwykłe odpowiedzi).
    "ORGANIZATION":   "allow",
    "LOCATION":       "allow",
    "PROJECT":        "allow",
    "CLIENT-ID":      "allow",     # kto ma narzędzie do rekordów, ten widzi ich identyfikatory
    "ACCOUNT-NO":     "allow",
    "EMPLOYEE-ID":    "allow",
}

# Typy, których wartości zamieniamy na stałe pseudonimy (HMAC) zamiast kolejnych znaczników.
ID_TYPES = ["CLIENT-ID", "ACCOUNT-NO", "EMPLOYEE-ID"]

# Kolumny CSV z danymi wrażliwymi: narzędzie -> kolumna -> typ.
COLUMN_TYPES = {
    "read_client_records": {
        "customer_id": "CLIENT-ID",
        "account_number": "ACCOUNT-NO",     # zawiera w sobie customer_id
        "estimated_salary": "SALARY",
    },
    "read_employee_records": {
        "EmployeeNumber": "EMPLOYEE-ID",
        "MonthlyIncome": "SALARY",
        "MonthlyRate": "SALARY",
        "DailyRate": "SALARY",
        "HourlyRate": "SALARY",
    },
}

# Jak skanować wynik narzędzia, zanim trafi do chatbota:
#   "columns" - polityka kolumn CSV (COLUMN_TYPES), bez detektora
#   "regex"   - tylko reguły (hasła, e-maile, telefony); dla dużych tekstów ze źródeł publicznych
#   "full"    - reguły + GLiNER, z pamięcią podręczną
#   "none"    - bez skanowania (wynik powstał już w strefie chatbota)
TOOL_RESULT_SCAN = {
    "read_client_records":   "columns",
    "read_employee_records": "columns",
    "read_bank_campaigns":   "none",
    "read_stock_prices":     "none",
    "list_projects":         "none",
    "list_earnings_calls":   "none",
    "read_project":          "regex",
    "read_earnings_call":    "regex",
    "create_subagent":       "none",
}
DEFAULT_TOOL_RESULT_SCAN = "full"

# Narzędzia czytające źródła publiczne: wartości z ich wyników nie są traktowane jak PII w odpowiedzi.
PUBLIC_SOURCE_TOOLS = [
    "list_projects", "read_project", "read_bank_campaigns",
    "read_stock_prices", "list_earnings_calls", "read_earnings_call",
]

# Narzędzia, których argumenty trafiają z powrotem do modelu w chmurze — nie odmaskowujemy ich.
CHATBOT_ZONE_TOOLS = ["create_subagent"]
