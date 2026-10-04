import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables (.env from backend or root directory)
load_dotenv()
load_dotenv(Path(__file__).parent / ".env")

# LLM Provider: "openrouter" (default) or "ollama"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter")

# OpenRouter configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemma-4-26b-a4b-it")

# Ollama configuration
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:12b")

# Active model assigned to provider
MODEL = OPENROUTER_MODEL if LLM_PROVIDER == "openrouter" else OLLAMA_MODEL

# PII / sensitive data detection model (GLiNER zero-shot NER)
PII_MODEL = os.getenv("PII_MODEL", "urchade/gliner_small-v2.1")
PII_THRESHOLD = float(os.getenv("PII_THRESHOLD", "0.35"))

# Security zone (guards, judges): sees raw data and targets local execution.
# Defaults to same provider as chatbot unless overridden in .env.
# Empty = security zone uses current chatbot provider and model (SETTINGS).
SECURITY_PROVIDER = os.getenv("SECURITY_PROVIDER", "")
SECURITY_MODEL = os.getenv("SECURITY_MODEL", "")

# Sensitive data masking in chatbot channel (prompt, history, tool results)
MASKING_ENABLED = os.getenv("MASKING_ENABLED", "true").lower() == "true"
# LLM judge for entity types marked "judge" in CHATBOT_PII_POLICY; false = always mask
PII_JUDGE_ENABLED = os.getenv("PII_JUDGE_ENABLED", "true").lower() == "true"
# HMAC key for identifier pseudonymization; empty = random per process lifetime
PSEUDONYM_KEY = os.getenv("PSEUDONYM_KEY", "")

# Prompt guard mode: "warn" (warns and allows through) or "block" (stops request)
PROMPT_GUARD_MODE = os.getenv("PROMPT_GUARD_MODE", "block")
# Intent classifier (LLM, security zone): determines if request fits role scope.
# When enabled, resolves ambiguity over keyword regex guard; disabled = regex guard decides.
INTENT_CLASSIFIER_ENABLED = os.getenv("INTENT_CLASSIFIER_ENABLED", "true").lower() == "true"

# Writable state directory: audit log, conversation DB, and spending DB. Defaults to local repo;
# in read-only container mount point, specify volume via STATE_DIR (e.g. /state).
STATE_DIR = Path(os.getenv("STATE_DIR") or Path(__file__).parent)
AUDIT_LOG = STATE_DIR / "audit" / "events.jsonl"
# Audit log destination: "file" (default), "stdout" (line-delimited JSON), "both", or "none".
AUDIT_SINK = os.getenv("AUDIT_SINK", "file").lower()


@dataclass
class Settings:
    """Runtime mutable settings (UI configuration form).

    Modules inspect settings at execution time; API updates take effect on next turn.
    Initial values are loaded from .env and reset on server restart.
    """
    provider: str             # "openrouter" | "ollama"
    model: str
    openrouter_api_key: str
    pii_threshold: float
    guard_mode: str           # "warn" | "block"
    mask_pii: bool            # masking in chatbot channel and response PII hiding
    filters: dict             # filter id from FILTERS -> is_enabled


# Filters toggleable via UI to observe system behavior with specific guardrails disabled.
# Order corresponds to turn stage sequence. Initial values: DEFAULT_FILTERS.
FILTERS = [
    {"id": "prompt_length", "label": "Prompt length limit",
     "description": "Rejects prompts longer than the character limit before any model sees them"},
    {"id": "prompt_guard", "label": "Prompt guard (keywords)",
     "description": "Pattern check for injection attempts and requests for data outside the role"},
    {"id": "intent_classifier", "label": "Intent classifier",
     "description": "LLM check that the request fits the role's work"},
    {"id": "company_policies", "label": "Company policies",
     "description": "Company rules applied to the prompt, tool arguments, tool results and the reply"},
    {"id": "tool_whitelist", "label": "Tool permissions",
     "description": "Role-based allow list of tools; off, any role can call any tool"},
    {"id": "code_guard", "label": "Code guard",
     "description": "Static check of Python code before it runs"},
    {"id": "output_filter", "label": "Reply filter",
     "description": "Hides or blocks PII in the reply according to the role; off, the user sees everything"},
]
DEFAULT_FILTERS = {f["id"]: True for f in FILTERS}
DEFAULT_FILTERS["intent_classifier"] = INTENT_CLASSIFIER_ENABLED
DEFAULT_FILTERS["company_policies"] = os.getenv("COMPANY_POLICIES_ENABLED", "true").lower() == "true"

SETTINGS = Settings(
    provider=LLM_PROVIDER,
    model=MODEL,
    openrouter_api_key=OPENROUTER_API_KEY,
    pii_threshold=PII_THRESHOLD,
    guard_mode=PROMPT_GUARD_MODE,
    mask_pii=MASKING_ENABLED,
    filters=dict(DEFAULT_FILTERS),
)

# Model choices for configuration UI.
MODEL_PRESETS = [
    {"id": "google/gemma-4-26b-a4b-it",      "label": "Gemma 4 26B",            "provider": "openrouter"},
    {"id": "google/gemma-4-26b-a4b-it:free", "label": "Gemma 4 26B, free tier", "provider": "openrouter"},
    {"id": "gemma4:12b",                     "label": "Gemma 4 12B",            "provider": "ollama"},
]

# PII sensitivity thresholds (GLiNER threshold): lower threshold = higher sensitivity.
PII_SENSITIVITY_LEVELS = [
    {"id": "low",      "label": "Low",      "threshold": 0.50},
    {"id": "balanced", "label": "Balanced", "threshold": 0.35},
    {"id": "high",     "label": "High",     "threshold": 0.20},
]

# Control stage names for human display and telemetry.
CONTROLS = {
    "prompt_length":  "Prompt length",
    "prompt_guard":   "Prompt guard",
    "tool_whitelist": "Tool permissions",
    "pii_policy":     "PII policy",
    "code_guard":     "Code guard",
    "company_policies": "Company policy",
    "chatbot_refusal": "Chatbot refusal",
    "budget":         "Budget",
    "model_policy":   "Model policy",
}

BASE_DIR       = Path(__file__).parent / "data"
CONTEXT_FOLDERS = ["bank_data", "clients_data", "employee_data", "projects", "stock_market"]

# Data for company_policies module. Kept separate from CONTEXT_FOLDERS so agent cannot read them via file tools.
COMPANY_DOCUMENTS_DIR = BASE_DIR / "company_documents"  # regulations, NDA, policies (.md with control: tags)
COMPANY_FIXTURES_DIR  = BASE_DIR / "company_fixtures"   # confidential material for fingerprinting

MAX_HISTORY    = 12
MAX_TOOL_STEPS = 10
# Spending limit per role in USD (cumulative, no daily reset) and database path.
MAX_SPENDING = 0.5
# Maximum user prompt length (in characters); longer prompts are rejected before reaching any model.
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "4000"))
# Limits for a single turn in chatbot zone (model, tool invocations, subagent).
# When exceeded, tool gate rejects further invocations and model finalizes answer.
MAX_TURN_TOKENS = int(os.getenv("MAX_TURN_TOKENS", "40000"))
MAX_TURN_COST = float(os.getenv("MAX_TURN_COST", "0.05"))
# Maximum tool result length (in characters) forwarded to model; longer outputs are truncated.
MAX_TOOL_RESULT_CHARS = int(os.getenv("MAX_TOOL_RESULT_CHARS", "24000"))
SPENDING_DB = STATE_DIR / "spending.db"

# Company policy enforcement module (security/company_policies) in turn pipeline.
COMPANY_POLICIES_ENABLED = os.getenv("COMPANY_POLICIES_ENABLED", "true").lower() == "true"
# Semantic classifier for module: "security" = security zone (SECURITY_PROVIDER/SECURITY_MODEL),
# "policy" = provider and model from rules.txt header (e.g. local Ollama).
COMPANY_POLICIES_CLASSIFIER = os.getenv("COMPANY_POLICIES_CLASSIFIER", "security")
# Keyword alone in tool result or reply is weak evidence, so it warns by default instead of blocking.
# Set true to enforce hard blocks on keywords in outputs as well.
COMPANY_POLICIES_STRICT_KEYWORDS = os.getenv("COMPANY_POLICIES_STRICT_KEYWORDS", "false").lower() == "true"
# Semantic classification without hard proof warns by default; true = block strictly.
COMPANY_POLICIES_SEMANTIC_BLOCKS = os.getenv("COMPANY_POLICIES_SEMANTIC_BLOCKS", "false").lower() == "true"
# When classifier is unavailable: true = fail-closed (block), false = warn and fall back to deterministic rules.
COMPANY_POLICIES_FAIL_CLOSED = os.getenv("COMPANY_POLICIES_FAIL_CLOSED", "false").lower() == "true"

# Refusal detection in chatbot response (security/refusal_detector.py): regex keywords, and if not matched,
# sentence embedding similarity against benchmark refusal exemplars via local embedding model.
REFUSAL_DETECTION_ENABLED = os.getenv("REFUSAL_DETECTION_ENABLED", "true").lower() == "true"
REFUSAL_EMBEDDINGS_ENABLED = os.getenv("REFUSAL_EMBEDDINGS_ENABLED", "true").lower() == "true"
REFUSAL_MODEL = os.getenv("REFUSAL_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
REFUSAL_THRESHOLD = float(os.getenv("REFUSAL_THRESHOLD", "0.5"))
# LLM judge validates refusal; keywords and similarity identify candidates.
REFUSAL_JUDGE_ENABLED = os.getenv("REFUSAL_JUDGE_ENABLED", "true").lower() == "true"
REFUSAL_TRIGGER_THRESHOLD = float(os.getenv("REFUSAL_TRIGGER_THRESHOLD", "0.35"))

# General conduct rules for chatbot. Layer injects rules into first user message notice.
CONDUCT_RULES_FILE = Path(__file__).parent / "security" / "rules.txt"
# Tools grouped by data domains (data/ subfolders).
_GENERIC_TOOLS = ["list_files", "read_file"]
_PROJECTS  = ["list_projects", "read_project"]
_HR        = ["read_employee_records", "summarize_employee_records"]
_CLIENTS   = ["read_client_records", "summarize_client_records"]
_CAMPAIGNS = ["read_bank_campaigns"]
_MARKET    = ["read_stock_prices", "list_earnings_calls", "read_earnings_call"]
_CODE      = ["run_python"]
_SUBAGENT  = ["create_subagent"]

# Data access areas displayed in UI role matrix: id -> label and tools.
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

# Data resource -> tools reading it. Prompt guard verifies role access from this mapping.
RESOURCE_TOOLS = {
    "employee_data":  _HR,
    "client_data":    _CLIENTS,
    "bank_campaigns": _CAMPAIGNS,
    "stock_prices":   ["read_stock_prices"],
    "earnings_calls": ["list_earnings_calls", "read_earnings_call"],
}

# PII categories handled globally, regardless of role allowed_pii:
# - BLOCKED: response blocked entirely,
# - REDACTED: snippet replaced with [TYPE] placeholder.
GLOBAL_BLOCKED_PII  = ["PASSWORD", "CREDIT-CARD-NO"]
GLOBAL_REDACTED_PII = ["EMAIL", "PHONE-NO"]

# Display names for UI: [TYPE] markers in response; REDACTED for table cells hidden at source.
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
        "description": "Standard employee without elevated permissions; accesses general project knowledge.",
        "allowed_tools": _PROJECTS,
        "allowed_pii": ["PROJECT", "ORGANIZATION"],
    },
    "kadry": {
        "description": "HR department (Dział kadr); works with employee records: positions, compensation, performance, attrition.",
        "allowed_tools": _PROJECTS + _HR,
        "allowed_pii": ["SALARY", "PROJECT", "ORGANIZATION"],
    },
    "administrator": {
        "description": "System administrator with full access to all tools and company data.",
        "allowed_tools": _PROJECTS + _HR + _CLIENTS + _CAMPAIGNS + _MARKET + _CODE + _GENERIC_TOOLS + _SUBAGENT,
        "allowed_pii": ["NAME", "SALARY", "ORGANIZATION", "LOCATION", "PROJECT"],
    },
    "bankier": {
        "description": "Bank relationship advisor; manages bank client accounts and deposit marketing campaigns.",
        "allowed_tools": _PROJECTS + _CLIENTS + _CAMPAIGNS,
        "allowed_pii": ["SALARY", "LOCATION", "PROJECT", "ORGANIZATION"],
    },
    "IT": {
        "description": "IT engineering; utilizes technical project documentation and code tools.",
        "allowed_tools": _PROJECTS + _SUBAGENT,
        "allowed_pii": ["PROJECT", "ORGANIZATION"],
    },
    "analityk": {
        "description": "Data analyst; works on marketing campaigns, pseudonymized client records, and market data.",
        "allowed_tools": _PROJECTS + _CLIENTS + _CAMPAIGNS + _MARKET + _SUBAGENT,
        "allowed_pii": ["SALARY", "ORGANIZATION", "LOCATION", "PROJECT"],
        # Sees client records, but identifiers are kept as stable pseudonyms.
        "pii_policy": {"CLIENT-ID": "pseudonymize", "ACCOUNT-NO": "pseudonymize", "EMPLOYEE-ID": "pseudonymize"},
    },
    "prawnik": {
        "description": "Legal counsel; analyzes public disclosures and quarterly earnings calls.",
        "allowed_tools": _PROJECTS + ["list_earnings_calls", "read_earnings_call"],
        "allowed_pii": ["ORGANIZATION", "NAME", "LOCATION", "PROJECT"],
    },
    "Portfolio Manager": {
        "description": "Portfolio manager; analyzes stock performance and public corporate earnings calls.",
        "allowed_tools": _PROJECTS + _MARKET,
        "allowed_pii": ["SALARY", "ORGANIZATION", "NAME", "LOCATION", "PROJECT"],
    },
}

# Role identity in API and UI: id, label, example user and daily token budget.
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
# Role ordering in UI: from least privilege, admin last.
ROLES = {_name: ROLES[_name] for _name in _ROLE_PROFILES}


# --- Sensitive data policies -------------------------------------------------------------
# Actions: "allow", "redact", "block", "judge" (LLM judge in chatbot channel), "pseudonymize".

# Chatbot channel: what from user prompt and tool outputs can be seen by external cloud model.
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

# User channel policy precedence (security/masking.py: role_policy):
#   1. DEFAULT_ROLE_PII_POLICY - baseline policy; omitted types are hidden,
#   2. `allowed_pii` of role   - "allow",
#   3. `pii_policy` of role    - overrides specific types,
#   4. GLOBAL_BLOCKED_PII / GLOBAL_REDACTED_PII - enforced across all roles.
DEFAULT_ROLE_PII_POLICY = {
    "NAME":           "redact",
    "SALARY":         "redact",
    "PESEL":          "redact",
    "ORGANIZATION":   "allow",
    "LOCATION":       "allow",
    "PROJECT":        "allow",
    "CLIENT-ID":      "allow",
    "ACCOUNT-NO":     "allow",
    "EMPLOYEE-ID":    "allow",
}

# Identifier types converted to stable HMAC pseudonyms.
ID_TYPES = ["CLIENT-ID", "ACCOUNT-NO", "EMPLOYEE-ID"]

# Sensitive CSV columns: tool -> column -> type.
COLUMN_TYPES = {
    "read_client_records": {
        "customer_id": "CLIENT-ID",
        "account_number": "ACCOUNT-NO",
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

# How to scan tool results before passing back to model:
#   "columns" - CSV column policy (COLUMN_TYPES), no NER detector
#   "regex"   - regex only (passwords, emails, phones); for large public texts
#   "full"    - regex + GLiNER with caching
#   "none"    - no scanning
TOOL_RESULT_SCAN = {
    "read_client_records":   "columns",
    "read_employee_records": "columns",
    "summarize_client_records":   "none",
    "summarize_employee_records": "none",
    "read_bank_campaigns":   "none",
    "read_stock_prices":     "none",
    "list_projects":         "none",
    "list_earnings_calls":   "none",
    "read_project":          "regex",
    "read_earnings_call":    "regex",
    "create_subagent":       "none",
}
DEFAULT_TOOL_RESULT_SCAN = "full"

# Tools accessing public sources: outputs are not treated as internal PII in replies.
PUBLIC_SOURCE_TOOLS = [
    "list_projects", "read_project", "read_bank_campaigns",
    "read_stock_prices", "list_earnings_calls", "read_earnings_call",
]

# Tools whose arguments return to the cloud model: do not unmask them.
CHATBOT_ZONE_TOOLS = ["create_subagent"]

