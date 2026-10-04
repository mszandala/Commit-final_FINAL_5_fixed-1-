"""Schemat pliku polityki warstwy bezpieczeństwa.

Kontrole i budżety mają wartości domyślne równe dzisiejszemu zachowaniu systemu, więc ich sekcje
mogą być częściowe. Usunięcie sekcji kontroli nie wyłącza jej: kontrola zostaje włączona z wartościami
domyślnymi (wyłącza się wyłącznie jawnie: `enabled: false`). Role, narzędzia i polityki PII nie mają
wartości domyślnych: opisuje je plik. Nieznane klucze są odrzucane, żeby literówka w pliku nie
kończyła się cichym brakiem zabezpieczenia.
"""
import hashlib
import hmac
from fnmatch import fnmatchcase
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

Mode = Literal["warn", "block"]
RoleAction = Literal["allow", "redact", "block", "pseudonymize"]
ChatbotAction = Literal["allow", "redact", "block", "judge"]
Scan = Literal["columns", "regex", "full", "none"]

# Od najłagodniejszego do najostrzejszego; nadpisanie roli może regułę globalną tylko zaostrzyć.
SEVERITY = ["allow", "pseudonymize", "redact", "block"]

# Kontrole, które można włączać i wyłączać (kolejność jak w etapach tury).
FILTER_IDS = ("prompt_length", "prompt_guard", "intent_classifier", "company_policies",
              "tool_whitelist", "code_guard", "output_filter")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- kontrole ---------------------------------------------------------------------------------

class Toggle(_Model):
    enabled: bool = True


class PromptLength(_Model):
    enabled: bool = True
    max_chars: int = Field(4000, gt=0)


class PromptGuard(_Model):
    """Tryb strażnika dotyczy też klasyfikatora intencji (tak działa dzisiejszy pipeline)."""
    enabled: bool = True
    mode: Mode = "block"


class CompanyPolicies(_Model):
    enabled: bool = True
    classifier: Literal["security", "policy"] = "security"
    strict_keywords: bool = False
    semantic_blocks: bool = False
    fail_closed: bool = False


class Pii(_Model):
    mask_in_chatbot_channel: bool = True
    judge_enabled: bool = True
    threshold: float = Field(0.35, ge=0, le=1)


class RefusalDetection(_Model):
    enabled: bool = True
    embeddings_enabled: bool = True
    judge_enabled: bool = True
    model: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    threshold: float = Field(0.5, ge=0, le=1)
    trigger_threshold: float = Field(0.35, ge=0, le=1)


class Controls(_Model):
    prompt_length: PromptLength = PromptLength()
    prompt_guard: PromptGuard = PromptGuard()
    intent_classifier: Toggle = Toggle()
    company_policies: CompanyPolicies = CompanyPolicies()
    tool_whitelist: Toggle = Toggle()
    code_guard: Toggle = Toggle()
    output_filter: Toggle = Toggle()
    pii: Pii = Pii()
    refusal_detection: RefusalDetection = RefusalDetection()


# --- modele -----------------------------------------------------------------------------------

class ModelsPolicy(_Model):
    """Dozwolone modele LLM. Wpisy to nazwy albo wzorce z `*` (np. `google/gemma-*`).

    Pusta lista oznacza brak ograniczeń (nie ma jak wybrać bezpiecznej listy za wdrożenie);
    kontrolę wyłącza też jawne `enabled: false`.
    """
    enabled: bool = True
    allowed: list[str] = []


# --- budżety ----------------------------------------------------------------------------------

class PerTurn(_Model):
    max_tokens: int = Field(40000, gt=0)
    max_cost_usd: float = Field(0.05, gt=0)
    max_tool_steps: int = Field(10, gt=0)
    max_tool_result_chars: int = Field(24000, gt=0)


class Budgets(_Model):
    per_turn: PerTurn = PerTurn()
    # Łączny limit wydatków roli w dolarach (bez dziennego zerowania).
    spending_limit_usd: float = Field(0.5, gt=0)


# --- dane wrażliwe ----------------------------------------------------------------------------

class PiiSection(_Model):
    global_blocked: list[str] = ["PASSWORD", "CREDIT-CARD-NO"]
    global_redacted: list[str] = ["EMAIL", "PHONE-NO"]
    chatbot_policy: dict[str, ChatbotAction] = {}
    default_role_policy: dict[str, RoleAction] = {}
    id_types: list[str] = []


# --- narzędzia i role -------------------------------------------------------------------------

class ToolMeta(_Model):
    scan: Optional[Scan] = None          # None = `tool_defaults.scan`
    public: bool = False                 # źródło publiczne: wartości z wyniku nie są PII w odpowiedzi
    chatbot_zone: bool = False           # argumenty wracają do modelu w chmurze: nie odmaskowujemy
    column_types: dict[str, str] = {}    # kolumna CSV -> typ danych wrażliwych


class ToolDefaults(_Model):
    scan: Scan = "full"


class Area(_Model):
    label: str
    tools: list[str]


class Role(_Model):
    id: str
    description: str = ""
    allowed_tools: list[str] = []
    allowed_pii: list[str] = []
    pii_policy: dict[str, RoleAction] = {}
    daily_tokens: int = Field(gt=0)


class Client(_Model):
    """Klient proxy: klucz API (w pliku tylko jego skrót SHA-256) przypisany do roli."""
    name: str
    role: str
    key_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class ProxySettings(_Model):
    """Ustawienia proxy `/v1/chat/completions`."""
    default_model: str = ""                         # pusty = model wdrożenia (z konfiguracji procesu)
    max_reasks: int = Field(2, ge=0, le=5)          # ile razy proxy ponawia pytanie do modelu po odrzuconym narzędziu
    session_ttl_seconds: int = Field(3600, gt=0)    # po tylu sekundach bez ruchu sejf rozmowy jest usuwany
    max_sessions: int = Field(1000, gt=0)
    max_body_bytes: int = Field(1_048_576, gt=0)
    max_messages: int = Field(200, gt=0)


class ProfileOverride(_Model):
    """Profil ścisłości: częściowe nadpisanie sekcji `controls` i `budgets` (scalane rekurencyjnie)."""
    controls: dict = {}
    budgets: dict = {}


class Policy(_Model):
    version: Literal[1] = 1
    profile: str = "balanced"
    profile_names: tuple[str, ...] = ()
    controls: Controls = Controls()
    models: ModelsPolicy = ModelsPolicy()
    proxy: ProxySettings = ProxySettings()
    clients: list[Client] = []
    budgets: Budgets = Budgets()
    pii: PiiSection = PiiSection()
    tool_defaults: ToolDefaults = ToolDefaults()
    tools: dict[str, ToolMeta] = {}
    areas: dict[str, Area] = {}
    resources: dict[str, list[str]] = {}
    roles: dict[str, Role] = {}

    @model_validator(mode="after")
    def _consistent(self):
        ids = [r.id for r in self.roles.values()]
        if len(ids) != len(set(ids)):
            raise ValueError("roles: identyfikatory (id) ról muszą być unikalne")
        names = [c.name for c in self.clients]
        if len(names) != len(set(names)):
            raise ValueError("clients: nazwy klientów muszą być unikalne")
        unknown = sorted({c.role for c in self.clients if self.roles and c.role not in self.roles})
        if unknown:
            raise ValueError(f"clients: nieznane role {unknown}; dostępne: {', '.join(self.roles)}")
        return self

    # --- zapytania o politykę (czyste funkcje, bez stanu) -------------------------------------

    def filter_on(self, name: str) -> bool:
        """Czy kontrola jest włączona; nieznana liczy się jako włączona (jak dotychczas)."""
        control = getattr(self.controls, name, None) if name in FILTER_IDS else None
        return True if control is None else bool(control.enabled)

    def filters(self) -> dict[str, bool]:
        return {name: self.filter_on(name) for name in FILTER_IDS}

    def client_for_key(self, token: str) -> Optional["Client"]:
        """Klient o podanym kluczu API (porównanie skrótów w stałym czasie) albo None."""
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        found = None
        for client in self.clients:             # bez wcześniejszego wyjścia: czas nie zdradza pozycji klucza
            if hmac.compare_digest(client.key_sha256.lower(), digest):
                found = client
        return found

    def is_model_allowed(self, model: str) -> bool:
        """Czy model wolno wywołać; bez listy dozwolonych (albo przy wyłączonej kontroli) każdy."""
        if not self.models.enabled or not self.models.allowed:
            return True
        return any(fnmatchcase(model, pattern) for pattern in self.models.allowed)

    def role(self, name: str) -> Optional[Role]:
        return self.roles.get(name)

    def is_tool_allowed(self, role: str, tool: str) -> bool:
        cfg = self.roles.get(role)
        return bool(cfg) and tool in cfg.allowed_tools

    def role_areas(self, role: str) -> list[str]:
        """Etykiety obszarów danych dostępnych dla roli (pokazywane modelowi zamiast nazw narzędzi)."""
        cfg = self.roles.get(role)
        allowed = set(cfg.allowed_tools) if cfg else set()
        return [a.label for a in self.areas.values() if set(a.tools) <= allowed]

    def pii_policy_for(self, role: str) -> dict[str, str]:
        """Polityka kanału użytkownika dla roli: typ -> allow / redact / block / pseudonymize.

        Kolejność: domyślna polityka, `allowed_pii` roli, `pii_policy` roli, potem reguły globalne,
        które nadpisanie roli może tylko zaostrzyć.
        """
        policy: dict[str, str] = dict(self.pii.default_role_policy)
        cfg = self.roles.get(role)
        if cfg:
            for entity_type in cfg.allowed_pii:
                policy[entity_type] = "allow"
            policy.update(cfg.pii_policy)
        for entity_types, action in ((self.pii.global_redacted, "redact"), (self.pii.global_blocked, "block")):
            for entity_type in entity_types:
                current = policy.get(entity_type, "allow")
                policy[entity_type] = max(current, action, key=SEVERITY.index)
        return policy

    def chatbot_action(self, entity_type: str) -> str:
        """Co zrobić z typem w kanale chatbota; nieznany typ maskujemy."""
        return self.pii.chatbot_policy.get(entity_type, "redact")

    def tool(self, name: str) -> ToolMeta:
        """Metadane narzędzia z uzupełnioną domyślną metodą skanowania wyniku."""
        meta = self.tools.get(name, ToolMeta())
        return meta if meta.scan else meta.model_copy(update={"scan": self.tool_defaults.scan})
