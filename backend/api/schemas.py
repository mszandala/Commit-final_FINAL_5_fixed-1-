from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    """W JSON-ie pola są w camelCase (guardMode), w Pythonie w snake_case (guard_mode)."""
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# --- czat ------------------------------------------------------------------------------------

Decision = Literal["pass", "warn", "redact", "block"]


class Verdict(ApiModel):
    decision: Decision
    stage: str = Field(description="Etap kontroli; klucze i nazwy w GET /meta -> controls")
    reason: str


class ToolCall(ApiModel):
    tool: str
    args: dict[str, Any] = Field(description="Argumenty w postaci, w jakiej wysłał je model (zamaskowane)")
    allowed: bool
    stage: Optional[str] = Field(None, description="Kto odrzucił wywołanie: tool_whitelist albo code_guard")
    reason: Optional[str] = None


class Budget(ApiModel):
    limit: int
    used: int


class ChatRequest(ApiModel):
    role_id: str = Field(description="Id roli z GET /roles, np. basic_user")
    message: str = Field(min_length=1)
    conversation_id: Optional[str] = Field(None, description="Puste = nowa rozmowa")


class ChatResponse(ApiModel):
    conversation_id: str
    event_id: int = Field(description="Wiersz logu tej tury; szczegóły w GET /events/{id}")
    text: Optional[str] = Field(description="Odpowiedź dla użytkownika; null, gdy tura została zablokowana")
    tools: list[ToolCall]
    verdict: Optional[Verdict] = Field(description="Najważniejsza decyzja tury; null, gdy nic nie zadziałało")
    verdicts: list[Verdict] = Field(description="Wszystkie decyzje tury, od najważniejszej (np. redact i warn naraz)")
    masked_for_model: list[str] = Field(
        description="Typy danych z promptu ukryte przed chatbotem; użytkownik i tak widzi swoje wartości")
    tokens: int
    latency_ms: int
    budget: Budget


# --- role i konfiguracja ---------------------------------------------------------------------

class RoleConfig(ApiModel):
    id: str
    label: str
    access: list[str] = Field(description="Id obszarów z GET /meta -> dataAccess")
    pii: list[str] = Field(description="Typy PII widoczne dla roli, z GET /meta -> piiTags")


class Role(RoleConfig):
    description: str
    user: str = Field(description="Przykładowy użytkownik tej roli")
    budget: Budget


class Config(ApiModel):
    provider: Literal["openrouter", "ollama"]
    model: str
    api_key_set: bool
    api_key_hint: str = Field(description="Ostatnie 4 znaki klucza; pełny klucz nigdy nie wraca z API")
    sensitivity: Optional[str] = Field(description="Id poziomu z GET /meta -> sensitivityLevels; null = własny próg")
    pii_threshold: float
    guard_mode: Literal["warn", "block"]
    mask_pii: bool
    roles: list[RoleConfig]


class ConfigUpdate(ApiModel):
    """Wszystkie pola opcjonalne: pominięte zostają bez zmian."""
    provider: Optional[Literal["openrouter", "ollama"]] = None
    model: Optional[str] = None
    api_key: Optional[str] = Field(None, description="Nowy klucz OpenRouter; pominięty = bez zmian")
    sensitivity: Optional[str] = None
    guard_mode: Optional[Literal["warn", "block"]] = None
    mask_pii: Optional[bool] = None
    roles: Optional[list[RoleConfig]] = None


# --- słowniki dla interfejsu -----------------------------------------------------------------

class ModelPreset(ApiModel):
    id: str
    label: str
    provider: str


class SensitivityLevel(ApiModel):
    id: str
    label: str
    threshold: float


class DataAccessArea(ApiModel):
    id: str
    label: str
    tools: list[str]


class Meta(ApiModel):
    models: list[ModelPreset]
    sensitivity_levels: list[SensitivityLevel]
    data_access: list[DataAccessArea]
    pii_tags: list[str] = Field(description="Typy PII ustawiane per rola")
    redacted_pii: list[str] = Field(description="Typy zawsze ukrywane, niezależnie od roli")
    blocked_pii: list[str] = Field(description="Typy zawsze blokujące odpowiedź")
    pii_labels: dict[str, str] = Field(description="Typ ze znacznika [TYP] w tekście -> nazwa dla ludzi")
    controls: dict[str, str] = Field(description="Etap kontroli -> nazwa dla ludzi")
    stages: dict[str, str] = Field(description="Etap tury (zdarzenie stage w strumieniu) -> nazwa dla ludzi")
    examples: list[str]


# --- log -------------------------------------------------------------------------------------

EventDecision = Literal["Allowed", "Redacted", "Blocked", "Error"]


class Event(ApiModel):
    id: int
    time: datetime
    user: str
    role: str = Field(description="Etykieta roli")
    role_id: str
    conversation_id: str
    decision: EventDecision
    stage: Optional[str] = Field(description="Etap, który zdecydował; null dla zwykłej tury")
    control: str = Field(description="Nazwa etapu dla ludzi; pusta dla zwykłej tury")
    reason: str
    masked_for_model: list[str] = Field(description="Typy danych z promptu ukryte przed chatbotem")
    model: Optional[str] = Field(description="Model chatbota w tej turze; null, gdy nie był wołany")
    tokens: int
    latency_ms: int


class EventDetail(Event):
    masked_prompt: str = Field(description="Prompt w postaci wysłanej do chatbota")
    tools: list[ToolCall]
    leaks_to_chatbot: int = Field(description="Ile wartości z sejfu trafiło do chatbota (oczekiwane 0)")
    trail: list[dict[str, Any]] = Field(description="Zdarzenia audytu tury z polem zone; bez surowych wartości")


class Stats(ApiModel):
    total: int
    by_decision: dict[str, int]
    by_control: dict[str, int]
    tokens: int
    avg_latency_ms: int


class Health(ApiModel):
    status: str
    provider: str
    model: str
