from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    """W JSON-ie pola są w camelCase (guardMode), w Pythonie w snake_case (guard_mode)."""
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# --- czat ------------------------------------------------------------------------------------

Decision = Literal["pass", "warn", "refuse", "redact", "block"]


class Verdict(ApiModel):
    decision: Decision
    stage: str = Field(description="Etap kontroli; klucze i nazwy w GET /meta -> controls")
    reason: str


class ToolCall(ApiModel):
    tool: str
    args: dict[str, Any] = Field(description="Argumenty w postaci, w jakiej wysłał je model (zamaskowane)")
    allowed: bool
    stage: Optional[str] = Field(None, description="Kto odrzucił wywołanie: tool_whitelist, code_guard, "
                                                   "company_policies albo budget")
    reason: Optional[str] = None
    tokens: Optional[int] = Field(None, description="Tokeny zużyte w trakcie wywołania (np. przez subagenta)")
    cost: Optional[float] = Field(None, description="Koszt wywołania w dolarach")
    result_tokens: Optional[int] = Field(None, description="Szacunek, ile tokenów wynik dokłada do kontekstu modelu")


class Budget(ApiModel):
    limit: int = Field(description="Dzienny budżet tokenów roli")
    used: int = Field(description="Tokeny zużyte dzisiaj")
    spending_limit: float = Field(description="Limit wydatków roli w dolarach (łączny)")
    spent: float = Field(description="Dotychczasowe wydatki roli w dolarach")


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
    cost: float = Field(description="Koszt tury w dolarach zgłoszony przez dostawcę modelu")
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
    filters: dict[str, bool] = Field(description="Id filtra z GET /meta -> filters -> czy jest włączony")
    roles: list[RoleConfig]


class ConfigUpdate(ApiModel):
    """Wszystkie pola opcjonalne: pominięte zostają bez zmian."""
    provider: Optional[Literal["openrouter", "ollama"]] = None
    model: Optional[str] = None
    api_key: Optional[str] = Field(None, description="Nowy klucz OpenRouter; pominięty = bez zmian")
    sensitivity: Optional[str] = None
    guard_mode: Optional[Literal["warn", "block"]] = None
    mask_pii: Optional[bool] = None
    filters: Optional[dict[str, bool]] = Field(None, description="Tylko filtry do zmiany; pominięte zostają bez zmian")
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


class FilterInfo(ApiModel):
    id: str
    label: str
    description: str


class FilterState(FilterInfo):
    enabled: bool


class Meta(ApiModel):
    models: list[ModelPreset]
    filters: list[FilterInfo] = Field(description="Filtry, które można wyłączyć; stan w GET /config -> filters")
    sensitivity_levels: list[SensitivityLevel]
    data_access: list[DataAccessArea]
    pii_tags: list[str] = Field(description="Typy PII ustawiane per rola")
    redacted_pii: list[str] = Field(description="Typy zawsze ukrywane, niezależnie od roli")
    blocked_pii: list[str] = Field(description="Typy zawsze blokujące odpowiedź")
    pii_labels: dict[str, str] = Field(description="Typ ze znacznika [TYP] w tekście -> nazwa dla ludzi")
    controls: dict[str, str] = Field(description="Etap kontroli -> nazwa dla ludzi")
    step_kinds: dict[str, str] = Field(description="Rodzaj kroku w logu -> nazwa dla ludzi")
    zones: dict[str, str] = Field(description="Strefa kroku -> nazwa dla ludzi")
    stages: dict[str, str] = Field(description="Etap tury (zdarzenie stage w strumieniu) -> nazwa dla ludzi")
    examples: list[str]


# --- log -------------------------------------------------------------------------------------

EventDecision = Literal["Allowed", "Refused", "Redacted", "Blocked", "Error"]
Level = Literal["info", "warn", "block"]


class Step(ApiModel):
    """Jeden krok tury: decyzja strażnika, wywołanie modelu albo narzędzia."""
    index: int
    kind: str = Field(description="Rodzaj kroku; klucze i nazwy w GET /meta -> stepKinds")
    label: str
    zone: str = Field(description="Gdzie krok się wykonał; klucze i nazwy w GET /meta -> zones")
    level: Level = Field(description="info = bez zastrzeżeń, warn = ostrzeżenie lub ukrycie danych, block = blokada")
    summary: str
    at_ms: int = Field(description="Czas od początku tury do końca kroku")
    duration_ms: int
    details: dict[str, Any] = Field(description="Pełne zdarzenie audytu; bez surowych wartości wrażliwych")


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
    level: Level = Field(description="Najwyższy poziom spośród kroków tury")
    step_count: int
    comment_count: int = Field(0, description="Liczba komentarzy do rozmowy, do której należy tura")
    steps: Optional[list[Step]] = Field(None, description="Kroki tury; w liście tylko przy ?steps=true")
    masked_prompt: str = Field(description="Prompt w postaci wysłanej do chatbota; dla tury zablokowanej przed "
                                           "modelem — prompt z wartościami wrażliwymi zamienionymi na etykiety")
    reply: str = Field("", description="Odpowiedź chatbota z wartościami wrażliwymi zamienionymi na etykiety; "
                                       "pusta, gdy model nie odpowiedział")
    masked_for_model: list[str] = Field(description="Typy danych z promptu ukryte przed chatbotem")
    model: Optional[str] = Field(description="Model chatbota w tej turze; null, gdy nie był wołany")
    tokens: int
    latency_ms: int


class EventDetail(Event):
    steps: list[Step]
    tools: list[ToolCall]
    leaks_to_chatbot: int = Field(description="Ile wartości z sejfu trafiło do chatbota (oczekiwane 0)")
    trail: list[dict[str, Any]] = Field(description="Zdarzenia audytu tury z polem zone; bez surowych wartości")


class Comment(ApiModel):
    id: int
    conversation_id: str
    event_id: Optional[int] = Field(description="Tura, której dotyczy komentarz; null = cała rozmowa")
    author: str
    text: str
    time: datetime


class CommentCreate(ApiModel):
    text: str = Field(min_length=1, max_length=4000)
    author: str = Field("QA", min_length=1, max_length=80)
    event_id: Optional[int] = None


class Conversation(ApiModel):
    id: str
    role: str
    role_id: str
    user: str
    started_at: datetime
    last_at: datetime
    turn_count: int
    level: Level = Field(description="Najwyższy poziom spośród tur rozmowy")
    comment_count: int


class ConversationTurn(EventDetail):
    comments: list[Comment] = Field(default_factory=list, description="Komentarze dodane przy tej turze")


class ConversationDetail(Conversation):
    # Komentarze przed turami: w wyeksportowanym pliku są wtedy na początku rozmowy, a nie po
    # kilkuset liniach kroków.
    comments: list[Comment] = Field(description="Wszystkie komentarze rozmowy")
    turns: list[ConversationTurn]


class Stats(ApiModel):
    total: int
    by_decision: dict[str, int]
    by_control: dict[str, int]
    tokens: int
    avg_latency_ms: int


class Metrics(ApiModel):
    total: int = Field(description="Liczba tur w oknie")
    window: dict[str, Optional[datetime]] = Field(description="Czas pierwszej i ostatniej tury: from, to")
    by_decision: dict[str, int]
    by_control: dict[str, int] = Field(description="Które kontrole zdecydowały (nazwy jak w GET /meta -> controls)")
    by_role: dict[str, int]
    by_level: dict[str, int]
    blocked_rate: float = Field(description="Udział tur zablokowanych (0-1)")
    intervention_rate: float = Field(description="Udział tur, w których warstwa coś zrobiła: blokada, ukrycie, odmowa, ostrzeżenie")
    tokens: int = Field(description="Tokeny strefy chatbota (to, co liczy się do budżetu)")
    cost_usd: float
    security_tokens: int = Field(description="Tokeny strażników i sędziów (nie obciążają budżetu użytkownika)")
    security_cost_usd: float
    latency_ms: dict[str, int] = Field(description="Czas całej tury: avg, p50, p95, p99, max")
    step_timings_ms: dict[str, dict[str, int]] = Field(
        description="Czas każdego rodzaju kroku (kontroli): count, avg, p50, p95, p99, max; nazwy w GET /meta -> stepKinds")
    zone_avg_ms: dict[str, int] = Field(description="Średni czas na turę w strefach: security, chatbot, local")
    blocked_by_step: dict[str, int] = Field(description="Ile razy dany krok zablokował")
    warned_by_step: dict[str, int] = Field(description="Ile razy dany krok ostrzegł albo ukrył dane")
    by_attack_type: dict[str, int] = Field(description="Wykryte ataki po typie (Prompt_Injection, Sandbox_Escape, ...)")


class PolicyChange(ApiModel):
    path: str = Field(description="Klucz w pliku polityki, np. controls.prompt_guard.mode")
    old: Any = None
    new: Any = None


class PolicyProblem(ApiModel):
    message: str
    problems: list[str] = Field(description="Po jednym opisie na błąd, ze ścieżką klucza")
    at: float = Field(description="Czas błędu (sekundy od epoki)")


class PolicyStatus(ApiModel):
    path: str = Field(description="Plik polityki")
    version: int = Field(description="Rośnie przy każdej zmianie treści polityki (od 1 przy starcie)")
    digest: str = Field(description="Skrót obowiązującej polityki; ten sam skrót = ta sama polityka")
    profile: str = Field(description="Aktywny profil ścisłości")
    profiles: list[str] = Field(description="Profile zdefiniowane w pliku")
    loaded_at: Optional[float] = Field(description="Kiedy wczytano obowiązującą wersję (sekundy od epoki)")
    overridden: list[str] = Field(description="Klucze nadpisane z interfejsu (wygrywają z plikiem i profilem)")
    last_changes: list[PolicyChange] = Field(description="Co zmieniło ostatnie przeładowanie")
    error: Optional[PolicyProblem] = Field(description="Błąd ostatniej próby przeładowania; wtedy obowiązuje "
                                                      "poprzednia poprawna wersja. null = plik jest poprawny")
    policy: Optional[dict[str, Any]] = Field(None, description="Cała obowiązująca polityka; tylko przy ?full=true")


class Health(ApiModel):
    status: str = Field(description='"ok" albo "degraded", gdy konfiguracja nie pozwala wołać modelu')
    provider: str
    model: str
    problem: Optional[str] = Field(None, description="Co jest nie tak z konfiguracją; null, gdy wszystko w porządku")
