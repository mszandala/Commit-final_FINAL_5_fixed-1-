from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Verdict:
    """Wspólna struktura wyniku oceny dla strażników i sędziów w warstwie bezpieczeństwa.

    Atrybuty:
        decision: Wynik decyzji - "pass" (zezwolono), "warn" (ostrzeżenie), "redact" (zamaskowano fragmenty),
            "block" (odmowa/blokada).
        reason: Uzasadnienie decyzji dla audytu i użytkownika.
        stage: Nazwa etapu oceny ("prompt_guard", "tool_whitelist", "tool_violation_judge", "pii_access_judge").
        details: Dodatkowe metadane (wykryte encje, brakujące uprawnienia, flagi podejrzliwości).
        is_blocked: Informacja, czy przetwarzanie ma zostać twardo przerwane (na obecnym etapie PoC False).
    """

    decision: str
    reason: str
    stage: str
    details: dict = field(default_factory=dict)
    is_blocked: bool = False

    @property
    def has_warning(self) -> bool:
        return self.decision == "warn" or bool(self.details.get("warning"))

    @property
    def warning(self) -> Optional[str]:
        if self.decision == "warn":
            return self.reason
        return self.details.get("warning")
