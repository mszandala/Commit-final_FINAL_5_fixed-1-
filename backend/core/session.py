"""Stan jednej rozmowy po stronie warstwy bezpieczeństwa."""
import uuid
from dataclasses import dataclass, field
from typing import Optional

from security.common.roles import normalize_role
from security.masking import Vault


@dataclass
class Conversation:
    """Stan jednej rozmowy. Historia należy do strefy chatbota, więc zawiera tylko dane zamaskowane."""
    role: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    history: Optional[list] = None
    vault: Vault = field(default_factory=Vault)
    user_texts: list = field(default_factory=list)     # surowe prompty: wartości, które użytkownik sam podał
    public_texts: list = field(default_factory=list)   # wyniki narzędzi czytających źródła publiczne
    private_context: bool = False                      # czy do rozmowy trafił wynik narzędzia niepublicznego
    turns: int = 0

    def __post_init__(self):
        self.role = normalize_role(self.role)
