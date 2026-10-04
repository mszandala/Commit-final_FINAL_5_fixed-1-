import re
from typing import TYPE_CHECKING, Optional

from security.common.roles import normalize_role
from security.common.verdicts import Verdict

if TYPE_CHECKING:
    from core.models import Policy

# "Ignore directive" pattern: verb, up to four modifiers ("all previous", "wszystkie
# poprzednie", "o wszystkich") and the target object to ignore.
_IGNORE_VERBS = r"(?:ignor\w*|zignoruj\w*|disregard|forget|override|pomi[ńn]\w*|zapomnij|zlekceważ\w*)"
_MODIFIERS = (r"(?:all|any|every|the|your|of|previous|prior|above|earlier|former|those|these|about|"
              r"safety|security|system|content|ethical|bezpiecze\w*|systemow\w*|"
              r"wszystk\w*|wszelk\w*|poprzedni\w*|powyższ\w*|wcześniejsz\w*|dotychczasow\w*|swoje|twoje|moje|o)")
_TARGETS = (r"(?:instructions?|rules|prompts?|guidelines|directives|constraints|restrictions|"
            r"instrukcj\w*|zasad\w*|polece\w*|regu[łl]\w*|wytyczn\w*|ogranicze\w*|zabezpiecze\w*)")

# Known attack patterns (Jailbreak / Prompt Injection)
INJECTION_PATTERNS = [
    (r"\b(?:dan|do anything now)\b", "Detected DAN (Do Anything Now) jailbreak signature"),
    (rf"\b{_IGNORE_VERBS}\s+(?:{_MODIFIERS}\s+){{0,4}}{_TARGETS}", "Detected attempt to ignore system instructions"),
    (r"(?:from now on you are|od teraz jesteś|act as|wciel się w)", "Detected attempt to override model identity or role"),
    (r"(?:new system directive|system prompt override|---BEGIN RESPONSE---)", "Detected attempt to inject system directive"),
    (r"[A-Za-z0-9+/=]{50,}", "Detected potentially obfuscated Base64 / Payload"),
    (r"(?:jestem adminem|i am (?:the )?admin|bypass (?:all )?restrictions|bez ograniczeń)", "Detected attempt to impersonate administrator or bypass policies"),
]

# Keywords (stems for inflection support) indicating resource from config.RESOURCE_TOOLS.
RESOURCE_KEYWORDS = {
    "employee_data": [
        "salary", "salaries", "payroll", "monthlyincome", "monthly income", "employee", "attrition",
        "pensj", "wynagrodze", "zarob", "pracowni", "kadr", "rotacj",
    ],
    "client_data": [
        "customer", "client", "credit score", "credit_score", "churn",
        "klient", "scoring", "saldo", "salda",
    ],
    "bank_campaigns": [
        "campaign", "term deposit", "kampani", "lokat",
    ],
    "stock_prices": [
        "stock price", "closing price", "trading volume", "ticker", "nasdaq", "nyse",
        "notowa", "kurs akcji", "kursy akcji", "giełd",
    ],
    "earnings_calls": [
        "earnings call", "transcript", "telekonferencj", "transkrypcj",
    ],
}

RESOURCE_LABELS = {
    "employee_data":  "HR and payroll data",
    "client_data":    "bank customer data",
    "bank_campaigns": "bank campaign data",
    "stock_prices":   "stock market quotes",
    "earnings_calls": "earnings call transcripts",
}

_INJECTION_REGEXES = [(re.compile(p, re.IGNORECASE), d) for p, d in INJECTION_PATTERNS]


def _check_heuristic_injections(text: str) -> Optional[str]:
    """Fast regex-based injection/jailbreak pattern detection."""
    for pattern, description in _INJECTION_REGEXES:
        if pattern.search(text):
            return description
    return None


def _role_access(canonical_role: str, policy: Optional["Policy"]) -> tuple[set, dict]:
    """(role tools, resource tools dict) from policy or fallback to config.py."""
    if policy is not None:
        cfg = policy.role(canonical_role)
        return (set(cfg.allowed_tools) if cfg else set()), policy.resources
    import config
    return set(config.ROLES.get(canonical_role, {}).get("allowed_tools", [])), config.RESOURCE_TOOLS


def _check_role_resource_access(canonical_role: str, text: str,
                                policy: Optional["Policy"] = None) -> Optional[tuple[str, str]]:
    """Checks whether prompt requests a resource whose tools the role lacks."""
    allowed_tools, resource_tools = _role_access(canonical_role, policy)
    text_lower = text.lower()

    for resource, keywords in RESOURCE_KEYWORDS.items():
        if not any(k in text_lower for k in keywords):
            continue
        tools = resource_tools.get(resource)
        if tools and allowed_tools.isdisjoint(tools):       # resource without assigned tools does not restrict role
            return resource, f"Role '{canonical_role}' does not have access to {RESOURCE_LABELS[resource]}."
    return None


def check_prompt(role: str, user_prompt: str, policy: Optional["Policy"] = None) -> Verdict:
    """Evaluates user prompt for security and role compliance.

    Roles and resources are obtained from `policy`; fallback to config.py if None.
    """
    canonical_role = normalize_role(role)
    clean_prompt = (user_prompt or "").strip()

    if not clean_prompt:
        return Verdict(
            decision="pass",
            reason="Empty prompt",
            stage="prompt_guard",
            is_blocked=False,
            details={"role": canonical_role, "suspicious": False},
        )

    # 1. Heuristic pattern checks (Prompt Injection / Jailbreak)
    injection_reason = _check_heuristic_injections(clean_prompt)
    if injection_reason:
        return Verdict(
            decision="warn",
            reason=f"[PROMPT GUARD WARNING] {injection_reason}",
            stage="prompt_guard",
            is_blocked=False,
            details={
                "role": canonical_role,
                "suspicious": True,
                "attack_type": "Prompt_Injection",
                "warning": injection_reason,
            },
        )

    # 2. RBAC resource scope check
    resource_violation = _check_role_resource_access(canonical_role, clean_prompt, policy)
    if resource_violation:
        resource_name, violation_reason = resource_violation
        return Verdict(
            decision="warn",
            reason=f"[PROMPT GUARD WARNING] {violation_reason}",
            stage="prompt_guard",
            is_blocked=False,
            details={
                "role": canonical_role,
                "suspicious": False,
                "requested_resource": resource_name,
                "warning": violation_reason,
            },
        )

    # 3. Request compliant with role scope
    return Verdict(
        decision="pass",
        reason="Prompt compliant with role and safe",
        stage="prompt_guard",
        is_blocked=False,
        details={
            "role": canonical_role,
            "suspicious": False,
            "warning": None,
        },
    )
