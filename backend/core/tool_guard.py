"""Bramka narzędzi: decyzje przed wykonaniem narzędzia i po nim.

Bramka niczego nie wykonuje. `before()` rozstrzyga, czy wywołanie wolno wykonać (whitelist roli,
budżet tury, strażnik kodu, regulaminy na argumentach) i podaje argumenty z prawdziwymi wartościami.
`after()` sprawdza wynik, zanim zobaczy go model (regulaminy, maskowanie, przycięcie). Wykonanie
narzędzia należy do wywołującego: w demo jest to pipeline, w proxy będzie to aplikacja klienta,
a bramka zobaczy wynik w kolejnym żądaniu.
"""
from dataclasses import dataclass, field
from typing import Callable, Optional

from audit import logger as audit
from security import masking
from security.code_guard import check_code
from security.pii.regex_detector import detect_regex_pii

from .company import record_check, soften
from .context import TurnContext
from .models import Policy

BUDGET_MESSAGE = ("Tool call refused: the cost limit for this request is used up. Do not call any more tools. "
                  "Answer with what you already have and tell the user the request was too large to finish.")


class ToolWhitelist:
    """Whitelist narzędzi roli wg polityki. Każde wywołanie trafia do `calls` jako {"tool", "args",
    "allowed"}, a odrzucone dodatkowo z {"stage", "reason"} — z tego czyta interfejs. Na razie każde
    naruszenie traktujemy jak błąd modelu (pracuje dalej bez narzędzia)."""

    def __init__(self, policy: Policy, role: str):
        self.policy = policy
        self.role = role
        self.calls: list[dict] = []

    def __call__(self, name: str, args: dict) -> Optional[str]:
        allowed = self.policy.is_tool_allowed(self.role, name)
        call = {"tool": name, "args": args, "allowed": allowed}
        if not allowed:
            call.update(stage="tool_whitelist", reason=f"Narzędzie niedostępne dla roli „{self.role}”")
        self.calls.append(call)
        if allowed:
            return None
        areas = ", ".join(self.policy.role_areas(self.role)) or "none"
        return (
            f"Access denied: this data is not available for the user's role ('{self.role}'). "
            f"Data areas available to this role: {areas}. Do not make this call again. If an available area "
            "can answer the user's question, use it; otherwise tell the user this data is not available for "
            "their role. Do not mention the names of internal tools in your reply."
        )


@dataclass
class ToolDecision:
    """Wynik `before()`: czy wykonać narzędzie, a przy odmowie — tekst dla modelu."""
    allowed: bool
    call: dict                              # wpis w `calls` (czyta go interfejs)
    message: Optional[str] = None           # odmowa pokazywana modelowi
    real_args: dict = field(default_factory=dict)   # argumenty z prawdziwymi wartościami (po odmaskowaniu)


@dataclass
class ToolOutcome:
    """Wynik `after()`: tekst dla modelu (wynik albo odmowa) i szczegóły do logu."""
    allowed: bool
    text: str
    scan: str = "none"
    stats: dict = field(default_factory=dict)
    cut: int = 0


class ToolGuard:
    def __init__(self, ctx: TurnContext, spent: Callable[[], tuple[int, float]],
                 limits: Optional[dict] = None):
        self.ctx = ctx
        self.whitelist = ToolWhitelist(ctx.policy, ctx.role)
        self.spent = spent
        # Limit tury to mniejsza z wartości: stały limit jednej tury i to, co zostało roli w budżecie.
        limits = limits or {}
        per_turn = ctx.policy.budgets.per_turn
        self.token_limit = min(per_turn.max_tokens, limits.get("tokens", per_turn.max_tokens))
        self.cost_limit = min(per_turn.max_cost_usd, limits.get("cost", per_turn.max_cost_usd))

    @property
    def calls(self) -> list[dict]:
        return self.whitelist.calls

    def _over_limit(self) -> Optional[str]:
        tokens, cost = self.spent()
        if tokens >= self.token_limit:
            return f"Tura zużyła {tokens} tokenów; limit to {self.token_limit}"
        if cost >= self.cost_limit:
            return f"Tura kosztowała ${cost:.4f}; limit to ${self.cost_limit:.4f}"
        return None

    def _deny(self, call: dict, name: str, args: dict, stage: str, reason: str, **extra) -> None:
        call.update(allowed=False, stage=stage, reason=reason)
        audit.record("tool_call", "security", tool=name, allowed=False, args=args, stage=stage, reason=reason,
                     **extra)

    def before(self, name: str, args: dict) -> ToolDecision:
        ctx, policy = self.ctx, self.ctx.policy
        if policy.filter_on("tool_whitelist"):
            refusal = self.whitelist(name, args)
        else:
            self.whitelist.calls.append({"tool": name, "args": args, "allowed": True})
            refusal = None
        # Subagent dopisuje własne wywołania do `calls`, zanim to się skończy — trzymamy własny wpis.
        call = self.calls[-1]
        if refusal is not None:
            audit.record("tool_call", "security", tool=name, allowed=False, args=args, stage="tool_whitelist",
                         reason=call.get("reason"))
            return ToolDecision(False, call, refusal)

        # Zbyt droga tura: kolejne narzędzia nie ruszają, model ma odpowiedzieć z tego, co już zebrał.
        over = self._over_limit()
        if over:
            self._deny(call, name, args, "budget", over)
            return ToolDecision(False, call, BUDGET_MESSAGE)

        # Kod do uruchomienia sprawdzamy tu, żeby odrzucenie było widoczne jako decyzja warstwy
        # bezpieczeństwa, a nie tylko jako tekst błędu narzędzia.
        if name == "run_python" and policy.filter_on("code_guard"):
            verdict = check_code(str(args.get("code", "")))
            if verdict.is_blocked:
                self._deny(call, name, args, "code_guard", verdict.reason,
                           attack_type=verdict.details.get("attack_type"))
                return ToolDecision(False, call, f"Code rejected by security policy: {verdict.reason}")

        # Narzędzia działają lokalnie na prawdziwych wartościach. Wyjątek: subagent, którego
        # argument trafia z powrotem do modelu w chmurze.
        local = not policy.tool(name).chatbot_zone
        mask_on = policy.controls.pii.mask_in_chatbot_channel
        real_args = ctx.conv.vault.unmask_args(args) if local and mask_on else args

        # Regulaminy firmowe: argumenty wywołania.
        if ctx.engine:
            verdict, softened = soften(policy, ctx.engine, ctx.role, "",
                                       ctx.engine.check_tool_call(ctx.role, name, real_args), point="input")
            record_check("tool", verdict, softened)
            if verdict.decision in ("block", "redact"):
                self._deny(call, name, args, verdict.stage, verdict.reason)
                return ToolDecision(False, call, f"Access denied by company policy: {verdict.reason} Do not call "
                                                 "this tool again with this data. Tell the user the request is "
                                                 "not allowed.")
        return ToolDecision(True, call, real_args=real_args)

    def after(self, name: str, call: dict, raw_result: str) -> ToolOutcome:
        """Sprawdza wynik narzędzia; `call` to wpis zwrócony przez `before()`."""
        ctx, policy = self.ctx, self.ctx.policy
        meta = policy.tool(name)
        local = not meta.chatbot_zone
        result = masking.sanitize_paths(raw_result)

        # Regulaminy firmowe: wynik, zanim zobaczy go model.
        if ctx.engine and local:
            verdict, softened = soften(policy, ctx.engine, ctx.role, result,
                                       ctx.engine.filter_context(ctx.role, result, source=name),
                                       point="retrieval", public_only=meta.public)
            record_check("retrieval", verdict, softened)
            if verdict.decision == "block":
                self._deny(call, name, call["args"], verdict.stage, verdict.reason)
                return ToolOutcome(False, f"Tool result withheld by company policy: {verdict.reason}")
            result = verdict.details.get("redacted_text") or result
        masked, scan, stats = self._mask_result(name, result)
        max_chars = policy.budgets.per_turn.max_tool_result_chars
        cut = max(0, len(masked) - max_chars)
        if cut:
            masked = (masked[:max_chars]
                      + f"\n[truncated: {cut} more characters; narrow the request to see the rest]")
        if meta.public:
            ctx.conv.public_texts.append(masked)
        else:
            ctx.conv.private_context = True
        return ToolOutcome(True, masked, scan, stats, cut)

    def _mask_result(self, name: str, result: str) -> tuple[str, str, dict]:
        ctx, policy = self.ctx, self.ctx.policy
        meta = policy.tool(name)
        if not policy.controls.pii.mask_in_chatbot_channel or meta.scan == "none":
            return result, "none", {}
        vault = ctx.conv.vault
        if meta.scan == "columns":
            masked, stats = masking.mask_csv(result, meta.column_types, policy.pii_policy_for(ctx.role), vault)
        else:
            found = detect_regex_pii(result) if meta.scan == "regex" else ctx.detect(result, ctx.threshold)
            sensitive = [e for e in found if policy.chatbot_action(e["type"]) != "allow"]
            masked = vault.mask_entities(result, sensitive)
            stats = {"masked": len(sensitive)}
        return vault.mask_known(masked), meta.scan, stats
