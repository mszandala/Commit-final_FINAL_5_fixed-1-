"""Silnik proxy: jedno żądanie /v1/chat/completions przechodzi przez warstwę bezpieczeństwa.

Proxy stoi między aplikacją a modelem i nie wykonuje narzędzi: wywołania narzędzi widzi w odpowiedzi
modelu i ocenia, a ich wyniki widzi w kolejnym żądaniu (wiadomości `role: tool`). Model dostaje tylko dane
zamaskowane; klient dostaje odpowiedź z odwróconymi znacznikami (wg polityki roli) i argumenty narzędzi
z prawdziwymi wartościami.

Przebieg żądania, którego ostatnia wiadomość pochodzi od użytkownika (nowa tura):
  budżet roli -> sprawdzenie zapytania (model, długość, strażnik, intencja, regulaminy, maskowanie)
  -> wywołanie modelu -> ocena wywołań narzędzi (whitelist, budżet tury, kod, regulaminy)
     [odmowa: proxy samo ponawia pytanie z komunikatem odmowy, jak bramka w demo] -> filtr odpowiedzi.
Żądanie z wynikami narzędzi (ostatnia wiadomość `tool`) kontynuuje turę: wyniki są sprawdzane i maskowane,
zanim zobaczy je model.
"""
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Optional

import config
from audit import logger as audit
from core import Policy, get_store
from core.company import security_zone_classifier
from core.context import TurnContext
from core.models import Client
from core.notice import build_notice
from core.pii import well_formed
from core.stages import RequestDecision, check_request, check_response
from core.tool_guard import ToolDecision, ToolGuard
from security.budget import Budget
from security.company_policies import CompanyPolicyEngine
from security.pii.pii_detector import detect_pii

from .sessions import ProxySession, SessionStore, Turn, derived_session_id
from .upstream import OpenAIUpstream, Upstream, UpstreamError

log = logging.getLogger("control_layer.proxy")

ROLES = {"system", "developer", "user", "assistant", "tool"}
# Parametry zapytania przekazywane modelowi bez zmian; reszta (np. stream, n, user) jest odrzucana albo pomijana.
PASSTHROUGH = ("temperature", "top_p", "max_tokens", "max_completion_tokens", "stop", "seed", "presence_penalty",
               "frequency_penalty", "response_format", "tool_choice", "parallel_tool_calls")
NOT_EXECUTED = ("Not executed: another tool call in the same step was refused. "
                "Call only tools that are permitted, or answer without tools.")
# Wywołanie narzędzia wypisane jako tekst zamiast wykonane: <|tool_call>call:nazwa{...}<tool_call|>
RAW_TOOL_CALL = re.compile(r"<\|?tool_call\|?>|\bcall:\w+\{")
RETRY_MESSAGE = ("Your previous message contained a tool call written as plain text, so it was not executed. "
                 "If you need a tool, call it through the tool interface; otherwise answer in plain text.")


class ProxyError(Exception):
    """Błąd zwracany klientowi w formacie błędu OpenAI."""

    def __init__(self, status: int, message: str, code: str = "invalid_request_error"):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


@dataclass
class ProxyResult:
    body: dict
    headers: dict
    report: dict


@dataclass
class _Run:
    """Stan jednego żądania HTTP."""
    client: Client
    policy: Policy
    session: ProxySession
    ctx: TurnContext
    events: list
    started: float
    model: str
    tokens: int = 0
    cost: float = 0.0
    guard: Optional[ToolGuard] = None
    request: Optional[RequestDecision] = None
    masked_prompt: str = ""
    entities: list = field(default_factory=list)
    degraded: bool = False        # tura wznowiona bez zapisanego stanu


# --- detektor PII z pamięcią podręczną -------------------------------------------------------------------------

@lru_cache(maxsize=512)
def _detect_cached(text: str, threshold: Optional[float]) -> tuple:
    return tuple(tuple(sorted(e.items())) for e in detect_pii(text, threshold=threshold))


def default_detect(text: str, threshold: Optional[float] = None) -> list[dict]:
    return [e for e in (dict(e) for e in _detect_cached(text, threshold)) if well_formed(e, text)]


# --- pomocnicze ------------------------------------------------------------------------------------------------

def _text(content: Any) -> str:
    """Treść wiadomości jako tekst; obsługiwany jest tylko tekst (też jako lista części `text`)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                parts.append(part["text"])
            else:
                raise ProxyError(400, "Only text content is supported", "unsupported_content")
        return "\n".join(parts)
    raise ProxyError(400, "Invalid message content")


def _completion(model: str, content: Optional[str], tool_calls: Optional[list], finish: str, usage: dict,
                security: dict) -> dict:
    message: dict = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex, "object": "chat.completion", "created": int(time.time()),
        "model": model, "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": usage, "x_security": security,
    }


class ProxyEngine:
    def __init__(self, store=None, upstream: Optional[Upstream] = None, detect: Optional[Callable] = None,
                 budget: Optional[Budget] = None, sessions: Optional[SessionStore] = None,
                 on_turn: Optional[Callable[[dict], None]] = None, conduct_rules: Optional[Callable[[], str]] = None):
        self._store = store
        self.upstream = upstream or OpenAIUpstream()
        self.detect = detect or default_detect
        self.budget = budget or Budget(policy=self.policy)
        self.sessions = sessions or SessionStore()
        self.on_turn = on_turn
        self._conduct_rules = conduct_rules or self._read_conduct_rules
        self._company: Optional[CompanyPolicyEngine] = None

    # --- polityka i klienci ---

    @property
    def store(self):
        return self._store or get_store()

    def policy(self) -> Policy:
        return self.store.get()

    def authenticate(self, header: Optional[str]) -> Client:
        if not header or len(header) > 512 or not header.startswith("Bearer "):
            raise ProxyError(401, "Missing or malformed Authorization header (expected: Bearer <key>)",
                             "invalid_api_key")
        client = self.policy().client_for_key(header[7:].strip())
        if client is None:
            raise ProxyError(401, "Invalid API key", "invalid_api_key")
        return client

    def models(self) -> list[str]:
        policy = self.policy()
        names = [m for m in policy.models.allowed if "*" not in m]
        default = policy.proxy.default_model or config.MODEL
        return names if default in names else [default, *names]

    # --- żądanie ---

    def complete(self, client: Client, payload: Any, session_header: Optional[str] = None) -> ProxyResult:
        started = time.perf_counter()
        policy = self.policy()
        self._validate(payload, policy)
        messages = payload["messages"]
        model = payload.get("model") or policy.proxy.default_model or config.MODEL
        session_id = (session_header or "").strip()[:64] or derived_session_id(client.name, messages)
        session = self.sessions.get(client.name, session_id, client.role, policy.proxy.session_ttl_seconds,
                                    policy.proxy.max_sessions)
        with session.lock:
            events = audit.start_turn()
            session.turns += 1
            threshold = policy.controls.pii.threshold
            ctx = TurnContext(session.conv, policy, self.detect, self._engine_factory(policy), threshold)
            run = _Run(client, policy, session, ctx, events, started, model)
            try:
                return self._run(run, payload, messages)
            except ProxyError:
                audit.flush(events, conversation=session.id, role=session.conv.role, turn=session.turns,
                            client=client.name)
                raise

    def _validate(self, payload: Any, policy: Policy) -> None:
        if not isinstance(payload, dict):
            raise ProxyError(400, "The request body must be a JSON object")
        if payload.get("stream"):
            raise ProxyError(400, "stream=true is not supported yet; send stream=false", "unsupported_parameter")
        if payload.get("n", 1) != 1:
            raise ProxyError(400, "Only n=1 is supported", "unsupported_parameter")
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ProxyError(400, "messages must be a non-empty list")
        if len(messages) > policy.proxy.max_messages:
            raise ProxyError(413, f"Too many messages (limit: {policy.proxy.max_messages})")
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in ROLES:
                raise ProxyError(400, f"Each message needs a role from: {', '.join(sorted(ROLES))}")
            if message["role"] == "tool" and not isinstance(message.get("tool_call_id"), str):
                raise ProxyError(400, "A tool message needs a tool_call_id")
            for call in message.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, dict) else None
                if (not isinstance(function, dict) or not isinstance(function.get("name"), str)
                        or not isinstance(call.get("id"), str)):
                    raise ProxyError(400, "Invalid tool_calls in an assistant message")
        for tool in payload.get("tools") or []:
            function = tool.get("function") if isinstance(tool, dict) else None
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise ProxyError(400, "Invalid tools definition")
        model = payload.get("model")
        if model is not None and not isinstance(model, str):
            raise ProxyError(400, "model must be a string")

    def _engine_factory(self, policy: Policy) -> Callable[[], Optional[CompanyPolicyEngine]]:
        if not policy.filter_on("company_policies"):
            return lambda: None

        def factory():
            if self._company is None:
                known = lambda: self.policy().roles          # noqa: E731 - żywa lista ról z polityki
                self._company = (CompanyPolicyEngine(classifier=security_zone_classifier, known_roles=known)
                                 if policy.controls.company_policies.classifier == "security"
                                 else CompanyPolicyEngine(known_roles=known))
            return self._company
        return factory

    @staticmethod
    def _read_conduct_rules() -> str:
        path = config.CONDUCT_RULES_FILE
        return path.read_text(encoding="utf-8") if path.exists() else ""

    # --- przebieg ---

    def _run(self, run: _Run, payload: dict, messages: list) -> ProxyResult:
        last = messages[-1]
        fresh = last["role"] == "user"
        if fresh:
            early = self._begin_turn(run, _text(last.get("content")))
            if early is not None:
                return early
        elif last["role"] == "tool":
            self._resume_turn(run, messages)
        else:
            raise ProxyError(400, "The last message must come from the user or be a tool result")
        turn = run.session.turn
        run.guard = ToolGuard(run.ctx, lambda: (turn.tokens, turn.cost), turn.limits)
        params = self._params(payload, run.model, self._upstream_messages(run, messages, fresh))
        return self._converse(run, params, [t["function"]["name"] for t in payload.get("tools") or []])

    def _begin_turn(self, run: _Run, user_text: str) -> Optional[ProxyResult]:
        role, session = run.session.conv.role, run.session
        over = self.budget.check(role, user_text)
        if over:
            audit.record("budget", "security", reason=over["reason"])
            return self._reply(run, f"Request blocked: {over['reason']}", verdict=over)
        request = check_request(run.ctx, user_text, model=run.model)
        run.request, run.masked_prompt, run.entities = request, request.masked_prompt, request.entities
        if request.blocked:
            return self._reply(run, request.reply, verdict=request.verdict)
        session.turn = Turn(request, user_text, run.model, self._limits(role))
        return None

    def _resume_turn(self, run: _Run, messages: list) -> None:
        session = run.session
        if session.turn is None:
            # Sesja wygasła albo żądanie przyszło bez stanu: wznawiamy turę na podstawie ostatniej wiadomości
            # użytkownika. Wyniki narzędzi i tak przechodzą pełne sprawdzenie, a historia jest maskowana.
            text = next((_text(m.get("content")) for m in reversed(messages) if m["role"] == "user"), "")
            request = RequestDecision(False, masked_prompt="")
            session.turn = Turn(request, text, run.model, self._limits(session.conv.role), degraded=True)
            run.degraded = True
        run.request = session.turn.request

    def _limits(self, role: str) -> dict:
        return {"tokens": self.budget.token_limit(role) - self.budget.tokens_used(role),
                "cost": self.budget.spending_limit() - self.budget.spent(role)}

    # --- wiadomości dla modelu ---

    def _mask(self, run: _Run, text: str) -> str:
        """Tekst z historii rozmowy w wersji, którą wolno pokazać modelowi (zapamiętane wartości i wykryte PII)."""
        if not text or not run.policy.controls.pii.mask_in_chatbot_channel:
            return text
        key = hashlib.sha1(text.encode("utf-8")).hexdigest()
        cached = run.session.text_cache.get(key)
        if cached is not None:
            return cached
        policy, vault = run.policy, run.ctx.conv.vault
        sensitive = [e for e in run.ctx.detect(text, run.ctx.threshold) if policy.chatbot_action(e["type"]) != "allow"]
        masked = vault.mask_known(vault.mask_entities(text, sensitive))
        run.session.remember(run.session.text_cache, key, masked)
        return masked

    def _tool_result(self, run: _Run, message: dict, calls: dict) -> str:
        """Wynik narzędzia po sprawdzeniu i zamaskowaniu; każdy wynik jest sprawdzany raz na sesję."""
        call_id = message["tool_call_id"]
        cached = run.session.tool_cache.get(call_id)
        if cached is not None:
            return cached
        name, args = calls.get(call_id, (message.get("name") or "unknown", {}))
        record = {"tool": name, "args": args, "allowed": True}
        outcome = run.guard.after(name, record, _text(message.get("content")))
        audit.record("tool_result", "security", tool=name, allowed=outcome.allowed, scan=outcome.scan,
                     masked=outcome.stats, result_chars=len(outcome.text), truncated_chars=outcome.cut)
        run.session.remember(run.session.tool_cache, call_id, outcome.text)
        return outcome.text

    def _upstream_messages(self, run: _Run, messages: list, fresh: bool) -> list:
        calls = {}
        for message in messages:
            for call in message.get("tool_calls") or []:
                try:
                    args = json.loads(call["function"].get("arguments") or "{}")
                except ValueError:
                    args = {}
                calls[call["id"]] = (call["function"]["name"], args if isinstance(args, dict) else {})
        first_user = next(i for i, m in enumerate(messages) if m["role"] == "user")
        last_user = max(i for i, m in enumerate(messages) if m["role"] == "user")
        notice = build_notice(run.session.conv.role, run.policy, self._conduct_rules())
        out = []
        for i, message in enumerate(messages):
            role = message["role"]
            if role == "user":
                text = run.masked_prompt if (fresh and i == last_user) else self._mask(run, _text(message.get("content")))
                out.append({"role": "user", "content": (notice + text) if i == first_user else text})
            elif role == "tool":
                out.append({"role": "tool", "tool_call_id": message["tool_call_id"],
                            "content": self._tool_result(run, message, calls)})
            elif role == "assistant":
                entry = {"role": "assistant", "content": self._mask(run, _text(message.get("content"))) or None}
                if message.get("tool_calls"):
                    entry["tool_calls"] = [
                        {"id": c["id"], "type": "function",
                         "function": {"name": c["function"]["name"],
                                      "arguments": self._mask(run, c["function"].get("arguments") or "{}")}}
                        for c in message["tool_calls"]]
                out.append(entry)
            else:
                out.append({"role": "system", "content": self._mask(run, _text(message.get("content")))})
        return out

    @staticmethod
    def _params(payload: dict, model: str, messages: list) -> dict:
        params: dict = {"model": model, "messages": messages}
        for key in PASSTHROUGH:
            if payload.get(key) is not None:
                params[key] = payload[key]
        if payload.get("tools"):
            params["tools"] = payload["tools"]
        return params

    # --- rozmowa z modelem ---

    def _call_model(self, run: _Run, params: dict) -> dict:
        try:
            response = self.upstream(params)
        except UpstreamError as exc:
            audit.record("error", "chatbot", error=exc.kind)
            raise ProxyError(exc.status if exc.status in (401, 403, 404, 429, 503) else 502,
                             "The upstream model failed to answer", "upstream_error") from None
        usage = response.get("usage") or {}
        tokens, cost = int(usage.get("total_tokens") or 0), float(usage.get("cost") or 0)
        audit.record("llm_call", "chatbot", purpose="chat", provider="upstream", model=params["model"],
                     messages=len(params["messages"]), tokens=tokens, cost=cost)
        turn = run.session.turn
        turn.tokens += tokens
        turn.cost += cost
        run.tokens += tokens
        run.cost += cost
        self.budget.add(run.session.conv.role, tokens, cost, params["model"])
        return response

    def _judge_call(self, run: _Run, call: dict) -> ToolDecision:
        name = call["function"]["name"]
        try:
            args = json.loads(call["function"].get("arguments") or "{}")
            if not isinstance(args, dict):
                raise ValueError("not an object")
        except ValueError:
            reason = "Argumenty wywołania nie są poprawnym obiektem JSON"
            record = {"tool": name, "args": {}, "allowed": False, "stage": "tool_arguments", "reason": reason}
            run.guard.calls.append(record)
            audit.record("tool_call", "security", tool=name, allowed=False, args={}, stage="tool_arguments",
                         reason=reason)
            run.session.turn.denied.add(name)
            return ToolDecision(False, record, "Tool call refused: the arguments are not a valid JSON object. "
                                               "Call the tool again with valid JSON arguments.")
        decision = run.guard.before(name, args)
        if not decision.allowed:
            run.session.turn.denied.add(name)
        else:
            local = not run.policy.tool(name).chatbot_zone
            audit.record("tool_call", "local" if local else "chatbot", tool=name, allowed=True, args=args)
        return decision

    def _converse(self, run: _Run, params: dict, client_tools: list) -> ProxyResult:
        reasks = run.policy.proxy.max_reasks
        refused: list[ToolDecision] = []
        for attempt in range(reasks + 1):
            response = self._call_model(run, params)
            message = ((response.get("choices") or [{}])[0].get("message")) or {}
            content, calls = message.get("content") or "", message.get("tool_calls") or []
            if calls:
                decisions = [self._judge_call(run, call) for call in calls]
                if all(d.allowed for d in decisions):
                    return self._tool_calls(run, calls, decisions)
                refused = [d for d in decisions if not d.allowed]
                if attempt < reasks:
                    results = [{"role": "tool", "tool_call_id": call["id"], "content": d.message or NOT_EXECUTED}
                               for call, d in zip(calls, decisions)]
                    params["messages"] = params["messages"] + [
                        {"role": "assistant", "content": content or None, "tool_calls": calls}, *results]
                    continue
                break
            if RAW_TOOL_CALL.search(content):
                audit.record("retry", "chatbot", reason="tool call written as text")
                if attempt < reasks:
                    params["messages"] = params["messages"] + [
                        {"role": "assistant", "content": content}, {"role": "user", "content": RETRY_MESSAGE}]
                    continue
                audit.record("error", "chatbot", error="MalformedToolCall")
                raise ProxyError(502, "The upstream model did not return an answer", "upstream_error")
            return self._final(run, content, client_tools)
        call = refused[-1].call
        reason = call.get("reason") or "Tool call is not permitted"
        verdict = {"decision": "block", "stage": call.get("stage") or "tool_whitelist", "reason": reason}
        return self._reply(run, f"Response blocked: {reason}", verdict=verdict)

    def _tool_calls(self, run: _Run, calls: list, decisions: list[ToolDecision]) -> ProxyResult:
        """Wywołania dozwolone: klient dostaje je z prawdziwymi wartościami argumentów i sam je wykonuje."""
        tool_calls = [{"id": call["id"], "type": "function",
                       "function": {"name": call["function"]["name"],
                                    "arguments": json.dumps(d.real_args, ensure_ascii=False)}}
                      for call, d in zip(calls, decisions)]
        return self._reply(run, None, tool_calls=tool_calls, finish="tool_calls")

    def _final(self, run: _Run, content: str, client_tools: list) -> ProxyResult:
        turn = run.session.turn
        response = check_response(run.ctx, content, turn.user_message, turn.request,
                                  denied_tools=sorted(turn.denied), tool_names=client_tools)
        run.session.turn = None
        return self._reply(run, response.reply, verdict=response.verdict, response=response)

    # --- odpowiedź ---

    def _reply(self, run: _Run, content: Optional[str], *, tool_calls: Optional[list] = None,
               finish: str = "stop", verdict: Optional[dict] = None, response: Any = None) -> ProxyResult:
        session, request = run.session, run.request
        blocked = bool(verdict and verdict["decision"] == "block")
        if blocked:
            session.turn = None
        verdicts = [verdict] if verdict else []
        if request is not None and request.flagged and not (verdict and verdict["stage"] == "prompt_guard"):
            verdicts.append({"decision": "warn", "stage": "prompt_guard", "reason": request.guard_reason})
        calls = run.guard.calls if run.guard else []
        stopped = next((c for c in calls if c.get("stage") == "budget"), None)
        if stopped:
            verdicts.append({"decision": "warn", "stage": "budget",
                             "reason": f"Przerwano wywołania narzędzi: {stopped['reason']}"})
        refusal = response.refusal if response is not None else None
        if refusal and refusal is not verdict:
            verdicts.append(refusal)
        decision = verdict["decision"] if verdict else "pass"
        entities = run.entities if request is not None else []
        masked_for_model = sorted({e["type"] for e in entities if e.get("decision") == "mask"})
        latency = int((time.perf_counter() - run.started) * 1000)
        logged = response.logged_reply if response is not None else ""
        audit.record("turn", "security", blocked=blocked, block_reason=verdict["stage"] if blocked else None,
                     verdict=verdict, reply=logged, leaks_to_chatbot=0, vault_size=len(session.conv.vault),
                     tokens=run.tokens, cost=run.cost, security_tokens=0, security_cost=0.0, latency_ms=latency)
        audit.flush(run.events, conversation=session.id, role=session.conv.role, turn=session.turns,
                    client=run.client.name)
        status = self.store.status()
        security = {
            "decision": decision, "verdict": verdict, "verdicts": verdicts, "session_id": session.id,
            "masked_for_model": masked_for_model, "latency_ms": latency,
            "tools": [{"tool": c["tool"], "allowed": c["allowed"], "stage": c.get("stage"), "reason": c.get("reason")}
                      for c in calls],
            "policy": {"version": status["version"], "digest": status["digest"], "profile": status["profile"]},
            "degraded": run.degraded,
        }
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": run.tokens}
        body = _completion(run.model, content, tool_calls, finish, usage, security)
        headers = {"X-Session-Id": session.id, "X-Security-Decision": decision,
                   "X-Policy-Version": str(status["version"])}
        report = {
            "role": session.conv.role, "conversation_id": session.id, "verdict": verdict, "verdicts": verdicts,
            "reply": content or "", "blocked": blocked, "block_reason": verdict["stage"] if blocked else None,
            "masked_prompt": run.masked_prompt, "entities": entities, "masked_for_model": masked_for_model,
            "tool_calls": calls, "output": response.output if response is not None else
            {"entities": [], "restored": [], "redacted": [], "blocked": [], "exempt": [], "found": []},
            "events": run.events, "tokens": run.tokens, "cost": run.cost, "latency_ms": latency,
            "guard": request.guard if request is not None else None, "client": run.client.name,
        }
        if self.on_turn:
            try:
                self.on_turn(report)
            except Exception:       # raport do panelu nie może zepsuć odpowiedzi
                log.exception("on_turn failed")
        return ProxyResult(body, headers, report)
