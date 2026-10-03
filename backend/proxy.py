"""Small authenticated, non-streaming Gemma 4 proxy with server-side tools."""

import asyncio
import hmac
import inspect
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from chatbot.agent import ResponseBlocked, run_agent
from config import LLM_PROVIDER, OPENROUTER_MODEL, ROLES
from security.pii.pii_detector import detect_pii
from security.pii.pii_policy import check_pii
from security.prompt_guard import check_prompt
from security.tool_whitelist import ToolGate
from tools.registry import TOOL_MAP, TOOLS, run_tool

MAX_BODY = 16384
# Generic file access and subagents are excluded until argument and nested-call policies exist.
PROXY_TOOLS = frozenset({"list_projects", "read_project", "read_employee_records", "read_client_records",
                        "read_bank_campaigns", "read_stock_prices", "list_earnings_calls", "read_earnings_call", "run_python"})


def load_keys():
    raw = json.loads(os.environ.get("PROXY_API_KEYS", "{}"))
    if not isinstance(raw, dict) or not raw or any(not isinstance(k, str) or len(k) < 16 or v not in ROLES for k, v in raw.items()):
        raise ValueError("PROXY_API_KEYS must map nonempty keys (at least 16 chars) to configured roles")
    return raw


def authorize(header, keys):
    if not header or len(header) > 512 or not header.startswith("Bearer "):
        return None
    token = header[7:]
    for key, role in keys.items():
        if hmac.compare_digest(key, token):
            return role
    return None


def make_gate(role):
    whitelist = ToolGate(role)
    allowed = set(ROLES[role]["allowed_tools"]) & PROXY_TOOLS

    def gate(name, args):
        if name not in allowed or not isinstance(args, dict) or whitelist(name, args) is not None:
            logging.warning("tool denied role=%s tool=%r", role, name)
            raise ResponseBlocked("Tool not allowed for this role")
        try:
            signature = inspect.signature(TOOL_MAP[name])
            bound = signature.bind(**args)
            for param, value in bound.arguments.items():
                expected = signature.parameters[param].annotation
                if expected in (str, int) and type(value) is not expected:
                    raise ValueError("Invalid argument type")
                if isinstance(value, str) and len(value) > (8192 if param == "code" else 512):
                    raise ValueError("Argument too large")
        except (TypeError, ValueError) as exc:
            logging.warning("tool arguments rejected role=%s tool=%r", role, name)
            raise ResponseBlocked("Invalid tool arguments") from exc
        result = run_tool(name, args)
        if result.startswith("Tool error:") or (name == "run_python" and result.startswith("Python executor ")):
            logging.error("tool failed role=%s tool=%r", role, name)
            raise ResponseBlocked("Tool failed")
        logging.info("tool allowed role=%s tool=%r", role, name)
        return result

    tools = [fn for fn in TOOLS if fn.__name__ in allowed]
    return gate, tools


@asynccontextmanager
async def lifespan(application):
    if LLM_PROVIDER != "openrouter" or not os.environ.get("OPENROUTER_API_KEY"):
        raise RuntimeError("Proxy requires LLM_PROVIDER=openrouter and OPENROUTER_API_KEY")
    application.state.api_keys = load_keys()
    logging.basicConfig(level=logging.INFO)
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def error(status, message):
    return JSONResponse(status_code=status, content={"error": {"message": message}})


def complete(role, prompt):
    if check_prompt(role, prompt).decision != "pass":
        return error(403, "Prompt not permitted")
    gate, tools = make_gate(role)
    answer, _ = run_agent(prompt, tool_gate=gate, tools=tools)
    verdict = check_pii(role, answer, detect_pii(answer))
    if verdict.is_blocked:
        return error(403, "Response blocked by data policy")
    if verdict.decision == "redact":
        answer = verdict.details["redacted_text"]
    return {"id": "chatcmpl-" + uuid.uuid4().hex, "object": "chat.completion",
            "model": OPENROUTER_MODEL, "choices": [{"index": 0, "message": {"role": "assistant", "content": answer},
                                             "finish_reason": "stop"}]}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    role = authorize(request.headers.get("Authorization"), request.app.state.api_keys)
    if role is None:
        return error(401, "Unauthorized")
    try:
        size = int(request.headers.get("Content-Length", "0"))
    except ValueError:
        return error(400, "Invalid request size")
    if size < 1 or size > MAX_BODY:
        return error(413, "Invalid request size")
    body = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY:
                    return error(413, "Invalid request size")
                body.extend(chunk)
    except TimeoutError:
        return error(408, "Request timed out")
    if len(body) != size:
        return error(400, "Invalid request size")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return error(400, "Invalid JSON request")
    if not isinstance(payload, dict) or set(payload) - {"messages", "model", "stream"}:
        return error(400, "Unsupported request fields")
    messages = payload.get("messages")
    if (payload.get("model", OPENROUTER_MODEL) != OPENROUTER_MODEL or payload.get("stream", False) is not False
            or not isinstance(messages, list) or len(messages) != 1 or not isinstance(messages[0], dict)
            or set(messages[0]) != {"role", "content"} or messages[0]["role"] != "user"
            or not isinstance(messages[0]["content"], str) or not messages[0]["content"].strip()):
        return error(400, "Expected one user message, fixed model, and stream=false")
    try:
        return await run_in_threadpool(complete, role, messages[0]["content"])
    except ResponseBlocked:
        return error(403, "Tool call blocked")
    except Exception as exc:
        logging.error("Proxy failed: %s", type(exc).__name__)
        return error(502, "Upstream or policy failure")
