import json
import uuid
from types import SimpleNamespace
from typing import Optional

import ollama
from openai import OpenAI

from audit import logger as audit
from config import (
    LLM_PROVIDER,
    MODEL,
    OLLAMA_MODEL,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    SECURITY_MODEL,
    SECURITY_PROVIDER,
)


def _format_tools_for_openrouter(tools: Optional[list]) -> Optional[list]:
    """Konwertuje listę narzędzi (funkcje Python lub słowniki) do formatu OpenAI tools."""
    if not tools:
        return None

    try:
        from ollama._client import _copy_tools

        return [
            t.model_dump(exclude_none=True) if hasattr(t, "model_dump") else dict(t)
            for t in _copy_tools(tools)
        ]
    except Exception:
        # Fallback jeśli ollama._client nie jest dostępny
        formatted = []
        for t in tools:
            if isinstance(t, dict):
                formatted.append(t)
            elif hasattr(t, "__name__"):
                formatted.append({
                    "type": "function",
                    "function": {
                        "name": t.__name__,
                        "description": getattr(t, "__doc__", "") or "",
                        "parameters": {"type": "object", "properties": {}},
                    },
                })
        return formatted


def _format_messages_for_openrouter(messages: list) -> list:
    """Konwertuje historię wiadomości na format akceptowany przez OpenRouter/OpenAI API."""
    formatted = []
    pending_tool_call_ids: list[str] = []

    for m in messages:
        if isinstance(m, dict):
            role = m.get("role")
            if role == "tool":
                call_id = m.get("tool_call_id")
                if not call_id and pending_tool_call_ids:
                    call_id = pending_tool_call_ids.pop(0)
                formatted.append({
                    "role": "tool",
                    "tool_call_id": call_id or "call_0",
                    "content": str(m.get("content", "")),
                })
            else:
                formatted.append(m)
        elif hasattr(m, "role"):
            role = getattr(m, "role", "assistant")
            content = getattr(m, "content", "") or ""
            tool_calls = getattr(m, "tool_calls", None)

            entry = {"role": role, "content": content}
            if tool_calls:
                entry_tool_calls = []
                for i, tc in enumerate(tool_calls):
                    call_id = getattr(tc, "id", None) or f"call_{i}"
                    pending_tool_call_ids.append(call_id)
                    raw_args = tc.function.arguments
                    args_str = json.dumps(raw_args) if isinstance(raw_args, dict) else str(raw_args)
                    entry_tool_calls.append({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": args_str,
                        },
                    })
                entry["tool_calls"] = entry_tool_calls
            formatted.append(entry)
        else:
            formatted.append(dict(m))

    return formatted


def _chat_openrouter(messages: list, tools: Optional[list] = None, model: Optional[str] = None):
    """Wywołanie modelu przez OpenRouter."""
    if not OPENROUTER_API_KEY:
        raise ValueError(
            "Brak klucza OPENROUTER_API_KEY. Ustaw go w pliku .env lub jako zmienną środowiskową."
        )

    client = OpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=OPENROUTER_API_KEY,
    )

    formatted_messages = _format_messages_for_openrouter(messages)
    formatted_tools = _format_tools_for_openrouter(tools)

    params = {
        "model": model or OPENROUTER_MODEL,
        "messages": formatted_messages,
    }
    if formatted_tools:
        params["tools"] = formatted_tools

    response = client.chat.completions.create(**params)
    choice = response.choices[0]
    raw_msg = choice.message

    tool_calls = None
    if raw_msg.tool_calls:
        tool_calls = []
        for tc in raw_msg.tool_calls:
            raw_args = tc.function.arguments
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args.strip() else {}
                except Exception:
                    args = {}
            elif isinstance(raw_args, dict):
                args = raw_args
            else:
                args = dict(raw_args)

            tool_calls.append(
                SimpleNamespace(
                    id=getattr(tc, "id", None) or f"call_{uuid.uuid4().hex[:8]}",
                    function=SimpleNamespace(name=tc.function.name, arguments=args),
                    type="function",
                )
            )

    return SimpleNamespace(
        role="assistant",
        content=raw_msg.content or "",
        tool_calls=tool_calls,
    )


def _chat_ollama(messages: list, tools: Optional[list] = None, model: Optional[str] = None):
    """Wywołanie modelu przez lokalną Ollamę."""
    params = {
        "model": model or OLLAMA_MODEL,
        "messages": messages,
    }
    if tools:
        params["tools"] = tools

    response = ollama.chat(**params)
    return response.message


def chat(
    messages: list,
    tools: Optional[list] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    zone: str = "chatbot",
    purpose: str = "chat",
):
    """Jedno wywołanie modelu. Zwraca wiadomość asystenta (content + tool_calls).

    Dostępne providery:
      - 'openrouter' (domyślny)
      - 'ollama'

    Strefy:
      - 'chatbot'  (domyślna): model odpowiadający użytkownikowi; dostaje dane zamaskowane
      - 'security': strażnicy i sędziowie; własny provider i model (SECURITY_*), dane surowe
    """
    if zone == "security":
        provider = provider or SECURITY_PROVIDER
        model = model or SECURITY_MODEL
    chosen_provider = (provider or LLM_PROVIDER).lower()

    if chosen_provider == "openrouter":
        call, used_model = _chat_openrouter, model or OPENROUTER_MODEL
    elif chosen_provider == "ollama":
        call, used_model = _chat_ollama, model or OLLAMA_MODEL
    else:
        raise ValueError(
            f"Nieznany provider: {chosen_provider}. Dostępne opcje to 'openrouter' i 'ollama'."
        )

    audit.record("llm_call", zone, purpose=purpose, provider=chosen_provider, model=used_model,
                 messages=len(messages))
    return call(messages, tools=tools, model=model)
