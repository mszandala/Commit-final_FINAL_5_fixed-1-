from typing import Callable, Optional
from contextvars import ContextVar
from chatbot import llm_client
from config import MAX_TOOL_STEPS
from tools.registry import TOOLS, run_tool

SYSTEM = (
    "You are a helpful assistant answering questions from the company knowledge base. "
    "You have file tools available. Use them whenever the user asks about data or documents. "
    "You have a total of 10 tool calls per message. if that's not enough, tell it directly. "
    "Be concise."
)

ToolGate = Callable[[str, dict], Optional[str]]


class ResponseBlocked(Exception):
    pass


_current_tool_gate: ContextVar[Optional[ToolGate]] = ContextVar(
    "_current_tool_gate",
    default=None,
)


def new_history() -> list:
    return [{"role": "system", "content": SYSTEM}]


def run_agent(user_message: str, history: Optional[list] = None,
    tool_gate: Optional[ToolGate] = None) -> tuple[str, list]:
    """Odpowiada na jedną wiadomość użytkownika.

    Zwraca (odpowiedź, nowa historia). Przekazana historia nie jest modyfikowana,
    więc przy błędzie lub blokadzie wywołujący zostaje ze stanem sprzed wiadomości.
    """
    messages = list(history) if history else new_history()
    messages.append({"role": "user", "content": user_message})

    token = _current_tool_gate.set(tool_gate)
    try:
        for step in range(MAX_TOOL_STEPS):
            msg = llm_client.chat(messages, tools=TOOLS)

            if not msg.tool_calls:
                messages.append({"role": "assistant", "content": msg.content})
                return msg.content, messages

            messages.append(msg)

            for tc in msg.tool_calls:
                name = tc.function.name
                args = dict(tc.function.arguments)

                refusal = tool_gate(name, args) if tool_gate else None
                result = refusal if refusal is not None else run_tool(name, args)

                messages.append({
                    "role": "tool",
                    "content": result,
                })

        messages.append({
            "role": "user",
            "content": "Please give your final answer now.",
        })
        msg = llm_client.chat(messages)
        messages.append({"role": "assistant", "content": msg.content})
        return msg.content, messages

    finally:
        _current_tool_gate.reset(token)