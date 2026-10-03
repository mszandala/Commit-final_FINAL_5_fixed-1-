from typing import Optional

import ollama

from config import MODEL


def chat(messages: list, tools: Optional[list] = None):
    """Jedno wywołanie modelu. Zwraca wiadomość asystenta (content + tool_calls)."""
    response = ollama.chat(model=MODEL, messages=messages, tools=tools)
    return response.message
