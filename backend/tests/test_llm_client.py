from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from chatbot import llm_client


def test_invalid_provider_raises_error():
    with pytest.raises(ValueError, match="Nieznany provider"):
        llm_client.chat([{"role": "user", "content": "hi"}], provider="nieistniejacy")


def test_ollama_provider_invoked():
    mock_reply = SimpleNamespace(message=SimpleNamespace(role="assistant", content="Cześć z Ollamy", tool_calls=None))
    with patch("chatbot.llm_client.ollama.chat", return_value=mock_reply) as mock_chat:
        resp = llm_client.chat([{"role": "user", "content": "hej"}], provider="ollama")
        assert resp.content == "Cześć z Ollamy"
        mock_chat.assert_called_once()


def test_openrouter_provider_invoked():
    mock_choice = SimpleNamespace(
        message=SimpleNamespace(
            role="assistant",
            content="Cześć z OpenRoutera",
            tool_calls=None,
        )
    )
    mock_resp = SimpleNamespace(choices=[mock_choice])

    with patch("chatbot.llm_client.OpenAI") as mock_openai_cls, \
            patch.object(llm_client.SETTINGS, "openrouter_api_key", "sk-or-v1-test"):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_openai_cls.return_value = mock_client

        resp = llm_client.chat([{"role": "user", "content": "hej"}], provider="openrouter")
        assert resp.content == "Cześć z OpenRoutera"
        mock_client.chat.completions.create.assert_called_once()
