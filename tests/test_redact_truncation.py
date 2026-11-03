"""An extraction cut at the output-token cap is its own refusal (#358).

Redact on a 52 KB Project Gutenberg text refused with ``t2_unavailable``
after two provider calls. The capture below is what the provider returned
both times: turn 2 transcribing the document instead of answering, stopped
at 4,096 output tokens with its JSON unclosed. That is not a malformed
answer to ask for again: the same request reaches the same cap.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from trentina.errors import (
    MalformedResponseError,
    QuarantineAgentError,
    TruncatedResponseError,
)
from trentina.quarantine import agent
from trentina.quarantine.prompts import (
    EXTRACTION_RESPONSE_SCHEMA,
    EXTRACTION_SYSTEM_PROMPT,
)
from trentina.quarantine.providers import reset_provider
from trentina.quarantine.providers.anthropic import AnthropicProvider
from trentina.quarantine.providers.base import Provider, ProviderResult
from trentina.quarantine.providers.gemini import GeminiProvider
from trentina.quarantine.providers.ollama import OllamaProvider
from trentina.quarantine.providers.openai import OpenAIProvider

# Captured on peergw 2026-10-05, google/gemini-2.5-flash-lite through
# OpenRouter: finish_reason "length", native MAX_TOKENS, 4096 completion
# tokens, 15,468 characters. The head is kept; the middle is elided.
_CAPTURED_HEAD = (
    '{\n  "extracted_text": "The Project Gutenberg eBook of The Yellow Wallpaper\\n'
    "    \\nThis eBook is for the use of anyone anywhere in the United States and\\n"
)
_CAPTURED_TAIL = "Half the time now I am awfully lazy, and lie down ever so much.\\n"
CAPTURED = _CAPTURED_HEAD + _CAPTURED_TAIL

_DOCUMENT = "The Yellow Wallpaper, by Charlotte Perkins Gilman. " * 40
_QUESTION = "What is the title of this work? One line."


def _response(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=body, request=httpx.Request("POST", "https://example.com"))


def _openai(reason: str) -> dict[str, Any]:
    return {
        "choices": [{"message": {"content": CAPTURED}, "finish_reason": reason}],
        "usage": {"prompt_tokens": 14136, "completion_tokens": 4096},
    }


def _gemini(reason: str) -> dict[str, Any]:
    return {"candidates": [{"content": {"parts": [{"text": CAPTURED}]}, "finishReason": reason}]}


def _anthropic(reason: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": CAPTURED}], "stop_reason": reason}


def _ollama(reason: str) -> dict[str, Any]:
    return {"message": {"role": "assistant", "content": CAPTURED}, "done_reason": reason}


_DRIVERS: list[tuple[Provider, Any, str, str]] = [
    (OpenAIProvider(api_key="sk-test"), _openai, "length", "stop"),
    (GeminiProvider(api_key="test", model="test"), _gemini, "MAX_TOKENS", "STOP"),
    (AnthropicProvider(api_key="test"), _anthropic, "max_tokens", "end_turn"),
    (OllamaProvider(), _ollama, "length", "stop"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "body", "cut", "finished"),
    _DRIVERS,
    ids=["openai", "gemini", "anthropic", "ollama"],
)
async def test_every_driver_reports_the_cap(
    provider: Provider, body: Any, cut: str, finished: str
) -> None:
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = _response(body(cut))
        assert (await provider.generate("system", "user")).truncated is True
        post.return_value = _response(body(finished))
        assert (await provider.generate("system", "user")).truncated is False


def test_a_result_is_not_truncated_unless_the_driver_says_so() -> None:
    assert ProviderResult(text="{}").truncated is False


def test_truncation_is_a_provider_error_but_not_one_to_ask_again() -> None:
    """A detection turn cut short is still ``l3_unavailable``, never clean;
    only a ``MalformedResponseError`` earns the second ask."""
    assert issubclass(TruncatedResponseError, QuarantineAgentError)
    assert not issubclass(TruncatedResponseError, MalformedResponseError)
    assert not agent._is_retryable(TruncatedResponseError())


@pytest.mark.asyncio
@pytest.mark.usefixtures("_openrouter")
async def test_a_detection_turn_cut_short_is_unavailable_never_clean() -> None:
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = _response(_openai("length"))
        verdict = await agent.quarantine_detect(_DOCUMENT)
    assert verdict.get("l3_unavailable") is True
    assert post.await_count == 1


@pytest.fixture
def _openrouter(monkeypatch: pytest.MonkeyPatch) -> None:
    import trentina.config as config_module

    monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
    monkeypatch.setattr(config_module, "_config", None)
    reset_provider()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_openrouter")
async def test_the_captured_response_refuses_as_truncated_after_one_call(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = _response(_openai("length"))
        result = await agent.quarantine_redact(_DOCUMENT, _QUESTION, detection=None)
    assert result.refused_by == "t2_truncated"
    assert not result.content
    assert post.await_count == 1, "the same request reaches the same cap: no second ask"
    assert "asking once more" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.usefixtures("_openrouter")
async def test_a_fallback_provider_is_not_tried_on_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import trentina.config as config_module

    monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(config_module, "_config", None)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = _response(_openai("length"))
        result = await agent.quarantine_redact(_DOCUMENT, _QUESTION, detection=None)
    assert result.refused_by == "t2_truncated"
    assert post.await_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("_openrouter")
async def test_unclosed_json_that_was_not_capped_is_still_asked_again() -> None:
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = _response(_openai("stop"))
        result = await agent.quarantine_redact(_DOCUMENT, _QUESTION, detection=None)
    assert result.refused_by == "t2_unavailable"
    assert post.await_count == 2


def test_the_extraction_turn_is_told_to_answer_not_transcribe() -> None:
    assert "NEVER transcribe" in EXTRACTION_SYSTEM_PROMPT
    assert "Answer the extraction request" in EXTRACTION_SYSTEM_PROMPT
    description = EXTRACTION_RESPONSE_SCHEMA["properties"]["extracted_text"]["description"]
    assert "answer to the extraction request" in description
