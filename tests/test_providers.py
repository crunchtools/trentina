"""Tests for quarantine/providers — mocked unit tests for each driver."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import SecretStr

from trentina.errors import QuarantineAgentError
from trentina.quarantine.providers import get_provider, reset_provider
from trentina.quarantine.providers.anthropic import AnthropicProvider
from trentina.quarantine.providers.gemini import GeminiProvider
from trentina.quarantine.providers.ollama import OllamaProvider
from trentina.quarantine.providers.openai import (
    OPENROUTER_API_BASE,
    OPENROUTER_ROUTING,
    OpenAIProvider,
)


def _gemini_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [{"content": {"parts": [{"text": text}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _openai_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _anthropic_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _ollama_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "message": {"role": "assistant", "content": text},
            "prompt_eval_count": 10,
            "eval_count": 5,
        },
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )


SAMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
}


@pytest.mark.asyncio
class TestGeminiProvider:
    async def test_generate_returns_text(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="gemini-2.5-flash-lite")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _gemini_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10
        assert result.output_tokens == 5

    async def test_api_key_travels_in_a_header_never_the_url(self) -> None:
        """httpx logs the full request URL at INFO, so a `?key=` credential
        lands in podman logs and journald the moment anyone raises
        TRENTINA_LOG_LEVEL to debug something unrelated — a leak armed by a
        routine troubleshooting step, warned about by nothing. Observed live.
        See #156.
        """
        provider = GeminiProvider(api_key="super-secret-key", model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _gemini_response('{"answer":"hi"}')
            await provider.generate("sys", "user")

        url = mock_post.call_args.args[0]
        assert "super-secret-key" not in url
        assert "key=" not in url
        assert mock_post.call_args.kwargs["headers"]["x-goog-api-key"] == ("super-secret-key")

    async def test_generate_with_schema(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _gemini_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            assert request_body["generationConfig"]["responseSchema"] == SAMPLE_SCHEMA

    async def test_timeout_raises(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timeout")
            with pytest.raises(QuarantineAgentError, match="timed out"):
                await provider.generate("sys", "user")

    async def test_no_candidates_raises(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        empty_resp = httpx.Response(
            200,
            json={"candidates": []},
            request=httpx.Request("POST", "https://example.com"),
        )
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = empty_resp
            with pytest.raises(QuarantineAgentError, match="No candidates"):
                await provider.generate("sys", "user")


@pytest.mark.asyncio
class TestOpenAIProvider:
    async def test_generate_returns_text(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_generate_with_schema_sends_json_schema(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            assert request_body["response_format"]["type"] == "json_schema"

    async def test_auth_header_sent(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response("{}")
            await provider.generate("sys", "user")
            headers = mock_post.call_args.kwargs["headers"]
            assert headers["Authorization"] == "Bearer sk-test"

    async def test_plain_openai_sends_no_routing(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response("{}")
            await provider.generate("sys", "user")
        assert "provider" not in mock_post.call_args.kwargs["json"]


@pytest.mark.asyncio
class TestOpenRouterProvider:
    """OpenRouter is the OpenAI driver pointed at OpenRouter, with host routing."""

    def _provider(self) -> OpenAIProvider:
        return OpenAIProvider(
            api_key="sk-or-test",
            model="google/gemini-3.8-flash",
            base_url=OPENROUTER_API_BASE,
            routing=OPENROUTER_ROUTING,
        )

    @staticmethod
    def _not_found(message: str) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"message": message, "code": 404}},
            request=httpx.Request("POST", "https://example.com"),
        )

    async def test_a_judge_that_fixes_its_own_temperature_is_asked_without_it(self) -> None:
        """Gemini 3.8 Flash and GPT-6 Luna have no host that takes ``temperature``
        under ``require_parameters``: every call was a 404 and an unavailable judge."""
        provider = self._provider()
        refused = self._not_found("No endpoints found that can handle the requested parameters.")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = [refused, _openai_response("one"), _openai_response("two")]
            first = await provider.generate("sys", "user")
            second = await provider.generate("sys", "user")
        assert (first.text, second.text) == ("one", "two")
        sent = [call.kwargs["json"] for call in mock_post.call_args_list]
        assert ["temperature" in body for body in sent] == [True, False, False]
        assert all(body["provider"] == OPENROUTER_ROUTING for body in sent)

    async def test_reasoning_effort_is_sent_only_when_set(self) -> None:
        thinking = OpenAIProvider(
            api_key="k", base_url=OPENROUTER_API_BASE, routing=OPENROUTER_ROUTING,
            reasoning_effort="minimal",
        )  # fmt: skip
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response("ok")
            await thinking.generate("sys", "user")
            await self._provider().generate("sys", "user")
        first, second = (call.kwargs["json"] for call in mock_post.call_args_list)
        assert first["reasoning"] == {"effort": "minimal"}
        assert "reasoning" not in second

    async def test_a_model_that_does_not_exist_is_not_asked_twice(self) -> None:
        provider = self._provider()
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = self._not_found("No such model.")
            with pytest.raises(QuarantineAgentError) as raised:
                await provider.generate("sys", "user")
        assert raised.value.status_code == 404
        assert mock_post.call_count == 1

    async def test_a_judge_that_refuses_something_else_fails_after_one_more_ask(self) -> None:
        provider = self._provider()
        refused = self._not_found("No endpoints found that can handle the requested parameters.")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = refused
            with pytest.raises(QuarantineAgentError):
                await provider.generate("sys", "user")
        assert mock_post.call_count == 2

    async def test_posts_to_openrouter_with_routing(self) -> None:
        provider = OpenAIProvider(
            api_key="sk-or-test",
            model="google/gemini-2.5-flash-lite",
            base_url=OPENROUTER_API_BASE,
            routing=OPENROUTER_ROUTING,
        )
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
        assert mock_post.call_args.args[0] == f"{OPENROUTER_API_BASE}/chat/completions"
        body = mock_post.call_args.kwargs["json"]
        # A host that would ignore response_format, or keep the payload, is not eligible.
        assert body["provider"] == {"require_parameters": True, "data_collection": "deny"}
        assert body["response_format"]["type"] == "json_schema"


@pytest.mark.asyncio
class TestAnthropicProvider:
    async def test_generate_returns_text(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_auth_headers_sent(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response("{}")
            await provider.generate("sys", "user")
            headers = mock_post.call_args.kwargs["headers"]
            assert headers["x-api-key"] == "sk-ant-test"
            assert headers["anthropic-version"] == "2023-06-01"

    async def test_schema_hint_appended_to_user_content(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response('{"answer":"hi"}')
            await provider.generate("sys", "user text", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            user_msg = request_body["messages"][0]["content"]
            assert "user text" in user_msg
            assert "answer" in user_msg


@pytest.mark.asyncio
class TestOllamaProvider:
    async def test_generate_returns_text(self) -> None:
        provider = OllamaProvider(model="qwen2.5:0.5b")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _ollama_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_json_format_with_schema(self) -> None:
        provider = OllamaProvider(model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _ollama_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1]["json"]
            assert request_body["format"] == "json"

    async def test_connect_error_raises(self) -> None:
        provider = OllamaProvider(model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("refused")
            with pytest.raises(QuarantineAgentError, match="Ollama unreachable"):
                await provider.generate("sys", "user")


class TestGetProviderFactory:
    def setup_method(self) -> None:
        reset_provider()

    def teardown_method(self) -> None:
        reset_provider()

    def test_gemini_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_MODEL_PROVIDER", raising=False)
        from trentina import config as config_mod

        config_mod._config = None
        provider = get_provider()
        assert isinstance(provider, GeminiProvider)
        config_mod._config = None

    def test_openai_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        from trentina import config as config_mod

        config_mod._config = None
        provider = get_provider()
        assert isinstance(provider, OpenAIProvider)
        config_mod._config = None

    def test_openrouter_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        monkeypatch.delenv("QUARANTINE_MODEL", raising=False)
        from trentina import config as config_mod

        config_mod._config = None
        provider = get_provider()
        assert isinstance(provider, OpenAIProvider)
        # The default model, spelled the way OpenRouter names it.
        assert provider.judge == ("openrouter", "google/gemini-3.5-flash-lite")
        config_mod._config = None

    def test_openrouter_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        from trentina import config as config_mod

        config_mod._config = None
        with pytest.raises(QuarantineAgentError, match="OPENROUTER_API_KEY"):
            get_provider()
        config_mod._config = None

    async def test_openrouter_profile_key_needs_no_global(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        from trentina import config as config_mod

        config_mod._config = None
        provider = get_provider("openrouter", api_key=SecretStr("sk-or-profile"))
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response("{}")
            await provider.generate("sys", "user")
        assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-or-profile"
        config_mod._config = None

    def test_unknown_provider_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "unknown")
        from trentina import config as config_mod

        config_mod._config = None
        with pytest.raises(QuarantineAgentError, match="Unknown provider"):
            get_provider()
        config_mod._config = None

    def test_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from trentina import config as config_mod

        config_mod._config = None
        with pytest.raises(QuarantineAgentError, match="OPENAI_API_KEY"):
            get_provider()
        config_mod._config = None

    def test_explicit_provider_name_overrides_global(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        from trentina import config as config_mod

        config_mod._config = None
        default_provider = get_provider()
        assert isinstance(default_provider, GeminiProvider)
        override_provider = get_provider("openai")
        assert isinstance(override_provider, OpenAIProvider)
        config_mod._config = None

    def test_per_name_caching(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        from trentina import config as config_mod

        config_mod._config = None
        p1 = get_provider("gemini")
        p2 = get_provider("gemini")
        assert p1 is p2
        p3 = get_provider("openai")
        assert p3 is not p1
        assert isinstance(p3, OpenAIProvider)
        config_mod._config = None

    def test_none_falls_back_to_global(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        from trentina import config as config_mod

        config_mod._config = None
        p = get_provider(None)
        assert isinstance(p, GeminiProvider)
        config_mod._config = None


class TestReasoningEffort:
    def test_an_unknown_effort_refuses_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config
        from trentina.errors import ConfigError

        monkeypatch.setenv("QUARANTINE_REASONING_EFFORT", "none")
        with pytest.raises(ConfigError, match="QUARANTINE_REASONING_EFFORT"):
            Config()
        monkeypatch.setenv("QUARANTINE_REASONING_EFFORT", "minimal")
        assert Config().reasoning_effort == "minimal"
        monkeypatch.setenv("QUARANTINE_REASONING_EFFORT", "")
        assert Config().reasoning_effort is None
