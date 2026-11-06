"""Tests for the automatic provider fallback chain (issue #42)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from trentina.config import get_config
from trentina.errors import ConfigError, QuarantineAgentError
from trentina.gateway.standalone import standalone_profile
from trentina.quarantine.agent import (
    _call_with_fallback,
    _is_retryable,
)
from trentina.quarantine.providers import (
    get_fallback_providers,
    get_provider,
    reset_provider,
)


@pytest.fixture(autouse=True)
def reset_config_and_providers(monkeypatch):
    """Clear singletons between tests."""
    import trentina.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "_config", None)
    reset_provider()
    yield
    reset_provider()


class TestIsRetryable:
    def test_429_is_retryable(self):
        exc = QuarantineAgentError("rate limited", status_code=429)
        assert _is_retryable(exc)

    def test_503_is_retryable(self):
        exc = QuarantineAgentError("service unavailable", status_code=503)
        assert _is_retryable(exc)

    def test_400_not_retryable(self):
        exc = QuarantineAgentError("bad request", status_code=400)
        assert not _is_retryable(exc)

    def test_401_not_retryable(self):
        exc = QuarantineAgentError("unauthorized", status_code=401)
        assert not _is_retryable(exc)

    def test_403_not_retryable(self):
        exc = QuarantineAgentError("forbidden", status_code=403)
        assert not _is_retryable(exc)

    def test_timeout_message_retryable(self):
        exc = QuarantineAgentError("Request timed out")
        assert _is_retryable(exc)

    def test_unreachable_message_retryable(self):
        exc = QuarantineAgentError("Ollama unreachable at http://localhost:11434: ...")
        assert _is_retryable(exc)

    def test_json_error_not_retryable(self):
        exc = QuarantineAgentError("Invalid JSON in provider response")
        assert not _is_retryable(exc)

    def test_canary_error_not_retryable(self):
        exc = QuarantineAgentError("SECURITY: canary token leaked")
        assert not _is_retryable(exc)

    def test_no_status_code_generic_error_not_retryable(self):
        exc = QuarantineAgentError("GEMINI_API_KEY not configured")
        assert not _is_retryable(exc)


class TestConfigFallbackParsing:
    def test_empty_fallback_defaults_to_empty_list(self, monkeypatch):
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == []

    def test_single_fallback(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai"]

    def test_multiple_fallbacks(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai,anthropic")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai", "anthropic"]

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", " openai , anthropic ")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai", "anthropic"]

    def test_invalid_provider_raises_config_error(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "invalid-llm")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        with pytest.raises(ConfigError, match="Unknown fallback provider"):
            get_config()

    def test_ollama_valid_in_chain(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "ollama")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["ollama"]


class TestGetFallbackProvidersStandalone:
    def test_empty_chain_returns_empty(self, monkeypatch):
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        assert get_fallback_providers(standalone_profile(get_config())) == []

    def test_openai_with_key(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        chain = get_fallback_providers(standalone_profile(get_config()))
        assert len(chain) == 1
        name, key = chain[0]
        assert name == "openai"
        assert key is not None
        assert key.get_secret_value() == "sk-test"

    def test_provider_without_key_skipped(self, monkeypatch, caplog):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        chain = get_fallback_providers(standalone_profile(get_config()))
        assert chain == []
        assert "skipping" in caplog.text

    def test_ollama_has_none_key(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "ollama")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        chain = get_fallback_providers(standalone_profile(get_config()))
        assert len(chain) == 1
        name, key = chain[0]
        assert name == "ollama"
        assert key is None


FAKE_EXTRACTED = {
    "extracted_text": "hello world",
    "confidence": "high",
    "injection_detected": False,
}
FAKE_SCHEMA = {
    "type": "object",
    "properties": {"extracted_text": {"type": "string"}},
}


def make_provider_result(text: str) -> object:
    from trentina.quarantine.providers.base import ProviderResult

    return ProviderResult(text=text, input_tokens=10, output_tokens=5)


def make_good_response() -> str:
    return json.dumps(FAKE_EXTRACTED)


def make_429_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 429", status_code=429)


def make_503_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 503", status_code=503)


def make_400_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 400", status_code=400)


@pytest.mark.asyncio
class TestCallWithFallback:
    async def test_primary_succeeds_no_fallback_called(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        get_config()

        call_count = {"n": 0}
        good_result = make_provider_result(make_good_response())

        async def fake_generate(*_args, **_kwargs):
            call_count["n"] += 1
            return good_result

        with patch(
            "trentina.quarantine.providers.gemini.GeminiProvider.generate",
            new=fake_generate,
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        assert call_count["n"] == 1
        assert result["extracted_text"] == "hello world"

    @pytest.mark.parametrize(
        ("replies", "succeeds"), [(["{bad", "good"], True), (["{bad", "{bad"], False)]
    )
    async def test_a_malformed_reply_is_asked_once_more(self, monkeypatch, replies, succeeds):
        """One bad sample must not make L3 unavailable: under Matrix withholding
        that costs the agent a sync's events (#227). Two in a row still does."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        get_config()
        texts = [make_good_response() if r == "good" else r for r in replies]
        mock = AsyncMock(side_effect=[make_provider_result(t) for t in texts])

        with patch(
            "trentina.quarantine.providers.gemini.GeminiProvider.generate",
            new=mock,
        ):
            call = _call_with_fallback(
                content="test content", system_prompt="test prompt", response_schema=FAKE_SCHEMA
            )
            if succeeds:
                result, _ = await call
                assert result["extracted_text"] == "hello world"
            else:
                with pytest.raises(QuarantineAgentError, match="Malformed provider response"):
                    await call
        assert mock.await_count == 2

    async def test_a_retry_that_fails_retryably_falls_back(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()
        gemini_mock = AsyncMock(side_effect=[make_provider_result("{bad"), make_429_error()])
        openai_mock = AsyncMock(return_value=make_provider_result(make_good_response()))

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content", system_prompt="test prompt", response_schema=FAKE_SCHEMA
            )
        assert gemini_mock.await_count == 2
        assert openai_mock.await_count == 1
        assert result["extracted_text"] == "hello world"

    async def test_429_triggers_fallback(self, monkeypatch):
        # No throttle budget: a 429 moves down the chain at once.
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"

    async def test_503_triggers_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_503_error())
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"

    async def test_400_does_not_trigger_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_400_error())
        openai_mock = AsyncMock()

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
            pytest.raises(QuarantineAgentError, match="HTTP 400"),
        ):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_not_called()

    async def test_all_providers_exhausted_raises(self, monkeypatch):
        # No throttle budget: a 429 moves down the chain at once.
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_mock = AsyncMock(side_effect=make_503_error())

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
            pytest.raises(QuarantineAgentError, match="all providers exhausted"),
        ):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()

    async def test_empty_chain_single_provider_fails_raises(self, monkeypatch):
        # No throttle budget: a 429 moves down the chain at once.
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            pytest.raises(QuarantineAgentError, match="all providers exhausted"),
        ):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

    async def test_timeout_triggers_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=QuarantineAgentError("Request timed out"))
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        assert result["extracted_text"] == "hello world"

    async def test_three_provider_chain(self, monkeypatch):
        """Gemini fails, OpenAI fails, Anthropic succeeds."""
        # No throttle budget: a 429 moves down the chain at once.
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai,anthropic")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_mock = AsyncMock(side_effect=make_503_error())
        anthropic_result = make_provider_result(make_good_response())
        anthropic_mock = AsyncMock(return_value=anthropic_result)

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
            patch(
                "trentina.quarantine.providers.anthropic.AnthropicProvider.generate",
                new=anthropic_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        anthropic_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"


class TestThrottleRetry:
    """A 429 waits on the same provider while the budget lasts (#216)."""

    async def test_429_retries_same_provider_within_budget(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        throttled = QuarantineAgentError("HTTP 429", status_code=429, retry_after=0.0)
        gemini_mock = AsyncMock(side_effect=[throttled, make_provider_result(make_good_response())])
        openai_mock = AsyncMock()

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="c", system_prompt="p", response_schema=FAKE_SCHEMA
            )

        assert gemini_mock.call_count == 2
        openai_mock.assert_not_called()
        assert result["extracted_text"] == "hello world"

    async def test_pause_beyond_budget_falls_back(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "5")
        get_config()

        # Retry-After longer than the budget: waiting cannot succeed in time.
        gemini_mock = AsyncMock(
            side_effect=QuarantineAgentError("HTTP 429", status_code=429, retry_after=60.0)
        )
        openai_mock = AsyncMock(return_value=make_provider_result(make_good_response()))

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            await _call_with_fallback(content="c", system_prompt="p", response_schema=FAKE_SCHEMA)

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()

    async def test_503_still_falls_back_at_once(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "300")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_503_error())
        openai_mock = AsyncMock(return_value=make_provider_result(make_good_response()))

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            await _call_with_fallback(content="c", system_prompt="p", response_schema=FAKE_SCHEMA)

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()


class TestThrottleBudgetPerProvider:
    async def test_budget_starts_at_the_first_429(self, monkeypatch):
        """A slow first attempt does not eat the time allowed for waiting."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "1")
        get_config()

        calls = {"n": 0}

        async def slow_then_throttled_then_ok(*_a, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                await asyncio.sleep(1.1)  # longer than the whole budget
                raise QuarantineAgentError("HTTP 429", status_code=429, retry_after=0.0)
            return make_provider_result(make_good_response())

        with patch(
            "trentina.quarantine.providers.gemini.GeminiProvider.generate",
            new=slow_then_throttled_then_ok,
        ):
            result, _ = await _call_with_fallback(
                content="c", system_prompt="p", response_schema=FAKE_SCHEMA
            )

        assert calls["n"] == 2
        assert result["extracted_text"] == "hello world"


class TestThrottleBudgetCumulative:
    async def test_repeated_short_pauses_exhaust_the_budget(self, monkeypatch):
        """Each pause fits; together they spend the budget, then fall back."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "1")
        get_config()

        gemini_mock = AsyncMock(
            side_effect=QuarantineAgentError("HTTP 429", status_code=429, retry_after=0.3)
        )
        openai_mock = AsyncMock(return_value=make_provider_result(make_good_response()))

        with (
            patch(
                "trentina.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "trentina.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            await _call_with_fallback(content="c", system_prompt="p", response_schema=FAKE_SCHEMA)

        assert 2 <= gemini_mock.call_count <= 4
        openai_mock.assert_called_once()


class TestDriversKeepRetryAfter:
    @pytest.mark.parametrize(
        ("name", "env"),
        [
            ("gemini", "GEMINI_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("ollama", None),
        ],
    )
    async def test_429_carries_retry_after(self, monkeypatch, name, env):
        if env:
            monkeypatch.setenv(env, "k")
        get_config()

        async def throttled(_client, url, **_kw):
            request = httpx.Request("POST", url)
            return httpx.Response(429, headers={"Retry-After": "4"}, request=request)

        monkeypatch.setattr(httpx.AsyncClient, "post", throttled)
        provider = get_provider(name)
        with pytest.raises(QuarantineAgentError) as info:
            await provider.generate(system_prompt="s", user_content="u")
        assert info.value.status_code == 429
        assert info.value.retry_after == 4.0
