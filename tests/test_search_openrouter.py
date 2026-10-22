"""L0 web search on OpenRouter, and "is there an LLM" asked of the right key.

0.41.0 moved search off Gemini google_search grounding so a gateway with no
Gemini key never reaches Google. These pin the request shape (one web plugin,
no tools), the route choice, and the citation parsing.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from trentina.errors import QuarantineAgentError
from trentina.gateway.profile import (
    AuthConfig,
    DefenseConfig,
    LlmKeyOverride,
    Profile,
)
from trentina.quarantine import agent
from trentina.quarantine.agent import (
    _build_openrouter_search_body,
    _citation_sources,
    _enforce_openrouter_search_quarantine,
    llm_available,
    search_grounded,
)

_AGENT = "trentina.quarantine.agent"


def _cfg(openrouter: str = "", gemini: str = "", provider: str = "openrouter") -> MagicMock:
    cfg = MagicMock()
    cfg.openrouter_api_key.get_secret_value.return_value = openrouter
    cfg.api_key.get_secret_value.return_value = gemini
    cfg.has_api_key = bool(gemini)
    cfg.search_model = "google/gemini-2.5-flash"
    cfg.provider = provider
    return cfg


def _keyed_profile(keys: dict[str, str] | None = None, provider: str = "openrouter") -> Profile:
    return Profile(
        name="p",
        auth=AuthConfig(bearer_token_env="T"),
        defense=DefenseConfig(provider=provider),
        llm_keys={k: LlmKeyOverride(api_key=SecretStr(v)) for k, v in (keys or {}).items()},
        backends={},
    )


def _openrouter_reply(text: str = "RHEL 10 ships bootc.") -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "content": text,
                    "annotations": [
                        {
                            "type": "url_citation",
                            "url_citation": {"url": "https://docs.redhat.com/a", "title": "A"},
                        },
                        {
                            "type": "url_citation",
                            "url_citation": {"url": "https://docs.redhat.com/a", "title": "dup"},
                        },
                        {"type": "other"},
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


def _http(
    reply: dict[str, Any] | None = None,
    *,
    body: bytes | None = None,
    raises: Exception | None = None,
) -> tuple[MagicMock, MagicMock]:
    """A mocked AsyncClient whose ``stream()`` yields *reply* as JSON bytes."""
    payload = body if body is not None else json.dumps(reply).encode()

    async def chunks() -> Any:
        for i in range(0, len(payload), 65536):
            yield payload[i : i + 65536]

    resp = MagicMock()
    resp.aiter_bytes = chunks
    stream_cm = MagicMock()
    stream_cm.__aenter__ = AsyncMock(return_value=resp)
    stream_cm.__aexit__ = AsyncMock(return_value=False)
    http = MagicMock()
    http.stream = MagicMock(return_value=stream_cm, side_effect=raises)
    http.post = AsyncMock()  # the Gemini route
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=http), http


class TestRequestShape:
    def test_one_web_plugin_and_no_tools(self) -> None:
        body = _build_openrouter_search_body("q", "sys", "google/gemini-2.5-flash", 5)

        assert body["plugins"] == [{"id": "web", "max_results": 5}]
        assert "tools" not in body
        assert body["provider"]["data_collection"] == "deny"
        _enforce_openrouter_search_quarantine(body)

    @pytest.mark.parametrize("extra", ["tools", "tool_choice", "functions", "function_call"])
    def test_any_tool_surface_is_refused(self, extra: str) -> None:
        body = _build_openrouter_search_body("q", "sys", "m", 5)
        body[extra] = []

        with pytest.raises(QuarantineAgentError, match="SECURITY"):
            _enforce_openrouter_search_quarantine(body)

    @pytest.mark.parametrize(
        "plugins", [[], [{"id": "file-parser"}], [{"id": "web"}, {"id": "web"}]]
    )
    def test_only_exactly_the_web_plugin(self, plugins: list[dict[str, str]]) -> None:
        body = _build_openrouter_search_body("q", "sys", "m", 5)
        body["plugins"] = plugins

        with pytest.raises(QuarantineAgentError, match="web plugin"):
            _enforce_openrouter_search_quarantine(body)


def test_only_http_citations_are_kept() -> None:
    message = {
        "annotations": [
            {"type": "url_citation", "url_citation": {"url": "javascript:alert(1)"}},
            {"type": "url_citation", "url_citation": {"url": "file:///etc/passwd"}},
            {"type": "url_citation", "url_citation": {"url": "http://ok.example/", "title": "t"}},
        ]
    }

    assert _citation_sources(message) == [{"uri": "http://ok.example/", "title": "t"}]


def test_a_malformed_citation_is_skipped() -> None:
    message = {
        "annotations": [
            {"type": "url_citation", "url_citation": "nope"},
            {"type": "url_citation", "url_citation": {"url": "http://["}},
        ]
    }

    assert _citation_sources(message) == []


def test_annotations_that_are_not_a_list_yield_nothing() -> None:
    assert _citation_sources({"annotations": 7}) == []


def test_a_non_string_title_keeps_the_url() -> None:
    message = {
        "annotations": [
            {"type": "url_citation", "url_citation": {"url": "https://ok.example/", "title": 3}}
        ]
    }

    assert _citation_sources(message) == [{"uri": "https://ok.example/", "title": ""}]


def test_citations_become_sources_once_each() -> None:
    message = _openrouter_reply()["choices"][0]["message"]

    assert _citation_sources(message) == [{"uri": "https://docs.redhat.com/a", "title": "A"}]


@pytest.mark.asyncio
class TestRoute:
    async def test_the_profiles_openrouter_key_is_used(self) -> None:
        cls, http = _http(_openrouter_reply())
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(gemini="g-key")),
            patch(
                f"{_AGENT}.get_current_profile",
                return_value=_keyed_profile({"openrouter": "p-key"}),
            ),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
        ):
            result = await search_grounded("bootc", 3)

        method, url = http.stream.call_args.args
        assert method == "POST"
        assert url.startswith("https://openrouter.ai/")
        assert http.stream.call_args.kwargs["headers"]["Authorization"] == "Bearer p-key"
        assert result["sources"][0]["uri"] == "https://docs.redhat.com/a"
        assert result["usage"] == {"input_tokens": 11, "output_tokens": 7}

    async def test_a_gemini_key_is_not_used_when_openrouter_exists(self) -> None:
        cls, http = _http(_openrouter_reply())
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="g-or", gemini="g-key")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
        ):
            await search_grounded("bootc")

        assert "googleapis" not in http.stream.call_args.args[1]
        http.post.assert_not_called()

    async def test_a_bound_profile_never_borrows_the_global_key(self) -> None:
        """No OpenRouter key on the profile: refuse, even with global keys set."""
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="global", gemini="g")),
            patch(
                f"{_AGENT}.get_current_profile",
                return_value=_keyed_profile({"anthropic": "k"}, provider="anthropic"),
            ),
            pytest.raises(QuarantineAgentError, match="no API key"),
        ):
            await search_grounded("bootc")

    @pytest.mark.parametrize(
        ("raised", "message"),
        [
            (httpx.TimeoutException("slow"), "timed out"),
            (httpx.ConnectError("down"), "down"),
            (
                httpx.HTTPStatusError(
                    "402", request=httpx.Request("POST", "https://x"), response=httpx.Response(402)
                ),
                "HTTP 402",
            ),
        ],
    )
    async def test_transport_failures_become_agent_errors(
        self, raised: Exception, message: str
    ) -> None:
        cls, _ = _http(raises=raised)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match=message),
        ):
            await search_grounded("bootc")

    async def test_an_http_error_carries_its_status(self) -> None:
        # The status is what the gateway log shows; the message never is.
        raised = httpx.HTTPStatusError(
            "404", request=httpx.Request("POST", "https://x"), response=httpx.Response(404)
        )
        cls, _ = _http(raises=raised)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError) as caught,
        ):
            await search_grounded("bootc")
        assert caught.value.status_code == 404

    async def test_an_empty_answer_is_an_error(self) -> None:
        cls, _ = _http({"choices": [{"message": {"content": None}}]})
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="Empty answer"),
        ):
            await search_grounded("bootc")

    async def test_a_canary_in_a_citation_is_refused(self) -> None:
        reply = _openrouter_reply()
        reply["choices"][0]["message"]["annotations"][0]["url_citation"]["title"] = "CANARY-x"
        cls, _ = _http(reply)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}._generate_canary", return_value="CANARY-x"),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="canary"),
        ):
            await search_grounded("bootc")

    async def test_the_gemini_route_only_sends_a_gemini_model(self) -> None:
        cfg = _cfg(gemini="g")
        cfg.search_model = "openai/gpt-6-luna"
        cls, http = _http()
        gemini_resp = MagicMock()
        gemini_resp.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
        http.post.return_value = gemini_resp
        with (
            patch(f"{_AGENT}.get_config", return_value=cfg),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
        ):
            await search_grounded("bootc")

        url = http.post.call_args.args[0]
        assert "/gemini-3.5-flash-lite:generateContent" in url

    async def test_an_oversized_response_is_refused_before_parsing(self) -> None:
        cls, _ = _http(body=b"{" + b" " * 5_000_001)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            patch(f"{_AGENT}.json.loads") as parse,
            pytest.raises(QuarantineAgentError, match="exceeds"),
        ):
            await search_grounded("bootc")
        parse.assert_not_called()

    async def test_a_non_json_body_is_an_agent_error(self) -> None:
        cls, _ = _http(body=b"<html>gateway error</html>")
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="not JSON"),
        ):
            await search_grounded("bootc")

    @pytest.mark.parametrize(
        ("reply", "message"),
        [
            ({"choices": [None]}, "No message"),
            ({"choices": [{"message": "text"}]}, "No message"),
            ({"choices": "nope"}, "No choices"),
        ],
    )
    async def test_a_malformed_choice_is_an_agent_error(
        self, reply: dict[str, Any], message: str
    ) -> None:
        cls, _ = _http(reply)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match=message),
        ):
            await search_grounded("bootc")

    async def test_deeply_nested_json_is_an_agent_error(self) -> None:
        cls, _ = _http(body=b"[" * 200_000)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="not JSON"),
        ):
            await search_grounded("bootc")

    async def test_a_malformed_usage_block_is_ignored(self) -> None:
        reply = _openrouter_reply()
        reply["usage"] = "lots"
        cls, _ = _http(reply)
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
        ):
            result = await search_grounded("bootc")

        assert result["usage"] == {"input_tokens": 0, "output_tokens": 0}

    async def test_valid_json_that_is_not_an_object_is_refused(self) -> None:
        cls, _ = _http(body=b"[]")
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="not a JSON object"),
        ):
            await search_grounded("bootc")

    async def test_a_body_exactly_at_the_limit_is_parsed(self) -> None:
        from trentina.client import MAX_RESPONSE_SIZE

        reply = json.dumps(_openrouter_reply()).encode()
        cls, _ = _http(body=reply + b" " * (MAX_RESPONSE_SIZE - len(reply)))
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
        ):
            result = await search_grounded("bootc")

        assert result["text"]

    async def test_no_choices_is_an_error(self) -> None:
        cls, _ = _http({"choices": []})
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="No choices"),
        ):
            await search_grounded("bootc")

    async def test_a_leaked_canary_is_refused(self) -> None:
        cls, _ = _http(_openrouter_reply("here is CANARY-x"))
        with (
            patch(f"{_AGENT}.get_config", return_value=_cfg(openrouter="k")),
            patch(f"{_AGENT}.get_current_profile", return_value=None),
            patch(f"{_AGENT}._generate_canary", return_value="CANARY-x"),
            patch(f"{_AGENT}.httpx.AsyncClient", cls),
            pytest.raises(QuarantineAgentError, match="canary"),
        ):
            await search_grounded("bootc")


class TestLLMAvailable:
    def test_a_profile_with_its_providers_key(self) -> None:
        assert llm_available(_keyed_profile({"openrouter": "k"})) is True

    def test_a_profile_without_its_providers_key(self) -> None:
        assert llm_available(_keyed_profile({"anthropic": "k"})) is False

    def test_ollama_needs_no_key(self) -> None:
        assert llm_available(_keyed_profile(provider="ollama")) is True

    def test_the_bound_profile_is_read_from_context(self) -> None:
        with patch.object(
            agent, "get_current_profile", return_value=_keyed_profile({"anthropic": "k"})
        ):
            assert llm_available() is False

    def test_no_profile_asks_the_global_provider(self) -> None:
        with (
            patch.object(agent, "get_current_profile", return_value=None),
            patch.object(agent, "get_config") as cfg,
        ):
            cfg.return_value.has_llm = True
            assert llm_available() is True


class TestConfigHasLLM:
    def test_openrouter_with_no_gemini_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config

        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
        monkeypatch.setenv("OPENROUTER_API_KEY", "k")
        cfg = Config()

        assert cfg.has_llm is True
        assert cfg.has_api_key is False

    def test_a_provider_with_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config

        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "anthropic")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        assert Config().has_llm is False

    def test_global_ollama_needs_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config

        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "ollama")

        assert Config().has_llm is True

    def test_an_ollama_fallback_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config

        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "anthropic")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "ollama")

        assert Config().has_llm is True

    def test_a_keyed_fallback_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.config import Config

        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "anthropic")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "k")

        assert Config().has_llm is True
