"""Tests for gateway/llm_policy.py — what an agent may ask a provider to do (#297)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from trentina.gateway.llm_policy import (
    LlmApi,
    LlmRefusedError,
    Reason,
    admit,
    forward_headers,
    with_session,
)

A, OA, R, G = LlmApi.ANTHROPIC, LlmApi.OPENAI, LlmApi.OPENROUTER, LlmApi.GEMINI

_CLAUDE = {"model": "claude-sonnet-4-5", "max_tokens": 8, "messages": []}
_GPT = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}
_ROUTER = {**_GPT, "model": "anthropic/claude-sonnet-4"}
_GEMINI_PATH = "v1beta/models/gemini-2.5-flash:generateContent"


def _admit(api: LlmApi, path: str, body: dict[str, Any] | None, **kw: Any) -> Any:
    raw = json.dumps(body).encode() if body is not None else b""
    return admit(api, kw.pop("method", "POST"), path, kw.pop("query", ""), raw, **kw)


def _reason(api: LlmApi, path: str, body: dict[str, Any] | None, **kw: Any) -> Reason:
    with pytest.raises(LlmRefusedError) as err:
        _admit(api, path, body, **kw)
    return err.value.reason


class TestPlainCallsPass:
    """A completion with caller-run function tools is what the proxy is for."""

    def test_anthropic_messages_with_custom_tool(self) -> None:
        body = {
            **_CLAUDE,
            "system": [{"type": "text", "text": "be brief"}],
            "tools": [{"name": "read", "input_schema": {}}, {"type": "custom", "name": "w"}],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "see https://example.com"},
                        {"type": "image", "source": {"type": "base64", "data": "AA=="}},
                        {"type": "tool_result", "tool_use_id": "t", "content": "ok"},
                    ],
                }
            ],
        }
        admitted = _admit(A, "v1/messages", body, query="beta=true")
        assert admitted.endpoint == "messages"
        assert admitted.model == "claude-sonnet-4-5"
        assert admitted.query == "beta=true"
        assert json.loads(admitted.body) == body

    def test_openai_chat_with_function_and_inline_image(self) -> None:
        body = {
            **_GPT,
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "tool_choice": {"type": "function", "function": {"name": "f"}},
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "x"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}},
                    ],
                }
            ],
        }
        assert _admit(OA, "v1/chat/completions", body).endpoint == "chat/completions"

    def test_openrouter_with_its_own_fields(self) -> None:
        body = {**_ROUTER, "provider": {"order": ["anthropic"]}, "models": ["openai/gpt-4.1"]}
        assert _admit(R, "v1/chat/completions", body).model == "anthropic/claude-sonnet-4"

    def test_openai_responses_with_function_tool(self) -> None:
        body = {
            "model": "gpt-5",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "x"}]}],
            "tools": [{"type": "function", "name": "f", "parameters": {}}],
        }
        assert _admit(OA, "v1/responses", body).endpoint == "responses"

    def test_gemini_generate_with_function_declarations(self) -> None:
        body = {
            "contents": [{"role": "user", "parts": [{"text": "x"}]}],
            "tools": [{"functionDeclarations": [{"name": "f"}]}],
            "generationConfig": {"temperature": 0},
        }
        admitted = _admit(G, _GEMINI_PATH, body, query="alt=sse")
        assert admitted.model == "gemini-2.5-flash"

    def test_model_listing_get(self) -> None:
        admitted = _admit(A, "v1/models", None, method="GET")
        assert admitted.body is None


class TestServerToolsRefused:
    """Every provider-run tool is a path to the internet the gateway never sees."""

    @pytest.mark.parametrize(
        "tool",
        [
            "web_fetch_20250910",
            "web_search_20250305",
            "code_execution_20250825",
            "computer_20250124",
            "bash_20250124",
        ],
    )
    def test_anthropic_tool_types(self, tool: str) -> None:
        body = {**_CLAUDE, "tools": [{"type": tool, "name": "x"}]}
        assert _reason(A, "v1/messages", body) is Reason.SERVER_TOOL

    def test_anthropic_mcp_servers(self) -> None:
        body = {**_CLAUDE, "mcp_servers": [{"type": "url", "url": "https://evil/mcp"}]}
        assert _reason(A, "v1/messages", body) is Reason.MCP_SERVERS

    def test_anthropic_container(self) -> None:
        assert _reason(A, "v1/messages", {**_CLAUDE, "container": "c"}) is Reason.SERVER_TOOL

    def test_openai_web_search_options(self) -> None:
        body = {**_GPT, "web_search_options": {}}
        assert _reason(OA, "v1/chat/completions", body) is Reason.SERVER_TOOL

    @pytest.mark.parametrize("tool", ["web_search_preview", "mcp", "file_search", "computer"])
    def test_openai_responses_tools(self, tool: str) -> None:
        body = {"model": "gpt-5", "input": "x", "tools": [{"type": tool}]}
        assert _reason(OA, "v1/responses", body) is Reason.SERVER_TOOL

    def test_openai_tool_choice_naming_a_server_tool(self) -> None:
        body = {"model": "gpt-5", "input": "x", "tool_choice": {"type": "web_search_preview"}}
        assert _reason(OA, "v1/responses", body) is Reason.SERVER_TOOL

    def test_openrouter_web_plugin(self) -> None:
        body = {**_ROUTER, "plugins": [{"id": "web"}]}
        assert _reason(R, "v1/chat/completions", body) is Reason.PLUGINS

    @pytest.mark.parametrize(
        "tool",
        [
            {"googleSearch": {}},
            {"google_search_retrieval": {}},
            {"urlContext": {}},
            {"codeExecution": {}},
        ],
    )
    def test_gemini_grounding_and_url_context(self, tool: dict[str, Any]) -> None:
        body = {"contents": [], "tools": [tool]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.SERVER_TOOL


class TestOnlineModelsRefused:
    @pytest.mark.parametrize(
        ("api", "path", "body"),
        [
            (R, "v1/chat/completions", {**_ROUTER, "model": "openai/gpt-4.1:online"}),
            (R, "v1/chat/completions", {**_ROUTER, "models": ["x/y:online"]}),
            (R, "v1/chat/completions", {**_ROUTER, "model": "perplexity/sonar-pro"}),
            (OA, "v1/chat/completions", {**_GPT, "model": "gpt-4o-search-preview"}),
        ],
    )
    def test_self_searching_model(self, api: LlmApi, path: str, body: dict[str, Any]) -> None:
        assert _reason(api, path, body) is Reason.ONLINE_MODEL

    def test_allowed_models_narrows(self) -> None:
        reason = _reason(OA, "v1/chat/completions", _GPT, allowed_models=["gpt-5*"])
        assert reason is Reason.MODEL_NOT_ALLOWED
        gpt5 = {**_GPT, "model": "gpt-5-mini"}
        _admit(OA, "v1/chat/completions", gpt5, allowed_models=["gpt-5*"])

    def test_gemini_path_model_checked(self) -> None:
        path = "v1beta/models/gemini-2.5-flash:generateContent"
        reason = _reason(G, path, {"contents": []}, allowed_models=["gemini-2.5-pro"])
        assert reason is Reason.MODEL_NOT_ALLOWED


class TestUrlSourcesRefused:
    """A content source the provider dereferences is a fetch by another name."""

    def test_anthropic_image_url_source(self) -> None:
        block = {"type": "image", "source": {"type": "url", "url": "https://evil/?d=secret"}}
        body = {**_CLAUDE, "messages": [{"role": "user", "content": [block]}]}
        assert _reason(A, "v1/messages", body) is Reason.URL_SOURCE

    def test_anthropic_document_url_inside_tool_result(self) -> None:
        doc = {"type": "document", "source": {"type": "url", "url": "https://evil"}}
        result = {"type": "tool_result", "tool_use_id": "t", "content": [doc]}
        body = {**_CLAUDE, "messages": [{"role": "user", "content": [result]}]}
        assert _reason(A, "v1/messages", body) is Reason.URL_SOURCE

    def test_anthropic_server_tool_result_block(self) -> None:
        block = {"type": "web_fetch_tool_result", "tool_use_id": "t", "content": {}}
        body = {**_CLAUDE, "messages": [{"role": "assistant", "content": [block]}]}
        assert _reason(A, "v1/messages", body) is Reason.CONTENT_TYPE

    @pytest.mark.parametrize(
        "image", [{"url": "https://evil/x.png"}, "https://evil/x.png", {"url": "HTTP://e"}]
    )
    def test_openai_image_url(self, image: Any) -> None:
        part = {"type": "image_url", "image_url": image}
        body = {**_GPT, "messages": [{"role": "user", "content": [part]}]}
        assert _reason(OA, "v1/chat/completions", body) is Reason.URL_SOURCE

    def test_openrouter_file_data_url(self) -> None:
        part = {"type": "file", "file": {"filename": "a.pdf", "file_data": "https://evil/a.pdf"}}
        body = {**_ROUTER, "messages": [{"role": "user", "content": [part]}]}
        assert _reason(R, "v1/chat/completions", body) is Reason.URL_SOURCE

    def test_responses_input_file_url(self) -> None:
        part = {"type": "input_file", "file_url": "https://evil/a.pdf"}
        body = {"model": "gpt-5", "input": [{"role": "user", "content": [part]}]}
        assert _reason(OA, "v1/responses", body) is Reason.URL_SOURCE

    def test_gemini_file_data_outside_files_api(self) -> None:
        part = {"fileData": {"fileUri": "https://www.youtube.com/watch?v=x"}}
        body = {"contents": [{"role": "user", "parts": [part]}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.URL_SOURCE

    def test_gemini_file_data_in_files_api_passes(self) -> None:
        uri = "https://generativelanguage.googleapis.com/v1beta/files/abc"
        part = {"file_data": {"file_uri": uri, "mime_type": "application/pdf"}}
        admitted = _admit(G, _GEMINI_PATH, {"contents": [{"role": "user", "parts": [part]}]})
        assert admitted.endpoint == "generateContent"

    def test_gemini_both_spellings_of_one_key_refused(self) -> None:
        """Only one of ``fileData``/``file_data`` would be judged; Google reads either."""
        good = {"file_uri": "https://generativelanguage.googleapis.com/v1beta/files/a"}
        part = {"file_data": good, "fileData": {"fileUri": "https://evil/x"}}
        body = {"contents": [{"role": "user", "parts": [part]}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.MALFORMED

    def test_gemini_both_spellings_of_tools_refused(self) -> None:
        body = {"contents": [], "tools": [], "Tools": [{"googleSearch": {}}]}
        assert _reason(G, _GEMINI_PATH, body) is Reason.MALFORMED


class TestStoredStateRefused:
    @pytest.mark.parametrize(
        "key", ["prompt", "conversation", "background", "previous_response_id"]
    )
    def test_responses(self, key: str) -> None:
        body = {"model": "gpt-5", "input": "x", key: {"id": "p"}}
        assert _reason(OA, "v1/responses", body) is Reason.STORED_STATE

    def test_gemini_cached_content(self) -> None:
        body = {"contents": [], "cachedContent": "cachedContents/x"}
        assert _reason(G, _GEMINI_PATH, body) is Reason.STORED_STATE


class TestShape:
    def test_unknown_param_refused(self) -> None:
        assert _reason(A, "v1/messages", {**_CLAUDE, "new_thing": 1}) is Reason.UNKNOWN_PARAM

    @pytest.mark.parametrize(
        ("api", "path"),
        [
            (A, "v1/files"),
            (A, "v1/messages/batches"),
            (A, "v1/skills"),
            (OA, "v1/files"),
            (OA, "v1/assistants"),
            (G, "v1beta/cachedContents"),
            (G, "v1beta/files"),
            (G, "upload/v1beta/files"),
        ],
    )
    def test_endpoint_refused(self, api: LlmApi, path: str) -> None:
        assert _reason(api, path, {}) is Reason.ENDPOINT

    def test_wrong_method(self) -> None:
        assert _reason(A, "v1/messages", None, method="DELETE") is Reason.METHOD

    def test_gemini_key_in_query_refused(self) -> None:
        assert _reason(G, _GEMINI_PATH, {"contents": []}, query="key=abc") is Reason.QUERY

    def test_duplicate_query_param_refused(self) -> None:
        assert _reason(A, "v1/messages", _CLAUDE, query="beta=true&beta=x") is Reason.QUERY

    def test_non_object_body(self) -> None:
        with pytest.raises(LlmRefusedError) as err:
            admit(A, "POST", "v1/messages", "", b"[1]")
        assert err.value.reason is Reason.MALFORMED

    def test_nan_refused(self) -> None:
        with pytest.raises(LlmRefusedError) as err:
            admit(A, "POST", "v1/messages", "", b'{"temperature": NaN}')
        assert err.value.reason is Reason.MALFORMED

    def test_tools_not_a_list(self) -> None:
        body = {**_CLAUDE, "tools": {"type": "web_search_20250305"}}
        assert _reason(A, "v1/messages", body) is Reason.MALFORMED

    def test_get_with_body_refused(self) -> None:
        assert _reason(A, "v1/models", {"x": 1}, method="GET") is Reason.MALFORMED


class TestForwardHeaders:
    def test_allowlist(self) -> None:
        headers = forward_headers(
            OA,
            [
                ("Accept", "text/event-stream"),
                ("Authorization", "Bearer gateway"),
                ("OpenAI-Organization", "org-x"),
                ("OpenAI-Project", "proj-x"),
                ("anthropic-beta", "context-1m-2025-08-07"),
                ("HTTP-Referer", "https://x"),
            ],
        )
        assert headers == {"accept": "text/event-stream"}

    def test_anthropic_beta_filtered(self) -> None:
        headers = forward_headers(
            A,
            [("anthropic-beta", "web-fetch-2025-09-10,claude-code-20250219,files-api-2025-04-14")],
        )
        assert headers == {"anthropic-beta": "claude-code-20250219"}

    def test_anthropic_beta_all_unsafe_dropped(self) -> None:
        assert forward_headers(A, [("anthropic-beta", "mcp-client-2025-04-04")]) == {}


class TestCurrentAnthropicParams:
    """What Claude Code and current SDKs send must pass (#304 review)."""

    def test_output_config_and_top_level_params(self) -> None:
        body = {
            **_CLAUDE,
            "output_config": {"effort": "high", "format": {"type": "json_schema"}},
            "output_format": {"type": "json_schema"},
            "cache_control": {"type": "ephemeral"},
            "inference_geo": "us",
            "speed": "fast",
            "diagnostics": {"cache": True},
        }
        assert _admit(A, "v1/messages", body).endpoint == "messages"

    def test_output_config_task_budget(self) -> None:
        body = {**_CLAUDE, "output_config": {"task_budget": {"tokens": 1000}}}
        assert _admit(A, "v1/messages", body).endpoint == "messages"

    def test_output_config_unknown_key_refused(self) -> None:
        body = {**_CLAUDE, "output_config": {"effort": "low", "tools": []}}
        assert _reason(A, "v1/messages", body) is Reason.UNKNOWN_PARAM

    def test_output_config_not_an_object(self) -> None:
        assert _reason(A, "v1/messages", {**_CLAUDE, "output_config": "x"}) is Reason.MALFORMED

    def test_fallbacks_default(self) -> None:
        assert _admit(A, "v1/messages", {**_CLAUDE, "fallbacks": "default"}).model

    def test_fallbacks_default_refused_under_allowed_models(self) -> None:
        body = {**_CLAUDE, "fallbacks": "default"}
        reason = _reason(A, "v1/messages", body, allowed_models=["claude-*"])
        assert reason is Reason.MODEL_NOT_ALLOWED

    def test_fallbacks_list_checked_against_allowed_models(self) -> None:
        body = {**_CLAUDE, "fallbacks": [{"model": "claude-opus-4-1"}]}
        assert _admit(A, "v1/messages", body, allowed_models=["claude-*"]).model
        reason = _reason(A, "v1/messages", body, allowed_models=["claude-sonnet-*"])
        assert reason is Reason.MODEL_NOT_ALLOWED

    def test_fallbacks_online_model_refused(self) -> None:
        body = {**_CLAUDE, "fallbacks": [{"model": "x:online"}]}
        assert _reason(A, "v1/messages", body) is Reason.ONLINE_MODEL

    @pytest.mark.parametrize(
        "fallbacks", [[{"model": "claude-opus-4-1", "tools": []}], ["claude-opus-4-1"], "other"]
    )
    def test_fallbacks_shape(self, fallbacks: Any) -> None:
        reason = _reason(A, "v1/messages", {**_CLAUDE, "fallbacks": fallbacks})
        assert reason in (Reason.UNKNOWN_PARAM, Reason.MALFORMED)

    @pytest.mark.parametrize("kind", ["compaction", "fallback"])
    def test_replayed_response_blocks(self, kind: str) -> None:
        block = {"type": kind, "content": "summary"}
        body = {**_CLAUDE, "messages": [{"role": "assistant", "content": [block]}]}
        assert _admit(A, "v1/messages", body).endpoint == "messages"

    def test_mid_conversation_system_message(self) -> None:
        messages = [
            {"role": "user", "content": "hi"},
            {"role": "system", "content": [{"type": "text", "text": "be brief"}]},
            {"role": "system", "content": "plain string"},
        ]
        body = {**_CLAUDE, "messages": messages}
        assert _admit(A, "v1/messages", body).endpoint == "messages"

    def test_system_message_still_checks_blocks(self) -> None:
        block = {"type": "image", "source": {"type": "url", "url": "https://evil"}}
        body = {**_CLAUDE, "messages": [{"role": "system", "content": [block]}]}
        assert _reason(A, "v1/messages", body) is Reason.URL_SOURCE

    @pytest.mark.parametrize(
        "flag",
        [
            "fast-mode-2026-02-01",
            "server-side-fallback-2026-03-01",
            "task-budgets-2026-01-01",
            "mid-conversation-system-2026-01-01",
            "compact-2026-01-12",
            "cache-diagnosis-2026-01-01",
            "thinking-display-2026-01-01",
            "effort-2025-11-24",
        ],
    )
    def test_safe_betas_kept(self, flag: str) -> None:
        assert forward_headers(A, [("anthropic-beta", flag)]) == {"anthropic-beta": flag}

    @pytest.mark.parametrize(
        "flag",
        [
            "mcp-client-2025-11-20",
            "code-execution-2025-08-25",
            "web-fetch-2025-09-10",
            "web-search-2025-03-05",
            "files-api-2025-04-14",
            "skills-2025-10-02",
            "oauth-2025-04-20",
        ],
    )
    def test_unsafe_betas_dropped(self, flag: str) -> None:
        assert forward_headers(A, [("anthropic-beta", flag)]) == {}


class TestCurrentOpenAiChatParams:
    def test_current_params_pass(self) -> None:
        body = {
            **_GPT,
            "reasoning_effort": "low",
            "max_completion_tokens": 100,
            "modalities": ["text"],
            "prediction": {"type": "content", "content": "x"},
            "store": False,
            "verbosity": "low",
            "parallel_tool_calls": False,
            "stream": True,
            "stream_options": {"include_usage": True},
            "response_format": {"type": "json_object"},
            "seed": 1,
            "logprobs": True,
            "top_logprobs": 2,
            "n": 1,
            "service_tier": "auto",
            "prompt_cache_key": "k",
            "safety_identifier": "u",
        }
        assert _admit(OA, "v1/chat/completions", body).endpoint == "chat/completions"

    @pytest.mark.parametrize("store", [True, "true", 1])
    def test_store_refused(self, store: Any) -> None:
        body = {**_GPT, "store": store, "metadata": {"k": "v"}}
        assert _reason(OA, "v1/chat/completions", body) is Reason.STORED_STATE

    def test_store_refused_on_openrouter_too(self) -> None:
        body = {**_ROUTER, "store": True}
        assert _reason(R, "v1/chat/completions", body) is Reason.STORED_STATE


@pytest.mark.parametrize(
    ("api", "path", "body"),
    [
        (
            LlmApi.ANTHROPIC,
            "v1/messages",
            {**_CLAUDE, "messages": [{"role": "user", "content": [{"type": ["text"]}]}]},
        ),
        (
            LlmApi.OPENAI,
            "v1/chat/completions",
            {"model": "gpt-x", "messages": [{"role": "user", "content": [{"type": ["x"]}]}]},
        ),
    ],
)
def test_an_unhashable_type_is_refused_not_a_crash(api: LlmApi, path: str, body: Any) -> None:
    assert _reason(api, path, body) is Reason.MALFORMED


class TestOpenRouterSession:
    """#556: the gateway, never the agent, sets OpenRouter's session_id."""

    def test_an_agent_cannot_set_session_id(self) -> None:
        assert _reason(R, "v1/chat/completions", {**_ROUTER, "session_id": "mine"}) is not None

    def test_the_gateway_sets_it_on_an_openrouter_chat(self) -> None:
        admitted = with_session(R, _admit(R, "v1/chat/completions", _ROUTER), "abc123")
        assert json.loads(admitted.body) == {**_ROUTER, "session_id": "abc123"}

    @pytest.mark.parametrize(
        ("api", "path", "body", "session"),
        [
            (R, "v1/chat/completions", _ROUTER, None),
            (OA, "v1/chat/completions", _GPT, "abc123"),
            (A, "v1/messages", _CLAUDE, "abc123"),
            (R, "v1/models", None, "abc123"),
        ],
    )
    def test_anything_else_is_unchanged(
        self, api: LlmApi, path: str, body: dict[str, Any] | None, session: str | None
    ) -> None:
        method = "GET" if body is None else "POST"
        admitted = _admit(api, path, body, method=method)
        assert with_session(api, admitted, session) is admitted
