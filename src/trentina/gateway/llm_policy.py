"""What the LLM proxy lets an agent ask a provider to do (#297).

The proxy used to forward the caller's path, query, raw body and every header
but ``Authorization``. A provider is not only a model: Anthropic runs
``web_fetch``, ``web_search`` and code execution itself and connects to MCP
servers named in ``mcp_servers``; OpenAI has search models and server tools in
the Responses API; OpenRouter adds a ``web`` plugin and the ``:online`` model
suffix; Gemini grounds on Google Search and reads ``url_context``. Each one
fetches a URL the agent chose, on the profile's key, from the provider's
network. An agent on ``--network=none`` had a two-way channel to any host, and
neither ``egress.py`` nor the audit saw it.

So a request is admitted, not forwarded. Everything is an allowlist and
anything unrecognized is refused, per API shape:

- the endpoint (path and method) is one of a short list of completion,
  token-count, embedding and model-listing endpoints;
- query parameters and request headers are from a list, and ``anthropic-beta``
  keeps only the feature flags that change nothing about where data goes;
- body keys are from a list, and a tool is a function the CALLER runs: any
  provider-run tool type, ``mcp_servers``, stored-state references
  (``prompt``, ``conversation``, ``previous_response_id``,
  ``cachedContent``), and a content source the provider would fetch by URL
  are refused with a closed reason code;
- a model that searches by itself (``:online``, ``*search*``, ``sonar``,
  ``perplexity/``, ``compound``) is refused, and a provider's
  ``allowed_models`` narrows the rest.

The body is parsed with duplicate keys refused and forwarded RE-SERIALIZED,
so the provider parses exactly the object that was judged. Raw bytes would
leave a parser differential: ``{"tools": [web_search], "tools": []}`` reads
one way here and possibly the other there.

Message text is not judged: a model without a server-side tool cannot
dereference a URL in a prompt. The completion is judged after it streams
(recorded, not withheld; see ``llm_proxy._streaming_response``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


class LlmApi(StrEnum):
    """The request shape a provider speaks, which decides what is admitted."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    GEMINI = "gemini"


#: Known upstream hosts. Any other upstream must declare ``api``.
API_BY_HOST: dict[str, LlmApi] = {
    "api.anthropic.com": LlmApi.ANTHROPIC,
    "api.openai.com": LlmApi.OPENAI,
    "openrouter.ai": LlmApi.OPENROUTER,
    "generativelanguage.googleapis.com": LlmApi.GEMINI,
}


class Reason(StrEnum):
    """Why a request was refused. A closed set: it is logged and audited."""

    ENDPOINT = "endpoint_not_allowed"
    METHOD = "method_not_allowed"
    QUERY = "query_not_allowed"
    MALFORMED = "malformed_body"
    UNKNOWN_PARAM = "unknown_param"
    SERVER_TOOL = "server_tool"
    MCP_SERVERS = "mcp_servers"
    PLUGINS = "plugins"
    URL_SOURCE = "url_source"
    FILE_REFERENCE = "file_reference"
    STORED_STATE = "stored_state"
    CONTENT_TYPE = "content_type"
    ONLINE_MODEL = "online_model"
    MODEL_NOT_ALLOWED = "model_not_allowed"
    TOO_LARGE = "too_large"
    # #511: the request content, judged after admission. A credential shape is
    # deterministic; FLAGGED and UNJUDGED carry L1/L2/L3's verdict and gaps.
    CREDENTIAL = "credential_in_request"
    FLAGGED = "flagged"
    UNJUDGED = "not_fully_judged"


class LlmRefusedError(Exception):
    """The request is not admitted. ``detail`` is the caller's own token.

    ``detail`` names the key or type that was refused so the caller can see
    what to drop. It is the caller's own text: it goes back to that caller
    only, never to a log record (#262) and never to the audit row.
    """

    def __init__(self, reason: Reason, detail: Any = "", status: int = 403) -> None:
        self.reason = reason
        self.detail = str(detail)[:64]
        self.status = status
        super().__init__(reason.value)


@dataclass(frozen=True)
class Admitted:
    """A request the policy admitted, rebuilt from what was judged."""

    endpoint: str
    query: str
    body: bytes | None
    model: str | None


# --- models -----------------------------------------------------------------

# Models whose provider searches or browses without being asked: OpenRouter's
# ``:online``, OpenAI's ``*-search-preview``, Perplexity's ``sonar``, Groq's
# ``compound``. A heuristic floor; ``allowed_models`` is the real control.
_ONLINE_MODEL = re.compile(r":online\b|search|sonar|perplexity/|compound", re.IGNORECASE)


def check_model(model: Any, allowed: Iterable[str]) -> None:
    """Refuse a self-searching model, or one outside ``allowed`` when set."""
    if model is None:
        return
    if not isinstance(model, str):
        raise LlmRefusedError(Reason.MALFORMED, "model")
    if _ONLINE_MODEL.search(model):
        raise LlmRefusedError(Reason.ONLINE_MODEL, model)
    patterns = list(allowed)
    if patterns and not any(fnmatchcase(model, p) for p in patterns):
        raise LlmRefusedError(Reason.MODEL_NOT_ALLOWED, model)


# --- shared shape helpers ----------------------------------------------------


def _seq(value: Any, field: str) -> list[Any]:
    """A list field, absent as empty. Anything else is malformed."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise LlmRefusedError(Reason.MALFORMED, field)
    return value


def _obj(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LlmRefusedError(Reason.MALFORMED, field)
    return value


def _check_keys(
    body: Mapping[str, Any],
    allowed: frozenset[str],
    named: Mapping[str, Reason],
) -> None:
    """Every key is allowed. A known-dangerous one gets its own reason."""
    for name in body:
        if name in named:
            raise LlmRefusedError(named[name], name)
        if name not in allowed:
            raise LlmRefusedError(Reason.UNKNOWN_PARAM, name)


def _data_url(value: Any, field: str) -> None:
    """Inline data only. A URL here is one the provider would fetch."""
    if not isinstance(value, str):
        raise LlmRefusedError(Reason.MALFORMED, field)
    if not value.startswith("data:"):
        raise LlmRefusedError(Reason.URL_SOURCE, field)


# --- Anthropic Messages ------------------------------------------------------

_ANTHROPIC_KEYS = frozenset(
    {
        "model",
        "messages",
        "system",
        "max_tokens",
        "metadata",
        "stop_sequences",
        "stream",
        "temperature",
        "top_k",
        "top_p",
        "tools",
        "tool_choice",
        "thinking",
        "service_tier",
        "context_management",
        "output_config",
        # The older spelling of ``output_config.format``; the API still takes it.
        "output_format",
        "cache_control",
        "inference_geo",
        "speed",
        "diagnostics",
        "fallbacks",
    }
)
_ANTHROPIC_OUTPUT_CONFIG = frozenset({"effort", "format", "task_budget"})
_ANTHROPIC_NAMED = {
    "mcp_servers": Reason.MCP_SERVERS,
    "container": Reason.SERVER_TOOL,
}
_ANTHROPIC_BLOCKS = frozenset(
    {
        "text",
        "image",
        "document",
        "tool_use",
        "tool_result",
        "thinking",
        "redacted_thinking",
        "search_result",
        # Both come back in ``response.content`` and a client replays them.
        "compaction",
        "fallback",
    }
)
_ANTHROPIC_SOURCES = frozenset({"base64", "text", "content"})


def _anthropic_blocks(blocks: list[Any], field: str) -> None:
    for raw in blocks:
        block = _obj(raw, field)
        kind = block.get("type")
        if kind not in _ANTHROPIC_BLOCKS:
            raise LlmRefusedError(Reason.CONTENT_TYPE, kind)
        if kind in ("image", "document"):
            source = _obj(block.get("source"), "source")
            if source.get("type") not in _ANTHROPIC_SOURCES:
                raise LlmRefusedError(Reason.URL_SOURCE, source.get("type"))
            if isinstance(source.get("content"), list):
                _anthropic_blocks(source["content"], "source.content")
        if kind == "tool_result" and isinstance(block.get("content"), list):
            _anthropic_blocks(block["content"], "tool_result.content")


def _fallback_shape(fallbacks: Any) -> None:
    """``"default"``, or a list of ``{"model": ...}``. The models are checked in ``_models``."""
    if fallbacks is None or fallbacks == "default":
        return
    for raw in _seq(fallbacks, "fallbacks"):
        _check_keys(_obj(raw, "fallbacks"), frozenset({"model"}), {})


def _anthropic_messages(body: dict[str, Any]) -> None:
    _check_keys(body, _ANTHROPIC_KEYS, _ANTHROPIC_NAMED)
    for raw in _seq(body.get("tools"), "tools"):
        # A custom tool has no type, or "custom". Every other type is one
        # Anthropic runs or defines: web_fetch, web_search, code_execution,
        # bash, text_editor, computer, memory, tool_search.
        kind = _obj(raw, "tools").get("type")
        if kind not in (None, "custom"):
            raise LlmRefusedError(Reason.SERVER_TOOL, kind)
    if "output_config" in body:
        _check_keys(_obj(body["output_config"], "output_config"), _ANTHROPIC_OUTPUT_CONFIG, {})
    _fallback_shape(body.get("fallbacks"))
    if isinstance(body.get("system"), list):
        _anthropic_blocks(body["system"], "system")
    # A mid-conversation ``role: system`` message is checked like any other.
    for raw in _seq(body.get("messages"), "messages"):
        content = _obj(raw, "messages").get("content")
        if isinstance(content, list):
            _anthropic_blocks(content, "content")


# --- OpenAI-compatible -------------------------------------------------------

_OPENAI_CHAT_KEYS = frozenset(
    {
        "model",
        "messages",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "n",
        "stream",
        "stream_options",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "logit_bias",
        "logprobs",
        "top_logprobs",
        "user",
        "seed",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "functions",
        "function_call",
        "response_format",
        "reasoning_effort",
        "metadata",
        "store",
        "service_tier",
        "modalities",
        "audio",
        "prediction",
        "verbosity",
        "safety_identifier",
        "prompt_cache_key",
    }
)
# OpenRouter's own request fields. ``models`` is a fallback list, each
# entry checked like ``model``; ``plugins`` is refused by name.
_OPENROUTER_EXTRA = frozenset(
    {
        "provider",
        "transforms",
        "models",
        "route",
        "reasoning",
        "usage",
        "top_k",
        "min_p",
        "top_a",
        "repetition_penalty",
        "include_reasoning",
    }
)
_OPENAI_NAMED = {
    "web_search_options": Reason.SERVER_TOOL,
    "plugins": Reason.PLUGINS,
}
_OPENAI_COMPLETION_KEYS = frozenset(
    {
        "model",
        "prompt",
        "max_tokens",
        "temperature",
        "top_p",
        "n",
        "stream",
        "stream_options",
        "logprobs",
        "echo",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "best_of",
        "logit_bias",
        "user",
        "suffix",
        "seed",
    }
)
_OPENAI_EMBEDDING_KEYS = frozenset({"model", "input", "encoding_format", "dimensions", "user"})
_CHAT_PARTS = frozenset({"text", "image_url", "input_audio", "file", "refusal"})


def _function_tools(tools: Any, allowed: frozenset[str]) -> None:
    for raw in _seq(tools, "tools"):
        kind = _obj(raw, "tools").get("type")
        if kind not in allowed:
            raise LlmRefusedError(Reason.SERVER_TOOL, kind)


def _tool_choice(choice: Any, allowed: frozenset[str]) -> None:
    """A forced tool must be one the caller runs, as in ``tools``."""
    if not isinstance(choice, dict):
        return
    kind = choice.get("type")
    if kind == "allowed_tools":
        inner = choice.get("allowed_tools", choice)
        _function_tools(_obj(inner, "tool_choice").get("tools"), allowed)
    elif kind not in allowed | {"auto", "none", "required"}:
        raise LlmRefusedError(Reason.SERVER_TOOL, kind)


def _file_part(file: Any) -> None:
    file = _obj(file, "file")
    if "file_id" in file:
        raise LlmRefusedError(Reason.FILE_REFERENCE, "file_id")
    if "file_data" in file:
        _data_url(file["file_data"], "file_data")


def _chat_parts(parts: list[Any]) -> None:
    for raw in parts:
        part = _obj(raw, "content")
        kind = part.get("type")
        if kind not in _CHAT_PARTS:
            raise LlmRefusedError(Reason.CONTENT_TYPE, kind)
        if kind == "image_url":
            image = part.get("image_url")
            _data_url(image.get("url") if isinstance(image, dict) else image, "image_url")
        elif kind == "file":
            _file_part(part.get("file"))


def _models(body: dict[str, Any], allowed_models: Iterable[str]) -> None:
    """Every model a request names, not only ``model``.

    OpenRouter's ``models`` and Anthropic's ``fallbacks`` both name a model
    the provider may run instead; skipping either bypasses ``allowed_models``.
    """
    patterns = list(allowed_models)
    check_model(body.get("model"), patterns)
    for model in _seq(body.get("models"), "models"):
        check_model(model, patterns)
    fallbacks = body.get("fallbacks")
    # "default" lets the provider pick the fallback model, which no pattern
    # can check; with allowed_models set that is the bypass it exists to stop.
    if fallbacks == "default" and patterns:
        raise LlmRefusedError(Reason.MODEL_NOT_ALLOWED, "fallbacks")
    if isinstance(fallbacks, list):
        for raw in fallbacks:
            check_model(_obj(raw, "fallbacks").get("model"), patterns)


_FUNCTION = frozenset({"function"})


def _openai_chat(keys: frozenset[str]) -> Callable[[dict[str, Any]], None]:
    def validate(body: dict[str, Any]) -> None:
        _check_keys(body, keys, _OPENAI_NAMED)
        # ``store: true`` keeps the completion (and its ``metadata``) on the
        # provider, retrievable later outside anything judged here.
        store = body.get("store")
        if store is not None and store is not False:
            raise LlmRefusedError(Reason.STORED_STATE, "store")
        _function_tools(body.get("tools"), _FUNCTION)
        _tool_choice(body.get("tool_choice"), _FUNCTION)
        for raw in _seq(body.get("messages"), "messages"):
            content = _obj(raw, "messages").get("content")
            if isinstance(content, list):
                _chat_parts(content)

    return validate


def _plain(keys: frozenset[str]) -> Callable[[dict[str, Any]], None]:
    def validate(body: dict[str, Any]) -> None:
        _check_keys(body, keys, _OPENAI_NAMED)

    return validate


_RESPONSES_KEYS = frozenset(
    {
        "model",
        "input",
        "instructions",
        "max_output_tokens",
        "max_tool_calls",
        "metadata",
        "parallel_tool_calls",
        "reasoning",
        "service_tier",
        "store",
        "stream",
        "stream_options",
        "temperature",
        "text",
        "tool_choice",
        "tools",
        "top_logprobs",
        "top_p",
        "truncation",
        "user",
        "safety_identifier",
        "prompt_cache_key",
        "include",
    }
)
_RESPONSES_NAMED = {
    **_OPENAI_NAMED,
    "prompt": Reason.STORED_STATE,
    "conversation": Reason.STORED_STATE,
    "background": Reason.STORED_STATE,
    # Continues a response the provider stored; its context is not in this
    # request, so it was never judged here.
    "previous_response_id": Reason.STORED_STATE,
}
_RESPONSES_TOOLS = frozenset({"function", "custom"})
_RESPONSES_ITEMS = frozenset(
    {
        "message",
        "function_call",
        "function_call_output",
        "reasoning",
        "custom_tool_call",
        "custom_tool_call_output",
    }
)
_RESPONSES_PARTS = frozenset(
    {
        "input_text",
        "output_text",
        "input_image",
        "input_file",
        "refusal",
        "summary_text",
        "reasoning_text",
    }
)


def _responses_parts(parts: list[Any]) -> None:
    for raw in parts:
        part = _obj(raw, "content")
        kind = part.get("type")
        if kind not in _RESPONSES_PARTS:
            raise LlmRefusedError(Reason.CONTENT_TYPE, kind)
        if "file_id" in part:
            raise LlmRefusedError(Reason.FILE_REFERENCE, "file_id")
        if "file_url" in part:
            raise LlmRefusedError(Reason.URL_SOURCE, "file_url")
        if part.get("image_url") is not None:
            _data_url(part["image_url"], "image_url")
        if "file_data" in part:
            _data_url(part["file_data"], "file_data")


def _openai_responses(body: dict[str, Any]) -> None:
    _check_keys(body, _RESPONSES_KEYS, _RESPONSES_NAMED)
    _function_tools(body.get("tools"), _RESPONSES_TOOLS)
    _tool_choice(body.get("tool_choice"), _RESPONSES_TOOLS)
    items = body.get("input")
    if isinstance(items, str):
        return
    for raw in _seq(items, "input"):
        item = _obj(raw, "input")
        # An item with a role and no type is a message.
        kind = item.get("type", "message" if "role" in item else None)
        if kind not in _RESPONSES_ITEMS:
            raise LlmRefusedError(Reason.CONTENT_TYPE, kind)
        if isinstance(item.get("content"), list):
            _responses_parts(item["content"])


# --- Gemini ------------------------------------------------------------------

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def _snake_keys(raw: Any, field: str) -> dict[str, Any]:
    """An object with its keys in snake case.

    Google's JSON parser takes ``fileData`` and ``file_data`` alike, so the
    two spellings are one key. An object carrying both is refused: which one
    the provider reads is its choice, and only one of them would be judged.
    """
    out: dict[str, Any] = {}
    for key, value in _obj(raw, field).items():
        name = _CAMEL.sub("_", key).lower()
        if name in out:
            raise LlmRefusedError(Reason.MALFORMED, key, status=400)
        out[name] = value
    return out


_GEMINI_KEYS = frozenset(
    {
        "contents",
        "system_instruction",
        "tools",
        "tool_config",
        "generation_config",
        "safety_settings",
        "labels",
        "model",
    }
)
_GEMINI_NAMED = {"cached_content": Reason.STORED_STATE}
_GEMINI_EMBED_KEYS = frozenset({"content", "task_type", "title", "output_dimensionality", "model"})
_GEMINI_TOOL_KEYS = frozenset({"function_declarations"})
_GEMINI_PART_KEYS = frozenset(
    {
        "text",
        "inline_data",
        "function_call",
        "function_response",
        "file_data",
        "thought",
        "thought_signature",
        "video_metadata",
        "media_resolution",
    }
)
# ``file_data`` names a file the provider reads. Its own Files API is the
# only place it may be: a YouTube or arbitrary https URI is fetched.
_GEMINI_FILES = "https://generativelanguage.googleapis.com/"


def _gemini_content(raw: Any, field: str) -> None:
    content = _snake_keys(raw, field)
    for part_raw in _seq(content.get("parts"), "parts"):
        part = _snake_keys(part_raw, "parts")
        for name, value in part.items():
            if name not in _GEMINI_PART_KEYS:
                raise LlmRefusedError(Reason.CONTENT_TYPE, name)
            if name == "file_data":
                uri = _snake_keys(value, name).get("file_uri")
                if not isinstance(uri, str) or not uri.startswith(_GEMINI_FILES):
                    raise LlmRefusedError(Reason.URL_SOURCE, name)


def _gemini_generate(body: dict[str, Any]) -> None:
    fields = _snake_keys(body, "body")
    _check_keys(fields, _GEMINI_KEYS | {"generate_content_request"}, _GEMINI_NAMED)
    for raw in _seq(fields.get("tools"), "tools"):
        for name in _snake_keys(raw, "tools"):
            # Only declared functions. google_search, url_context,
            # code_execution, google_maps, file_search and computer_use
            # all run on Google's side.
            if name not in _GEMINI_TOOL_KEYS:
                raise LlmRefusedError(Reason.SERVER_TOOL, name)
    for raw in _seq(fields.get("contents"), "contents"):
        _gemini_content(raw, "contents")
    if isinstance(fields.get("system_instruction"), dict):
        _gemini_content(fields["system_instruction"], "system_instruction")
    if "generate_content_request" in fields:  # countTokens' long form
        inner = _snake_keys(fields["generate_content_request"], "generate_content_request")
        _check_keys(inner, _GEMINI_KEYS, _GEMINI_NAMED)
        _gemini_generate(inner)


def _gemini_embed(body: dict[str, Any]) -> None:
    fields = _snake_keys(body, "body")
    _check_keys(fields, _GEMINI_EMBED_KEYS, _GEMINI_NAMED)
    if "content" in fields:
        _gemini_content(fields["content"], "content")


# --- endpoints ---------------------------------------------------------------

Validator = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class _Endpoint:
    """A path pattern (``fullmatch`` on the unversioned path) and its method."""

    pattern: str
    method: str
    label: str
    validate: Validator | None = None


_MODEL_ID = r"[A-Za-z0-9._:-]+"
# OpenRouter model ids carry the author: ``anthropic/claude-sonnet-4``.
_MODEL_PATH = r"models(?:/[A-Za-z0-9._:-]+){1,3}"

_OPENAI_ENDPOINTS = (
    _Endpoint(r"chat/completions", "POST", "chat/completions", _openai_chat(_OPENAI_CHAT_KEYS)),
    _Endpoint(r"completions", "POST", "completions", _plain(_OPENAI_COMPLETION_KEYS)),
    _Endpoint(r"embeddings", "POST", "embeddings", _plain(_OPENAI_EMBEDDING_KEYS)),
    _Endpoint(r"responses", "POST", "responses", _openai_responses),
    _Endpoint(r"models", "GET", "models"),
    _Endpoint(_MODEL_PATH, "GET", "models"),
)

_ENDPOINTS: dict[LlmApi, tuple[_Endpoint, ...]] = {
    LlmApi.ANTHROPIC: (
        _Endpoint(r"messages", "POST", "messages", _anthropic_messages),
        _Endpoint(r"messages/count_tokens", "POST", "messages/count_tokens", _anthropic_messages),
        _Endpoint(r"models", "GET", "models"),
        _Endpoint(rf"models/{_MODEL_ID}", "GET", "models"),
    ),
    LlmApi.OPENAI: _OPENAI_ENDPOINTS,
    LlmApi.OPENROUTER: (
        _Endpoint(
            r"chat/completions",
            "POST",
            "chat/completions",
            _openai_chat(_OPENAI_CHAT_KEYS | _OPENROUTER_EXTRA),
        ),
        *_OPENAI_ENDPOINTS[1:],
    ),
    LlmApi.GEMINI: (
        _Endpoint(
            rf"models/(?P<model>{_MODEL_ID}):generateContent",
            "POST",
            "generateContent",
            _gemini_generate,
        ),
        _Endpoint(
            rf"models/(?P<model>{_MODEL_ID}):streamGenerateContent",
            "POST",
            "streamGenerateContent",
            _gemini_generate,
        ),
        _Endpoint(
            rf"models/(?P<model>{_MODEL_ID}):countTokens", "POST", "countTokens", _gemini_generate
        ),
        _Endpoint(
            rf"models/(?P<model>{_MODEL_ID}):embedContent", "POST", "embedContent", _gemini_embed
        ),
        _Endpoint(r"models", "GET", "models"),
        _Endpoint(rf"models/{_MODEL_ID}", "GET", "models"),
    ),
}

# The version prefix an upstream may leave to the caller: ``openrouter.ai/api``
# is called with ``v1/chat/completions``, ``api.openai.com/v1`` with
# ``chat/completions``. Gemini versions its path itself.
_PREFIX: dict[LlmApi, re.Pattern[str]] = {
    LlmApi.ANTHROPIC: re.compile(r"(?:v1/)?"),
    LlmApi.OPENAI: re.compile(r"(?:(?:api/)?v1/)?"),
    LlmApi.OPENROUTER: re.compile(r"(?:(?:api/)?v1/)?"),
    LlmApi.GEMINI: re.compile(r"(?:v1|v1beta|v1alpha)/"),
}

_QUERY: dict[LlmApi, frozenset[str]] = {
    # Claude Code calls ``/v1/messages?beta=true``.
    LlmApi.ANTHROPIC: frozenset({"beta", "limit", "after_id", "before_id"}),
    LlmApi.OPENAI: frozenset({"limit", "after", "order"}),
    LlmApi.OPENROUTER: frozenset({"limit", "after", "order"}),
    # ``key`` is refused: the gateway injects the key.
    LlmApi.GEMINI: frozenset({"alt", "pageSize", "pageToken"}),
}


def _route(api: LlmApi, method: str, path: str) -> tuple[_Endpoint, re.Match[str]]:
    prefix = _PREFIX[api].match(path)
    tail = path[prefix.end() :] if prefix else None
    if tail is None:
        raise LlmRefusedError(Reason.ENDPOINT)
    method_mismatch = False
    for endpoint in _ENDPOINTS[api]:
        match = re.fullmatch(endpoint.pattern, tail)
        if match is None:
            continue
        if endpoint.method == method:
            return endpoint, match
        method_mismatch = True
    if method_mismatch:
        raise LlmRefusedError(Reason.METHOD, status=405)
    raise LlmRefusedError(Reason.ENDPOINT)


def _query(api: LlmApi, raw: str) -> str:
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=bool(raw))
    except ValueError:
        raise LlmRefusedError(Reason.QUERY) from None
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise LlmRefusedError(Reason.QUERY)
    for name in names:
        if name not in _QUERY[api]:
            raise LlmRefusedError(Reason.QUERY, name)
    return urlencode(pairs)


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise LlmRefusedError(Reason.MALFORMED, key, status=400)
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise LlmRefusedError(Reason.MALFORMED, name, status=400)


def _parse(body: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            body,
            object_pairs_hook=_refuse_duplicates,
            parse_constant=_refuse_constant,
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise LlmRefusedError(Reason.MALFORMED, status=400) from None
    if not isinstance(parsed, dict):
        raise LlmRefusedError(Reason.MALFORMED, status=400)
    return parsed


def admit(
    api: LlmApi,
    method: str,
    path: str,
    query: str,
    body: bytes,
    allowed_models: Iterable[str] = (),
) -> Admitted:
    """Admit one request or raise ``LlmRefusedError``.

    Args:
        api: The provider's request shape.
        method: The HTTP method.
        path: The upstream path, already traversal-checked.
        query: The raw query string.
        body: The whole request body; empty for a GET.
        allowed_models: Globs a model must match, when not empty.

    Returns:
        The endpoint's closed-set label, the rebuilt query, the body to send
        (re-serialized, or None for a GET) and the model named, if any.
    """
    endpoint, match = _route(api, method, path)
    rebuilt_query = _query(api, query)
    patterns = list(allowed_models)
    path_model = match.groupdict().get("model")
    if endpoint.validate is None:
        if body.strip():
            raise LlmRefusedError(Reason.MALFORMED, status=400)
        return Admitted(endpoint.label, rebuilt_query, None, None)

    parsed = _parse(body)
    try:
        endpoint.validate(parsed)
        _models(parsed, patterns)
    except (TypeError, AttributeError) as exc:
        # A shape no validator expected, e.g. a list where a type name goes
        # (unhashable in a set test). Refused, never a 500 that skips audit.
        raise LlmRefusedError(Reason.MALFORMED, status=400) from exc
    check_model(path_model, patterns)
    model = path_model or parsed.get("model")
    serialized = json.dumps(parsed, ensure_ascii=True, separators=(",", ":"))
    return Admitted(
        endpoint.label,
        rebuilt_query,
        serialized.encode("ascii"),
        model if isinstance(model, str) else None,
    )


# --- headers -----------------------------------------------------------------

_HEADERS = frozenset({"accept", "anthropic-version"})

# ``anthropic-beta`` flags that change how a response is shaped or cached,
# never what the provider fetches or runs. ``mcp-client``, ``code-execution``,
# ``web-fetch``, ``files-api``, ``skills`` and ``oauth`` are dropped.
_SAFE_BETAS = (
    "claude-code-",
    "interleaved-thinking-",
    "fine-grained-tool-streaming-",
    "context-1m-",
    "context-management-",
    "token-efficient-tools-",
    "output-128k-",
    "prompt-caching-",
    "extended-cache-ttl-",
    "structured-outputs-",
    "fast-mode-",
    "server-side-fallback-",
    "task-budgets-",
    "mid-conversation-",
    "compact-",
    "cache-diagnosis-",
    "thinking-display-",
    "effort-",
)


def forward_headers(api: LlmApi, raw: Iterable[tuple[str, str]]) -> dict[str, str]:
    """The caller's headers the provider may see. Allowlisted, not stripped.

    ``Authorization``, ``OpenAI-Organization``/``-Project`` (which would point
    the profile's key at another org), ``x-goog-api-key`` and every SDK or
    attribution header are dropped. ``Content-Type`` is set by the proxy.
    """
    out: dict[str, str] = {}
    for name, value in raw:
        lower = name.lower()
        if lower in _HEADERS:
            out[lower] = value
        elif lower == "anthropic-beta" and api is LlmApi.ANTHROPIC:
            kept = [
                flag.strip() for flag in value.split(",") if flag.strip().startswith(_SAFE_BETAS)
            ]
            if kept:
                out[lower] = ",".join(kept)
    return out
