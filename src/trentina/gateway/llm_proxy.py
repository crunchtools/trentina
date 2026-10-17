"""Config-driven LLM API reverse proxy.

Forwards requests from ``/llm/{provider}/{path}`` to the configured upstream
LLM provider, injecting the real API key.  Agents on the internal network
never hold provider credentials — Trentina is the choke point.

Adding a new provider is a YAML entry, not code::

    llm_providers:
      anthropic:
        enabled: true
        upstream: https://api.anthropic.com
        auth_header: x-api-key
        api_key_env: ANTHROPIC_API_KEY

Streaming (SSE) and non-streaming responses are forwarded transparently.

A request is ADMITTED, not forwarded (#297): ``llm_policy`` allowlists the
endpoint, query, headers and body for the provider's API shape and refuses
anything that would have the provider fetch, search or connect on the
agent's behalf. Every call, admitted or refused, writes a ``gateway_calls``
row.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from starlette.responses import Response, StreamingResponse

from ..database import record_gateway_call
from ..logsafe import exc_kind, exc_where, redact_source
from ..outcomes import Outcome
from .auth import resolve_profile_by_token
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, DestinationKind
from .errors import ProfileConfigError
from .llm_policy import API_BY_HOST, LlmApi, LlmRefusedError, Reason, admit, forward_headers
from .loader import read_secret_env
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    normalize_proxy_path,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

_LLM_TIMEOUT = httpx.Timeout(
    connect=10.0,
    read=300.0,
    write=10.0,
    pool=5.0,
)

LLM_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# A request body is read whole to be judged. Anthropic's own request limit is
# 32 MB; nothing an admitted endpoint takes needs more.
MAX_LLM_REQUEST_BYTES = 32 * 1024 * 1024

_llm_client: httpx.AsyncClient | None = None


def _get_llm_client() -> httpx.AsyncClient:
    global _llm_client
    if _llm_client is None:
        # nosemgrep: trentina-httpx-client-outside-egress -- operator host, no redirects
        _llm_client = httpx.AsyncClient(timeout=_LLM_TIMEOUT)
    return _llm_client


async def close_llm_client() -> None:
    """Close the LLM proxy httpx client. Called on application shutdown."""
    global _llm_client
    if _llm_client is not None:
        await _llm_client.aclose()
        _llm_client = None


class LlmProvider(BaseModel):
    """One LLM provider driver entry."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    enabled: bool = Field(default=False)
    upstream: str = Field(
        ...,
        description="Provider base URL (https://...)",
    )
    auth_header: str = Field(
        ...,
        description="Header name for the API key",
    )
    auth_prefix: str = Field(
        default="",
        description="Prefix before the key value",
    )
    api_key_env: str = Field(
        ...,
        description="Env var holding the real API key",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        exclude=True,
        description="Resolved key (load-time)",
    )
    api: LlmApi | None = Field(
        default=None,
        description="Request shape; inferred for the four known upstream hosts",
    )
    allowed_models: list[str] = Field(
        default_factory=list,
        description="Globs a requested model must match; empty allows any",
    )

    @field_validator("upstream")
    @classmethod
    def upstream_must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError(
                f"upstream must start with https://: {v!r}",
            )
        return v.rstrip("/")

    @model_validator(mode="after")
    def api_must_be_known(self) -> LlmProvider:
        """An upstream we cannot name a shape for has no admission policy.

        Only an enabled provider needs one: a disabled entry is never loaded,
        and refusing to start over it took a working gateway down on upgrade.
        """
        if self.api is None:
            self.api = API_BY_HOST.get(urlsplit(self.upstream).hostname or "")
        if self.api is None and self.enabled:
            raise ValueError(
                "api must be set (anthropic, openai, openrouter or gemini) "
                "for an upstream other than the four known hosts",
            )
        return self


def load_llm_providers(
    llm_section: dict[str, Any],
) -> dict[str, LlmProvider]:
    """Parse LLM provider entries and resolve API keys.

    Accepts the ``llm_providers`` config section directly (not the full
    gateway config). Returns only enabled providers. Fails closed on a
    missing env var.
    """
    if not llm_section:
        logger.info("llm_proxy: no llm_providers — disabled")
        return {}

    providers: dict[str, LlmProvider] = {}
    for name, body in llm_section.items():
        if not isinstance(body, dict):
            raise ProfileConfigError(
                f"llm_providers.{name}: must be a mapping",
            )
        try:
            provider = LlmProvider(**body)
        except ValidationError as exc:
            # Name the entry and field: pydantic's message says which rule only.
            reasons = "; ".join(
                f"{'.'.join(map(str, e['loc'])) or 'entry'}: {e['msg']}" for e in exc.errors()
            )
            raise ProfileConfigError(f"llm_providers.{name}: {reasons}") from exc
        if not provider.enabled:
            continue
        key = read_secret_env(provider.api_key_env)
        if not key:
            raise ProfileConfigError(
                f"llm_providers.{name}: env var {provider.api_key_env} (or "
                f"{provider.api_key_env}_FILE) not set or empty",
            )
        provider.api_key = SecretStr(key)
        providers[name] = provider

    if providers:
        names = ", ".join(sorted(providers))
        logger.info(
            "llm_proxy: loaded %d provider(s): %s",
            len(providers),
            names,
        )
    return providers


def validate_profile_llm_keys(
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> None:
    """Fail closed if any profile references an unconfigured LLM provider.

    A profile's ``llm_keys`` may only name providers that exist in the enabled
    ``llm_providers`` set — a dangling reference is an operator error we refuse
    to serve past.
    """
    for name, profile in profiles.items():
        for provider_name in profile.llm_keys:
            if provider_name not in providers:
                raise ProfileConfigError(
                    f"Profile {name!r} llm_keys references provider "
                    f"{provider_name!r}, which is not a configured/enabled "
                    "llm_providers entry"
                )


def register_llm_routes(
    mcp_server: Any,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> None:
    """Wire ``/llm/{provider}/{path:path}`` onto the FastMCP server.

    The endpoint authenticates each request against the caller's gateway
    token (via ``profiles``) and injects that profile's provider key.

    Cross-validation runs before the no-providers early return: a profile that
    declares ``llm_keys`` for a provider that does not exist is a misconfig
    regardless of whether any providers ended up enabled.
    """
    validate_profile_llm_keys(providers, profiles)

    if not providers:
        return

    async def llm_proxy_endpoint(request: Request) -> Response:
        return await _proxy_llm(request, providers, profiles)

    mcp_server.custom_route(
        "/llm/{provider}/{path:path}",
        methods=LLM_HTTP_METHODS,
    )(llm_proxy_endpoint)

    logger.info(
        "llm_proxy: registered /llm/{provider}/{path} for %d provider(s)",
        len(providers),
    )


def _audit(
    profile: Profile,
    provider_name: str,
    endpoint: str,
    outcome: Outcome,
    started: float,
    reason: Reason | None = None,
    model: str | None = None,
) -> None:
    """One ``gateway_calls`` row per proxied call, admitted or refused.

    ``endpoint`` and ``reason`` are closed sets. ``model`` is the caller's
    text, so it is stored as a destination and goes nowhere else (#266).
    Like ``router._audit``, a lost row never fails the call it records.
    """
    try:
        record_gateway_call(
            profile.name,
            f"llm:{provider_name}",
            endpoint,
            outcome.value,
            int((time.monotonic() - started) * 1000),
            reason.value if reason else None,
            destination=model[:MAX_DESTINATION_CHARS] if model else None,
            destination_kind=DestinationKind.MODEL.value if model else None,
        )
    except Exception as exc:
        logger.warning("llm_proxy: audit row lost profile=%s err=%s", profile.name, exc_kind(exc))


def _refusal_response(refusal: LlmRefusedError) -> Response:
    """The refusal, to its own caller. ``detail`` is that caller's token."""
    body = {
        "error": {
            "type": "trentina_refused",
            "reason": refusal.reason.value,
            "detail": refusal.detail,
            "message": f"refused by Trentina: {refusal.reason.value}",
        }
    }
    return Response(
        content=json.dumps(body),
        status_code=refusal.status,
        media_type="application/json",
    )


async def _read_body(request: Request) -> bytes:
    """The whole body, refused past ``MAX_LLM_REQUEST_BYTES``.

    A compressed body is refused rather than inflated: what is judged must
    be what the provider parses.

    Raises:
        LlmRefusedError: ``too_large`` (413) past the cap, declared or read;
            ``malformed_body`` (415) for any ``Content-Encoding`` but identity.
    """
    encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise LlmRefusedError(
            Reason.MALFORMED, "content-encoding", status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE
        )
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_LLM_REQUEST_BYTES:
        raise LlmRefusedError(Reason.TOO_LARGE, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_LLM_REQUEST_BYTES:
            raise LlmRefusedError(Reason.TOO_LARGE, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
    return bytes(body)


def _caller_token(request: Request, api: LlmApi | None) -> str | None:
    """The caller's gateway token, as an ``Authorization`` value.

    Anthropic SDKs send their key as ``x-api-key`` to any base URL they do
    not know to want Bearer, so on the Anthropic shape that header carries
    the gateway token when ``Authorization`` is absent. It is never
    forwarded: ``forward_headers`` drops it and the profile's key replaces it.
    """
    authorization = request.headers.get("authorization")
    if authorization is not None or api is not LlmApi.ANTHROPIC:
        return authorization
    api_key = request.headers.get("x-api-key")
    return f"Bearer {api_key}" if api_key else None


async def _proxy_llm(
    request: Request,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> Response:
    """Admit one LLM request and forward it to the upstream provider.

    Authenticates against the caller's gateway token (``Authorization:
    Bearer``, or ``x-api-key`` on the Anthropic shape), resolves the
    calling profile, admits the request through ``llm_policy`` and injects
    that profile's provider key. Only allowlisted caller headers reach the
    provider; the caller's token is never one of them.
    """
    started = time.monotonic()
    provider_name = request.path_params.get("provider", "")
    raw_path = request.path_params.get("path", "")

    provider = providers.get(provider_name)
    if provider is None:
        return Response(
            content="LLM provider not found or disabled",
            status_code=404,
            media_type=PLAIN_TEXT,
        )

    profile = resolve_profile_by_token(_caller_token(request, provider.api), profiles)
    if profile is None:
        return Response(
            content="Unauthorized",
            status_code=401,
            media_type=PLAIN_TEXT,
        )

    override = profile.llm_keys.get(provider_name)
    if override is None:
        logger.info(
            "llm_proxy: profile=%s has no key for provider=%s",
            profile.name,
            provider_name,
        )
        _audit(profile, provider_name, "-", Outcome.DENIED_ALLOWLIST, started)
        return Response(
            content="No API key configured for this provider",
            status_code=502,
            media_type=PLAIN_TEXT,
        )

    path = normalize_proxy_path(raw_path)
    if path is None:
        _audit(profile, provider_name, "-", Outcome.DENIED_GUARD, started, Reason.ENDPOINT)
        return Response(
            content="Path traversal rejected",
            status_code=400,
            media_type=PLAIN_TEXT,
        )

    # TRUST: an agent's request to a provider that can fetch and run tools
    #   untrusted: method, path, query, headers and body, all agent-chosen
    #   judged-by: llm_policy.admit (allowlists per API shape) and forward_headers
    #   on-failure: fail-closed; anything not on a list is refused and audited
    #   owner: gateway/llm_policy.py
    #   evidence: T3 llm_policy module docstring; T4 the body sent is the one
    #     admit() re-serialized, so the provider parses what was judged
    api = provider.api
    if api is None:  # api_must_be_known sets it; a provider without one has no policy
        raise ProfileConfigError(f"llm_providers.{provider_name}: no api shape")
    try:
        body = await _read_body(request)
        admitted = admit(
            api,
            request.method,
            path,
            request.url.query,
            body,
            provider.allowed_models,
        )
    except LlmRefusedError as refusal:
        logger.info(
            "llm_proxy: refused profile=%s provider=%s reason=%s",
            profile.name,
            provider_name,
            refusal.reason.value,
        )
        _audit(profile, provider_name, "-", Outcome.DENIED_GUARD, started, refusal.reason)
        return _refusal_response(refusal)

    logger.info(
        "llm_proxy: profile=%s provider=%s endpoint=%s path=%s",
        profile.name,
        provider_name,
        admitted.endpoint,
        redact_source(path),
    )

    upstream_url = f"{provider.upstream}/{path}"
    if admitted.query:
        upstream_url = f"{upstream_url}?{admitted.query}"

    fwd_headers = forward_headers(api, request.headers.items())
    if admitted.body is not None:
        fwd_headers["content-type"] = "application/json"
    key_value = override.api_key.get_secret_value()
    fwd_headers[provider.auth_header] = f"{provider.auth_prefix}{key_value}"

    return await _forward_upstream(
        request.method,
        upstream_url,
        fwd_headers,
        admitted.body,
        provider_name,
        profile,
        lambda outcome: _audit(
            profile, provider_name, admitted.endpoint, outcome, started, model=admitted.model
        ),
    )


async def _forward_upstream(
    method: str,
    upstream_url: str,
    fwd_headers: dict[str, str],
    body: bytes | None,
    provider_name: str,
    profile: Profile,
    audit: Callable[[Outcome], None],
) -> Response:
    """Send the (already-admitted, key-injected) request to the provider."""
    client = _get_llm_client()

    try:
        resp = await client.send(
            client.build_request(
                method,
                upstream_url,
                headers=fwd_headers,
                content=body,
            ),
            stream=True,
        )
    except httpx.TimeoutException:
        audit(Outcome.BACKEND_ERROR)
        return Response(
            content="LLM upstream timeout",
            status_code=504,
            media_type=PLAIN_TEXT,
        )
    except httpx.ConnectError as exc:
        logger.warning(
            "llm_proxy: connect error provider=%s: %s",
            provider_name,
            exc_kind(exc),
        )
        audit(Outcome.BACKEND_ERROR)
        return Response(
            content="LLM upstream unreachable",
            status_code=502,
            media_type=PLAIN_TEXT,
        )

    if resp.status_code >= 500:
        audit(Outcome.BACKEND_ERROR)
    elif resp.status_code >= 400:
        audit(Outcome.TOOL_ERROR)
    else:
        audit(Outcome.OK)
    return _streaming_response(resp, provider_name, profile)


# Buffer completions up to this size for the post-hoc scan; a longer stream
# is passed through with its tail unscanned and a logged warning.
_MAX_COMPLETION_SCAN_BYTES = 16 * 1024 * 1024


def _streaming_response(
    resp: httpx.Response,
    provider_name: str,
    profile: Profile,
) -> StreamingResponse:
    """Stream the provider response through, then judge what streamed.

    Per-frame scanning is theater: a 512-token-window classifier over
    ~5-token deltas never sees an instruction whole, anything spanning two
    frames is invisible, and a verdict at frame N cannot retract frames
    1..N-1 already sent. So the stream passes untouched and the ASSEMBLED
    completion is judged after the last frame — that cannot protect this
    response, but it records the flag (source_type=llm_completion), feeds
    step 7's calibration, and is exactly what flag mode means for a
    transport that cannot carry an annotation. When enforcement modes land,
    block profiles switch to buffer-scan-release instead: an autonomous
    agent has no human waiting on time-to-first-token.
    """
    resp_headers = filter_response_headers(list(resp.headers.items()))

    collected: list[bytes] = []
    size_seen = 0

    async def stream_body() -> AsyncIterator[bytes]:
        nonlocal size_seen
        try:
            async for chunk in resp.aiter_bytes():
                if size_seen <= _MAX_COMPLETION_SCAN_BYTES:
                    collected.append(chunk)
                size_seen += len(chunk)
                yield chunk
        finally:
            await resp.aclose()
            _schedule_completion_scan(
                b"".join(collected),
                size_seen,
                provider_name,
                profile,
            )

    ct = resp.headers.get("content-type", "application/json")
    return StreamingResponse(
        stream_body(),
        status_code=resp.status_code,
        headers=resp_headers,
        media_type=ct,
    )


def _schedule_completion_scan(
    body: bytes,
    size_seen: int,
    provider_name: str,
    profile: Profile,
) -> None:
    """Fire-and-forget the post-hoc completion scan; never block the stream."""
    if not body:
        return
    if size_seen > _MAX_COMPLETION_SCAN_BYTES:
        logger.warning(
            "llm_proxy: completion from %s exceeded %d bytes — tail unscanned",
            provider_name,
            _MAX_COMPLETION_SCAN_BYTES,
        )

    async def _scan() -> None:
        try:
            from ..defense import Provenance, defend

            text = body.decode("utf-8", errors="replace")
            # Bound here, not at the handler: this runs after the stream ends,
            # outside the request's context (RT #1505).
            with profile_context(profile):
                verdict = await defend(
                    text,
                    source=f"llm:{profile.name}:{provider_name}",
                    source_type="llm_completion",
                    defense=profile.defense,
                    provenance=Provenance.MODEL_OUTPUT,
                )
            if verdict.flagged:
                logger.warning(
                    "llm_proxy: completion flagged profile=%s provider=%s "
                    "risk=%s flagged_by=%s (already streamed — recorded only)",
                    profile.name,
                    provider_name,
                    verdict.risk_level,
                    verdict.flagged_by.value if verdict.flagged_by else None,
                )
        except Exception as exc:
            logger.error(  # the message may carry the completion (#262)
                "llm_proxy: post-hoc completion scan failed: %s at %s",
                exc_kind(exc),
                exc_where(exc),
            )

    try:
        task = asyncio.get_running_loop().create_task(_scan())
        _scan_tasks.add(task)
        task.add_done_callback(_scan_tasks.discard)
    except RuntimeError:
        logger.debug("llm_proxy: no event loop for post-hoc scan")


_scan_tasks: set[Any] = set()
