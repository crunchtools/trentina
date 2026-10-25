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

from ..logsafe import exc_kind, exc_where, redact_source
from ..modes import Mode
from ..outcomes import Outcome
from .auth import resolve_profile_by_token
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, DestinationKind
from .errors import ProfileConfigError
from .ingress_defense import effective_mode
from .llm_policy import (
    API_BY_HOST,
    Admitted,
    LlmApi,
    LlmRefusedError,
    Reason,
    admit,
    forward_headers,
)
from .loader import read_secret_env
from .outbound import (
    REASON_CREDENTIAL,
    REASON_FLAGGED,
    REASON_UNJUDGED,
    body_text,
    judge_outbound,
)
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    normalize_proxy_path,
)
from .relay import Operation, Slots

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

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

# In-flight model requests one profile may hold. Set high, like the tunnel's
# cap and unlike the 8 of /egress and /git: one profile serves every session of
# its agent, and a fan-out of parallel subagents holds a streaming completion
# each for the length of a turn. The cap only stops a runaway, never normal
# fan-out.
LLM_MAX_OPERATIONS_PER_PROFILE = 64
_SLOTS = Slots(LLM_MAX_OPERATIONS_PER_PROFILE)

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


def _deny_marker(
    reason: str,
    *,
    detail: str = "",
    flagged_by: str | None = None,
    gaps: list[str] | None = None,
    kinds: list[str] | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """The refusal body: gateway-authored fields only, no payload, no L3 prose.

    Carries the egress-benchmark deny marker (``blocked``, ``block_reason``,
    ``scanner``) at the top level so a runner that reads an opaque proxy
    response still observes the verdict (#507). ``gaps`` names what the layers
    could not finish (``modes.Gaps``); ``kinds`` names credential shapes found
    — kept apart so a client does not read a key find as a layer outage.
    ``alternatives`` is always empty: the mode is profile-fixed and ``redact``
    is meaningless on an outbound call, so there is nothing to retry with.
    """
    error: dict[str, Any] = {
        "type": "trentina_refused",
        "reason": reason,
        "message": f"refused by Trentina: {reason}",
    }
    if detail:
        error["detail"] = detail
    if flagged_by is not None:
        error["flagged_by"] = flagged_by
    if gaps:
        error["gaps"] = gaps
    if kinds:
        error["kinds"] = kinds
    if mode is not None:
        error["mode"] = mode
        error["alternatives"] = []
    return {"error": error, "blocked": True, "block_reason": reason, "scanner": "trentina"}


#: flag mode forwards the request and rides the verdict back on this header,
#: the one annotation an opaque HTTP response can carry (the Matrix path's
#: ``_trentina_warning`` has no equivalent on a raw byte stream). Lowercase, as
#: httpx normalizes header names, so an upstream's own ``x-trentina-warning``
#: is the same key and can be dropped before ours is set (never two).
WARNING_HEADER = "x-trentina-warning"

#: Wall-clock an outbound request scan may take before it is treated as
#: unjudged. A hung L3 must not stall the proxy for its own HTTP timeout.
_JUDGE_DEADLINE = 60.0

JSON = "application/json"

#: The outbound reason code -> this route's audit Reason.
_REASON_OF = {
    REASON_CREDENTIAL: Reason.CREDENTIAL,
    REASON_FLAGGED: Reason.FLAGGED,
    REASON_UNJUDGED: Reason.UNJUDGED,
}


def _request_document(
    method: str, path: str, admitted: Admitted, fwd_headers: dict[str, str]
) -> str:
    """The outbound request as one document for the layers and the detector (#511).

    Method and path, the query, the headers that will actually be forwarded
    (the caller's gateway token is dropped by ``forward_headers`` and the
    provider key is not injected until after judging), and the body. This is
    the request the agent is trying to send — what L1/L2/L3 read and what the
    credential detector scans.
    """
    parts = [f"{method} {path}"]
    if admitted.query:
        parts.append(f"?{admitted.query}")  # the `?` the [?&]-anchored patterns need
    parts.extend(f"{name}: {value}" for name, value in fwd_headers.items())
    if admitted.body is not None:
        parts.append(body_text(admitted.body))
    return "\n".join(parts)


async def _judge_request(
    op: Operation,
    document: str,
    provider_name: str,
    profile: Profile,
    mode: Mode,
) -> tuple[Response | None, str | None]:
    """Judge an outbound request. Returns ``(refusal, warning)``.

    The shared ``judge_outbound`` always runs L1/L2/L3 over a credential-redacted
    copy and scans for credential shapes (the layer contract: the detector adds
    a signal, it is not a per-layer off switch). Under ``block`` a credential, a
    flag or a blocking gap refuses before anything is sent — the Operation is
    settled ``BLOCKED_DEFENSE`` and nothing executed. Under ``flag`` the request
    forwards, the verdict rides back on ``X-Trentina-Warning``, and
    ``op.flag_reason`` carries the finding onto the forwarded call's audit row so
    a flag-mode finding is recorded, not only shown to the agent.
    """
    verdict = await judge_outbound(
        document,
        source=f"llm:{profile.name}:{provider_name}",
        source_type="llm_request",
        backend=f"llm:{provider_name}",
        profile=profile,
        mode=mode,
        deadline=_JUDGE_DEADLINE,
    )
    # reason is non-None whenever blocks()/warning holds; the `or` only narrows
    # the Optional for the type checker.
    reason_code = verdict.reason or REASON_UNJUDGED
    if mode is Mode.BLOCK and verdict.blocks():
        reason = _REASON_OF[reason_code]
        op.settle(Outcome.BLOCKED_DEFENSE, reason.value)
        logger.warning(
            "llm_proxy: request blocked profile=%s provider=%s reason=%s",
            profile.name,
            provider_name,
            reason.value,
        )
        body = _deny_marker(
            reason.value,
            flagged_by=verdict.flagged_by,
            gaps=verdict.gaps or None,
            kinds=verdict.kinds or None,
            mode=mode.value,
        )
        return (Response(content=json.dumps(body), status_code=403, media_type=JSON), None)

    warning = verdict.warning
    if warning is not None:
        op.flag_reason = _REASON_OF[reason_code].value
        logger.warning(
            "llm_proxy: request %s (flag) profile=%s provider=%s",
            warning,
            profile.name,
            provider_name,
        )
        return (None, warning)
    return (None, None)


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


def _caller_token(request: Request) -> str | None:
    """The caller's gateway token, as an ``Authorization`` value.

    ``Authorization`` if present; otherwise ``x-api-key`` (Anthropic SDKs send
    their key there to a base URL they do not know wants Bearer). Read WITHOUT
    the provider's API shape, so authentication can precede the provider lookup
    and an unknown-provider 404 is never an unauthenticated name oracle. The
    caller's own value is never forwarded: ``forward_headers`` drops both and
    the profile's key replaces them.
    """
    authorization = request.headers.get("authorization")
    if authorization is not None:
        return authorization
    api_key = request.headers.get("x-api-key")
    return f"Bearer {api_key}" if api_key else None


def _resolve_caller(
    request: Request,
    provider_name: str,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> tuple[LlmProvider, Profile] | Response:
    """The provider and the calling profile, or an error Response.

    Authentication comes FIRST: a token that resolves to no profile is 401
    before the provider name is looked up, so an unauthenticated caller cannot
    learn which providers exist by probing for 404s. The profile's key for this
    provider is checked by ``_proxy_llm``, which holds the Operation that
    records a no-key refusal.
    """
    profile = resolve_profile_by_token(_caller_token(request), profiles)
    if profile is None:
        return Response(content="Unauthorized", status_code=401, media_type=PLAIN_TEXT)

    provider = providers.get(provider_name)
    if provider is None:
        return Response(
            content="LLM provider not found or disabled", status_code=404, media_type=PLAIN_TEXT
        )
    return provider, profile


async def _admit_or_refuse(
    op: Operation,
    request: Request,
    api: LlmApi,
    provider: LlmProvider,
    provider_name: str,
) -> tuple[str, Admitted] | Response:
    """Normalize the path and admit the request, or finish ``op`` and return the refusal.

    Returns ``(path, admitted)`` on success. On a path traversal (400) or an
    admission refusal, it settles and finishes ``op`` and returns the deny
    Response, so the caller only forwards it.

    TRUST: an agent's request to a provider that can fetch and run tools
      untrusted: method, path, query, headers and body, all agent-chosen
      judged-by: llm_policy.admit (allowlists per API shape) and forward_headers
      on-failure: fail-closed; anything not on a list is refused and audited
      owner: gateway/llm_policy.py
      evidence: T3 llm_policy module docstring; T4 the body sent is the one
        admit() re-serialized, so the provider parses what was judged
    """
    path = normalize_proxy_path(request.path_params.get("path", ""))
    if path is None:
        op.settle(Outcome.DENIED_GUARD, Reason.ENDPOINT.value)
        await op.finish()
        return Response(content="Path traversal rejected", status_code=400, media_type=PLAIN_TEXT)
    try:
        body = await _read_body(request)
        admitted = admit(
            api, request.method, path, request.url.query, body, provider.allowed_models
        )
    except LlmRefusedError as refusal:
        logger.info(
            "llm_proxy: refused profile=%s provider=%s reason=%s",
            op.profile.name,
            provider_name,
            refusal.reason.value,
        )
        op.settle(Outcome.DENIED_GUARD, refusal.reason.value)
        await op.finish()
        # The admission refusal, to its own caller; detail is that caller's token.
        marker = _deny_marker(refusal.reason.value, detail=refusal.detail)
        return Response(content=json.dumps(marker), status_code=refusal.status, media_type=JSON)
    return path, admitted


async def _proxy_llm(
    request: Request,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> Response:
    """Admit one LLM request and forward it to the upstream provider.

    Authenticates against the caller's gateway token (``Authorization:
    Bearer``, or ``x-api-key`` on any shape when ``Authorization`` is absent),
    resolves the calling profile, admits the request through ``llm_policy`` and injects
    that profile's provider key. Only allowlisted caller headers reach the
    provider; the caller's token is never one of them.
    """
    provider_name = request.path_params.get("provider", "")

    resolved = _resolve_caller(request, provider_name, providers, profiles)
    if isinstance(resolved, Response):
        return resolved
    provider, profile = resolved
    api = provider.api
    if api is None:  # api_must_be_known sets it; a provider without one has no policy
        raise ProfileConfigError(f"llm_providers.{provider_name}: no api shape")

    op = Operation(profile, backend=f"llm:{provider_name}", destination_kind=DestinationKind.MODEL)
    try:
        override = profile.llm_keys.get(provider_name)
        if override is None:
            logger.info(
                "llm_proxy: profile=%s has no key for provider=%s", profile.name, provider_name
            )
            op.settle(Outcome.DENIED_ALLOWLIST)
            await op.finish()
            return Response(
                content="No API key configured for this provider",
                status_code=502,
                media_type=PLAIN_TEXT,
            )

        admitted_or_refusal = await _admit_or_refuse(op, request, api, provider, provider_name)
        if isinstance(admitted_or_refusal, Response):
            return admitted_or_refusal
        path, admitted = admitted_or_refusal

        op.tool = admitted.endpoint
        op.destination = admitted.model[:MAX_DESTINATION_CHARS] if admitted.model else None
        if not op.take_slot(_SLOTS):
            op.settle(Outcome.DENIED_GUARD, "busy")
            await op.finish()
            return Response(
                content=json.dumps(_deny_marker("busy")), status_code=503, media_type=JSON
            )

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

        # #511: judge the request CONTENT, not only its shape. llm_policy.admit
        # above allowlisted the endpoint, params and headers; this reads the body,
        # query and forwarded headers as one document for L1/L2/L3 and the
        # credential detector. The mode is the profile's per-provider enforcement
        # (default flag), with the kill switch over it.
        mode = effective_mode(profile, Mode(override.enforcement))
        refusal_resp, warning = await _judge_request(
            op,
            _request_document(request.method, path, admitted, fwd_headers),
            provider_name,
            profile,
            mode,
        )
        if refusal_resp is not None:  # op already settled BLOCKED_DEFENSE
            await op.finish()
            return refusal_resp

        if admitted.body is not None:
            fwd_headers["content-type"] = JSON
        key_value = override.api_key.get_secret_value()
        fwd_headers[provider.auth_header] = f"{provider.auth_prefix}{key_value}"

        # On success this returns a StreamingResponse that finishes op when the
        # stream ends; on a forward error it finishes op and returns a plain
        # Response. Either way the row is written exactly once.
        return await _forward_upstream(
            op,
            request.method,
            upstream_url,
            fwd_headers,
            admitted.body,
            provider_name,
            profile,
            warning,
        )
    except Exception:
        # An unexpected error before the response streams: record it, once.
        op.settle(Outcome.GATEWAY_ERROR)
        await op.finish()
        raise


async def _forward_upstream(
    op: Operation,
    method: str,
    upstream_url: str,
    fwd_headers: dict[str, str],
    body: bytes | None,
    provider_name: str,
    profile: Profile,
    warning: str | None = None,
) -> Response:
    """Send the (already-admitted, key-injected) request to the provider.

    On a send failure the Operation is settled ``BACKEND_ERROR`` and finished
    here (a plain Response goes back). On success the Operation is settled by
    status and handed to ``_streaming_response``, which finishes it when the
    stream ends — so the row carries the bytes actually relayed and is written
    once, at the end, not when the headers arrived.
    """
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
        op.settle(Outcome.BACKEND_ERROR)
        await op.finish()
        return Response(content="LLM upstream timeout", status_code=504, media_type=PLAIN_TEXT)
    except httpx.ConnectError as exc:
        logger.warning("llm_proxy: connect error provider=%s: %s", provider_name, exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR)
        await op.finish()
        return Response(content="LLM upstream unreachable", status_code=502, media_type=PLAIN_TEXT)
    except httpx.HTTPError as exc:
        # Any other upstream failure (read error, protocol error, a stream that
        # broke before headers): still one audit row, never an unlogged 500.
        logger.warning("llm_proxy: upstream error provider=%s: %s", provider_name, exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR)
        await op.finish()
        return Response(content="LLM upstream error", status_code=502, media_type=PLAIN_TEXT)

    # The request is on the wire; its body is what went upstream.
    op.sent = len(body) if body else 0
    if resp.status_code >= 500:
        op.settle(Outcome.BACKEND_ERROR, op.flag_reason)
    elif resp.status_code >= 400:
        op.settle(Outcome.TOOL_ERROR, op.flag_reason)
    else:
        op.settle(Outcome.OK, op.flag_reason)
    return _streaming_response(op, resp, provider_name, profile, warning)


# Buffer completions up to this size for the post-hoc scan; a longer stream
# is passed through with its tail unscanned and a logged warning.
_MAX_COMPLETION_SCAN_BYTES = 16 * 1024 * 1024


def _streaming_response(
    op: Operation,
    resp: httpx.Response,
    provider_name: str,
    profile: Profile,
    warning: str | None = None,
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
    # Never let the upstream forge our verdict header, nor emit it twice: drop
    # any it sent (httpx lowercases names, so this one key covers every casing)
    # before setting ours. flag mode: the request was forwarded, verdict rides back.
    resp_headers.pop(WARNING_HEADER, None)
    if warning:
        resp_headers[WARNING_HEADER] = warning

    collected: list[bytes] = []
    size_seen = 0

    async def stream_body() -> AsyncIterator[bytes]:
        nonlocal size_seen
        completed = False
        try:
            async for chunk in resp.aiter_bytes():
                op.received += len(chunk)
                if size_seen <= _MAX_COMPLETION_SCAN_BYTES:
                    collected.append(chunk)
                size_seen += len(chunk)
                yield chunk
            completed = True
        finally:
            await resp.aclose()
            # A stream that did not run to the end — the agent disconnected, or
            # the body broke after the headers — is not a clean delivery: settle
            # CANCELLED (only over a success; a 4xx/5xx keeps its error outcome).
            # The row carries the bytes actually relayed and is written at the
            # stream's END, not when the headers arrived.
            if not completed and op.outcome is Outcome.OK:
                op.settle(Outcome.CANCELLED, op.reason)
            await op.finish()
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
            # outside the request's context (RT #1505). A hung L3 must not leave
            # an unbounded task running per completion, so the scan is deadlined
            # like the request-side judge.
            with profile_context(profile):
                async with asyncio.timeout(_JUDGE_DEADLINE):
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
        except TimeoutError:
            # The scan outran JUDGE_DEADLINE. This is a background task (the
            # response already streamed), so the timeout cannot affect the
            # caller — it is recorded and dropped, like any other scan failure.
            logger.warning(
                "llm_proxy: post-hoc completion scan timed out profile=%s provider=%s",
                profile.name,
                provider_name,
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
