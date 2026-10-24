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
import re
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

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

from ..credential_shapes import kinds as credential_kinds
from ..credential_shapes import redact as credential_redact
from ..database import record_gateway_call
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
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    normalize_proxy_path,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from starlette.requests import Request

    from .profile import LlmKeyOverride, Profile

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


#: A run of percent-escapes long enough to be an encoded secret or blob rather
#: than one escaped character — masked out of the judge input (never delivery).
_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}){8,}")


def _judge_input(document: str) -> str:
    """The copy L1/L2/L3 read — NOT what is forwarded upstream.

    Credentials are cut (``credential_shapes.redact``) so a secret never reaches
    the external judge, and a long run of percent-escapes (an encoded secret or
    blob the detector reads decoded) is masked. Injection content is neither a
    credential shape nor a percent run, so every layer still reads it. The
    original admitted body is what forwards upstream (#511).
    """
    return _PERCENT_RUN.sub("[REDACTED]", credential_redact(document))


def _body_text(body: bytes) -> str:
    """The admitted body as text the LAYERS can read.

    ``admit`` re-serialized the body with ``ensure_ascii=True``, so a non-Latin
    prompt arrives as ``\\uXXXX`` escapes that L2 cannot read and L1 does not
    count; parse and re-dump unescaped for judging. The bytes FORWARDED upstream
    are the ASCII ones ``admit`` produced and are not touched here.
    """
    try:
        return json.dumps(json.loads(body), ensure_ascii=False)
    except (ValueError, TypeError):
        return body.decode("utf-8", errors="replace")


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
        parts.append(admitted.query)
    parts.extend(f"{name}: {value}" for name, value in fwd_headers.items())
    if admitted.body is not None:
        parts.append(_body_text(admitted.body))
    return "\n".join(parts)


async def _judge_request(
    document: str,
    provider_name: str,
    profile: Profile,
    mode: Mode,
    audit: Callable[[Outcome, Reason], None],
) -> tuple[Response | None, str | None, Reason | None]:
    """Judge an outbound request. Returns ``(refusal, warning, flag_reason)``.

    L1/L2/L3 ALWAYS read the document as one piece — the credential detector is
    an ADDITIONAL deterministic signal, never a replacement that skips a layer
    (the layer contract forbids a per-layer off switch; the mode controls
    delivery, not which layers run). The scan is under a deadline and an
    exception boundary: a hung or failed scan is treated as unjudged, as the
    Matrix path does. Under ``block`` a credential shape, a flag or a blocking
    gap refuses before anything is sent — nothing executed, so there is no
    "response withheld" to report. Under ``flag`` the request is forwarded and
    the verdict rides back on ``X-Trentina-Warning``; ``flag_reason`` is carried
    to the forward audit row so a flag-mode finding is recorded, not only shown
    to the agent. Credential > flagged > unjudged when more than one holds.
    """
    from ..defense import Provenance, defend  # a seam test_llm_proxy monkeypatches
    from ..modes import gaps_of

    # Detect over the raw document and, only if that is clean, its percent-decoded
    # form: a key sent as ``%41%4B...`` that a server would decode must not slip
    # the block. The judge reads a redacted copy either way.
    found = credential_kinds(document)
    if not found:
        decoded = unquote(document)
        if decoded != document:
            found = credential_kinds(decoded)
    names = sorted(k.value for k in found)

    flagged, unjudged, flagged_by, risk = False, True, None, "unknown"
    gap_names = ["l3_unavailable"]  # the default while no verdict is reached
    try:
        with profile_context(profile):
            async with asyncio.timeout(_JUDGE_DEADLINE):
                verdict = await defend(
                    _judge_input(document),
                    source=f"llm:{profile.name}:{provider_name}",
                    source_type="llm_request",
                    defense=profile.defense,
                    provenance=Provenance.MODEL_OUTPUT,
                    stop_on_partial=mode is Mode.BLOCK,
                    attribution={
                        "direction": "request",
                        "blocked": mode is Mode.BLOCK,
                        "profile": profile.name,
                        "backend": f"llm:{provider_name}",
                    },
                )
        flagged = verdict.flagged
        flagged_by = verdict.flagged_by.value if verdict.flagged_by else None
        gaps = gaps_of(verdict)
        unjudged = gaps.blocking()
        gap_names = gaps.names()
        risk = verdict.risk_level
    except Exception as exc:  # TimeoutError too: no verdict was reached
        logger.error(  # the message may carry the request (#262)
            "llm_proxy: request scan failed profile=%s provider=%s: %s at %s",
            profile.name,
            provider_name,
            exc_kind(exc),
            exc_where(exc),
        )

    if mode is Mode.BLOCK and (found or flagged or unjudged):
        reason = Reason.CREDENTIAL if found else Reason.FLAGGED if flagged else Reason.UNJUDGED
        audit(Outcome.BLOCKED_DEFENSE, reason)
        logger.warning(
            "llm_proxy: request blocked profile=%s provider=%s reason=%s credential=%s",
            profile.name,
            provider_name,
            reason.value,
            ",".join(names) or "-",
        )
        body = _deny_marker(
            reason.value,
            flagged_by=flagged_by,
            gaps=gap_names or None,
            kinds=names or None,
            mode=mode.value,
        )
        return (Response(content=json.dumps(body), status_code=403, media_type=JSON), None, None)

    # flag (or clean): forward. A finding is logged (closed-set, #262-safe) and
    # its reason carried to the forward audit row so flag mode is measurable.
    if found:
        logger.warning(
            "llm_proxy: request credential (flag) profile=%s provider=%s credential=%s",
            profile.name,
            provider_name,
            ",".join(names),
        )
        return (None, "credential", Reason.CREDENTIAL)
    if flagged:
        logger.warning(
            "llm_proxy: request flagged (flag) profile=%s provider=%s risk=%s flagged_by=%s",
            profile.name,
            provider_name,
            risk,
            flagged_by,
        )
        return (None, risk, Reason.FLAGGED)
    if unjudged:
        logger.warning(
            "llm_proxy: request unjudged (flag) profile=%s provider=%s",
            profile.name,
            provider_name,
        )
        return (None, "unjudged", Reason.UNJUDGED)
    return (None, None, None)


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


def _resolve_caller(
    request: Request,
    provider_name: str,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
    started: float,
) -> tuple[LlmProvider, Profile, LlmKeyOverride] | Response:
    """The provider, calling profile and that profile's key, or an error Response.

    Three fail-closed guards, kept out of ``_proxy_llm`` so its return count
    stays legible: an unknown provider (404), a token that resolves to no
    profile (401), and a profile with no key for this provider (502, audited).
    """
    provider = providers.get(provider_name)
    if provider is None:
        return Response(
            content="LLM provider not found or disabled", status_code=404, media_type=PLAIN_TEXT
        )

    profile = resolve_profile_by_token(_caller_token(request, provider.api), profiles)
    if profile is None:
        return Response(content="Unauthorized", status_code=401, media_type=PLAIN_TEXT)

    override = profile.llm_keys.get(provider_name)
    if override is None:
        logger.info("llm_proxy: profile=%s has no key for provider=%s", profile.name, provider_name)
        _audit(profile, provider_name, "-", Outcome.DENIED_ALLOWLIST, started)
        return Response(
            content="No API key configured for this provider",
            status_code=502,
            media_type=PLAIN_TEXT,
        )
    return provider, profile, override


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

    resolved = _resolve_caller(request, provider_name, providers, profiles, started)
    if isinstance(resolved, Response):
        return resolved
    provider, profile, override = resolved

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
        # The admission refusal, to its own caller; detail is that caller's token.
        marker = _deny_marker(refusal.reason.value, detail=refusal.detail)
        return Response(content=json.dumps(marker), status_code=refusal.status, media_type=JSON)

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
    refusal_resp, warning, flag_reason = await _judge_request(
        _request_document(request.method, path, admitted, fwd_headers),
        provider_name,
        profile,
        mode,
        lambda outcome, reason: _audit(
            profile,
            provider_name,
            admitted.endpoint,
            outcome,
            started,
            reason,
            model=admitted.model,
        ),
    )
    if refusal_resp is not None:
        return refusal_resp

    if admitted.body is not None:
        fwd_headers["content-type"] = JSON
    key_value = override.api_key.get_secret_value()
    fwd_headers[provider.auth_header] = f"{provider.auth_prefix}{key_value}"

    # flag_reason carries a flag-mode finding onto the forwarded call's audit row.
    return await _forward_upstream(
        request.method,
        upstream_url,
        fwd_headers,
        admitted.body,
        provider_name,
        profile,
        lambda outcome: _audit(
            profile,
            provider_name,
            admitted.endpoint,
            outcome,
            started,
            flag_reason,
            model=admitted.model,
        ),
        warning,
    )


async def _forward_upstream(
    method: str,
    upstream_url: str,
    fwd_headers: dict[str, str],
    body: bytes | None,
    provider_name: str,
    profile: Profile,
    audit: Callable[[Outcome], None],
    warning: str | None = None,
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
    return _streaming_response(resp, provider_name, profile, warning)


# Buffer completions up to this size for the post-hoc scan; a longer stream
# is passed through with its tail unscanned and a logged warning.
_MAX_COMPLETION_SCAN_BYTES = 16 * 1024 * 1024


def _streaming_response(
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
