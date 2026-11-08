"""Config-driven LLM API reverse proxy.

Forwards requests from ``/proxy/llm/{provider}/{path}`` to the configured upstream
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
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from starlette.responses import Response

from .. import telemetry
from ..logsafe import redact_source
from ..orchestrator import judge_llm_completion, judge_outbound
from ..outcomes import Outcome
from ..transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Bearer,
    Grant,
    Instance,
    OperatorOrigin,
    Refusal,
    RefusedError,
    Route,
    Wire,
)
from ..transports.perimeter import InTree
from .destination import MAX_DESTINATION_CHARS
from .errors import ProfileConfigError
from .llm_policy import (
    API_BY_HOST,
    LlmApi,
    LlmRefusedError,
    Reason,
    admit,
    forward_headers,
    with_session,
)
from .llm_policy import Admitted as Shaped
from .loader import read_secret_env
from .modes_policy import effective_mode
from .outbound import (
    REASON_CREDENTIAL,
    REASON_FLAGGED,
    REASON_UNJUDGED,
    body_text,
)
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    normalize_proxy_path,
)
from .relay import Relayed, upstream_outcome

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from ..modes import Mode
    from .profile import Profile
    from .relay import Operation

logger = logging.getLogger(__name__)

#: Seconds any one read or write to the provider may take (SSE between tokens,
#: or a non-streaming body). Passed to the pinned pool as its idle timeout.
_LLM_IDLE = 300.0

LLM_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# A request body is read whole to be judged. Anthropic's own request limit is
# 32 MB; nothing an admitted endpoint takes needs more.
MAX_LLM_REQUEST_BYTES = 32 * 1024 * 1024

# In-flight model requests one profile may hold. Set high, like the tunnel's
# cap and unlike the 8 of /egress and /git: one profile serves every session of
# its agent, and a fan-out of parallel subagents holds a streaming completion
# each for the length of a turn. The cap only stops a runaway, never normal
# fan-out.
MAX_LLM_OPERATIONS_PER_PROFILE = 64


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
    api_key_env: str | None = Field(
        default=None,
        description=(
            "Env var holding a gateway-wide key. Optional: the proxy injects each "
            "profile's own llm_keys entry, and a key named here is still read (and "
            "fails closed when unset) so an older file keeps its meaning"
        ),
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
        if provider.api_key_env is None:
            providers[name] = provider
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


def _request_document(method: str, path: str, admitted: Shaped, fwd_headers: dict[str, str]) -> str:
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


#: llm's refusals: the spine's, the admission policy's (each raise carries its
#: own status), and the three llm answers before anything is read: an unknown
#: provider is 404, a profile with no key for it 502, a path that climbs out
#: 400 (recorded as the endpoint refusal it always was).
REFUSALS: Mapping[str, Refusal] = {
    **{reason.value: Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_GUARD) for reason in Reason},
    **SPINE_REFUSALS,
    "unknown_upstream": Refusal(HTTPStatus.NOT_FOUND, Outcome.DENIED_ALLOWLIST),
    "no_key": Refusal(HTTPStatus.BAD_GATEWAY, Outcome.DENIED_ALLOWLIST),
    "path_traversal": Refusal(
        HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD, wire=Reason.ENDPOINT.value
    ),
}

#: The answers that are a line of text, not a deny marker, by canonical reason.
_PLAIN: Mapping[str, str] = {
    "unauthorized": "Unauthorized",
    "unknown_upstream": "LLM provider not found or disabled",
    "no_key": "No API key configured for this provider",
    "path_traversal": "Path traversal rejected",
}

#: How a send that never got an answer is worded, by the spine's reason. Each
#: is a backend error recorded with any flag-mode finding, as before #535.
_UPSTREAM_FAILED: Mapping[str, tuple[int, str]] = {
    "upstream_idle": (HTTPStatus.GATEWAY_TIMEOUT, "LLM upstream timeout"),
    "upstream_unreachable": (HTTPStatus.BAD_GATEWAY, "LLM upstream unreachable"),
    "upstream_failed": (HTTPStatus.BAD_GATEWAY, "LLM upstream error"),
}

#: The origin key every llm instance has: one provider per instance.
ORIGIN = "origin"


class MarkedRefusalError(RefusedError):
    """An llm refusal and the deny marker's facts for it: the caller's own
    token for an admission refusal, or the request judge's verdict. The facts
    go to this caller's marker only, never to a log or the audit row."""

    def __init__(self, reason: str, *, status: int | None = None, **marker: Any) -> None:
        super().__init__(reason, status=status)
        self.marker = marker


@dataclass(frozen=True)
class LlmAdmitted(Admitted):
    """The path below the provider, traversal-checked."""

    path: str = ""


def _session_for_provider(trace: telemetry.TraceContext | None) -> str | None:
    """What OpenRouter groups this run's generations by: the agent's session
    fingerprint, else its trace id when the agent sent one; None for a call
    that started no trace of its own (a fresh, unshared trace groups nothing)."""
    if trace is None:
        return None
    if trace.agent_session:
        return trace.agent_session
    return trace.trace_id if trace.parent_span_id else None


class LlmRoute(Route[LlmAdmitted, InTree]):
    """``/proxy/llm/<provider>/<path>``: a model call, admitted by its API shape."""

    name = "llm"
    methods = tuple(LLM_HTTP_METHODS)
    #: SDKs that do not know the base URL wants Bearer send the key as x-api-key.
    auth = Bearer(fallback_headers=("x-api-key",))
    refusals = REFUSALS
    max_request_bytes = MAX_LLM_REQUEST_BYTES
    slots = MAX_LLM_OPERATIONS_PER_PROFILE
    idle = _LLM_IDLE

    async def admit(self, wire: Wire, grant: Grant, _instance: Instance) -> LlmAdmitted:
        """A key for the provider, and a path that stays below it."""
        if not grant.options["has_key"]:
            raise RefusedError("no_key")
        path = normalize_proxy_path(wire.path)
        if path is None:
            raise RefusedError("path_traversal")
        return LlmAdmitted(origin=OperatorOrigin(ORIGIN), path=path)

    async def deliver(self, admitted: LlmAdmitted, ctx: InTree) -> Response:
        """Admit the request by its shape, judge it, inject the key and forward.

        The shape is read from the body, so it is admitted once the profile
        holds a slot. A compressed body is refused rather than inflated: what is
        judged must be what the provider parses.

        TRUST: an agent's request to a provider that can fetch and run tools
          untrusted: method, path, query, headers and body, all agent-chosen
          judged-by: llm_policy.admit (allowlists per API shape), forward_headers
            and judge_outbound (L1/L2/L3 + the credential detector)
          on-failure: fail-closed; anything not on a list is refused and audited
          owner: gateway/llm_policy.py, gateway/llm_proxy.py
          evidence: T3 llm_policy module docstring; T4 the body sent is the one
            admit() re-serialized, so the provider parses what was judged
        """
        op, wire = ctx.op, ctx.wire
        api: LlmApi = ctx.instance.options["api"]
        encoding = wire.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise MarkedRefusalError(
                Reason.MALFORMED.value,
                status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                detail="content-encoding",
            )
        declared = wire.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_LLM_REQUEST_BYTES:
            raise RefusedError(Reason.TOO_LARGE.value)
        body = await ctx.body.read()
        try:
            shaped = admit(
                api,
                wire.method,
                admitted.path,
                wire.query,
                body,
                ctx.instance.options["allowed_models"],
            )
        except LlmRefusedError as refusal:
            logger.info(
                "llm_proxy: refused profile=%s reason=%s", op.profile.name, refusal.reason.value
            )
            raise MarkedRefusalError(
                refusal.reason.value, status=refusal.status, detail=refusal.detail
            ) from refusal
        # Set before judging, so the field is judged with the rest of the body.
        shaped = with_session(api, shaped, _session_for_provider(telemetry.current_trace.get()))
        op.tool = shaped.endpoint
        op.destination = shaped.model[:MAX_DESTINATION_CHARS] if shaped.model else None
        logger.info(
            "llm_proxy: profile=%s endpoint=%s path=%s",
            op.profile.name,
            shaped.endpoint,
            redact_source(admitted.path),
        )
        fwd = forward_headers(api, wire.headers.items())
        mode = effective_mode(op.profile, ctx.grant.enforcement)
        warning = await _judge_request(
            ctx, _request_document(wire.method, admitted.path, shaped, fwd), mode
        )
        if shaped.body is not None:
            fwd["content-type"] = JSON
        try:
            resp = await ctx.open(
                wire.method, admitted.path, query=shaped.query, headers=fwd, content=shaped.body
            )
        except RefusedError as failed:
            # The send never got an answer: llm's plain wording, a backend
            # error recorded with any flag-mode finding (as before #535).
            logger.warning("llm_proxy: upstream %s profile=%s", failed.reason, op.profile.name)
            status, text = _UPSTREAM_FAILED.get(
                failed.reason, (HTTPStatus.BAD_GATEWAY, "LLM upstream refused")
            )
            op.settle(Outcome.BACKEND_ERROR, op.flag_reason)
            return Response(content=text, status_code=status, media_type=PLAIN_TEXT)
        op.sent = len(shaped.body) if shaped.body else 0
        # The response edge, per profile (defense.llm_completion). flag streams
        # through and records post-hoc; block buffers the completion, judges it,
        # and withholds a flagged or unjudged one.
        if op.profile.defense.llm_completion == "block":
            return await _buffered_block_response(op, ctx, resp, warning)
        return _streaming_response(op, ctx, resp, warning)

    def render(self, refused: RefusedError) -> Response:
        """A line of text before anything is read; the deny marker after."""
        if (text := _PLAIN.get(refused.canonical)) is not None:
            return Response(
                content=text,
                status_code=refused.status or HTTPStatus.FORBIDDEN,
                media_type=PLAIN_TEXT,
            )
        marker = refused.marker if isinstance(refused, MarkedRefusalError) else {}
        return Response(
            content=json.dumps(_deny_marker(refused.reason, **marker)),
            status_code=refused.status or HTTPStatus.FORBIDDEN,
            media_type=JSON,
        )


async def _judge_request(ctx: InTree, document: str, mode: Mode) -> str | None:
    """Judge an outbound request; refuse under block, return flag's warning.

    The shared ``judge_outbound`` always runs L1/L2/L3 over a credential-redacted
    copy and scans for credential shapes (the layer contract: the detector adds
    a signal, it is not a per-layer off switch). Under ``block`` a credential, a
    flag or a blocking gap refuses before anything is sent. Under ``flag`` the
    request forwards, the verdict rides back on ``X-Trentina-Warning``, and the
    finding goes on the forwarded call's audit row.
    """
    op, name = ctx.op, ctx.instance.name
    verdict = await judge_outbound(
        document,
        source=f"llm:{op.profile.name}:{name}",
        source_type="llm_request",
        backend=f"llm:{name}",
        profile=op.profile,
        mode=mode,
        deadline=_JUDGE_DEADLINE,
    )
    reason = _REASON_OF[verdict.reason or REASON_UNJUDGED].value
    if verdict.refused:
        logger.warning("llm_proxy: request blocked profile=%s reason=%s", op.profile.name, reason)
        raise MarkedRefusalError(
            reason,
            flagged_by=verdict.flagged_by,
            gaps=verdict.gaps or None,
            kinds=verdict.kinds or None,
            mode=mode.value,
        )
    if verdict.warning is not None:
        op.flag_reason = reason
        logger.warning("llm_proxy: request %s (flag) profile=%s", verdict.warning, op.profile.name)
    return verdict.warning


# Buffer completions up to this size for the post-hoc scan; a longer stream
# is passed through with its tail unscanned and a logged warning.
_MAX_COMPLETION_SCAN_BYTES = 16 * 1024 * 1024


def _streaming_response(
    op: Operation, ctx: InTree, resp: Any, warning: str | None = None
) -> Relayed:
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

    status = resp.status_code
    collected: list[bytes] = []
    size_seen = 0

    async def stream_body() -> AsyncIterator[bytes]:
        nonlocal size_seen
        try:
            async for chunk in ctx.chunks(resp):
                op.received += len(chunk)
                if size_seen <= _MAX_COMPLETION_SCAN_BYTES:
                    collected.append(chunk)
                size_seen += len(chunk)
                yield chunk
        except (asyncio.CancelledError, GeneratorExit):
            # The agent went away mid-stream: keep the default CANCELLED; the row
            # still carries what was relayed. finish() runs in relay.Relayed.
            raise
        except Exception:
            # The upstream body broke after the headers — a backend fault, not a
            # cancellation. relay.Relayed still finishes the row.
            op.settle(Outcome.BACKEND_ERROR, "upstream_failed")
            raise
        else:
            # Drained fully: the outcome is the upstream's status (the ONE
            # mapping, shared with /egress), with any flag-mode finding on the row.
            op.settle(upstream_outcome(status), op.flag_reason)
        finally:
            # Best-effort: assemble and judge what streamed. The row and the slot
            # are finished by relay.Relayed, around the whole response, so they
            # are not lost if this generator's finally never runs (a client that
            # stopped reading, a response that never started).
            _schedule_completion_scan(b"".join(collected), size_seen, ctx.instance.name, op.profile)

    ct = resp.headers.get("content-type", "application/json")
    return Relayed(stream_body(), op, media_type=ct, status_code=status, headers=resp_headers)


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
        # The scan (defend + deadline + fail-closed handling) lives on the
        # response edge in the orchestrator; here flag mode only RECORDS the
        # finding, since the completion has already streamed.
        judgement = await judge_llm_completion(
            body.decode("utf-8", errors="replace"),
            profile=profile,
            provider_name=provider_name,
            deadline=_JUDGE_DEADLINE,
        )
        if judgement.flagged:
            logger.warning(
                "llm_proxy: completion flagged profile=%s provider=%s "
                "risk=%s flagged_by=%s (already streamed — recorded only)",
                profile.name,
                provider_name,
                judgement.risk,
                judgement.flagged_by,
            )

    try:
        task = asyncio.get_running_loop().create_task(_scan())
        _scan_tasks.add(task)
        task.add_done_callback(_scan_tasks.discard)
    except RuntimeError:
        logger.debug("llm_proxy: no event loop for post-hoc scan")


_scan_tasks: set[Any] = set()


async def _buffered_block_response(
    op: Operation, ctx: InTree, resp: Any, warning: str | None
) -> Response:
    """Block mode: buffer the completion, judge it, deliver only if clean.

    The opposite tradeoff from flag. An autonomous profile has no human waiting on
    time-to-first-token, so it pays the buffer-scan latency to gain the power to
    WITHHOLD a flagged or not-fully-judged completion rather than only record it
    after it has streamed. The whole body is read before a byte reaches the agent;
    a completion over the scan cap cannot be judged whole and is withheld as
    unjudged. ``op`` is settled and finished here — no streaming ``Relayed`` owns
    it — and the refusal is the same deny marker the request edge uses, with a
    closed reason code (#262/#263).
    """
    provider_name, profile = ctx.instance.name, op.profile
    resp_headers = filter_response_headers(list(resp.headers.items()))
    # Starlette recomputes content-length for a buffered body; never let the
    # upstream forge our verdict header either.
    resp_headers = {k: v for k, v in resp_headers.items() if k.lower() != "content-length"}
    resp_headers.pop(WARNING_HEADER, None)
    status = resp.status_code
    content_type = resp.headers.get("content-type", JSON)

    collected: list[bytes] = []
    size = 0
    oversize = False
    try:
        async for chunk in ctx.chunks(resp):
            size += len(chunk)
            if size > _MAX_COMPLETION_SCAN_BYTES:
                oversize = True
                break
            collected.append(chunk)
    except RefusedError as failed:
        logger.warning(
            "llm_proxy: upstream stream broke (block) provider=%s: %s",
            provider_name,
            failed.reason,
        )
        op.settle(Outcome.BACKEND_ERROR, op.flag_reason)
        return Response(content="LLM upstream error", status_code=502, media_type=PLAIN_TEXT)
    op.received = size

    if oversize:
        # Over the scan cap: unjudged, so block withholds (fail closed).
        op.settle(Outcome.BLOCKED_DEFENSE, "completion_oversize")
        logger.warning(
            "llm_proxy: completion withheld (block, over scan cap) profile=%s provider=%s",
            profile.name,
            provider_name,
        )
        return Response(
            content=json.dumps(_deny_marker("completion_oversize", mode="block")),
            status_code=403,
            media_type=JSON,
        )

    body = b"".join(collected)
    judgement = await judge_llm_completion(
        body.decode("utf-8", errors="replace"),
        profile=profile,
        provider_name=provider_name,
        deadline=_JUDGE_DEADLINE,
    )
    if judgement.flagged or judgement.unjudged:
        reason = "completion_flagged" if judgement.flagged else "completion_unjudged"
        op.settle(Outcome.BLOCKED_DEFENSE, reason)
        logger.warning(
            "llm_proxy: completion withheld (block) profile=%s provider=%s reason=%s risk=%s",
            profile.name,
            provider_name,
            reason,
            judgement.risk,
        )
        marker = _deny_marker(reason, flagged_by=judgement.flagged_by, mode="block")
        return Response(content=json.dumps(marker), status_code=403, media_type=JSON)

    # Clean: safe to deliver, buffered (the stream was traded for the scan).
    op.settle(upstream_outcome(status), op.flag_reason)
    if warning:
        resp_headers[WARNING_HEADER] = warning
    return Response(content=body, status_code=status, headers=resp_headers, media_type=content_type)
