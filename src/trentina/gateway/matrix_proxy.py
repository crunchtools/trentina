"""Matrix Client-Server API reverse proxy — authenticated, scanned.

Forwards requests from ``/matrix/_matrix/...`` to the configured Matrix
homeserver. Agents on the internal network point their homeserver URL at
``http://trentina:PORT/matrix`` instead of directly at matrix.org; the
Matrix client's own path segments (``_matrix/client/...``) follow the prefix
untouched, so the client needs no changes beyond the URL.

**Auth.** The caller's address resolves the profile: each profile's
``matrix_ingress.source_networks`` is the network its agent is on, no two
overlap, and a caller in none gets 401. Nothing secret is in the URL. Until
0.51.0 a token in the path did this, and a client prints the URL in every
timeout, so the token reached agent logs and model context (#330). The
address is uvicorn's ``scope["client"]``, which it rewrites from
``X-Forwarded-For`` for a trusted peer, so a request carrying that header is
refused (``_caller_address``). Before
any of this the proxy was an open relay. Matrix's OWN auth (the access token
in the Authorization header) still passes through untouched; this proxy
never injects or reads Matrix credentials.

**Scanning.** Every 200 response is buffered whole and judged by the
shared pipeline, except what ``_judgement`` exempts (#296): the
acknowledgements a write gets back, E2EE key traffic, and binary media.
Deny by default, because the endpoints that carry prose are not the seven
the proxy once listed: ``/members``, ``/state``, profiles and the room
directory return display names, topics and names any user chose. A JSON
body forwards byte-identical; a flagged one gains a root
``_trentina_warning`` key (Matrix clients ignore unknown root keys), and
the flag is recorded as ``source_type="matrix_sync"``. A body that is not
JSON has no key to carry a warning: it is judged as text, and a flagged or
unjudged one carries the ``X-Trentina-Warning`` header instead, or is
refused when unjudged under ``withhold``.

**Unjudged responses (#227).** A response no layer finished judging — over
the admission cap, past the deadline, a required layer absent — is not a
flagged one, and does not forward unchanged: under ``unjudged: withhold``
(the default) every room event keeps its ID, sender and place, and its
content becomes a notice. The client stays in sync, ``next_batch`` is
honoured, and the agent reads nothing unjudged. Judging runs with
``stop_on_partial``, so an over-cap response costs a token count, not ~74
L2 windows.

**E2EE honesty.** For encrypted rooms this proxy sees ciphertext;
plaintext materializes inside the agent's Matrix client, past the
perimeter. Scanning covers unencrypted rooms only, and no gateway can
claim otherwise.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Literal

import httpx
from starlette.responses import Response, StreamingResponse

from ..channels import Channel
from ..defense import defend_selection
from ..errors import EgressRefusedError
from ..logsafe import exc_kind, exc_where, redact_source, safe_url
from ..matrix.keybackup import KeyBackupProvider
from ..modes import gaps_of
from ..orchestrator import judge_matrix_response, judge_matrix_text_fallback
from ..outcomes import Outcome
from ..reserved import WARNING_KEY, strip_reserved, with_stripped
from ..transforms import SelectionContext
from ..unpack.ocr import MAX_IMAGE_BYTES
from ..warning import build_warning
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, DestinationKind
from .drivers import build_transforms
from .matrix_relation import withheld_relation
from .profile import profile_for_address
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    forward_request_headers,
    normalize_proxy_path,
)
from .relay import Operation
from .selection import describe, run_l1
from .upstream import RESOLVER_BUSY, matrix_pinned_send

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

#: The audit ``backend`` column for a Matrix proxy row (one per relayed
#: operation, never per idle ``/sync`` long-poll — see ``_proxy_matrix``).
BACKEND = "matrix"

_DEFAULT_UPSTREAM = "https://matrix-client.matrix.org"

#: Idle (read/write) budget for the pinned pool — a ``/sync`` long-poll holds the
#: read open this long. matrix.org is a Matrix-only pooled origin, so it does not
#: bleed onto the other proxies.
_MATRIX_IDLE = 120.0

#: Idle budget for a key-backup GET (#532). These are small JSON reads
#: (``/room_keys/version``, a room's keys), not a long-poll, so they need
#: nothing like ``_MATRIX_IDLE``.
_KEYBACKUP_IDLE = 30.0

MATRIX_HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
]

_CLIENT = r"_matrix/client/(?:v3|r0|v1|unstable(?:/[^/]+)?)/"
_MEDIA = r"_matrix/(?:media/(?:v3|r0|v1)|client/v1/media)/"

_ACKS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (method, re.compile(pattern))
    for method, pattern in (
        ("GET", r"_matrix/client/versions"),
        ("PUT", _CLIENT + r"rooms/[^/]+/(?:send|state|redact|typing)/.+"),
        ("PUT", _CLIENT + r"sendToDevice/[^/]+/[^/]+"),
        ("PUT", _CLIENT + r"user/[^/]+/(?:rooms/[^/]+/)?(?:account_data|tags)/.+"),
        ("PUT", _CLIENT + r"(?:profile|pushrules|directory)/.+"),
        ("PUT", _CLIENT + r"presence/[^/]+/status"),
        ("POST", _CLIENT + r"rooms/[^/]+/(?:receipt/.+|read_markers|join|leave|forget)"),
        ("POST", _CLIENT + r"rooms/[^/]+/(?:invite|kick|ban|unban)"),
        ("POST", _CLIENT + r"(?:join/[^/]+|createRoom|login|logout(?:/all)?|refresh)"),
        ("POST", _CLIENT + r"keys/(?:upload|claim|signatures/upload|device_signing/upload)"),
        ("POST", _CLIENT + r"user/[^/]+/filter"),
        ("POST", _MEDIA + r"(?:upload|create)"),
        ("PUT", _MEDIA + r"upload/.+"),
        ("GET", _CLIENT + r"room_keys/.+"),
        ("PUT", _CLIENT + r"room_keys/.+"),
    )
)
"""Responses carrying nothing another user wrote, matched on the WHOLE path.

The acknowledgement of a write (``{}``, or an event, room or content ID the
homeserver minted), the auth flows, and one-time and backup keys
(ciphertext: what it decrypts to is inside the agent's client, as the
module docstring says). Anchored, so a room or event ID chosen to contain
``/send/`` cannot carry a prose endpoint past the scan; a path not listed
is judged. ``/keys/query`` is not here: its ``device_display_name`` is any
user's choice. DELETE and OPTIONS are exempt by method: every DELETE in the
Client-Server API answers ``{}`` or a count, and OPTIONS is CORS."""

_MEDIA_DOWNLOAD = re.compile(_MEDIA + r"(?:download|thumbnail)/.+")

_BINARY_TYPES = ("image/", "audio/", "video/", "application/octet-stream")
"""Media types a media download cannot be judged as text or JSON. An image
is read by OCR and judged (#370). Nothing reads sound or moving pictures,
and an E2EE attachment is ``application/octet-stream`` ciphertext, so under
``unjudged: withhold`` those are refused (#371); ``annotate`` forwards them
with the warning header. A text, JSON or markup attachment is judged like
any other response."""


# Only buffer-and-scan bodies up to this size; a larger one is refused,
# under annotate too: it cannot be judged, stripped or annotated without
# buffering it (#296). /sync responses are typically tens of KB; 32MB is
# far past any honest one.
_MAX_SCAN_BYTES = 32 * 1024 * 1024

WARNING_HEADER = "x-trentina-warning"
"""Where a non-JSON response's warning rides: a risk level, nothing else."""

_FALLBACK_SCAN_DEADLINE_SECONDS = 20.0
"""Deadline used when a profile has no matrix_ingress config to read one from.

How long the whole judgement may take before the response forwards anyway.

There was no deadline here at all. ``defend_json`` runs L2 (ONNX, hundreds of
ms per window) and may call L3 (a network round-trip to a third-party LLM),
and a Matrix ``/sync`` sits on the client's critical path — OpenClaw gives a
channel 30 seconds to become ready and starts over if it does not. A slow or
hanging judge therefore did not degrade Matrix, it stopped it.

Twenty seconds is chosen against that 30 s budget: long enough that a healthy
scan never trips it, short enough to leave the client room to finish. On
expiry the body forwards — fail open on the request path, as everything else
here does — but it forwards WITH a warning, because an unscanned response must
never look like a clean one.
"""

WITHHELD = "[trentina] withheld: this event could not be fully judged"
"""What a withheld event's text becomes. Ours, never the payload's."""

_PROSE_FIELDS = frozenset(
    {"body", "formatted_body", "topic", "name", "displayname", "reason", "status_msg"}
)
"""Fields that carry language even as one word; withheld whatever their shape."""

_TOKEN_MAX = 255
"""Longest string an unjudged response keeps. Together with "no whitespace",
that admits every ID, token, enum and timestamp Matrix sends and no sentence."""

_E2EE_TO_DEVICE = frozenset(
    {
        "m.room.encrypted",
        "m.room_key",
        "m.room_key_request",
        "m.forwarded_room_key",
        "m.dummy",
        "m.secret.request",
        "m.secret.send",
    }
)
"""To-device types E2EE needs byte for byte. Ciphertext and keys are long
single tokens the rule above would cut; what they decrypt to is inside the
agent's client, past the perimeter, as the module docstring says."""

_CIPHER_KEYS = frozenset({"ciphertext", "session_key", "sender_key", "secret", "key"})
"""The fields of an E2EE to-device event that hold ciphertext or key
material. Only these, and everything under them, may exceed ``_TOKEN_MAX``;
every other field of the event is walked like any other."""

_MAX_WALK_DEPTH = 64


def _keybackup_send(profile: Profile) -> Any:
    """A pin-before-send GET for one profile's key-backup provider (#532).

    The provider's homeserver calls carry the Matrix access token, so they ride
    the SAME pinned pool as the ``/sync`` forward instead of a bare client: the
    origin is re-checked and pinned before each dial (``matrix_pinned_send`` →
    ``checked_target``), closing the DNS-rebinding window an unpinned client left
    open. The pool is torn down by ``upstream.close_pool`` at shutdown, so there
    is no separate client to leak. The provider owns the response's close.
    """

    async def send(method: str, url: str, headers: dict[str, str]) -> httpx.Response:
        return await matrix_pinned_send(profile, method, url, idle=_KEYBACKUP_IDLE, headers=headers)

    return send


def _caller_address(request: Request) -> str | None:
    """The address that connected, or None when it may not be that.

    uvicorn replaces ``scope["client"]`` with an ``X-Forwarded-For`` entry
    when the peer is in its trusted list, and only when that header is
    present (``ProxyHeadersMiddleware``). A request carrying the header may
    therefore hold an address someone named rather than one that connected,
    and the address is the credential: it is refused. An agent on its own
    network calls the gateway directly and sends no such header.
    """
    # TRUST: the peer address picks the profile (#330)
    #   untrusted: every header the caller sends
    #   judged-by: nothing; an address is resolved, not judged
    #   on-failure: fail-closed; with X-Forwarded-For present, no profile
    #   owner: matrix_proxy._caller_address
    #   evidence: T2 uvicorn ProxyHeadersMiddleware rewrites scope["client"]
    #     only from x-forwarded-for; T3 loader._check_matrix_networks (one
    #     profile per address)
    if "x-forwarded-for" in request.headers:
        return None
    return request.client.host if request.client else None


def register_matrix_routes(
    mcp_server: Any,
    profiles: dict[str, Profile],
    *,
    upstream: str = _DEFAULT_UPSTREAM,
) -> None:
    """Wire ``/matrix/{path:path}`` onto the FastMCP server.

    Only ``_matrix/...`` paths are served. A URL from before 0.51.0, with a
    token ahead of ``_matrix``, gets 404 and the token is not echoed.

    Raises:
        ValueError: an upstream that is not https.
    """
    if not upstream.startswith("https://"):
        raise ValueError(
            f"Matrix upstream must start with https://: {upstream!r}",
        )
    upstream = upstream.rstrip("/")

    matrix_profiles = [name for name, p in profiles.items() if p.matrix_ingress is not None]
    if not matrix_profiles:
        logger.warning(
            "matrix_proxy: matrix.enabled is set but no profile has "
            "matrix_ingress — every request will 401",
        )

    async def matrix_proxy_endpoint(request: Request) -> Response:
        if not request.path_params.get("path", "").startswith("_matrix/"):
            return Response(content="not found", status_code=404, media_type=PLAIN_TEXT)
        profile = profile_for_address(_caller_address(request), profiles, "matrix_ingress")
        if profile is None:
            return Response(
                content="unauthorized",
                status_code=401,
                media_type=PLAIN_TEXT,
            )
        # The sync scan runs on this profile's provider and key (RT #1505).
        with profile_context(profile):
            return await _proxy_matrix(request, upstream, profile)

    mcp_server.custom_route(
        "/matrix/{path:path}",
        methods=MATRIX_HTTP_METHODS,
    )(matrix_proxy_endpoint)

    logger.info(
        "matrix_proxy: registered /matrix/{path} → %s for %d profile(s): %s",
        safe_url(upstream),
        len(matrix_profiles),
        ", ".join(matrix_profiles) or "(none)",
    )


def _judgement(
    method: str, path: str, status: int, content_type: str
) -> Literal["json", "text", "media"] | None:
    """How a response is judged before it forwards, or None if it is not.

    The one place the decision is made. Only a 200 is judged; of those,
    the exempt set above forwards unjudged, a binary media download is
    ``media`` (``_media``: read if it is an image, withheld if not), JSON is
    judged as a document, and anything else as text.
    """
    exempt = (
        status != 200
        or method in ("DELETE", "OPTIONS")
        or any(m == method and p.fullmatch(path) for m, p in _ACKS)
    )
    if exempt:
        return None
    binary = content_type.strip().lower().startswith(_BINARY_TYPES)
    if method == "GET" and _MEDIA_DOWNLOAD.fullmatch(path) is not None and binary:
        return "media"
    return "json" if "json" in content_type.lower() else "text"


async def _proxy_matrix(
    request: Request,
    upstream: str,
    profile: Profile,
) -> Response:
    """Forward one Matrix Client-Server API request, and audit it on the ONE
    lifecycle (``relay.Operation``, #511).

    A ``gateway_calls`` row is written ONLY when the operation was refused, hit
    an upstream error, or carried a security finding — a flagged response, a
    blocking gap that withheld events, a withheld or too-large body. A clean
    response and the exempt pass-through (acks, ``/versions``, E2EE key traffic,
    media under annotate) write NO row, because ``/sync`` is a continuous
    long-poll and a row per poll would flood the audit database.

    The row is GATED on a ``reason`` being set, never on the outcome:
    ``Operation`` defaults its outcome to ``CANCELLED`` but its reason to
    ``None``, so gating on the outcome would turn any clean path that forgot to
    settle into a logged row — the exact flood this avoids. A forwarded-with-
    finding response settles ``(OK, <finding>)``, so the outcome column tells a
    delivered finding (``ok``) from a withhold/refusal (a block outcome), the
    way ``/proxy/http`` records a flag. Nothing is registered on ``op.upstream``
    (the httpx response is closed by ``_buffer``/``_streamed`` as before), so a
    skipped finish leaks nothing: no slot is taken and no close is pending.
    """
    op = Operation(
        profile, backend=BACKEND, tool=request.method, destination_kind=DestinationKind.MATRIX
    )
    try:
        return await _route(request, upstream, profile, op)
    except httpx.HTTPError:
        # A homeserver that drops mid-body (``_buffer`` reads outside the scan's
        # own try) must still be audited — the Phase 0 /llm bug, not reborn here.
        if op.reason is None:
            op.settle(Outcome.BACKEND_ERROR, "upstream_failed")
        raise
    except Exception:
        if op.reason is None:
            op.settle(Outcome.GATEWAY_ERROR, "proxy_error")
        raise
    finally:
        # The one place a Matrix row is (or is not) written. See the docstring:
        # a clean or idle operation leaves reason None and is never audited.
        if op.reason is not None:
            await op.finish()


async def _route(
    request: Request,
    upstream: str,
    profile: Profile,
    op: Operation,
) -> Response:
    """Forward one request; settle ``op`` on each refusal, error or finding."""
    raw_path = request.path_params.get("path", "")
    path = normalize_proxy_path(raw_path)
    if path is None:
        op.settle(Outcome.DENIED_GUARD, "path_traversal")
        return Response(
            content="Path traversal rejected",
            status_code=400,
            media_type=PLAIN_TEXT,
        )
    # The caller's path is the destination: stored in the audit row, never the
    # query (older clients carry state there), never logged (#266).
    op.destination = path[:MAX_DESTINATION_CHARS]

    upstream_url = f"{upstream}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    fwd_headers = forward_request_headers(list(request.headers.items()))
    has_body = request.method in ("POST", "PUT", "PATCH")

    try:
        # The pinned pool (#511): the homeserver origin is re-checked and the
        # connection pinned before the send (Matrix crosses the egress guard now,
        # like the other proxies), and reused. Matrix takes none of the
        # terminating-proxy contract — no forced identity, no redirect/encoded
        # refusal — so a 3xx is forwarded for the agent's client and a gzipped
        # /sync is decoded by _buffer as before. The response is returned OPEN;
        # _buffer / _streamed own its close.
        resp = await matrix_pinned_send(
            profile,
            request.method,
            upstream_url,
            idle=_MATRIX_IDLE,
            headers=fwd_headers,
            content=request.stream() if has_body else None,
        )
    except EgressRefusedError as exc:
        # The egress guard refused the homeserver origin (not global, not 443, or
        # the resolver was busy). resolver_busy is gateway load (503), not a
        # verdict on the name; everything else is the address rail (403).
        if exc.reason == RESOLVER_BUSY:
            op.settle(Outcome.DENIED_GUARD, exc.reason)
            status = 503
        else:
            op.settle(Outcome.BLOCKED_DEFENSE, exc.reason)
            status = 403
        logger.warning("matrix_proxy: upstream refused reason=%s", exc.reason)
        return Response(
            content="Matrix upstream refused", status_code=status, media_type=PLAIN_TEXT
        )
    except httpx.TimeoutException:
        op.settle(Outcome.BACKEND_ERROR, "upstream_timeout")
        return Response(content="Matrix upstream timeout", status_code=504, media_type=PLAIN_TEXT)
    except httpx.ConnectError as exc:
        logger.warning("matrix_proxy: connect error: %s", exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR, "upstream_unreachable")
        return Response(
            content="Matrix upstream unreachable", status_code=502, media_type=PLAIN_TEXT
        )

    # matrix_pinned_send returns a POOLED, pinned response held OPEN; until
    # _buffer / _streamed take over its close, an exception in this span would
    # leak a pinned connection to KEEPALIVE_EXPIRY, so close it here. The outer
    # _proxy_matrix settles the row (GATEWAY_ERROR / upstream_failed).
    try:
        resp_headers = filter_response_headers(list(resp.headers.items()))
        ct = resp.headers.get("content-type", "application/json")
        scanner = _SCANNERS.get(_judgement(request.method, path, resp.status_code, ct) or "")
        if scanner is not None:
            return await scanner(resp, resp_headers, ct, profile, path, op)
        # Exempt pass-through (acks, /versions, E2EE key traffic): nothing is
        # judged and nothing is settled, so no row is written.
        return _streamed(resp, resp_headers, ct)
    except Exception:
        await resp.aclose()
        raise


def _streamed(resp: httpx.Response, headers: dict[str, str], content_type: str) -> Response:
    """Forward a body as it arrives, unjudged: the exempt set, and media under annotate."""

    async def stream_body() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()

    return StreamingResponse(
        stream_body(), status_code=resp.status_code, headers=headers, media_type=content_type
    )


_EXTRACTORS: dict[str, Any] = {}
_PROVIDERS: dict[str, Any] = {}
_PROVIDER_LOCK = asyncio.Lock()


async def _provider_for(profile: Profile) -> Any:
    """The profile's key-backup provider, started once.

    Built lazily rather than at route registration because starting it makes
    network calls -- it verifies the backup version and checks that our
    recovery key derives the public key the homeserver published. Doing that
    in the first request that needs it keeps boot synchronous and keeps a
    homeserver outage from preventing startup.

    A failure here is logged and remembered as "no provider": decryption then
    degrades to the undecryptable path, which is reported, rather than taking
    the Matrix proxy down with it.
    """
    ingress = profile.matrix_ingress
    cfg = ingress.preprocess.decrypt if ingress is not None else None
    if cfg is None or not cfg.enabled:
        return None
    if profile.name in _PROVIDERS:
        return _PROVIDERS[profile.name]

    async with _PROVIDER_LOCK:
        if profile.name in _PROVIDERS:
            return _PROVIDERS[profile.name]
        provider: Any = None
        if cfg.access_token is None or cfg.recovery_key is None:
            # The loader resolves these at config load, so reaching here means
            # a Profile was built without going through it. Report and degrade
            # rather than raising into the request path.
            logger.error(
                "matrix_proxy: decrypt enabled for profile=%s but its secrets "
                "are unresolved — encrypted events will be unreadable",
                profile.name,
            )
            _PROVIDERS[profile.name] = None
            return None
        try:
            provider = KeyBackupProvider(
                homeserver=cfg.homeserver,
                access_token=cfg.access_token.get_secret_value(),
                recovery_key=cfg.recovery_key.get_secret_value(),
                send=_keybackup_send(profile),
                max_sessions=cfg.max_sessions,
                ttl_seconds=cfg.session_ttl_seconds,
                concurrency=cfg.concurrency,
                refetch_cooldown_seconds=cfg.refetch_cooldown_seconds,
            )
            await provider.start()
            logger.warning("matrix_proxy: key backup ready for profile=%s", profile.name)
        except Exception as exc:
            logger.error(  # the homeserver's text is not ours to log (#262)
                "matrix_proxy: key backup unavailable for profile=%s — "
                "encrypted events will be reported as undecryptable: %s at %s",
                profile.name,
                exc_kind(exc),
                exc_where(exc),
            )
            provider = None
        _PROVIDERS[profile.name] = provider
        return provider


async def _extractor_for(profile: Profile) -> Any:
    """The profile's document processor, built once, with its keys attached.

    ``None`` when the profile names no processor, which is the default and
    means read every leaf — ``run_l1`` handles it.

    Cached because the Matrix processor holds a Megolm session cache, and
    rebuilding it per request would throw that away on the path where it
    matters most. Async because the provider it depends on verifies the backup
    over the network the first time it is needed.
    """
    ingress = profile.matrix_ingress
    if ingress is None or not ingress.preprocess.processors:
        return None
    cfg = ingress.preprocess
    # Keyed on every input the factory reads, not just the name: two
    # profiles, or one profile across a reload, must not share an instance
    # built from different settings.
    key = f"{profile.name}:{','.join(cfg.processors)}:{cfg.skip_sample_bytes}"
    cached = _EXTRACTORS.get(key)
    if cached is None:
        # The channel takes at most one, enforced in build_transforms.
        cached = build_transforms(
            cfg,
            channel=Channel.MATRIX,
            profile_name=profile.name,
            keys=await _provider_for(profile),
        )[0]
        _EXTRACTORS[key] = cached
    return cached


def reset_extractors() -> None:
    """Drop cached extractors and providers. On reload and by tests."""
    _EXTRACTORS.clear()
    _PROVIDERS.clear()


async def _buffer(resp: httpx.Response, path: str) -> bytes | Response:
    """The whole body, or the refusal to send when it is too big to judge.

    Refused under annotate as well (#296). Forwarding it streamed, as this
    once did, delivered bytes no layer read, with no warning on them and no
    reserved key stripped: neither can be done to a body that is not held.
    """
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > _MAX_SCAN_BYTES:
                # Stop BUFFERING: the old guard kept accumulating and only
                # skipped the scan, an OOM lever.
                logger.warning(
                    "matrix_proxy: %s response exceeds %d bytes — refused, too large to judge",
                    redact_source(path),
                    _MAX_SCAN_BYTES,
                )
                return Response(
                    content="Matrix response too large to judge",
                    status_code=502,
                    media_type=PLAIN_TEXT,
                )
            chunks.append(chunk)
    finally:
        await resp.aclose()
    return b"".join(chunks)


async def _scan_and_forward(
    resp: httpx.Response,
    resp_headers: dict[str, str],
    content_type: str,
    profile: Profile,
    path: str,
    op: Operation,
) -> Response:
    """Buffer a message-bearing response, judge it, forward it.

    A judged response, clean or flagged, forwards intact; ``content-length``
    is recomputed only when a warning key is added. An unjudged one follows
    ``matrix_ingress.unjudged``: withheld event by event (``_respond``), or
    forwarded annotated. Unparseable JSON is scanned as text, then refused
    under withhold (there is no event to withhold, and no client can parse
    it either) or forwarded under annotate.

    ``op`` is settled for the audit row: ``flag_reason`` on a forward that
    carried a finding (flagged, or an annotate-mode unjudged forward), a
    non-OK outcome with a reason on a withhold/refusal; a clean forward
    settles nothing, so no row is written.
    """
    headers = {k: v for k, v in resp_headers.items() if k.lower() != "content-length"}

    buffered = await _buffer(resp, path)
    if isinstance(buffered, Response):
        op.settle(Outcome.BLOCKED_DEFENSE, "response_too_large")
        return buffered
    body = buffered
    op.received = op.sent = len(body)

    ingress = profile.matrix_ingress
    cfg = ingress.preprocess if ingress is not None else None
    deadline = cfg.deadline_seconds if cfg else _FALLBACK_SCAN_DEADLINE_SECONDS

    payload: Any = None
    view = None
    stripped = 0
    try:
        payload = json.loads(body)
        # Any room member can put the gateway's markers in an event (#265).
        # Removed before the scan, and the body rewritten only when one was,
        # so every path below forwards the stripped bytes.
        stripped = await asyncio.to_thread(strip_reserved, payload)
        if stripped:
            body = json.dumps(payload).encode("utf-8")
            logger.info(
                "matrix_proxy: stripped %d reserved key(s) from %s for profile=%s",
                stripped,
                redact_source(path),
                profile.name,
            )
        # The deadline wraps extraction AND judgement. Bounding only the
        # judge would leave any I/O an extractor does (a key fetch, later)
        # unbounded, which is the stall risk selection itself introduces.
        async with asyncio.timeout(deadline):
            extractor = await _extractor_for(profile)
            view = await run_l1(
                payload,
                extractor=extractor,
                ctx=SelectionContext(
                    source=f"matrix:{profile.name}:{path}",
                    profile_name=profile.name,
                    path=path,
                ),
            )
            verdict = await defend_selection(
                view,
                source=f"matrix:{profile.name}:{path}",
                source_type="matrix_sync",
                defense=profile.defense,
                # Withholding refuses a partial scan anyway, so it is refused
                # at admission rather than paid for (#227). annotate keeps
                # the head scan it forwards with.
                stop_on_partial=_withholds(profile),
                record=True,
                attribution={
                    "profile": profile.name,
                    "backend": "matrix",
                    "direction": "sync",
                    "blocked": False,
                },
            )
    except TimeoutError:
        # Must precede the bare `except Exception`: TimeoutError descends from
        # OSError, so the order here is what makes the deadline observable
        # rather than silently reported as a failed scan.
        # WARNING rather than ERROR, and deliberately not logger.exception:
        # a deadline is an expected condition, and the traceback would be the
        # timeout machinery's own. The finding an operator acts on is the
        # rate, which the annotation and the audit row carry.
        logger.warning(
            "matrix_proxy: scan deadline %.1fs exceeded for %s profile=%s — "
            "forwarding UNSCANNED with a warning",
            deadline,
            redact_source(path),
            profile.name,
        )
        withhold = _settle_unscanned(op, profile, "scan_timeout")
        return _respond(
            payload,
            body,
            headers,
            content_type,
            with_stripped({"risk_level": "unknown", "scan_timeout": True}, stripped),
            withhold=withhold,
        )
    except Exception as exc:
        # A parse failure here is attacker-reachable (any room member can
        # ship pathological JSON), so "scan failed" must not mean "clean":
        # the raw bytes are judged as TEXT for the record — L1/L2 still read
        # a plaintext payload buried beside the poison — and what forwards
        # is unjudged (#296): stripped and warned under annotate, withheld
        # under withhold, and nothing at all when there is no object, since
        # no client can parse that and nothing can be stripped from it.
        logger.error(  # the message may carry the payload (#262)
            "matrix_proxy: structured scan failed for %s — text-mode fallback: %s at %s",
            redact_source(path),
            exc_kind(exc),
            exc_where(exc),
        )
        flagged = await _text_fallback_scan(body, profile, path)
        restripped = await _restrip(payload)
        if restripped is None:
            op.settle(Outcome.BLOCKED_DEFENSE, "scan_failed")
            return _refused()
        withhold = _settle_unscanned(op, profile, "scan_failed", flagged=flagged)
        return _respond(
            restripped,
            body,
            headers,
            content_type,
            with_stripped({"risk_level": "unknown", "scan_failed": True}, stripped),
            withhold=withhold,
        )

    return _forward_judged(
        op, payload, body, view, verdict, headers, content_type, stripped, cfg, path
    )


def _settle_unscanned(
    op: Operation, profile: Profile, reason: str, *, flagged: bool = False
) -> bool:
    """Settle the audit row for a response FORWARDED without a full scan, and
    return whether its events are to be withheld.

    Under withhold the response is a defense block carrying ``reason``; under
    annotate it forwards, so it settles ``(OK, reason)`` (``,flagged`` when the
    text-mode fallback flagged it) — the finding is on the row either way, with
    the outcome telling the two apart.
    """
    withhold = _withholds(profile)
    if withhold:
        op.settle(Outcome.BLOCKED_DEFENSE, reason)
    else:
        op.settle(Outcome.OK, f"{reason},flagged" if flagged else reason)
    return withhold


def _forward_judged(
    op: Operation,
    payload: Any,
    body: bytes,
    view: Any,
    verdict: Any,
    headers: dict[str, str],
    content_type: str,
    stripped: int,
    cfg: Any,
    path: str,
) -> Response:
    """Deliver a fully-judged JSON response and settle its audit row.

    A clean forward settles nothing, so no row is written. A flagged or
    undecrypted-withheld forward settles ``(OK, <finding>)`` so the row records
    it; a blocking gap under withhold is a defense block that rewrites events.
    """
    profile = op.profile
    extras = describe(view, cfg) if (view is not None and cfg is not None) else {}
    warning = with_stripped(build_warning(verdict, extras=extras), stripped)
    gaps = gaps_of(verdict)
    if verdict.flagged:
        logger.warning(
            "matrix_proxy: flagged %s for profile=%s risk=%s flagged_by=%s",
            redact_source(path),
            profile.name,
            verdict.risk_level,
            verdict.flagged_by.value if verdict.flagged_by else None,
        )
    elif gaps.any():
        # Not flagged, but the scan did not fully happen — over the cap, the
        # classifier never loaded, or the judge was unavailable. Only the
        # gaps that are TRUE: the warning carries every gap key, False
        # included, and naming those made a coverage note on every /sync
        # read as a steady stream of truncated scans (#227).
        logger.warning(
            "matrix_proxy: incomplete scan of %s for profile=%s — %s",
            redact_source(path),
            profile.name,
            ",".join(gaps.names()),
        )

    unread = 0
    if _withholds(profile):
        unread = _withhold_undecrypted(payload, view)
        if unread:
            warning = {**(warning or {}), "undecrypted_withheld": unread}
    withhold = gaps.blocking() and _withholds(profile)
    if withhold:
        op.settle(Outcome.BLOCKED_DEFENSE, "events_withheld")
    elif verdict.flagged:
        op.settle(Outcome.OK, verdict.risk_level or "flagged")
    elif unread:
        op.settle(Outcome.OK, "undecrypted_withheld")
    return _respond(payload, body, headers, content_type, warning, withhold=withhold)


def _refused() -> Response:
    return Response(
        content="Matrix response could not be judged", status_code=502, media_type=PLAIN_TEXT
    )


async def _restrip(payload: Any) -> dict[str, Any] | None:
    """``payload`` with its reserved keys certainly gone, or None.

    The failure being handled may have been the strip itself, so it runs
    again; failing twice leaves nothing that may be forwarded.
    """
    if not isinstance(payload, dict):
        return None
    try:
        await asyncio.to_thread(strip_reserved, payload)
    except Exception as exc:
        logger.error(
            "matrix_proxy: reserved-key strip failed: %s at %s", exc_kind(exc), exc_where(exc)
        )
        return None
    return payload


async def _media(
    resp: httpx.Response,
    resp_headers: dict[str, str],
    content_type: str,
    profile: Profile,
    path: str,
    op: Operation,
) -> Response:
    """A binary media download: read if it is an image, never forwarded unread
    under withhold (#371).

    An image is handed to the layers as base64, which the unpack stage reads
    by OCR; one OCR cannot read is ``binary_unread`` and refused like any
    other unjudged body. Audio, video and ``application/octet-stream`` (an
    E2EE attachment is ciphertext under that type) have no reader, so they
    are refused under withhold. Under annotate every one of them forwards
    with the warning header, as the gap it is — a finding on the row.
    """
    if not _withholds(profile):
        op.settle(Outcome.OK, "media_unreadable")
        return _streamed(resp, {**resp_headers, WARNING_HEADER: "unknown"}, content_type)
    if content_type.strip().lower().startswith("image/"):
        return await _scan_text_and_forward(
            resp, resp_headers, content_type, profile, path, op, image=True
        )
    await resp.aclose()
    op.settle(Outcome.BLOCKED_DEFENSE, "media_withheld")
    logger.warning(
        "matrix_proxy: withheld a media download no layer can read, %s for profile=%s",
        redact_source(path),
        profile.name,
    )
    return _refused()


async def _scan_text_and_forward(
    resp: httpx.Response,
    resp_headers: dict[str, str],
    content_type: str,
    profile: Profile,
    path: str,
    op: Operation,
    *,
    image: bool = False,
) -> Response:
    """Judge a body that is not JSON as text, then forward or refuse it.

    No key in it can carry a warning, so a header does, holding only a risk
    level. Flagged forwards, as a flagged JSON body does; unjudged forwards
    only under annotate. An ``image`` is judged as its base64, which the
    unpack stage reads by OCR; one too large to read is unjudged.

    ``op`` is settled for the audit row as in ``_scan_and_forward``.
    """
    headers = {k: v for k, v in resp_headers.items() if k.lower() != "content-length"}
    buffered = await _buffer(resp, path)
    if isinstance(buffered, Response):
        op.settle(Outcome.BLOCKED_DEFENSE, "response_too_large")
        return buffered
    if image and len(buffered) > MAX_IMAGE_BYTES:
        op.settle(Outcome.BLOCKED_DEFENSE, "media_too_large")
        return _refused()
    op.received = op.sent = len(buffered)
    ingress = profile.matrix_ingress
    deadline = (
        ingress.preprocess.deadline_seconds
        if ingress is not None
        else _FALLBACK_SCAN_DEADLINE_SECONDS
    )
    judgement = await judge_matrix_response(
        base64.b64encode(buffered).decode("ascii")
        if image
        else buffered.decode("utf-8", errors="replace"),
        profile=profile,
        source=f"matrix:{profile.name}:{path}",
        stop_on_partial=_withholds(profile),
        deadline=deadline,
    )
    flagged, unjudged, risk = judgement.flagged, judgement.unjudged, judgement.risk
    if unjudged and _withholds(profile):
        op.settle(Outcome.BLOCKED_DEFENSE, "response_withheld")
        return _refused()
    if flagged or unjudged:
        logger.warning(
            "matrix_proxy: %s non-JSON response %s for profile=%s risk=%s",
            "flagged" if flagged else "unjudged",
            redact_source(path),
            profile.name,
            risk,
        )
        headers[WARNING_HEADER] = risk
        op.settle(Outcome.OK, risk if flagged else "unjudged")
    return Response(content=buffered, status_code=200, headers=headers, media_type=content_type)


_SCANNERS = {"json": _scan_and_forward, "text": _scan_text_and_forward, "media": _media}
"""How each of ``_judgement``'s answers is judged and forwarded."""


def _withholds(profile: Profile) -> bool:
    """``matrix_ingress.unjudged`` is withhold, which is also its default."""
    ingress = profile.matrix_ingress
    return ingress is None or ingress.unjudged == "withhold"


def _token(value: str, *, sealed: bool = False) -> bool:
    """Whether an unjudged string may survive: one printable token.

    ``isprintable`` is False for the format characters (zero-width space,
    joiners, bidi controls) and ``isspace`` catches the printable spaces
    (no-break, ideographic) that would otherwise join a sentence into one
    "token". A token can still be ``ignore-all-rules``; it cannot be longer
    than a Matrix ID may be, except ``sealed``: inside an E2EE to-device
    event, where ciphertext and keys are long single tokens.
    """
    return (
        (sealed or len(value) <= _TOKEN_MAX)
        and value.isprintable()
        and not any(c.isspace() for c in value)
    )


def _id_like(value: str) -> bool:
    """Whether a string carries a Matrix sigil or a digit, as IDs and aliases do."""
    return any(c in "@!#$:+" or c.isdigit() for c in value)


def _rebuild_room_event(node: dict[str, Any]) -> int:
    """1 if ``node`` is an event; a room event becomes the notice plus its relation."""
    content = node.get("content")
    if not (isinstance(content, dict) and isinstance(node.get("type"), str)):
        return 0
    if "state_key" not in node and isinstance(node.get("event_id"), str):
        _as_notice(node, content)
    return 1


def _as_notice(node: dict[str, Any], content: dict[str, Any]) -> None:
    """Make a room event the withheld notice, keeping only its relation."""
    relation = withheld_relation(content.get("m.relates_to"))
    node["content"] = {"msgtype": "m.notice", "body": WITHHELD}
    if relation is not None:
        node["content"]["m.relates_to"] = relation
    if node["type"] == "m.room.encrypted":
        node["type"] = "m.room.message"


def _withhold_undecrypted(payload: Any, view: Any) -> int:
    """Withhold, in place, each encrypted room event the gateway did not read.

    An agent's Matrix client holds the room keys and would decrypt it, so
    forwarding the ciphertext delivers text no layer read (#371). Each such
    event becomes the withheld notice; the rest of the response is judged
    and forwards as it is. Returns how many.

    Which events were read is the extractor's answer. One that decrypted
    nothing (``select``, or ``matrix`` with no key) read none of them. One
    that decrypted some lists the rest in ``undecryptable``, matched here on
    the event ID, or on the session ID where an event has none. Only Megolm
    room events are in question: an Olm to-device event carries its
    ciphertext as an object, and is key traffic, not prose.
    """
    unread = getattr(view, "undecryptable", ())
    all_unread = not getattr(view, "decrypted_events", 0)
    by_id = {event.event_id for event in unread if event.event_id}
    by_session = {event.session_id for event in unread if not event.event_id}
    withheld = 0
    for node, content in _megolm_room_events(payload):
        event_id = node.get("event_id")
        listed = event_id in by_id if event_id else content.get("session_id") in by_session
        if all_unread or listed:
            _as_notice(node, content)
            withheld += 1
    return withheld


def _megolm_room_events(payload: Any) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Every ``m.room.encrypted`` event with string ciphertext, and its content,
    to ``_MAX_WALK_DEPTH``. Collected before any is rewritten."""
    found: list[tuple[dict[str, Any], dict[str, Any]]] = []
    level: list[Any] = [payload]
    for _ in range(_MAX_WALK_DEPTH + 1):
        below: list[Any] = []
        for node in level:
            content = node.get("content") if isinstance(node, dict) else None
            if (
                isinstance(content, dict)
                and node.get("type") == "m.room.encrypted"
                and isinstance(content.get("ciphertext"), str)
            ):
                found.append((node, content))
            elif isinstance(node, dict):
                below.extend(node.values())
            elif isinstance(node, list):
                below.extend(node)
        level = below
    return iter(found)


_PATH_STEPS = {("root", "to_device"): "to_device", ("to_device", "events"): "to_device.events"}
"""Where the walk is, by the keys that lead to the one exempt position:
``to_device.events[i]`` of the response itself, never the same keys nested."""


def _withhold_events(node: Any, depth: int = 0, *, at: str = "root", sealed: bool = False) -> int:
    """Strip the language from an unjudged response in place; count the events.

    One rule everywhere: a string survives only as a single token
    (``_token``) outside ``_PROSE_FIELDS``, and a dict key only as a single
    token. IDs, sync tokens, types, memberships and timestamps pass, so the
    client's room model and ``next_batch`` survive; no sentence does, in
    content, ``unsigned``, extensions or anywhere else. On top of that, a
    room event (``event_id``, no ``state_key``) is rebuilt as the notice
    plus its relation; an encrypted one becomes a plain notice. An E2EE
    event at the response's own ``to_device.events[i]`` (``at``) is walked
    like everything else except its ``_CIPHER_KEYS``, which are ``sealed``:
    tokens there may be as long as ciphertext is, and ``body`` inside them is
    ciphertext, not prose. Whitespace text is withheld even there. The same
    shape anywhere else gets no allowance at all.
    Past ``_MAX_WALK_DEPTH`` a subtree is withheld whole: unwalked is
    withheld.
    """
    kind = node.get("type") if isinstance(node, dict) else None
    e2ee = at == "to_device.events[]" and isinstance(kind, str) and kind in _E2EE_TO_DEVICE
    cipher_level = at == "e2ee.content"
    if isinstance(node, list):
        slots: Any = enumerate(node)
        events = 0
    elif isinstance(node, dict):
        events = _rebuild_room_event(node)
        for key in [k for k in node if not _token(str(k), sealed=sealed)]:
            del node[key]
        slots = node.items()
    else:
        return 0
    # A list element must look like an identifier: ["ignore!", "your",
    # "rules."] is a sentence one element at a time, and every list Matrix
    # sends (user, room and event IDs, aliases) carries a sigil.
    in_list = isinstance(node, list) and not sealed
    for key, value in slots:
        long_ok = sealed or (cipher_level and key in _CIPHER_KEYS)
        if (key in _PROSE_FIELDS and not sealed) or (
            isinstance(value, str)
            and (not _token(value, sealed=long_ok) or (in_list and not _id_like(value)))
        ):
            node[key] = WITHHELD
        elif isinstance(value, str):
            continue
        elif depth >= _MAX_WALK_DEPTH and isinstance(value, (dict, list)):
            node[key] = WITHHELD
        else:
            step = (
                "e2ee.content"
                if e2ee and key == "content"
                else f"{at}[]"
                if at == "to_device.events"
                else _PATH_STEPS.get((at, key), "")
            )
            events += _withhold_events(value, depth + 1, at=step, sealed=long_ok)
    return events


def _respond(
    payload: Any,
    body: bytes,
    headers: dict[str, str],
    content_type: str,
    warning: dict[str, Any] | None,
    *,
    withhold: bool = False,
) -> Response:
    """Forward the upstream bytes, re-serialising only to attach a warning.

    The delivered content is the upstream buffer. The only thing this proxy
    adds is the `_trentina_warning` key, and only when there is something to
    say — so a response with nothing to report is byte-identical to what the
    homeserver sent. ``withhold`` is the exception: an unjudged response's
    events are rewritten first (``_withhold_events``), or, when there is no
    JSON object to rewrite, nothing is forwarded at all.
    """
    if withhold:
        if not isinstance(payload, dict):
            return _refused()
        warning = {**(warning or {}), "withheld_events": _withhold_events(payload)}
    if warning is not None and isinstance(payload, dict):
        payload[WARNING_KEY] = warning
        body = json.dumps(payload).encode("utf-8")
    return Response(content=body, status_code=200, headers=headers, media_type=content_type)


async def _text_fallback_scan(body: bytes, profile: Profile, path: str) -> bool:
    """Judge unparseable response bytes as plain text; record any flag.

    The annotation channel is gone (no JSON to attach a key to), so the flag
    lives in the detections table and the log — degraded, but never the
    silent clean the recursive-parse fail-open used to produce. Returns whether
    the text was flagged, so the caller can carry it onto the audit row.
    """
    judgement = await judge_matrix_text_fallback(
        body, profile=profile, source=f"matrix:{profile.name}:{path}"
    )
    if judgement.flagged:
        logger.error(
            "matrix_proxy: UNPARSEABLE response FLAGGED for profile=%s "
            "path=%s risk=%s — forwarded (no annotation channel); "
            "investigate the sender",
            profile.name,
            redact_source(path),
            judgement.risk,
        )
    return judgement.flagged
