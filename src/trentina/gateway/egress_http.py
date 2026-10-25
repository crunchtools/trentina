"""Terminating HTTP(S) egress (#511): judge an agent's outbound request, then
re-originate it to a named upstream, on the main port alongside ``/llm`` and
``/git``.

    /egress/{upstream}/{path}

What it decides, in order, each one deterministic:

- **who is calling**: the gateway bearer token, as on ``/llm`` and ``/git``.
  None of the caller's own credentials go upstream; the profile's token for the
  upstream is injected, so the agent never holds it.
- **which upstream and path**: a configured ``egress_upstreams`` name the
  profile was granted, and a path matched against the grant. The URL is built
  from the operator's origin and that path — never from anything the caller
  sent as a host. This is a reverse proxy to named destinations, not a
  proxy-to-anywhere.
- **what the request carries**: method, path, query, forwarded headers and body
  cross ``defend()`` as one document (``judge_outbound``), with a credential
  detector over the same document. Under ``block`` a credential, a flag or a
  blocking gap refuses before anything is sent — nothing executed. Under
  ``flag`` it is forwarded with the verdict on ``x-trentina-warning``.
- **its intent** (optional, ``block`` only): when the profile's
  ``guarded_execution`` names this upstream, the request — already past the
  layers — is handed to the profile's judge, with the gateway's own facts (the
  destination, whether the profile has reached it before, whether the session
  was flagged), and anything but an explicit allow refuses before it is sent
  (``gatekeeper``, ``gateway/gatekeeper.py``).
- **where it goes**: through the egress guard, to an address that was checked;
  no redirect is followed.
- **what comes back**: the response is untrusted content the agent will ingest,
  so it is judged like the ``fetch`` tool (``egress_response``) — buffered,
  judged, delivered or refused. A refusal here is "executed, response withheld"
  (#425): the request was sent.

One ``gateway_calls`` row per request. A terminating judged proxy buffers and
judges the whole response: it cannot hand the agent bytes it has not read, so
byte-for-byte streaming (an SSE relay) is incompatible with judge-before-deliver
and stays out of scope — that is the tunnel's territory (known gap 26). A
response past the admission cap is refused ``too_large`` (executed) rather than
split into judged parts; the raw-HTTP caller has no ``read_part`` channel, so
response paging is a documented limit, not a planned slice.
"""

from __future__ import annotations

import asyncio
import json
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import httpx
from starlette.requests import ClientDisconnect
from starlette.responses import Response

from .. import logsafe
from ..defense import Provenance, defend
from ..egress import open_pinned
from ..errors import EgressRefusedError as GuardRefusedError
from ..modes import Mode, gaps_of
from ..outcomes import Outcome
from .auth import resolve_profile_by_token
from .backend import response_byte_cap
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, Destination, DestinationKind, fingerprint
from .egress_policy import (
    EgressRefusedError,
    build_url,
    forward_request_headers,
    request_document,
    response_headers,
)
from .gatekeeper import judge_egress
from .ingress_defense import effective_mode
from .loader import get_active_config
from .outbound import (
    REASON_CREDENTIAL,
    REASON_FLAGGED,
    REASON_UNJUDGED,
    body_text,
    judge_input,
    judge_outbound,
)
from .proxy_utils import PLAIN_TEXT, normalize_proxy_path
from .relay import MAX_OPERATIONS_PER_PROFILE, NO_OPERATION, Operation, Slots
from .upstream import RESOLVER_BUSY, checked_target

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager

    from starlette.requests import Request

    from .profile import EgressGrant, EgressUpstream, Profile

logger = logging.getLogger(__name__)

ROUTE = "/egress/{upstream}/{path:path}"
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
BACKEND_PREFIX = "egress"
JSON = "application/json"
WARNING_HEADER = "x-trentina-warning"
REASON_HEADER = "X-Trentina-Reason"

IDLE_TIMEOUT = 300.0
JUDGE_DEADLINE = 60.0

_SLOTS = Slots(MAX_OPERATIONS_PER_PROFILE)

#: The audit outcome for each refusal reason — keyed on the reason, not on
#: whether the request executed: a timeout is a backend error, not a defense
#: block, however far the request got.
_OUTCOME_OF: dict[str, Outcome] = {
    "unauthorized": Outcome.DENIED_GUARD,
    "unknown_upstream": Outcome.DENIED_ALLOWLIST,
    "method_not_listed": Outcome.DENIED_ALLOWLIST,
    "path_not_listed": Outcome.DENIED_ALLOWLIST,
    "bad_path": Outcome.DENIED_GUARD,
    "too_large": Outcome.DENIED_GUARD,
    "malformed_body": Outcome.DENIED_GUARD,
    "not_json": Outcome.DENIED_GUARD,
    "binary_body": Outcome.BLOCKED_DEFENSE,
    "busy": Outcome.DENIED_GUARD,
    "resolver_busy": Outcome.DENIED_GUARD,
    "denied_guard": Outcome.BLOCKED_DEFENSE,
    "redirect": Outcome.BACKEND_ERROR,
    "upstream_failed": Outcome.BACKEND_ERROR,
    "upstream_idle": Outcome.BACKEND_ERROR,
    "upstream_status": Outcome.TOOL_ERROR,
    "credential_in_request": Outcome.BLOCKED_DEFENSE,
    "flagged": Outcome.BLOCKED_DEFENSE,
    "not_fully_judged": Outcome.BLOCKED_DEFENSE,
    "gatekeeper": Outcome.DENIED_GATEKEEPER,
    "response_flagged": Outcome.BLOCKED_DEFENSE,
    "response_unjudged": Outcome.BLOCKED_DEFENSE,
    "response_binary": Outcome.BLOCKED_DEFENSE,
}


def register_egress_routes(
    mcp_server: Any, upstreams: dict[str, EgressUpstream], profiles: dict[str, Profile]
) -> None:
    """Wire ``/egress/{upstream}/{path}`` onto the FastMCP server, if any upstream exists.

    With no ``egress_upstreams`` at startup there is no route. The upstreams and
    every profile's ``egress_http`` are read from the active config per request,
    so once the route exists an operator reload applies an edit in place.
    """
    if not upstreams:
        return

    async def egress_endpoint(request: Request) -> Response:
        return await serve(request, profiles)

    mcp_server.custom_route(ROUTE, methods=METHODS)(egress_endpoint)
    logger.info("egress: registered /egress/{upstream}/{path}")


async def serve(request: Request, profiles: dict[str, Profile]) -> Response:
    """Answer one egress request: resolve the caller, then carry it or refuse it.

    A token that matches no profile gets 401 and no audit row — a row belongs to
    a profile, and writing one for an unknown caller would let anyone who can
    reach the port fill the audit database.
    """
    # TRUST: an agent's outbound HTTP request, to a destination the operator named
    #   untrusted: upstream name, path, query, headers and body, all agent-chosen
    #   judged-by: EgressGrant (method/path), judge_outbound (L1/L2/L3 + credential
    #     detector over the request), egress (resolved address), defend (response)
    #   on-failure: fail-closed; refused with a closed reason and audited
    #   owner: gateway/egress_http.py, gateway/egress_policy.py
    #   evidence: T3 this module's docstring; T4 tests/test_egress_http.py
    profile = resolve_profile_by_token(request.headers.get("authorization"), profiles)
    if profile is None:
        logger.warning("egress: refused a caller whose token matches no profile")
        return Response(content="unauthorized\n", status_code=401, media_type=PLAIN_TEXT)
    op = Operation(
        profile,
        backend=f"{BACKEND_PREFIX}:{NO_OPERATION}",
        tool=request.method,
        destination_kind=DestinationKind.EGRESS,
    )
    try:
        return await _carry(request, op)
    except EgressRefusedError as refusal:
        # The caller-facing deny marker carries the closed ``reason``; the audit
        # row keeps the more specific ``detail`` when there is one (the
        # gatekeeper's own reason and facts), for incident reconstruction.
        op.settle(
            _OUTCOME_OF.get(refusal.reason, Outcome.DENIED_GUARD),
            refusal.detail or refusal.reason,
        )
        logger.info("egress: refused profile=%s reason=%s", profile.name, refusal.reason)
        # The deny marker, to its own caller; no payload, no L3 prose (#511).
        body: dict[str, Any] = {
            "error": {"type": "trentina_refused", "reason": refusal.reason},
            "blocked": True,
            "block_reason": refusal.reason,
            "scanner": "trentina",
        }
        if refusal.executed:
            # The request was sent; say so rather than imply it was not (#425).
            body["executed"] = True
            body["error"]["message"] = "executed by the destination, response withheld"
        return Response(
            content=json.dumps(body),
            status_code=refusal.status,
            media_type=JSON,
            headers={REASON_HEADER: refusal.reason},
        )
    except (ClientDisconnect, TimeoutError):
        op.settle(Outcome.CANCELLED)
        raise
    except Exception as exc:
        logger.error(
            "egress: failed profile=%s err=%s at %s",
            profile.name,
            logsafe.exc_kind(exc),
            logsafe.exc_where(exc),
        )
        op.settle(Outcome.GATEWAY_ERROR)
        raise
    finally:
        await op.finish()


def _unsafe_path(path: str) -> bool:
    """A decoded path that could re-split the URL or carry a control char."""
    return any(c in path for c in "?#") or any(ord(c) < 0x20 or c == "\x7f" for c in path)


def _resolve_upstream(
    request: Request, profile: Profile
) -> tuple[str, EgressUpstream, EgressGrant, str]:
    """The upstream, its config, the profile's grant and the normalized path.

    An unknown upstream and a profile with no grant for it are ONE refusal, so a
    caller cannot tell a destination it may not reach from one that does not
    exist.
    """
    name = request.path_params.get("upstream", "")
    active = get_active_config()
    upstream = active.config.egress_upstreams.get(name) if active is not None else None
    grant = profile.egress_http.get(name)
    if upstream is None or grant is None:
        raise EgressRefusedError(HTTPStatus.FORBIDDEN, "unknown_upstream")
    path = normalize_proxy_path(request.path_params.get("path", ""))
    # normalize_proxy_path handles '.'/'..'/backslash, but the path is also the
    # grant's rail: a decoded '?' or '#' (or a control char / CRLF) would let the
    # matched path and the sent path diverge — the match sees one endpoint, the
    # upstream another. Refuse them here; build_url percent-quotes the rest so
    # what was matched is byte-for-byte what is sent.
    if path is None or _unsafe_path(path):
        raise EgressRefusedError(HTTPStatus.BAD_REQUEST, "bad_path")
    denied = grant.allows(request.method, f"/{path}")
    if denied is not None:
        raise EgressRefusedError(HTTPStatus.FORBIDDEN, denied)
    return name, upstream, grant, path


async def _read_body(request: Request, upstream: EgressUpstream) -> bytes | None:
    """The whole request body, bounded and (for a json upstream) validated.

    Nothing streams until the body is read and judged. A compressed body is
    refused — what is judged must be what the destination parses.
    """
    cap = response_byte_cap()
    encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise EgressRefusedError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "malformed_body")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > cap:
        raise EgressRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > cap:
            raise EgressRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
    if not buffer:
        return None
    body = bytes(buffer)
    if upstream.body == "json":
        try:
            # Reject duplicate keys rather than silently keep the last: a
            # `{"k":"<secret>","k":"ok"}` body is a smuggling shape, and judging
            # one value while sending another is exactly the hole #511 closes.
            parsed = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
        except ValueError:
            raise EgressRefusedError(HTTPStatus.BAD_REQUEST, "not_json") from None
        # Re-serialize so the destination parses exactly the object that is judged.
        body = json.dumps(parsed, separators=(",", ":")).encode()
    return body


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen.add(key)
    return dict(pairs)


def _judged_body_text(body: bytes, upstream: EgressUpstream) -> str | None:
    """The body as the layers read it, matching what is forwarded (#511 blocker).

    A ``json`` upstream forwards the re-serialized object (already in ``body``),
    judged unescaped for L2. A ``verbatim`` upstream forwards the raw bytes, so
    they are judged raw — but only when they are valid UTF-8 text; a non-UTF-8
    (UTF-16, binary) body cannot be read by any layer as what the destination
    parses, so None is returned and the caller treats it as a binary body. What
    is judged is what is sent — never a re-dump that drops a duplicate key.
    """
    if upstream.body == "json":
        return body_text(body)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


async def _carry(request: Request, op: Operation) -> Response:
    """Admit, judge, re-originate and judge the response for one request."""
    name, upstream, grant, path = _resolve_upstream(request, op.profile)
    op.backend = f"{BACKEND_PREFIX}:{name}"
    if not op.take_slot(_SLOTS):
        raise EgressRefusedError(HTTPStatus.SERVICE_UNAVAILABLE, "busy")
    op.destination = f"{upstream.host[: MAX_DESTINATION_CHARS - 17]}#{fingerprint(path)}"

    body = await _read_body(request, upstream)
    fwd = forward_request_headers(list(request.headers.items()), upstream)
    mode = effective_mode(op.profile, Mode(grant.enforcement))

    document, warning = await _judge_request(op, request, upstream, name, path, body, fwd, mode)

    # The guarded-execution hook (#511): under block, a profile may ask its
    # judge to decide the request's intent — destination, first contact, flagged
    # session — before anything is sent. flag is the researcher grant; it never
    # reaches here. The request has not been sent, so a refusal is a plain denial.
    if document is not None and mode is Mode.BLOCK:
        await _gatekeep(op, name, request.method, document)

    # Inject the profile's credential (never judged, never logged) and send. The
    # bare token value is carried for response scrubbing: an upstream may echo it
    # with or without the prefix, and the bare value covers both.
    secret: str | None = None
    if upstream.credential is not None and grant.token is not None:
        secret = grant.token.get_secret_value()
        logsafe.hold(secret, grant.token_env or name)
        fwd[upstream.credential.header.lower()] = f"{upstream.credential.prefix}{secret}"
    url = build_url(upstream, path, request.url.query)
    return await _send_and_judge(
        op, upstream, mode, request.method, url, fwd, body, warning, secret
    )


async def _judge_request(
    op: Operation,
    request: Request,
    upstream: EgressUpstream,
    name: str,
    path: str,
    body: bytes | None,
    fwd: dict[str, str],
    mode: Mode,
) -> tuple[str | None, str | None]:
    """Judge the outbound request; raise to refuse under block, return a flag warning.

    Returns ``(document, warning)``: the request document the layers read (for
    the guarded-execution hook, ``None`` when there is no judgeable document)
    and the flag-mode warning (``None`` under block, which refuses instead).

    A non-UTF-8 verbatim body is a binary request no layer can read as the
    destination will: block refuses it. But the readable request — method, path,
    query, forwarded headers — ALWAYS crosses ``judge_outbound``; a binary body
    is left out of the judged document and identified by ``binary_unread``
    instead (the layer contract's flag-mode allowance), never used to skip
    judging the rest. Block refuses a credential, flag or gap before anything is
    sent; flag carries the finding, and a binary body, to the row.
    """
    judged_body = _judged_body_text(body, upstream) if body is not None else None
    binary_body = body is not None and judged_body is None
    if binary_body and mode is not Mode.FLAG:
        # Only flag (the researcher grant) forwards a body no layer can read;
        # block refuses it, as would redact — which egress rejects at load, so
        # the mode here is block or flag, never redact.
        raise EgressRefusedError(HTTPStatus.FORBIDDEN, "binary_body")

    # The binary body (if any) is dropped from the judged document — no layer can
    # read it — but the readable request is judged regardless of the body.
    document = request_document(
        request.method, f"/{path}", request.url.query, fwd, None if binary_body else judged_body
    )
    verdict = await judge_outbound(
        document,
        source=f"egress:{op.profile.name}:{name}",
        source_type="egress_request",
        backend=f"egress:{name}",
        profile=op.profile,
        mode=mode,
        deadline=JUDGE_DEADLINE,
    )
    if mode is Mode.BLOCK and verdict.blocks():
        reason = _request_reason(verdict.reason or REASON_UNJUDGED)
        logger.warning("egress: request blocked profile=%s reason=%s", op.profile.name, reason)
        raise EgressRefusedError(HTTPStatus.FORBIDDEN, reason)
    # flag mode from here. A finding in the readable request leads the warning
    # and the audit row (closed-set log, #262); a binary body rides as
    # binary_unread when the readable request was otherwise clean.
    warning = verdict.warning
    if verdict.warning is not None:
        op.flag_reason = _request_reason(verdict.reason or REASON_UNJUDGED)
        logger.warning(
            "egress: request %s (flag) profile=%s upstream=%s",
            verdict.warning,
            op.profile.name,
            name,
        )
    if binary_body:
        op.flag_reason = op.flag_reason or "binary_body"
        # Both signals ride the warning: the readable-request finding (if any)
        # AND binary_unread, so flag mode never silently hides that a body no
        # layer could read was delivered.
        warning = f"{warning},binary_unread" if warning else "binary_unread"
        logger.warning("egress: binary request body (flag) profile=%s", op.profile.name)
    return document, warning


async def _gatekeep(op: Operation, name: str, method: str, document: str) -> None:
    """The guarded-execution hook on a terminating-egress request (#511).

    Only the upstreams the profile's ``guarded_execution`` names are judged; a
    request to any other upstream costs nothing here. The request already
    passed the layers, so the judge decides its intent (``gatekeeper.py``), and
    anything but an explicit allow raises ``gatekeeper`` — a plain denial,
    nothing sent. The judge reads a credential-redacted, decoded copy, so no
    secret and no raw escaping reaches it.
    """
    cfg = op.profile.guarded_execution
    if cfg is None or not cfg.guards_egress(name) or op.destination is None:
        return
    refusal = await judge_egress(
        op.profile,
        cfg,
        backend=f"{BACKEND_PREFIX}:{name}",
        method=method,
        destination=Destination(op.destination, DestinationKind.EGRESS),
        document=judge_input(document),
    )
    if refusal is not None:
        logger.warning(
            "egress: gatekeeper refused profile=%s upstream=%s reason=%s",
            op.profile.name,
            name,
            refusal.reason,
        )
        # The caller sees only ``gatekeeper``; the audit keeps the judge's own
        # reason and facts (closed-enum, #262-safe), as the tool path does.
        raise EgressRefusedError(HTTPStatus.FORBIDDEN, "gatekeeper", detail=refusal.audit)


def _scrub_secret(value: str, secret: str) -> str:
    """Remove the injected credential from a response value the agent will read.

    A linear ``str.replace`` over a fixed set of forms: the raw token and its
    fully percent-encoded and JSON ``\\uXXXX``-escaped copies (both hex cases),
    the forms a mechanical encoder produces. A deliberately PARTIAL or mixed
    encoding by the (operator-named) upstream is a documented best-effort residue
    — NOT chased with a per-character regex, which backtracks on a near-match,
    and a response body is untrusted input, so that regex would be a DoS.
    Best-effort defence in depth (#511): the real protection is that the agent
    never holds the token and the upstream is operator-named; this is the belt.
    """
    forms = (
        secret,
        "".join(f"%{ord(c):02x}" for c in secret),
        "".join(f"%{ord(c):02X}" for c in secret),
        "".join(f"\\u{ord(c):04x}" for c in secret),
        "".join(f"\\u{ord(c):04X}" for c in secret),
    )
    for form in forms:
        value = value.replace(form, "[REDACTED]")
    return value


def _request_reason(code: str) -> str:
    """Map an outbound reason code to this route's closed reason set."""
    return {
        REASON_CREDENTIAL: "credential_in_request",
        REASON_FLAGGED: "flagged",
        REASON_UNJUDGED: "not_fully_judged",
    }[code]


async def _send_and_judge(
    op: Operation,
    upstream: EgressUpstream,
    mode: Mode,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    warning: str | None,
    secret: str | None,
) -> Response:
    """Send the request to a checked address and judge the response as ingress.

    The response is untrusted content the agent will ingest, so it is judged
    like the ``fetch`` tool. Under ``block`` a flagged, unjudged or unreadable
    (binary) response is withheld — the request already executed (#425). Under
    ``flag`` it is delivered with the verdict on ``x-trentina-warning``. The
    injected credential is scrubbed from a text response so an echo endpoint
    cannot hand the agent the token it never held.
    """
    raw, status, ct, hdrs = await _fetch(op, upstream, method, url, headers, body)
    op.received = len(raw)
    blocking = mode is Mode.BLOCK
    # The verdict header is ours; never let an upstream forge or echo it. And
    # an echo endpoint must not hand the agent the injected token in a header.
    hdrs.pop(WARNING_HEADER, None)
    hdrs.pop(REASON_HEADER.lower(), None)
    hdrs.pop(REASON_HEADER, None)
    if secret:
        hdrs = {k: _scrub_secret(v, secret) for k, v in hdrs.items()}

    # The response headers are delivered to the agent, so they cross the layers
    # too (the layer contract: nothing delivered unread). They are judged with
    # the body, as one document, the way the request's headers and body are.
    header_doc = "\n".join(f"{name}: {value}" for name, value in hdrs.items())
    # A NUL byte (or a non-text/absent content type) means the body is not text:
    # it is the binary_unread gap, judged by no layer.
    body_is_text = bool(raw) and _is_text(ct) and b"\x00" not in raw[:8192]
    if body_is_text:
        text = raw.decode("utf-8", errors="replace")
        if secret:
            # An echo endpoint returned our injected token — verbatim or in a
            # fully percent-/\\u-encoded copy the agent would decode: cut each
            # before the agent or the judge sees it.
            scrubbed = _scrub_secret(text, secret)
            if scrubbed != text:
                text = scrubbed
                raw = text.encode()
        document = f"{header_doc}\n\n{text}" if header_doc else text
    else:
        document = header_doc  # judge the headers even when the body is binary

    if document.strip():
        fv = await _judge_response(op, upstream, document, blocking)
        # A request-side finding (the exfil signal) is not overwritten by a
        # response one; the response finding fills in when the request was clean.
        warning = warning or fv
    if raw and not body_is_text:
        # A binary body no layer reads: the binary_unread gap (#367, gap 32).
        if blocking:
            raise EgressRefusedError(HTTPStatus.FORBIDDEN, "response_binary", executed=True)
        warning = warning or "binary_unread"

    op.settle(Outcome.OK if status < 400 else Outcome.TOOL_ERROR, op.flag_reason)
    if warning:
        hdrs[WARNING_HEADER] = warning
    return Response(content=raw, status_code=status, media_type=ct or None, headers=hdrs)


async def _judge_response(
    op: Operation, upstream: EgressUpstream, document: str, blocking: bool
) -> str | None:
    """Judge a response (its headers, and its body when text) as ingress.

    Returns a flag-mode warning, or None. Deadline- and exception-bounded like
    the request judge: a hung or failed scan is treated as unjudged (``block``
    withholds, ``flag`` warns). Under ``block`` a flagged or unjudged response
    raises — the request executed (#425).
    """
    try:
        with profile_context(op.profile):
            async with asyncio.timeout(JUDGE_DEADLINE):
                rv = await defend(
                    document,
                    source=op.destination or upstream.host,
                    source_type="egress_response",
                    defense=op.profile.defense,
                    provenance=Provenance.EXTERNAL,
                    stop_on_partial=blocking,
                    domain=upstream.host,
                )
        flagged, unjudged, risk = rv.flagged, gaps_of(rv).blocking(), rv.risk_level
    except Exception as exc:  # TimeoutError too: no verdict was reached
        logger.error(
            "egress: response scan failed profile=%s: %s at %s",
            op.profile.name,
            logsafe.exc_kind(exc),
            logsafe.exc_where(exc),
        )
        flagged, unjudged, risk = False, True, "unknown"
    if not flagged and not unjudged:
        return None
    if blocking:
        raise EgressRefusedError(
            HTTPStatus.FORBIDDEN,
            "response_flagged" if flagged else "response_unjudged",
            executed=True,
        )
    return risk if flagged else "unjudged"


async def _fetch(
    op: Operation,
    upstream: EgressUpstream,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[bytes, int, str, dict[str, str]]:
    """Send to a checked, pinned address and read the bounded response.

    A connect-phase failure is ``upstream_failed`` with nothing executed; a
    read/write timeout is ``upstream_idle`` executed (the request did go out).
    """
    cap = response_byte_cap()
    try:
        target = await checked_target(op.profile, upstream.host)
        opener: AbstractAsyncContextManager[httpx.Response] = open_pinned(
            method, url, target, idle=IDLE_TIMEOUT, headers=headers, content=body
        )
        async with opener as resp:
            if body is not None:
                op.sent = len(body)  # counted once the request is actually on the wire
            raw = await _read_response(resp, cap)
            return (
                raw,
                resp.status_code,
                resp.headers.get("content-type", ""),
                response_headers(list(resp.headers.items())),
            )
    except GuardRefusedError as exc:
        raise _from_guard(exc) from None
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        logger.warning("egress: upstream unreachable err=%s", logsafe.exc_kind(exc))
        raise EgressRefusedError(HTTPStatus.BAD_GATEWAY, "upstream_failed") from None
    except httpx.TimeoutException:
        raise EgressRefusedError(
            HTTPStatus.GATEWAY_TIMEOUT, "upstream_idle", executed=True
        ) from None
    except httpx.HTTPError as exc:
        logger.warning("egress: upstream failed err=%s", logsafe.exc_kind(exc))
        raise EgressRefusedError(HTTPStatus.BAD_GATEWAY, "upstream_failed", executed=True) from None


async def _read_response(resp: httpx.Response, cap: int) -> bytes:
    """The response body, refused past ``cap`` (executed, response withheld)."""
    buffer = bytearray()
    async for chunk in resp.aiter_raw():
        buffer.extend(chunk)
        if len(buffer) > cap:
            raise EgressRefusedError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", executed=True
            )
    return bytes(buffer)


def _is_text(content_type: str) -> bool:
    """Whether a response body is judged as text. Fail closed: a missing or
    unrecognized content type is NOT text — it is the binary_unread gap, so a
    body a layer cannot positively read is withheld under block rather than
    decoded with replacement characters and waved through."""
    ct = content_type.partition(";")[0].strip().lower()
    return (
        ct.startswith("text/")
        or ct.endswith(("+json", "+xml"))
        or ct in ("application/json", "application/xml", "application/javascript")
    )


def _from_guard(exc: GuardRefusedError) -> EgressRefusedError:
    """Map the egress guard's refusal to this route's reason and status.

    Three buckets, by whether the request reached the upstream:
    - ``resolver_busy`` is gateway load before the connection (503); nothing
      executed.
    - ``redirect`` (a 3xx) and ``encoded`` (a content-encoded body, refused
      because ``open_pinned`` sends ``Accept-Encoding: identity``) mean the
      upstream already ANSWERED — the request executed, so the response is
      withheld (502), not denied.
    - Everything else is the address rail firing BEFORE a byte leaves — a
      non-global address, an unresolvable host, a bad scheme/port: a defense
      block (403), nothing executed. The specific guard reason rides in
      ``detail`` for the audit; the caller sees only the ``denied_guard``
      bucket. This matches how ``/git`` and the CONNECT tunnel label the same
      refusals (Outcome.BLOCKED_DEFENSE), and stops the old mislabel that told
      the agent a never-sent request had "executed by the destination".
    """
    if exc.reason == RESOLVER_BUSY:
        return EgressRefusedError(HTTPStatus.SERVICE_UNAVAILABLE, "resolver_busy")
    if exc.reason == "redirect":
        return EgressRefusedError(HTTPStatus.BAD_GATEWAY, "redirect", executed=True)
    if exc.reason in ("encoded", "too_many_redirects", "downgrade"):
        return EgressRefusedError(HTTPStatus.BAD_GATEWAY, "upstream_failed", executed=True)
    return EgressRefusedError(
        HTTPStatus.FORBIDDEN, "denied_guard", executed=False, detail=exc.reason
    )
