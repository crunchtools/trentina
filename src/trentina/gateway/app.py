"""Starlette routes for the gateway endpoint family.

Phase 2: Streamable HTTP transport with session persistence.

``POST /gateway/{profile}/mcp`` handles JSON-RPC requests, optionally
returning an SSE stream when the ``Accept`` header includes
``text/event-stream``.  A new session is created on ``initialize`` and
tracked via the ``Mcp-Session-Id`` response header.

``GET /gateway/{profile}/mcp`` opens an SSE stream for server-initiated
notifications (e.g. ``tools/list_changed`` on circuit breaker state changes).

``DELETE /gateway/{profile}/mcp`` tears down a session.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from ..httpbody import STATUS_TOO_LARGE, RequestBodyCap, TooLargeError
from ..logsafe import exc_kind, exc_where, redact_source, safe_address
from ..perimeter_db import count_pending_pins
from ..quarantine.classifier import classifier_status
from ..transports.jsonrpc import JSONRPC_INTERNAL_ERROR
from ..transports.mcp import route_jsonrpc
from .auth import verify_bearer, verify_edge_jwt_header, verify_oauth
from .context import current_caller, current_session, session_fingerprint
from .errors import (
    AuthError,
    BackendCallError,
    GatewayError,
    OAuthForbiddenError,
    ProfileNotFoundError,
)
from .google_verifier import token_digest
from .matrix_bridge.routes import media_refused, outbound_refused
from .sessions import SessionRegistry, session_registry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

MCP_SESSION_ID_HEADER = "mcp-session-id"

SSE_KEEPALIVE_SECONDS = 25.0
"""Idle gap between keepalive frames. Under common proxy/gateway idle
timeouts (~60s) so quiet connections don't hit 504 upstream-timeout drops."""

SSE_RETRY_MS = 15000
"""Reconnect hint (ms) sent on stream open. Standard SSE clients honour
``retry:`` and back off at the protocol layer, bypassing app-level retry caps."""

STATUS_ACCEPTED = 202
"""Streamable HTTP's answer to a notification: accepted, no body."""


@dataclass(frozen=True)
class DelegatedAuth:
    """One profile's delegation to an external authorization server.

    In this mode Trentina is a pure resource server: it never issues a token
    for the profile, it names ``issuer`` in the profile's RFC 9728 document,
    and the client authenticates straight to that issuer. ``verifier`` checks
    the token that comes back and ``scopes`` is what the document advertises.
    """

    issuer: str
    scopes: tuple[str, ...]
    verifier: Any


@dataclass(frozen=True)
class OAuthContext:
    """What the gateway needs to enforce and advertise Google-backed OAuth.

    ``provider`` is the FastMCP OAuth provider (a ``GoogleProvider``/
    ``OAuthProxy``) that validates presented tokens; ``base_url`` is the public
    origin (no trailing slash) used to build the RFC 9728 resource-metadata URL
    in the 401 challenge. ``issuer`` is the authorization-server identifier the
    provider advertises as ``issuer`` in its own ``/.well-known/oauth-authorization-server``
    document — captured byte-for-byte so our protected-resource metadata names
    the AS with the *exact* same string. FastMCP renders the issuer through a
    pydantic ``AnyHttpUrl``, which appends a trailing slash to a bare-authority
    origin (``https://host`` -> ``https://host/``); RFC 8414 §3.3 requires the
    client to find ``issuer`` identical to the AS identifier it discovered, so a
    protected-resource doc naming ``https://host`` (no slash) against an AS
    issuer of ``https://host/`` is rejected as non-conformant — which is what
    made gemini.google.com report "automatic registration failed" without ever
    POSTing to ``/register``. Built once at startup and threaded into the
    handlers; None on a gateway with no OAuth-enabled profile.

    ``scopes`` is the scope list the provider advertises as ``scopes_supported``
    in its own AS metadata — the *normalized* form (GoogleProvider expands the
    ``email``/``profile`` shorthands to their full ``googleapis.com`` URIs). Our
    protected-resource document must advertise the identical list: a client that
    reads short names here but sees full URIs at the AS (or vice versa) can
    request a scope the AS does not recognize and fail authorization. Captured
    from the provider so the two documents never drift.

    ``delegated`` names the profiles that do NOT use the proxy at all: each
    entry carries the external issuer we advertise for that profile and the
    verifier for tokens that issuer minted. It is a map rather than a separate
    per-profile context because this object is threaded positionally through
    every handler and both metadata registration sites; keeping one container
    means both the 401 path and the metadata document read the same answer to
    "which authorization server is authoritative here", which is the drift this
    docstring already exists to prevent.

    ``provider`` and ``issuer`` are None on a gateway where every OAuth profile
    is delegated: there is no proxy to build, no upstream Google credentials to
    require, and no ``/authorize`` or ``/token`` to mount.
    """

    provider: Any | None
    base_url: str
    issuer: str | None
    scopes: tuple[str, ...]
    delegated: Mapping[str, DelegatedAuth] = field(default_factory=dict)

    def verifier_for(self, profile_name: str) -> Any | None:
        """The thing that validates a token presented to this profile.

        Both modes expose ``async verify_token(token) -> AccessToken | None``
        (fastmcp's ``OAuthProvider.verify_token`` just forwards to
        ``load_access_token``), so the caller never branches on mode.
        """
        entry = self.delegated.get(profile_name)
        if entry is not None:
            return entry.verifier
        return self.provider

    def metadata_for(self, profile_name: str) -> tuple[str, tuple[str, ...]] | None:
        """The (issuer, scopes) this profile's RFC 9728 document advertises.

        None when the profile is proxy-mode on a gateway that has no proxy —
        the document must 404 rather than advertise a null authorization server.
        """
        entry = self.delegated.get(profile_name)
        if entry is not None:
            return entry.issuer, entry.scopes
        if self.issuer is None:
            return None
        return self.issuer, self.scopes


async def _authorize(
    request: Request,
    profile: Profile,
    oauth: OAuthContext | None,
) -> Response | None:
    """Authorize one request against a profile. Return None if allowed.

    Static bearer is tried first and, on success, nothing else runs — every
    existing profile behaves exactly as before. Only when the static token does
    not match AND the profile opted into OAuth does the OAuth path run, so an
    OAuth failure never masks a plain static-token typo for a static profile.

    On failure returns the response to send: a bare 401 for a static-only
    profile (unchanged), a 401 carrying a ``WWW-Authenticate`` challenge for an
    OAuth-enabled profile with no usable token, or a 403 when a valid Google
    identity is simply not on the allowlist.
    """
    auth_header = request.headers.get("authorization")
    if _static_bearer_ok(auth_header, profile):
        return None

    # A federated peer's edge JWT (#592, C1), for a federation-ingress profile.
    # Only engages when the profile has federation.peers; a bad edge token is
    # fail-closed (401), never a fall-through.
    try:
        caller = verify_edge_jwt_header(auth_header, profile)
        if caller is not None:
            # The real caller (peer, sub), carried one hop on request.state and
            # bound to current_caller beside current_session (#592, C2), so the
            # audit records who really called through the federation profile.
            request.state.federation_caller = caller
            return None
    except AuthError:
        # The reason is always the fixed literal "invalid edge token", so there
        # is nothing to log beyond that it failed (no exc text — O8/#262).
        logger.info(
            "gateway: edge auth failed profile=%s [%s]", profile.name, _client_desc(request)
        )
        return _plain(401, "Unauthorized")

    if profile.oauth is not None and profile.oauth.enabled:
        # A bearer was presented if the header parses as one, whether or not it
        # turns out to be valid. RFC 6750 §3.1 lets us say `invalid_token` only
        # in that case -- a request carrying no credential at all must get a
        # bare challenge, because there is nothing yet to call invalid.
        presented = _bearer_presented(auth_header)
        try:
            access = await verify_oauth(
                auth_header,
                profile,
                oauth.verifier_for(profile.name) if oauth is not None else None,
            )
        except OAuthForbiddenError as exc:
            logger.info(  # logsafe: ours — auth.py raises only fixed literals
                "gateway: oauth forbidden profile=%s reason=%s [%s]",
                profile.name,
                exc,
                _client_desc(request),
            )
            return _plain(403, "Forbidden")
        except AuthError as exc:
            logger.info(  # logsafe: ours — auth.py raises only fixed literals
                "gateway: oauth challenge profile=%s reason=%s [%s]",
                profile.name,
                exc,
                _client_desc(request),
            )
            return _oauth_challenge(profile.name, oauth, invalid_token=presented)
        else:
            _log_oauth_success(profile, access)
            return None

    logger.info("gateway: auth failed profile=%s", profile.name)
    return _plain(401, "Unauthorized")


def _bearer_presented(authorization_header: str | None) -> bool:
    """True when the request carried something shaped like a bearer token.

    Separates "you sent a credential and it was refused" from "you sent no
    credential", which is the distinction RFC 6750 §3.1 draws for whether the
    challenge may carry an error code.
    """
    if not authorization_header:
        return False
    scheme, _, value = authorization_header.partition(" ")
    return scheme.lower() == "bearer" and bool(value)


def _log_oauth_success(profile: Profile, access: Any) -> None:
    """Record who was let in, at INFO, without recording their token.

    A refused request already logs a reason; an accepted one logged nothing at
    all, so there was no way to answer "which identity used this profile" after
    the fact. The token appears only as a digest prefix.
    """
    claims = getattr(access, "claims", None) or {}
    token = getattr(access, "token", "") or ""
    logger.info(
        "gateway: oauth ok profile=%s sub=%s email=%s aud=%s token=%s…",
        profile.name,
        claims.get("sub"),
        claims.get("email"),
        claims.get("aud"),
        token_digest(token)[:8] if token else "?",
    )


def _static_bearer_ok(authorization_header: str | None, profile: Profile) -> bool:
    """Return True iff the profile's static bearer token matches; never raises.

    A predicate over ``verify_bearer`` for the gateway's two-stage auth: a
    static-token miss is not an error here but the signal to try the OAuth path
    next, so the raised ``AuthError`` is converted to a plain False rather than
    swallowed — the decision to fall through is the recovery.
    """
    try:
        verify_bearer(authorization_header, profile)
    except AuthError:
        return False
    return True


def _oauth_challenge(
    profile_name: str,
    oauth: OAuthContext | None,
    *,
    invalid_token: bool = False,
) -> Response:
    """401 that points an MCP client at this resource's RFC 9728 metadata.

    The ``resource_metadata`` URL is where the client learns which authorization
    server to use, which is how gemini.google.com bootstraps the whole flow from
    a single unauthenticated request.

    ``invalid_token`` adds the RFC 6750 §3.1 error code, and ONLY when a bearer
    was actually presented and refused. The same section says a server SHOULD
    NOT include an error code when the request carried no authentication
    information at all, and this function serves both cases.
    """
    headers: dict[str, str] = {}
    if oauth is not None:
        metadata_url = (
            f"{oauth.base_url}/.well-known/oauth-protected-resource/gateway/{profile_name}/mcp"
        )
        challenge = f'Bearer resource_metadata="{metadata_url}"'
        if invalid_token:
            challenge += ', error="invalid_token"'
        headers["WWW-Authenticate"] = challenge
    return Response(
        content="Unauthorized",
        media_type="text/plain",
        status_code=401,
        headers=headers,
    )


def _client_desc(request: Request) -> str:
    """Identify the caller for correlating a disconnect with one client.

    Source port distinguishes concurrent clients behind the same address,
    which is what separates one agent terminal from another over a tunnel.
    The User-Agent is the client's own text, so it is fingerprinted: equal
    fingerprints still tell two clients apart (#262).
    """
    client = request.client
    peer = f"{safe_address(client.host)}:{client.port}" if client is not None else "unknown"
    agent = request.headers.get("user-agent")
    return f"peer={peer} ua={redact_source(agent) if agent else '-'}"


def gateway_app(
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
    oauth: OAuthContext | None = None,
) -> Starlette:
    """Build the Starlette sub-app exposing ``/{profile}/mcp``.

    Used by tests with Starlette's ``TestClient``.  Production deployment
    wires the same handler via ``register_with_fastmcp`` to avoid
    mount-composition issues with FastMCP's own internal routing, and adds
    the same ``RequestBodyCap`` at ``mcp_server.run`` (#267).
    """
    sr = sessions or session_registry

    async def handle_post(request: Request) -> Response:
        return await _handle_post(request, registry, sr, oauth)

    async def handle_get(request: Request) -> Response:
        return await _handle_get(request, registry, sr, oauth)

    async def handle_delete(request: Request) -> Response:
        return await _handle_delete(request, registry, sr, oauth)

    async def handle_health(_request: Request) -> Response:
        return _health_payload(registry)

    async def handle_resource_metadata(request: Request) -> Response:
        return _resource_metadata(request, registry, oauth)

    routes = [
        Route("/health", endpoint=handle_health, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource/gateway/{profile}/mcp",
            endpoint=handle_resource_metadata,
            methods=["GET"],
        ),
        Route("/{profile}/mcp", endpoint=handle_post, methods=["POST"]),
        Route("/{profile}/mcp", endpoint=handle_get, methods=["GET"]),
        Route("/{profile}/mcp", endpoint=handle_delete, methods=["DELETE"]),
    ]
    return Starlette(
        routes=routes, middleware=[Middleware(RequestBodyCap, applies=_is_profile_mcp_path)]
    )


def _is_profile_mcp_path(path: str) -> bool:
    """``/<profile>/mcp``: this sub-app's MCP route, which has no ``/gateway`` prefix."""
    parts = (path.rstrip("/") or "/").split("/")
    return len(parts) == 3 and parts[2] == "mcp" and bool(parts[1])


def _resource_metadata(
    request: Request,
    registry: dict[str, Profile],
    oauth: OAuthContext | None,
) -> Response:
    """Serve RFC 9728 protected-resource metadata for one gateway profile.

    FastMCP registers this document only for its own MCP mount path, never for
    the gateway's ``/gateway/{profile}/mcp`` routes, so the gateway serves its
    own — naming itself as the authorization server the client should use. Only
    OAuth-enabled profiles have one; everything else is a 404.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if oauth is None or profile is None or profile.oauth is None or not profile.oauth.enabled:
        return _plain(404, "Not Found")
    # Delegated profiles name their external issuer here; proxy profiles name
    # us. Both come from one place so the 401 challenge and this document can
    # never disagree about which AS is authoritative.
    advertised = oauth.metadata_for(profile_name)
    if advertised is None:
        logger.warning(
            "gateway: no authorization server to advertise for profile=%s",
            profile_name,
        )
        return _plain(404, "Not Found")
    issuer, scopes = advertised
    return JSONResponse(
        {
            "resource": f"{oauth.base_url}/gateway/{profile_name}/mcp",
            # The AS identifier must match what the client discovers byte-for-byte
            # (trailing slash included) or RFC 8414 §3.3 makes a strict client
            # reject it — see the OAuthContext docstring. For a delegated profile
            # that string is the external issuer, stored verbatim.
            "authorization_servers": [issuer],
            # Normalized to full googleapis URIs, not the shorthand — the two
            # discovery documents must name the same scope strings or a strict
            # client requests a scope the AS rejects.
            "scopes_supported": list(scopes),
            "bearer_methods_supported": ["header"],
        }
    )


def _health_payload(registry: dict[str, Profile]) -> Response:
    """Build the liveness response.

    The value here is not the body but the fact that it is served at all:
    the handler runs on the event loop, so a timeout means the loop is
    blocked.  During the 2026-08-22 incident an unbounded classifier scan
    wedged the loop for 90 minutes with no way to detect it from outside.
    """
    body: dict[str, Any] = {
        "status": "ok",
        "classifier": classifier_status(),
        "profiles": len(registry),
        # Tools held pending operator approval, gateway-wide (#592, E1c): a
        # number Nagios can alert on. Summed like the fields below, so the
        # unauthenticated probe names no profile; which backend holds what is in
        # the tool_pins operator tool.
        "pending_pins": count_pending_pins(),
    }
    # Summed, so the unauthenticated probe names no profile; which one is
    # in quarantine_stats' gateway_audit (backend matrix_bridge, #317).
    refused = outbound_refused()
    if refused is not None:
        body["matrix_bridge"] = {"outbound_refused": refused, "media_refused": media_refused()}
    return JSONResponse(body)


def register_with_fastmcp(
    mcp_server: Any,
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
    oauth: OAuthContext | None = None,
) -> None:
    """Wire gateway routes onto a FastMCP server via its custom_route decorator."""
    sr = sessions or session_registry

    @mcp_server.custom_route("/health", methods=["GET"])  # type: ignore[untyped-decorator]
    async def health_endpoint(_request: Request) -> Response:
        return _health_payload(registry)

    if oauth is not None:

        @mcp_server.custom_route(  # type: ignore[untyped-decorator]
            "/.well-known/oauth-protected-resource/gateway/{profile}/mcp",
            methods=["GET"],
        )
        async def resource_metadata_endpoint(request: Request) -> Response:
            return _resource_metadata(request, registry, oauth)

    @mcp_server.custom_route("/gateway/{profile}/mcp", methods=["POST", "GET", "DELETE"])  # type: ignore[untyped-decorator]
    async def gateway_endpoint(request: Request) -> Response:
        if request.method == "GET":
            return await _handle_get(request, registry, sr, oauth)
        if request.method == "DELETE":
            return await _handle_delete(request, registry, sr, oauth)
        return await _handle_post(request, registry, sr, oauth)


async def _handle_get(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
    oauth: OAuthContext | None = None,
) -> Response:
    """Open a long-lived SSE stream for server-push notifications.

    Requires a valid ``Mcp-Session-Id`` header.  The stream stays open
    until the client disconnects; ``notifications/tools/list_changed`` frames
    are delivered when circuit breaker state affects this session's profile
    (see :meth:`SessionRegistry.broadcast_tools_changed`).  Keepalive comment
    frames are interleaved during idle periods to hold the socket open.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        # 405, not 400. The streamable-HTTP spec reserves 405 for "this server
        # does not offer a standalone SSE stream here", which is exactly what a
        # GET with no session is asking for and not getting. A 400 says the
        # client sent something malformed, which sends whoever reads it looking
        # for a bug that is not there. Gemini's connector probes with HEAD and
        # GET and proceeds either way, so nothing depended on the old code — a
        # stricter client may. `Allow` is required on a 405 (RFC 9110 15.5.6).
        return _plain(
            405,
            "Method Not Allowed: no standalone SSE stream without an Mcp-Session-Id header",
            headers={"Allow": "POST, DELETE"},
        )

    session = sessions.get_session(session_id)
    if session is None:
        logger.warning(
            "gateway: SSE stream rejected — session=%s profile=%s not found: %s [%s]",
            redact_source(session_id),
            profile_name,
            sessions.explain_missing(session_id, profile_name),
            _client_desc(request),
        )
        return _session_gone(sessions, session_id, profile_name, None)

    if session.profile_name != profile_name:
        return _plain(403, "Session does not belong to this profile")

    logger.info(
        "gateway: SSE stream opened session=%s profile=%s [%s]",
        session_id[:8],
        profile_name,
        _client_desc(request),
    )
    return StreamingResponse(
        _sse_event_stream(sessions, session_id),
        media_type="text/event-stream",
        headers={
            MCP_SESSION_ID_HEADER: session_id,
            "Cache-Control": "no-cache",
        },
    )


async def _sse_event_stream(
    sessions: SessionRegistry,
    session_id: str,
    keepalive_seconds: float = SSE_KEEPALIVE_SECONDS,
) -> AsyncIterator[str]:
    """Yield SSE frames for one server-push stream.

    Subscribes a notification queue for ``session_id`` and drains it as
    MCP-compliant ``event: message`` frames.  When no notification arrives
    within ``keepalive_seconds``, emits a comment keepalive instead.  Always
    deregisters the queue on disconnect (``CancelledError``) or exit.

    Each keepalive tick doubles as a liveness check: once the session is gone
    the stream closes rather than sending keepalives forever to a session the
    registry has already dropped.

    The ``retry:`` reconnect hint is emitted before any data so it is set
    even if the client reconnects immediately.
    """
    queue = sessions.subscribe(session_id)
    try:
        yield f"retry: {SSE_RETRY_MS}\n\n"
        while True:
            try:
                notification = await asyncio.wait_for(queue.get(), timeout=keepalive_seconds)
            except TimeoutError:
                if not sessions.is_active(session_id):
                    return
                yield ": keepalive\n\n"
                continue
            yield f"event: message\ndata: {json.dumps(notification)}\n\n"
    except asyncio.CancelledError:
        return
    finally:
        sessions.unsubscribe(session_id, queue)


async def _handle_delete(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
    oauth: OAuthContext | None = None,
) -> Response:
    """Tear down an MCP session."""
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        return _plain(400, "Bad Request: missing Mcp-Session-Id header")

    session = sessions.get_session(session_id)
    if session is None:
        logger.warning(
            "gateway: DELETE rejected — session=%s profile=%s not found: %s [%s]",
            redact_source(session_id),
            profile_name,
            sessions.explain_missing(session_id, profile_name),
            _client_desc(request),
        )
        return _session_gone(sessions, session_id, profile_name, None)

    if session.profile_name != profile_name:
        return _plain(403, "Session does not belong to this profile")

    sessions.delete_session(session_id)
    logger.info("gateway: session %s deleted for profile=%s", session_id[:8], profile_name)
    return Response(status_code=204)


async def _handle_post(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
    oauth: OAuthContext | None = None,
) -> Response:
    """Authenticate, parse, dispatch, and return one gateway JSON-RPC request.

    On ``initialize``, creates a new session and returns the
    ``Mcp-Session-Id`` header.  Subsequent requests may include the
    session header for tracking; omitting it falls back to stateless
    mode for backwards compatibility.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        logger.info("gateway: unknown profile %s", redact_source(profile_name))
        return _plain(404, "Not Found")

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    try:
        # Read through RequestBodyCap's counting receive, AFTER authentication,
        # so an unauthenticated caller costs no body memory (#267).
        body_bytes = await request.body()
    except TooLargeError:
        return _plain(STATUS_TOO_LARGE, "Request body too large")
    except Exception as exc:
        # Same reasoning as alert_ingress: 400 is correct for every cause, but
        # discarding the cause loses the only signal that separates a flaky
        # client from someone probing the gateway. The kind, not the message.
        logger.warning(
            "gateway: could not read request body profile=%s: %s",
            profile_name,
            exc_kind(exc),
        )
        return _plain(400, "Bad Request: cannot read body")

    if not body_bytes:
        return _plain(400, "Bad Request: empty body")

    try:
        body: Any = json.loads(body_bytes)
    except json.JSONDecodeError:
        return _plain(400, "Bad Request: body is not valid JSON")

    if not isinstance(body, dict):
        return _plain(400, "Bad Request: JSON-RPC body must be an object")

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if session_id:
        session = sessions.get_session(session_id)
        if session is None and body.get("method") == "initialize":
            # A client re-initializing is doing exactly what the 404 asked
            # of it; a stale header left on that request is not a reason to
            # refuse the recovery (#104). It gets a fresh session below.
            logger.warning(
                "gateway: re-initialize over stale session=%s profile=%s: %s [%s]",
                redact_source(session_id),
                profile_name,
                sessions.explain_missing(session_id, profile_name),
                _client_desc(request),
            )
            session_id = ""
        elif session is None:
            logger.warning(
                "gateway: DISCONNECT — session=%s profile=%s rejected on "
                "method=%s: %s [%s] active=%d",
                redact_source(session_id),
                profile_name,
                redact_source(body.get("method", "")),
                sessions.explain_missing(session_id, profile_name),
                _client_desc(request),
                sessions.active(profile_name),
            )
            return _session_gone(sessions, session_id, profile_name, body.get("id"))
        elif session is not None and session.profile_name != profile_name:
            return _plain(403, "Session does not belong to this profile")

    # Each request is its own task, so the binding ends with it. The id is a
    # bearer of the session: only its fingerprint reaches the audit.
    current_session.set(session_fingerprint(session_id))
    # Unconditionally, from this request's own state (#592, C2): a federated
    # request carries (peer, sub); every other — including a static-bearer call
    # to a federation profile — lands None, never a value left by a reused task.
    current_caller.set(getattr(request.state, "federation_caller", None))
    try:
        response = await route_jsonrpc(profile, body)
    except ProfileNotFoundError:
        return _plain(404, "Not Found")
    except BackendCallError as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": str(exc)},
            },
            status_code=502,
        )
    except GatewayError as exc:
        # Where, not what: the message can carry the caller's arguments (#262).
        logger.error(
            "gateway: unexpected gateway error profile=%s: %s at %s",
            profile_name,
            exc_kind(exc),
            exc_where(exc),
        )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": "Internal gateway error"},
            },
            status_code=500,
        )
    except Exception as exc:
        logger.error(
            "gateway: unhandled error profile=%s: %s at %s",
            profile_name,
            exc_kind(exc),
            exc_where(exc),
        )
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": "Internal error"},
            },
            status_code=500,
        )

    headers: dict[str, str] = {}
    method = body.get("method", "")
    if method == "initialize":
        new_session_id = sessions.create_session(profile_name)
        headers[MCP_SESSION_ID_HEADER] = new_session_id
        logger.info(
            "gateway: initialize session=%s profile=%s [%s]",
            new_session_id[:8],
            profile_name,
            _client_desc(request),
        )
    elif session_id:
        headers[MCP_SESSION_ID_HEADER] = session_id

    if "id" not in body:
        # A notification gets 202 and no body (streamable HTTP). The TypeScript
        # SDK opens the standalone SSE stream only on a 202 to
        # notifications/initialized; a 200 left Claude Code with no stream, so
        # reload_profiles reached none of its sessions.
        return Response(status_code=STATUS_ACCEPTED, headers=headers)
    return JSONResponse(response, headers=headers)


JSONRPC_SESSION_NOT_FOUND = -32001
"""The code the TypeScript MCP SDK's own server sends with this 404.

Clients recognize an expired session by the 404 status, not by the body.
Claude Code re-initializes on a 404 to a POST, and deliberately does not on a
404 to the SSE GET. So the body is for whoever reads it next: a JSON-RPC
error, like both reference SDKs send, rather than a bare text line.
"""


def _session_gone(
    sessions: SessionRegistry, session_id: str, profile_name: str, req_id: Any
) -> JSONResponse:
    """404 for a session this gateway no longer holds, saying why and what to do.

    The explanation is scoped to the caller (#137): a session that belonged to
    another profile reads as one this process never issued.
    """
    why = sessions.explain_missing(session_id, profile_name)
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": JSONRPC_SESSION_NOT_FOUND,
                "message": (
                    f"Session not found: {why}. Re-initialize without an "
                    "Mcp-Session-Id header to start a new session."
                ),
            },
        },
        status_code=404,
    )


def _plain(status: int, text: str, *, headers: dict[str, str] | None = None) -> Response:
    """Build a plain-text response with the given status code."""
    return Response(
        content=text,
        media_type="text/plain",
        status_code=status,
        headers=headers,
    )
