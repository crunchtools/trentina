"""trentina: the MCP gateway between AI agents and everything they touch."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from . import logsafe

# Before anything else in this process can log (#341).
logsafe.guard()

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .gateway.app import OAuthContext
    from .gateway.circuit import CircuitBreaker
    from .gateway.loader import GatewayConfig
    from .gateway.profile import Profile
    from .gateway.sessions import SessionRegistry

__version__ = "5.0.0"

DEFAULT_PORT = 8019
DEFAULT_EGRESS_PORT = 8021
_TRUTHY = {"1", "true", "yes", "on"}
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastmcp import FastMCP


def main() -> None:
    """Entry point for trentina."""
    log_level = logsafe.configure("TRENTINA_LOG_LEVEL")
    from . import telemetry
    from .config import get_config

    telemetry.install(get_config().log_format)
    parser = argparse.ArgumentParser(
        prog="trentina",
        description="MCP gateway: injection defense, token savings, policy and auth for AI agents",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--egress-port",
        type=int,
        default=DEFAULT_EGRESS_PORT,
        help="Client-egress CONNECT listener port; served only if a profile has client_egress",
    )
    parser.add_argument(
        "--no-dbus",
        action="store_true",
        help="Disable D-Bus interface registration",
    )

    args = parser.parse_args()

    if args.transport != "stdio":
        # A network listener is a deployment; a stdio child of a desktop
        # client is not, and none of the container checks apply to it.
        from .posture import check_startup_posture

        check_startup_posture()

    from .database import get_db
    from .server import mcp

    get_db()

    if not args.no_dbus:
        from .dbus_interface import request_dbus

        # Started by the server's lifespan, on the loop that serves (#298).
        request_dbus()

    gateway_enabled = os.environ.get("TRENTINA_GATEWAY_ENABLED", "").strip().lower() in _TRUTHY

    match args.transport:
        case "stdio":
            mcp.run(transport="stdio")
        case "sse":
            mcp.run(transport="sse", host=args.host, port=args.port, log_level=log_level)
        case _:
            if gateway_enabled:
                from .gateway import client_egress

                # Where the CONNECT listener binds if a profile turns out to
                # have client_egress; the server's lifespan starts it (#442).
                client_egress.configure(args.host, args.egress_port)
                _run_with_gateway(mcp, host=args.host, port=args.port, log_level=log_level)
            else:
                mcp.run(
                    transport="streamable-http",
                    host=args.host,
                    port=args.port,
                    log_level=log_level,
                    middleware=_body_cap("/mcp"),
                )


def _register_push_ingresses(
    mcp_server: FastMCP,
    profiles: dict[str, Any],
    data_dir: Path,
    other_agents: frozenset[str] = frozenset(),
) -> None:
    """The paths content is pushed in on rather than fetched: alerts, the
    Matrix bridge, backend OAuth callbacks and the approval page. All bind at
    startup."""
    from .gateway.alert_ingress import register_alert_routes
    from .gateway.approval_routes import register_approval_routes
    from .gateway.backend_oauth import register_backend_oauth_routes
    from .gateway.matrix_bridge import register_bridge_routes

    register_alert_routes(mcp_server, profiles)
    register_bridge_routes(mcp_server, profiles, data_dir, other_agents=other_agents)
    # The return leg of a backend's OAuth flow (#479); mounted only with a key.
    register_backend_oauth_routes(mcp_server)
    # Where a person approves what an operator staged (#637). Mounted always:
    # nothing is staged at startup, and a route that appeared only once
    # something was pending would be a signal of its own.
    register_approval_routes(mcp_server)


def _register_proxies(mcp_server: FastMCP, gateway_config: GatewayConfig) -> dict[str, Any]:
    """The routes that carry an agent's own traffic out: model calls, Matrix
    and git (#453). Each binds at startup, and only if the file configures it.

    Returns:
        The enabled LLM providers, which the active config and the startup
        scrub both need.
    """
    from .gateway.egress_http import register_egress_routes
    from .gateway.git_transport import register_git_routes
    from .gateway.llm_proxy import load_llm_providers, register_llm_routes
    from .gateway.matrix_proxy import register_matrix_routes

    llm_providers = load_llm_providers(gateway_config.llm_providers)
    register_llm_routes(mcp_server, llm_providers, gateway_config.profiles)
    if gateway_config.matrix.get("enabled"):
        register_matrix_routes(
            mcp_server,
            gateway_config.profiles,
            upstream=gateway_config.matrix.get("upstream", "https://matrix-client.matrix.org"),
        )
    register_git_routes(mcp_server, gateway_config.git_remotes, gateway_config.profiles)
    register_egress_routes(mcp_server, gateway_config.egress_upstreams, gateway_config.profiles)
    return llm_providers


def _run_with_gateway(mcp_server: FastMCP, *, host: str, port: int, log_level: str) -> None:
    """Run trentina with gateway routes wired in via FastMCP's custom_route API.

    Loads profiles from TRENTINA_PROFILES_PATH and registers
    POST /gateway/{profile}/mcp endpoints on the FastMCP app. Trentina's own
    tools are bound as the in-process internal backend so profiles can surface
    them (via an ``internal://<label>`` backend) through the same gateway
    endpoint as the remote MCP backends.

    The legacy /mcp endpoint with the web-tools surface is still registered by
    mcp.run() at the same port, but Option C treats it as deprecated — consumers
    talk to the gateway only.

    Failure to load profiles is fatal — we fail closed rather than serve with
    no gateway when the operator asked for one.

    ``log_level`` is forwarded to ``mcp.run()`` so uvicorn's access/error
    loggers pick up the resolved ``TRENTINA_LOG_LEVEL``.
    """
    from .config import get_config
    from .gateway import load_profiles, register_internal_server, register_with_fastmcp
    from .gateway.backend_tokens import configure_backend_tokens
    from .gateway.circuit import breaker
    from .gateway.compress import load_compression_cache, set_profiles
    from .gateway.loader import matrix_other_agents, register_active_config
    from .gateway.service import log_service_identity
    from .gateway.sessions import session_registry

    profiles_path = Path(os.environ.get("TRENTINA_PROFILES_PATH", "/etc/trentina/profiles.yaml"))
    logger.info("gateway: loading profiles from %s", profiles_path)
    gateway_config = load_profiles(profiles_path)
    # Before _ready_to_serve scrubs the environment: the key is read once, here.
    configure_backend_tokens(gateway_config.profiles)

    session_registry.session_ttl = gateway_config.session_ttl_seconds
    session_registry.max_sessions_per_profile = gateway_config.max_sessions_per_profile
    logger.info(
        "gateway: session_ttl=%.0fs max_sessions_per_profile=%d "
        "(set gateway.session_ttl_seconds / gateway.max_sessions_per_profile "
        "in %s to change)",
        gateway_config.session_ttl_seconds,
        gateway_config.max_sessions_per_profile,
        profiles_path,
    )

    oauth_context = _build_oauth_context(gateway_config)
    if oauth_context is not None and oauth_context.provider is not None:
        # Mounts Google's authorize/token/register and the root
        # authorization-server metadata; http_app() reads this at run() time.
        # Guarded on a proxy existing: a delegated-only gateway advertising
        # itself as an AS here, while each profile's document names an external
        # one, hands a client two contradictory answers.
        mcp_server.auth = oauth_context.provider

    register_internal_server(mcp_server)
    register_with_fastmcp(
        mcp_server,
        gateway_config.profiles,
        session_registry,
        oauth_context,
    )

    _wire_circuit_notifications(breaker, session_registry, gateway_config.profiles)
    _wire_login_notifications(session_registry)

    logger.info(
        "gateway: registered %d profile(s) at /gateway/<profile>/mcp",
        len(gateway_config.profiles),
    )

    llm_providers = _register_proxies(mcp_server, gateway_config)

    # Bridge mapping stores live beside the blocklist, like perimeter.db.
    _register_push_ingresses(
        mcp_server,
        gateway_config.profiles,
        Path(get_config().db_path).parent,
        other_agents=matrix_other_agents(gateway_config.matrix),
    )

    from .gateway.backend import load_tool_list_cache
    from .gateway.verdict_cache import load_verdict_cache

    compressions = load_compression_cache()
    tool_lists = load_tool_list_cache()
    # Perimeter verdicts survive the restart that produced them. Without
    # this the first tools/list after a restart re-judges every description
    # through all three layers and times the client out.
    verdicts = load_verdict_cache()

    # WARNING, not INFO, and not because anything is wrong. Production runs
    # at TRENTINA_LOG_LEVEL=WARNING, so INFO is discarded — which meant the
    # one line that answers "did the caches load?" was invisible on the only
    # box where the question gets asked. A cold verdict cache PREDICTS a slow
    # first tools/list, and that prediction belongs in the journal before the
    # timeout, not in an SSH session after it.
    logger.warning(
        "startup: caches loaded — %d tool list(s), %d compression(s), %d perimeter verdict(s)%s",
        tool_lists,
        compressions,
        verdicts,
        ""
        if verdicts
        else " (COLD: the first tools/list will judge every tool description and may take minutes)",
    )
    set_profiles(gateway_config.profiles)
    log_service_identity(gateway_config.profiles)
    # Last, and after every route is wired: this records both the config and
    # the facts about what got wired that a later reload has to respect. See
    # tools/reload.py — without it, an edit to profiles.yaml costs a restart,
    # and a restart costs 40 minutes of re-judged tool descriptions.
    register_active_config(
        profiles_path,
        gateway_config,
        llm_providers,
        # Whether a PROXY was built, not merely whether OAuth is configured.
        # reload.py uses this to tell an operator that turning oauth on for a
        # profile needs a restart; a delegated-only gateway has no proxy, so
        # reporting True here would let a newly added proxied profile look
        # applied while every request to it 401s.
        oauth_route_registered=(oauth_context is not None and oauth_context.provider is not None),
    )

    _ready_to_serve(llm_providers)

    legacy_mcp = os.environ.get("TRENTINA_LEGACY_MCP", "").strip().lower() in _TRUTHY
    if legacy_mcp:
        logger.warning(
            "gateway: legacy /mcp endpoint ENABLED (TRENTINA_LEGACY_MCP) — it "
            "bypasses gateway auth, allowlists, and audit; migrate consumers "
            "to /gateway/<profile>/mcp and unset the variable",
        )
        mcp_path = "/mcp"
    else:
        # The legacy endpoint served Trentina's full tool surface with no
        # bearer, no allowlist, and no audit — a bypass of everything the
        # gateway enforces. FastMCP must still mount its own MCP app
        # somewhere, so it goes to a per-boot unguessable path that nothing
        # is told about, and /mcp itself answers 410 with directions.
        mcp_path = f"/mcp-internal-{secrets.token_hex(16)}"

        from starlette.responses import Response as _Response

        async def legacy_mcp_tombstone(_request: object) -> _Response:
            return _Response(
                content=(
                    "The unauthenticated /mcp endpoint is closed. Use "
                    "/gateway/<profile>/mcp with your profile's bearer token."
                ),
                status_code=410,
                media_type="text/plain",
            )

        mcp_server.custom_route("/mcp", methods=["GET", "POST", "DELETE"])(legacy_mcp_tombstone)
        logger.info("gateway: legacy /mcp closed (410); MCP app mounted internally")

    mcp_server.run(
        transport="streamable-http",
        host=host,
        port=port,
        log_level=log_level,
        path=mcp_path,
        middleware=_body_cap(mcp_path, "/mcp"),
        **_uvicorn_overrides(),
    )


def _ready_to_serve(llm_providers: Mapping[str, Any]) -> None:
    """Warm the classifier, then drop the secrets nothing reads again (#268).

    The scrub is last on purpose: everything that reads a startup-only secret
    has run by now. See ``gateway/envscrub.py`` for what goes, what stays,
    and why ``/proc/self/environ`` still holds them all.
    """
    from .gateway.envscrub import scrub_startup_secrets
    from .gateway.loader import secret_env_names
    from .posture import FILE_FORM_SECRETS, check_l2_gate, check_secret_sources

    # Before the scrub, which reads nothing back, and after every secret has
    # been read, so the names are complete.
    check_secret_sources(secret_env_names() - set(FILE_FORM_SECRETS))
    _warm_classifier()
    check_l2_gate()
    scrub_startup_secrets(provider.api_key_env for provider in llm_providers.values())


def _body_cap(*mcp_paths: str) -> list[Any]:
    """The request body cap on every MCP route, as FastMCP's ``middleware=`` (#267).

    Covers ``/gateway/<profile>/mcp`` and FastMCP's own mount, whose SDK
    handler reads the body with an unbounded ``request.body()``. Scoped by
    path so the LLM and Matrix proxies, which stream bodies through, are left
    alone. ``TRENTINA_MAX_REQUEST_BYTES`` sets it (default 1 MiB).
    """
    from starlette.middleware import Middleware

    from .httpbody import RequestBodyCap, max_request_bytes, mcp_path_matcher

    cap = max_request_bytes()
    logger.info("http: MCP request bodies capped at %d bytes", cap)
    return [Middleware(RequestBodyCap, cap=cap, applies=mcp_path_matcher(*mcp_paths))]


def _uvicorn_overrides() -> dict[str, Any]:
    """uvicorn settings the gateway pins, as kwargs for ``mcp_server.run()``.

    The rate limiter keys on ``scope["client"]``, which uvicorn rewrites from
    ``X-Forwarded-For`` only when the immediate peer is in its trusted set —
    ``127.0.0.1`` by default. In a container behind a reverse proxy the peer is
    the container network's gateway, not loopback, so without naming the proxy
    here every caller collapses onto one address and shares one bucket. That is
    what makes per-source limiting actually per-source.

    Returns nothing when ``TRENTINA_FORWARDED_ALLOW_IPS`` is unset, which
    leaves uvicorn's own default and its own ``FORWARDED_ALLOW_IPS`` handling
    exactly as they were.
    """
    forwarded = os.environ.get("TRENTINA_FORWARDED_ALLOW_IPS", "").strip()
    if not forwarded:
        return {}
    return {"uvicorn_config": {"forwarded_allow_ips": forwarded}}


_AS_METADATA_PREFIX = "/.well-known/oauth-authorization-server"

#: The one client-auth method this proxy enforces beyond "none". Named
#: rather than repeated as a literal so the advertisement in the metadata
#: and the method stored on the client can never drift apart.
_AUTH_METHOD_POST = "client_secret_post"


class _AdvertiseSecretPost:
    """ASGI wrapper that adds client_secret_post to the AS metadata document.

    FastMCP wraps the metadata handler in CORS middleware, so the route's
    endpoint is a full ASGI app rather than a request/response function — the
    body has to be intercepted on the way out. Buffering is safe here: the
    document is a few hundred bytes and is not streamed.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        start_message: dict[str, Any] | None = None
        chunks: list[bytes] = []

        async def capture(message: dict[str, Any]) -> None:
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body"):
                return
            await self._flush(start_message, b"".join(chunks), send)

        await self._inner(scope, receive, capture)

    async def _flush(self, start: dict[str, Any] | None, body: bytes, send: Any) -> None:
        """Emit the patched document, or the original when it is not ours."""
        if start is None:
            return
        try:
            document = json.loads(body)
            methods = list(document.get("token_endpoint_auth_methods_supported") or [])
            if _AUTH_METHOD_POST not in methods:
                methods.append(_AUTH_METHOD_POST)
            document["token_endpoint_auth_methods_supported"] = methods
            body = json.dumps(document).encode()
        except (ValueError, AttributeError):
            # A non-JSON body here means CORS answered a preflight or the route
            # errored; pass it through rather than turning it into a 500.
            pass

        headers = [
            (name, value)
            for name, value in start.get("headers", [])
            if name.lower() != b"content-length"
        ]
        headers.append((b"content-length", str(len(body)).encode()))
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def _advertise_secret_post(route: Any) -> Any:
    """Wrap one authorization-server metadata route; pass anything else through.

    The document is edited on the way out rather than rebuilt: FastMCP composes
    it from several options objects inside get_routes, and duplicating that
    construction here would be a second copy to keep in step on every upgrade.
    """
    from starlette.routing import Route

    if not isinstance(route, Route) or not route.path.startswith(_AS_METADATA_PREFIX):
        return route

    return Route(
        path=route.path,
        endpoint=_AdvertiseSecretPost(route.app),
        methods=list(route.methods or ["GET", "OPTIONS"]),
        name=route.name,
    )


#: One limiter per unauthenticated write path, built once and shared by every
#: request that route serves. Module-level rather than per-provider because the
#: bucket must outlive any single route object: rebuilding the limiter on a
#: route rebuild would hand a caller a fresh allowance for free.
_limiters: dict[str, Any] = {}


def _limiter(path: str) -> Any:
    """The limiter for one route path, created on first use."""
    from .gateway.ratelimit import (
        AUTHORIZE_LIMIT,
        CONSENT_LIMIT,
        REGISTER_LIMIT,
        RateLimiter,
    )

    allowances = {
        "/register": REGISTER_LIMIT,
        "/authorize": AUTHORIZE_LIMIT,
        "/consent": CONSENT_LIMIT,
    }
    existing = _limiters.get(path)
    if existing is not None:
        return existing
    capacity, per_hour = allowances[path]
    created = RateLimiter(capacity, per_hour, name=path)
    _limiters[path] = created
    return created


def _harden(route: Any, *, storage: Any) -> Any:
    """Rate-limit the unauthenticated write paths; pass everything else through.

    Applied to `/register`, `/authorize` and `/consent` only. `/token` is left
    alone deliberately: it is reached with an authorization code or a refresh
    token that this gateway itself issued, so it is not an unauthenticated
    write path, and limiting it would throttle a legitimate client's token
    refresh for no gain. The metadata documents are reads.

    Every route also gets the sweeper trigger, including the ones that are not
    limited — a flow that abandons after `/token` still leaves a transaction
    record behind, and the sweep is what removes it. See #156.
    """
    from starlette.routing import Route

    from .gateway.oauth_store import SweeperTrigger
    from .gateway.ratelimit import (
        UnauthenticatedWriteGuard,
        enabled,
        max_registration_bytes,
    )

    if not isinstance(route, Route):
        return route

    app: Any = route.app
    if route.path == "/consent":
        from .gateway.consent_ui import ConsentUsability

        # Innermost, so it sees the handler's own response — a 429 from the
        # limiter outside it is not a consent page and has nothing to patch.
        app = ConsentUsability(app)
    if enabled() and route.path in ("/register", "/authorize", "/consent"):
        app = UnauthenticatedWriteGuard(
            app,
            limiter=_limiter(route.path),
            max_body_bytes=(max_registration_bytes() if route.path == "/register" else None),
        )

    return Route(
        path=route.path,
        endpoint=SweeperTrigger(app, storage),
        methods=list(route.methods or ["GET"]),
        name=route.name,
        include_in_schema=route.include_in_schema,
    )


def _confidential_client(
    client_info: Any,
    *,
    secret: str,
    default_scope: str,
    allowed_patterns: Any,
) -> Any:
    """Rebuild a DCR registration as a confidential client, keeping its secret.

    Sits beside ``_provisioned_clients``, which builds the same record type
    from static config; this one builds it from what a client just asked for.

    The defaults are the SDK's own, restated because ``super()`` has already
    stripped the fields off the object by the time this runs: a registration
    that named no redirect URI or no grant type still needs both, and getting
    them wrong here would produce a record that authorizes nothing.
    """
    from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
    from pydantic import AnyUrl

    redirect_uris = (
        list(client_info.redirect_uris)
        if client_info.redirect_uris
        else [AnyUrl("http://localhost")]
    )
    grant_types = list(client_info.grant_types or ["authorization_code", "refresh_token"])
    return ProxyDCRClient(
        client_id=client_info.client_id,
        client_secret=secret,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        scope=client_info.scope or default_scope,
        token_endpoint_auth_method=_AUTH_METHOD_POST,
        application_type=client_info.application_type,
        allowed_redirect_uri_patterns=allowed_patterns,
        client_name=getattr(client_info, "client_name", None),
    )


def _provisioned_clients(profiles: Mapping[str, Profile], scope: str) -> dict[str, Any]:
    """Build the confidential clients declared across the OAuth profiles.

    OAuthConfig refuses a half-declared client and the loader fails closed on an
    unresolved secret, so every entry reaching here has an id, a secret and at
    least one redirect URI. Redirect URIs are registered verbatim and
    ``allowed_redirect_uri_patterns`` is pinned to that same list: a client the
    operator provisioned by hand has one known callback, and pattern widening
    exists for DCR clients on unpredictable localhost ports, not for this.

    ``scope`` is the provider's own normalized scope string, and registering the
    client with it is load-bearing: the SDK checks every requested scope against
    the client's registered scope, so a provisioned client left with none has
    every ``/authorize`` refused as ``invalid_scope`` before the flow reaches
    consent. FastMCP's DCR path gets this from ``_default_scope_str``; a
    provisioned client has to be handed the same value.
    """
    from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
    from pydantic import AnyUrl

    from .gateway.errors import ProfileConfigError

    clients: dict[str, Any] = {}
    for name, profile in sorted(profiles.items()):
        oauth = profile.oauth
        if oauth is None or oauth.client_id is None:
            continue
        secret = oauth.client_secret
        if secret is None:
            raise ProfileConfigError(
                f"profile {name!r}: oauth.client_id is set but the client "
                "secret did not resolve — refusing to serve a provisioned "
                "client whose secret would never be checked"
            )
        if oauth.client_id in clients:
            raise ProfileConfigError(
                f"profile {name!r}: oauth.client_id {oauth.client_id!r} is "
                "already provisioned by another profile — one client id cannot "
                "carry two secrets or two redirect sets"
            )
        clients[oauth.client_id] = ProxyDCRClient(
            client_id=oauth.client_id,
            client_secret=secret.get_secret_value(),
            redirect_uris=[AnyUrl(uri) for uri in oauth.client_redirect_uris],
            grant_types=["authorization_code", "refresh_token"],
            scope=scope,
            token_endpoint_auth_method=_AUTH_METHOD_POST,
            allowed_redirect_uri_patterns=list(oauth.client_redirect_uris),
            client_name=f"provisioned:{name}",
        )
    return clients


def _partition_oauth_profiles(
    profiles: Mapping[str, Profile], enabled: list[str]
) -> tuple[list[str], list[str]]:
    """Split OAuth-enabled profiles into delegated and proxied.

    A delegated profile names an external authorization server and runs none of
    ours; a proxied one is the original behaviour. The split decides whether a
    proxy gets built at all, and which profiles the RFC 8707 resource may pin to.
    """
    delegated = [
        name
        for name in enabled
        if (oauth := profiles[name].oauth) is not None and oauth.issuer is not None
    ]
    proxied = [name for name in enabled if name not in delegated]
    return delegated, proxied


DELEGATED_SCOPES = ("openid", "email", "profile")
"""Scopes a delegated profile ADVERTISES in its RFC 9728 document.

Advertised, not required. Requiring a scope means rejecting a token that lacks
it, and a rejection from this layer is invisible to the client — it re-links,
gets the same token, fails identically, forever. The real requirement is a
verified email, which cannot be present unless the email scope was granted, so
the check that matters enforces itself.
"""


def _delegated_auth(
    profiles: Mapping[str, Profile],
    names: list[str],
    *,
    proxy_client_id: str,
) -> dict[str, Any]:
    """Build the verifier for each profile that delegates to an external IdP.

    The audience rules are enforced here rather than on ``OAuthConfig`` because
    they are cross-profile, and a pydantic validator sees one profile at a time.
    Same reason ``_provisioned_clients`` checks client-id collisions here.

    Two profiles must not share an audience: the pin is what distinguishes one
    profile's tokens from another's, so sharing collapses both down to their
    allowlists. And no delegated audience may equal the gateway's own upstream
    Google client id, because the proxy holds live upstream tokens carrying
    exactly that ``aud`` — a delegated profile pinned to it would accept every
    one of them.
    """
    from .gateway.app import DelegatedAuth
    from .gateway.errors import ProfileConfigError
    from .gateway.google_verifier import GoogleTokeninfoVerifier
    from .gateway.profile import GOOGLE_ISSUER

    built: dict[str, Any] = {}
    seen: dict[str, str] = {}
    for name in sorted(names):
        oauth = profiles[name].oauth
        if oauth is None or oauth.issuer is None:
            continue
        audience = oauth.audience
        if not audience:
            raise ProfileConfigError(
                f"profile {name!r}: oauth.audience_env did not resolve — "
                "refusing to serve a delegated profile whose audience would "
                "never be checked"
            )
        if audience in seen:
            raise ProfileConfigError(
                f"profile {name!r}: oauth audience is already used by profile "
                f"{seen[audience]!r} — two delegated profiles sharing an "
                "audience accept each other's tokens"
            )
        if proxy_client_id and audience == proxy_client_id:
            raise ProfileConfigError(
                f"profile {name!r}: oauth audience equals "
                "TRENTINA_OAUTH_GOOGLE_CLIENT_ID — the proxy holds upstream "
                "tokens with that audience, so this profile would accept them"
            )
        if oauth.issuer != GOOGLE_ISSUER:
            raise ProfileConfigError(f"profile {name!r}: no verifier for issuer {oauth.issuer!r}")
        if profiles[name].role == "operator":
            logger.warning(
                "gateway: profile %s delegates authentication to %s AND holds "
                "role=operator — the gateway admin tools are reachable by "
                "anyone on its allowlist",
                name,
                oauth.issuer,
            )
        seen[audience] = name
        built[name] = DelegatedAuth(
            issuer=oauth.issuer,
            scopes=DELEGATED_SCOPES,
            verifier=GoogleTokeninfoVerifier(
                audience=audience,
                profile_name=name,
            ),
        )
    return built


def _clear_known_resource(params: Any, allowed: frozenset[str]) -> None:
    """Validate an RFC 8707 indicator against this gateway, then clear it.

    Clearing is what makes OAuthProxy's own single-URL check skip, and it is
    safe only because the value has been checked here first: an indicator
    naming something that is not a profile on this gateway raises
    ``AuthorizeError(invalid_target)`` and never reaches the base class.
    """
    requested = getattr(params, "resource", None)
    if not requested or not allowed:
        return

    from fastmcp.server.auth.identity_assertion import normalize_resource_url
    from mcp.server.auth.provider import AuthorizeError

    if normalize_resource_url(str(requested)) not in {
        normalize_resource_url(url) for url in allowed
    }:
        logger.warning(
            "gateway: refusing /authorize — resource %s is not a profile on this gateway",
            logsafe.redact_source(requested),
        )
        raise AuthorizeError(
            error="invalid_target",
            error_description="Resource does not match this server",
        )
    params.resource = None


#: Callbacks a self-registering client may use with no configuration: loopback,
#: where the code lands on the victim's own machine, plus fixed vendor URLs that
#: are identical for every user of that product. See _allowed_redirect_uris.
DEFAULT_ALLOWED_REDIRECT_URIS: tuple[str, ...] = (
    # Desktop MCP clients bind an unpredictable loopback port.
    "http://localhost:*",
    "http://127.0.0.1:*",
    # claude.ai custom connectors. Observed on the wire 2026-09-22; fixed for
    # every user, so it is a URL rather than a pattern.
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


def _allowed_redirect_uris(profiles: Mapping[str, Profile], proxied: list[str]) -> list[str]:
    """Every callback a self-registering client may use on this gateway.

    The union of the shipped defaults, each proxied profile's
    ``oauth.allowed_redirect_uris``, and the verbatim callbacks of any
    provisioned client. Registration happens before a client names a profile,
    so this list is necessarily gateway-wide.

    Why it exists at all
    --------------------
    ``/register`` is unauthenticated by design, and given no list FastMCP
    accepts ANY https callback (``redirect_validation.py:451-454``). That is an
    authorization-code theft path behind one consent click: register a client
    named "Claude" pointing at your own host, send the operator a crafted
    ``/authorize`` link, and their code arrives at you carrying their verified
    identity — which satisfies ``allowed_emails``, because it really is them.

    Why gemini.google.com is not in the defaults
    --------------------------------------------
    Its callback is per-user:
    ``oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-<id>-<host>``.
    Shipping it would mean shipping a prefix wildcard, and every Google user —
    including an attacker — has a callback under that prefix. The operator's own
    URL differs only in the account id, so listing it exactly blocks all the
    others. Only the operator knows theirs, so only they can configure it.
    """
    allowed = list(DEFAULT_ALLOWED_REDIRECT_URIS)
    for name in sorted(proxied):
        oauth = profiles[name].oauth
        if oauth is None:
            continue
        allowed.extend(oauth.allowed_redirect_uris)
        allowed.extend(oauth.client_redirect_uris)
    unique = list(dict.fromkeys(allowed))  # de-duplicate, order preserved
    logger.info(
        "gateway: %d callback URL(s) allowed for self-registering clients "
        "(%d shipped by default, %d from profile config)",
        len(unique),
        len(DEFAULT_ALLOWED_REDIRECT_URIS),
        len(unique) - len(DEFAULT_ALLOWED_REDIRECT_URIS),
    )
    return unique


def _build_proxy_provider(
    profiles: Mapping[str, Profile],
    proxied: list[str],
    *,
    base_url: str,
    signing_key: str | None,
) -> tuple[Any, str, tuple[str, ...]]:
    """Build the built-in OAuth proxy and report what it advertises.

    Returns the provider, the issuer string it will advertise, and its
    normalized scopes — the two values the gateway's own RFC 9728 document
    must reproduce byte-for-byte. Split out from _build_oauth_context so the
    delegated path, which builds none of this, stays readable.

    The upstream Google credentials are read here rather than passed in. They
    belong to the proxy and to nothing else: a delegated profile never uses
    them, and keeping the secret out of the caller means it exists only in the
    frame that hands it to the provider.

    The provider class is nested to keep the ``GoogleProvider`` import lazy,
    the way every other fastmcp import in this package is. It closes over no
    local, so anything that does not need that import — the registration
    lifetimes, in ``gateway/oauth_store.py`` — lives at module level instead
    of adding another method here. ``PromoteOnExchange`` leads the bases so
    its ``super()`` calls reach the provider.
    """
    from .gateway.errors import ProfileConfigError
    from .gateway.loader import read_secret_env

    client_id = os.environ.get("TRENTINA_OAUTH_GOOGLE_CLIENT_ID", "").strip()
    # Startup-only, so not recorded: the scrub drops it once the provider holds it.
    client_secret = read_secret_env("TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET", record=False).strip()
    if not client_id or not client_secret:
        raise ProfileConfigError(
            "profile(s) "
            f"{', '.join(sorted(proxied))} use the built-in OAuth proxy but "
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID / _CLIENT_SECRET are not set — "
            "refusing to start an OAuth seat with no provider"
        )
    from fastmcp.server.auth.providers.google import GoogleProvider

    from .gateway.oauth_binding import BindTokensToProfile, profile_resources
    from .gateway.oauth_storage import harden_provider_storage
    from .gateway.oauth_store import PromoteOnExchange

    class _GatewayGoogleProvider(BindTokensToProfile, PromoteOnExchange, GoogleProvider):
        """GoogleProvider whose protected-resource URL is the gateway endpoint.

        FastMCP derives the RFC 8707 resource (the audience of issued tokens and
        the value OAuthProxy's /authorize resource-indicator check compares
        against) from base_url + the path FastMCP mounts its OWN MCP app at.
        Trentina serves MCP from custom routes (/gateway/<profile>/mcp) and
        tombstones FastMCP's mount at a per-boot random internal path, so that
        derived resource is an unadvertisable internal URL that never matches the
        indicator a client takes from our RFC 9728 metadata (the gateway URL).
        gemini.google.com sends it and OAuthProxy rejected /authorize with
        invalid_target before ever reaching Google. Passing no path to the base
        set_mcp_path makes _get_resource_url return resource_base_url verbatim,
        and OAuthProxy.set_mcp_path then binds the JWT audience to it.
        """

        #: Statically provisioned confidential clients, by client_id.
        provisioned: ClassVar[dict[str, Any]] = {}

        #: Every proxied profile's RFC 8707 resource URL on this gateway.
        #: OAuthProxy holds exactly one; this is the set `authorize` accepts.
        gateway_resources: ClassVar[frozenset[str]] = frozenset()

        async def authorize(self, client: Any, params: Any) -> str:
            """Accept a resource indicator naming ANY profile on this gateway.

            OAuthProxy stores one ``_resource_url`` and refuses every other
            value with ``invalid_target`` (proxy.py:1141-1163). With a single
            OAuth profile that is right. With two it is an outage: the pin goes
            to whichever profile sorts first, and the other one's every login
            fails — the 0.8.3 incident, and the reason this gateway ran one
            OAuth seat until now.

            So the indicator is checked here, against every proxied profile's
            resource URL, and then cleared before delegating. Clearing is what
            makes the base check skip; it is not a loosening, because a value
            that is not one of ours has already been refused above. Downstream
            the parameter is only stored on the transaction and forwarded to
            Google, which implements no RFC 8707 and ignores it.

            The JWT audience stays the single pinned resource (proxy.py:785),
            so the audience cannot tell two seats apart. The profile the
            indicator names is bound to the flow here instead, and from there
            to the token (``gateway/oauth_binding.py``); ``verify_oauth``
            refuses a token at any other profile (#298). A flow naming no
            profile is refused when there is more than one it could mean.
            """
            requested = getattr(params, "resource", None)
            _clear_known_resource(params, self.gateway_resources)
            await self.bind_authorization(client, params, requested)
            return await super().authorize(client, params)

        def set_mcp_path(self, mcp_path: str | None) -> None:
            logger.debug(
                "gateway: ignoring FastMCP mount path %s; OAuth resource stays "
                "pinned to the advertised gateway endpoint",
                mcp_path,
            )
            super().set_mcp_path(None)

        async def get_client(self, client_id: str) -> Any:
            """Resolve a provisioned confidential client ahead of the DCR store.

            Both `/authorize` and the SDK's ClientAuthenticator at `/token` go
            through here, so returning the provisioned record is what makes the
            secret actually checked rather than merely advertised. Answering
            before the store also means DCR can never overwrite a provisioned
            client by registering the same id.
            """
            client = self.provisioned.get(client_id)
            if client is not None:
                return client
            return await super().get_client(client_id)

        async def register_client(self, client_info: Any) -> None:
            """Register a client, keeping the secret when one was asked for.

            OAuthProxy deliberately downgrades every DCR registration to a
            public client: it discards the secret the SDK minted and rewrites
            `token_endpoint_auth_method` to `"none"`, on the reasoning that the
            proxy holds the upstream credentials and never checks a downstream
            one. That reasoning stops holding the moment a client *requires* a
            confidential registration.

            gemini.google.com Custom Apps is such a client. Google Account
            Linking authenticates at the token endpoint with a client id AND
            secret, so a registration answered with "you are public, here is no
            secret" does not satisfy what it asked for. It reports "automatic
            registration failed" and stops — which is why nothing was ever
            logged here: the flow ended before a single POST was sent.

            So the SDK's secret is put back for a `client_secret_post`
            registration, and the stored record carries it, which is what makes
            the SDK's ClientAuthenticator enforce it at `/token` rather than
            merely advertise it. A client that registered `"none"` is left
            exactly as OAuthProxy made it, so Claude Code and every other public
            DCR client keeps the registration it already has.

            Note this is opt-OUT, not opt-in: the SDK defaults an omitted
            `token_endpoint_auth_method` to `client_secret_post`, so a client
            that says nothing gets a secret and must then present it. That
            default is the MCP SDK's own choice
            (`mcp/server/auth/handlers/register.py`), NOT the RFC's — RFC 7591
            §2 defaults the field to `client_secret_basic`. The 0.15.0 notes
            and an earlier version of this docstring both called it "RFC 7591's
            own default", which sent a reader to the RFC to find a sentence
            that is not there. The Python MCP client and FastMCP's client both
            send `"none"` explicitly, which is why the SDK default does not
            surprise them.

            Every registration is stored PROVISIONALLY — see
            `gateway/oauth_store.py`. It lives an hour unless a token exchange
            promotes it, which is what stops the ordinary connect/reconnect
            cycle from littering the store with permanent records nobody
            reads again. See #156.

            Only `client_secret_post` is honoured. The SDK reads `client_id`
            from the form body before it looks at the Authorization header, so
            `client_secret_basic` would reject the RFC 6749 §2.3.1 form that
            omits it — advertising a method that half works is worse than not
            offering it. See RT #1502.
            """
            # Captured before super(), which strips both off the object.
            requested_method = getattr(client_info, "token_endpoint_auth_method", None)
            issued_secret = getattr(client_info, "client_secret", None)
            expires_at = getattr(client_info, "client_secret_expires_at", None)

            from .gateway.oauth_store import (
                PROVISIONAL_TTL_SECONDS,
                mark_provisional,
            )

            await super().register_client(client_info)

            if requested_method != _AUTH_METHOD_POST or not issued_secret:
                await mark_provisional(self._client_store, client_info.client_id)
                return

            confidential = _confidential_client(
                client_info,
                secret=issued_secret,
                default_scope=self._default_scope_str,
                allowed_patterns=self._allowed_client_redirect_uris,
            )
            # Overwrites the public record super() just stored. get_client reads
            # this store, so from here the secret is the one that is checked.
            # Provisional like the public path: a confidential client that
            # registers and never exchanges a code is litter for the same
            # reason, and gets swept for the same reason.
            await self._client_store.put(
                key=client_info.client_id,
                value=confidential,
                ttl=PROVISIONAL_TTL_SECONDS,
            )

            # The SDK serializes this same object into the DCR response after we
            # return, so the client only learns its secret if it is put back.
            client_info.token_endpoint_auth_method = _AUTH_METHOD_POST
            client_info.client_secret = issued_secret
            client_info.client_secret_expires_at = expires_at

            logger.info(
                "gateway: registered confidential OAuth client %s "
                "(client_secret_post, %d redirect URI(s))",
                client_info.client_id,
                len(client_info.redirect_uris or []),
            )

        def get_routes(self, mcp_path: str | None = None) -> list[Any]:
            """Advertise the client-auth methods this proxy genuinely enforces.

            OAuthProxy hardcodes `token_endpoint_auth_methods_supported` to
            `["none"]` because it never enforces a downstream client secret.
            Both a provisioned client and, since RT #1502, a DCR client that
            registered confidentially do have one enforced by the SDK's
            ClientAuthenticator (hmac-compared, expiry-checked), so
            `client_secret_post` is true rather than decorative.

            It is advertised unconditionally, not only when a provisioned client
            exists: a client reads this document BEFORE it registers, and uses it
            to decide whether this server can issue it the confidential
            registration it needs. Advertising only after the fact would leave
            that client with nothing to go on.

            The metadata route is rebuilt deep inside the base `get_routes`, so
            the advertised document is patched on the way out instead of
            reimplementing that construction. See CHANGELOG 0.9.0, RT #1502.
            """
            return [
                _harden(
                    _advertise_secret_post(route),
                    storage=self._client_storage,
                )
                for route in super().get_routes(mcp_path)
            ]

    # Pin the resource to a PROXIED profile's endpoint (see
    # _GatewayGoogleProvider). OAuthProxy holds one resource, so with several
    # proxied profiles only the pinned one authorizes. See CHANGELOG 0.8.3.
    #
    # Never over `enabled`: a delegated profile presents no token here, and
    # names sort, so a delegated "gemini-app" would win over a proxied "web" and fail every proxy
    # /authorize with invalid_target.
    resource_profile = sorted(proxied)[0]
    resource_url = f"{base_url}/gateway/{resource_profile}/mcp"
    gateway_resources = frozenset(f"{base_url}/gateway/{name}/mcp" for name in proxied)
    _GatewayGoogleProvider.gateway_resources = gateway_resources
    # The audience of every issued token is `resource_url`, whichever profile
    # asked for it, so the audience cannot tell two seats apart; the binding
    # can (gateway/oauth_binding.py, #298).
    _GatewayGoogleProvider.gateway_profiles = profile_resources(base_url, proxied)

    # Provisioned confidential clients are resolved by get_client ahead of the
    # DCR store, and their presence is what turns on the client_secret_post
    # advertisement in get_routes. Built before the provider so the class
    # attribute is populated by the time FastMCP asks for routes.
    provider = _GatewayGoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        resource_base_url=resource_url,
        required_scopes=["openid", "email", "profile"],
        jwt_signing_key=signing_key,
        # Without this FastMCP accepts any https callback a client registers,
        # which is an authorization-code theft path behind one consent click.
        # See DEFAULT_ALLOWED_REDIRECT_URIS.
        allowed_client_redirect_uris=_allowed_redirect_uris(profiles, proxied),
        # CIMD on. 0.8.2 disabled it because OAuthProxy advertised support it
        # did not implement, which sent clients down a dead branch. That is no
        # longer true: fastmcp 2.14.4 ships CIMDClientManager with SSRF-safe
        # document fetching, cache validation and private_key_jwt checking, and
        # it honours the same allowed_redirect_uri_patterns as DCR. The MCP
        # spec now orders CIMD ahead of DCR, leaving DCR the last-resort
        # fallback, so suppressing the flag advertises us as older than we are.
        enable_cimd=True,
    )
    # FastMCP's own store, made strict in place, so a plaintext record planted
    # on disk reads as a miss (#495).
    harden_provider_storage(provider)
    # Provisioned confidential clients are resolved by get_client ahead of the
    # DCR store, and their presence is what turns on the client_secret_post
    # advertisement in get_routes. Built AFTER the provider so they can carry
    # its normalized scope string — registering them without it refuses every
    # /authorize as invalid_scope. Assigned before run(), which is when FastMCP
    # first asks for routes.
    provisioned = _provisioned_clients(profiles, " ".join(provider.required_scopes or []))
    _GatewayGoogleProvider.provisioned = provisioned
    if provisioned:
        logger.info(
            "gateway: %d provisioned OAuth client(s): %s "
            "(confidential, client_secret_post enforced)",
            len(provisioned),
            ", ".join(sorted(provisioned)),
        )

    # The issuer FastMCP will advertise in its own authorization-server metadata.
    # Sourced from the provider (not rebuilt from base_url) so our protected-
    # resource metadata names the AS with the identical string — a pydantic
    # AnyHttpUrl appends a trailing slash to a bare origin, and RFC 8414 §3.3
    # rejects any mismatch. See OAuthContext.
    issuer = str(provider.issuer_url)
    # The scopes the provider advertises as scopes_supported in its AS metadata,
    # normalized (email/profile -> full googleapis URIs). Captured so our
    # protected-resource document names the identical list. See OAuthContext.
    scopes = tuple(provider.required_scopes or [])
    # The proxy's modules are loaded now; read their format strings here,
    # off the request path, so its log lines keep them (#343).
    logsafe.warm_library_literals()
    logger.info(
        "gateway: Google OAuth proxy built for %d profile(s): %s (base_url=%s issuer=%s scopes=%s)",
        len(proxied),
        ", ".join(sorted(proxied)),
        base_url,
        issuer,
        " ".join(scopes),
    )
    # WARNING, not INFO, for the same reason the cache line is: production runs
    # at TRENTINA_LOG_LEVEL=WARNING, and the one question an operator asks after
    # a refused login is "what are the limits and what address are they keyed
    # on". That answer has to already be in the journal when they look.
    from .gateway.ratelimit import describe_limits

    logger.warning("%s", describe_limits())
    return provider, issuer, scopes


def _build_oauth_context(gateway_config: GatewayConfig) -> OAuthContext | None:
    """Construct the gateway's Google-backed OAuth context, or None.

    Returns None when no profile opts into OAuth — the common case, and the
    gateway behaves exactly as before. When at least one profile sets
    ``oauth.enabled`` this builds one ``GoogleProvider`` for the whole gateway
    (the human-facing authorization server that proxies login to Google) and
    fails closed if the client credentials are absent: an enabled profile with
    no provider is a misconfiguration, not a reason to serve it unprotected.

    Env:
        TRENTINA_OAUTH_GOOGLE_CLIENT_ID / _CLIENT_SECRET — the one Google OAuth
            client registered for this deployment (required when any profile
            enables OAuth).
        TRENTINA_OAUTH_BASE_URL — public origin clients reach (default
            https://mcp.crunchtools.com); the OAuth endpoints and the RFC 9728
            resource metadata are advertised under it.
        TRENTINA_OAUTH_JWT_SIGNING_KEY — optional. Pins the key that signs
            FastMCP tokens and derives the on-disk storage location. Set it so
            issued tokens and stored registrations survive a Google client
            secret rotation; if unset, the key derives from the secret.
            ``TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE`` names a file holding it
            instead, and wins when both are set (#268). Read once, here.
    """
    from .gateway.app import OAuthContext

    profiles = gateway_config.profiles
    enabled = [name for name, p in profiles.items() if p.oauth is not None and p.oauth.enabled]
    if not enabled:
        return None

    delegated_names, proxied = _partition_oauth_profiles(profiles, enabled)

    # The client id only — it is not a secret, and _delegated_auth needs it to
    # refuse an audience that would accept the proxy's own upstream tokens. The
    # matching secret is read inside _build_proxy_provider, which is the only
    # thing that uses it.
    client_id = os.environ.get("TRENTINA_OAUTH_GOOGLE_CLIENT_ID", "").strip()
    from .gateway.backend_oauth import public_base_url

    base_url = public_base_url()
    from .gateway.loader import read_secret_env

    # Once, at startup, and not recorded: the scrub removes it from os.environ
    # after the provider has derived its keys from it (#268).
    signing_key = read_secret_env("TRENTINA_OAUTH_JWT_SIGNING_KEY", record=False).strip() or None

    delegated = _delegated_auth(profiles, delegated_names, proxy_client_id=client_id)

    if not proxied:
        # Every OAuth profile delegates, so there is no authorization server to
        # build and no upstream Google credential to demand. Returning a context
        # with no provider is what keeps /authorize, /token and /register
        # unmounted — a gateway that is only a resource server must not also
        # advertise itself as an AS.
        logger.info(
            "gateway: OAuth delegated for %d profile(s): %s (no proxy built)",
            len(delegated_names),
            ", ".join(sorted(delegated_names)),
        )
        return OAuthContext(
            provider=None,
            base_url=base_url,
            issuer=None,
            scopes=(),
            delegated=delegated,
        )

    provider, issuer, scopes = _build_proxy_provider(
        profiles,
        proxied,
        base_url=base_url,
        signing_key=signing_key,
    )
    return OAuthContext(
        provider=provider,
        base_url=base_url,
        issuer=issuer,
        scopes=scopes,
        delegated=delegated,
    )


def _warm_classifier() -> None:
    """Load L2 at startup instead of on first scan, and say so out loud.

    The classifier lazy-loads on first use. In production on 2026-09-09 that
    first use arrived eight hours after the container started — so for eight
    hours the gateway was serving traffic with L2 unavailable, and nothing
    said so. `classify()` returns None when the model is absent and every
    caller proceeds, which means an absent layer is indistinguishable from a
    layer that looked and found nothing.

    Loading here converts a silent gap into a startup log line and a /health
    field that is true from the first request. It does not make the gateway
    refuse to start: a box with no model should still proxy, still run L1,
    and still be obviously degraded rather than quietly so.
    """
    from .quarantine.classifier import classifier_status, is_classifier_available

    log = logging.getLogger(__name__)
    if is_classifier_available():
        log.info("gateway: L2 classifier loaded at startup (%s)", classifier_status())
    else:
        log.warning(
            "gateway: L2 classifier UNAVAILABLE (%s) — L1 only. /health reports "
            "this; alert on it rather than assuming the layer is running.",
            classifier_status(),
        )


def _wire_login_notifications(session_registry: Any) -> None:
    """After a backend login, rebuild that profile's tool list and tell its sessions.

    A backend with ``auth`` is skipped from a profile's tools/list while the
    profile has no grant; once the human signs in, the client must hear that
    the list changed or it keeps the old one until it reconnects (#479).
    """
    from .gateway.aggregate import invalidate_profile_cache
    from .gateway.backend_oauth import on_grant_stored

    async def _after_login(profile_name: str) -> None:
        invalidate_profile_cache(profile_name)
        await session_registry.broadcast_tools_changed(profile_name)

    on_grant_stored(_after_login)


def _wire_circuit_notifications(
    circuit_breaker: CircuitBreaker,
    sessions: SessionRegistry,
    profiles: Mapping[str, Profile],
) -> None:
    """Connect circuit breaker state changes to session notification broadcast.

    When a circuit opens or closes, determines which profiles use the
    affected backend URL and broadcasts ``tools/list_changed`` to all
    active sessions for those profiles.
    """
    from .gateway.aggregate import invalidate_profile_cache
    from .gateway.circuit import State

    pending_tasks: set[asyncio.Task[int]] = set()

    def on_circuit_change(url: str, old_state: State, new_state: State) -> None:
        if old_state == new_state:
            return

        should_notify = (
            (old_state is State.CLOSED and new_state is State.OPEN)
            or (old_state is State.HALF_OPEN and new_state is State.CLOSED)
            or (old_state is State.HALF_OPEN and new_state is State.OPEN)
        )
        if not should_notify:
            return

        # Only the profiles that hold this backend. Wiping every aggregate
        # (#137) made one backend's flap cost every other profile a rebuild.
        # Read from config, not from the built aggregates, so a build already
        # in flight for an affected profile is disowned as well.
        affected = sessions.profiles_for_backend_url(url, dict(profiles))
        for profile_name in affected:
            invalidate_profile_cache(profile_name)
        for profile_name in affected:
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(sessions.broadcast_tools_changed(profile_name))
                pending_tasks.add(task)
                task.add_done_callback(pending_tasks.discard)
            except RuntimeError:
                logger.debug(
                    "gateway: no event loop for notification broadcast (url=%s profile=%s)",
                    logsafe.safe_url(url),
                    profile_name,
                )

    circuit_breaker.on_state_change(on_circuit_change)
    logger.info("gateway: circuit breaker → session notification wired")
