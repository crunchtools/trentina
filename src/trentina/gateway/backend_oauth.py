"""The gateway as an MCP OAuth client to its backends, one grant per profile (#479).

A backend with ``auth: {type: oauth}`` takes no static credential. The
gateway discovers its authorization server (RFC 9728, then RFC 8414),
registers a client if it must (RFC 7591), and sends a human through an
authorization-code flow with PKCE. What comes back is stored in the slot of
the profile that started the flow (``backend_tokens``), and refreshed there.

The pieces, in the order a grant is made:

- ``start`` discovers, registers, records a flow and returns a link to the
  gateway's own confirmation page, ``/oauth/backend/start``. The page names
  the backend and the profile before it sends the human on: whoever follows
  the link decides whose account lands in that profile's slot, and should
  see which slot that is.
- ``/oauth/backend/callback`` is where the authorization server sends the
  browser back. It is public and unauthenticated; the ``state`` it carries
  is the only thing that ties it to a flow, and each state is spent once.
- ``fresh_grant`` hands the router a usable grant, refreshing it when it is
  near expiry, against the token endpoint pinned when the grant was made.

Everything this module sends goes through ``egress.check_url`` and
``egress.open_pinned``: every address checked, nothing followed on a
redirect, every reply capped. The URLs it fetches come from the operator's
backend URL or from metadata served by it, and a backend that names the
gateway itself as its authorization server is refused.
"""

from __future__ import annotations

import asyncio
import base64
import html
import json
import logging
import os
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Literal, TypeVar
from urllib.parse import quote, urlencode, urlsplit

import httpx
from pydantic import BaseModel, SecretStr, ValidationError

from .. import egress
from ..database import record_gateway_call
from ..errors import EgressRefusedError
from ..logsafe import exc_kind, redact_source
from ..outcomes import Outcome
from .backend_tokens import (
    AuthMethod,
    BackendClient,
    BackendFlow,
    BackendGrant,
    BackendTokenStore,
    _now,
    backend_origin,
    backend_token_store,
    flow_key,
    slot_key,
)
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, DestinationKind

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

START_PATH = "/oauth/backend/start"
CALLBACK_PATH = "/oauth/backend/callback"
DONE_PATH = "/oauth/backend/done"
#: How long a flow waits for its callback (the issue's acceptance criterion).
FLOW_TTL = timedelta(minutes=10)
#: Live flows per slot. A fourth start drops the oldest.
MAX_FLOWS_PER_SLOT = 3
#: A metadata, registration or token reply is a few hundred bytes.
MAX_REPLY_BYTES = 65_536
#: Wall-clock seconds for one request and its whole reply.
REQUEST_DEADLINE = 15.0
#: A grant this close to expiry is refreshed before it is used.
REFRESH_MARGIN = timedelta(seconds=60)
#: A query value on the public routes longer than this is refused unread.
MAX_PARAM_CHARS = 2048
#: Burst and per-hour allowance, per source address, for the public pages.
PAGE_LIMIT = (20, 60)
_GRANT_TYPES = ["authorization_code", "refresh_token"]
#: Preferred first: the gateway keeps a client secret encrypted, so a
#: confidential client is the stronger registration.
_AUTH_METHODS: tuple[AuthMethod, ...] = (
    "client_secret_basic",
    "client_secret_post",
    "none",
)
#: Only https leaves the gateway. Tests serve plain http on loopback.
_REQUIRE_HTTPS = True
_WWW_FIELD = r'{}=(?:"([^"]+)"|([^\s,]+))'


class BackendAuthError(Exception):
    """A step of backend authorization refused. ``code`` is a constant, safe to log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def public_base_url() -> str:
    """Where the gateway is reached from outside: the root of every link it hands out."""
    return (
        os.environ.get("TRENTINA_OAUTH_BASE_URL", "https://mcp.crunchtools.com").strip().rstrip("/")
    )


def callback_url() -> str:
    """The redirect URI every backend client is registered with."""
    return f"{public_base_url()}{CALLBACK_PATH}"


# ------------------------------------------------------------------ egress


@dataclass(frozen=True)
class _Reply:
    status: int
    headers: httpx.Headers
    body: bytes

    def json(self) -> dict[str, Any] | None:
        """The body as a JSON object, or None."""
        try:
            value = json.loads(self.body)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None


async def _request(
    profile: Profile,
    method: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> _Reply:
    """One request to a backend or its authorization server, through the egress guard."""
    parsed = urlsplit(url)
    if _REQUIRE_HTTPS and parsed.scheme != "https":
        raise BackendAuthError("not_https")
    if (parsed.hostname or "").lower() == (urlsplit(public_base_url()).hostname or "").lower():
        raise BackendAuthError("self_host")
    sent = {"Accept": "application/json", **(headers or {})}
    content: bytes | None = None
    if form is not None:
        content = urlencode(form).encode()
        sent["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        content = json.dumps(json_body).encode()
        sent["Content-Type"] = "application/json"
    try:
        async with asyncio.timeout(REQUEST_DEADLINE):
            with profile_context(profile):
                target = await egress.check_url(url)
            async with egress.open_pinned(
                method, url, target, idle=REQUEST_DEADLINE, headers=sent, content=content
            ) as resp:
                received = bytearray()
                # open_pinned refused any encoded body, so these are the wire bytes.
                async for chunk in resp.aiter_bytes():
                    received += chunk
                    if len(received) > MAX_REPLY_BYTES:
                        raise BackendAuthError("reply_too_large")
                status, reply_headers = resp.status_code, resp.headers
    except EgressRefusedError as exc:
        raise BackendAuthError(f"egress_{exc.reason}") from None
    except (httpx.HTTPError, TimeoutError, OSError) as exc:
        logger.info("backend-oauth: request failed (%s)", exc_kind(exc))
        raise BackendAuthError("unreachable") from None
    return _Reply(status=status, headers=reply_headers, body=bytes(received))


_M = TypeVar("_M", bound=BaseModel)


def _parse(model: type[_M], reply: _Reply) -> _M | None:
    # TRUST: metadata, registration and token replies from a backend's authorization server
    #   untrusted: the whole body; the server is a third party the backend named
    #   judged-by: a pydantic model (unknown fields ignored, types enforced), then the
    #     caller's issuer, resource, PKCE and https checks
    #   on-failure: fail-closed; the step refuses with a constant code, the body is never logged
    #   owner: backend_oauth._parse
    #   evidence: T2 test_backend_oauth discovery and token refusal cases
    try:
        return model.model_validate_json(reply.body)
    except (ValidationError, ValueError):
        return None


def _www_field(header: str, name: str) -> str | None:
    match = re.search(_WWW_FIELD.format(name), header)
    return (match.group(1) or match.group(2)) if match else None


# --------------------------------------------------------------- discovery


@dataclass(frozen=True)
class Discovered:
    """What a backend's metadata says about how to authorize to it."""

    resource: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None
    scopes: tuple[str, ...]
    iss_required: bool
    #: ``token_endpoint_auth_methods_supported``; absent means basic (RFC 8414 2).
    auth_methods: tuple[str, ...]


async def _first_document(
    profile: Profile, urls: list[str], unavailable: str
) -> tuple[_Reply, dict[str, Any]] | None:
    """The first URL that serves a JSON object; a 429 or 5xx stops the search."""
    for url in urls:
        reply = await _request(profile, "GET", url)
        if reply.status == 200:
            document = reply.json()
            if document is not None:
                return reply, document
        elif reply.status == 429 or reply.status >= 500:
            raise BackendAuthError(unavailable)
    return None


async def _resource_metadata(profile: Profile, backend: Backend) -> tuple[Any, str, str | None]:
    """The backend's protected-resource metadata, its first issuer, and its asked-for scope."""
    from mcp.client.auth.utils import build_protected_resource_metadata_discovery_urls
    from mcp.shared.auth import ProtectedResourceMetadata
    from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url
    from mcp_types import LATEST_PROTOCOL_VERSION

    probe = await _request(
        profile,
        "POST",
        backend.url,
        json_body={"jsonrpc": "2.0", "id": 0, "method": "ping"},
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
        },
    )
    challenge = probe.headers.get("www-authenticate", "") if probe.status in (401, 403) else ""
    found = await _first_document(
        profile,
        build_protected_resource_metadata_discovery_urls(
            _www_field(challenge, "resource_metadata"), backend.url
        ),
        "resource_metadata_unavailable",
    )
    prm = _parse(ProtectedResourceMetadata, found[0]) if found else None
    if found is None or prm is None:
        raise BackendAuthError("no_resource_metadata")
    if not check_resource_allowed(resource_url_from_server_url(backend.url), str(prm.resource)):
        raise BackendAuthError("resource_mismatch")
    servers = found[1].get("authorization_servers")
    issuer = servers[0] if isinstance(servers, list) and servers else None
    if not isinstance(issuer, str):
        raise BackendAuthError("no_authorization_server")
    return prm, issuer, _www_field(challenge, "scope")


async def _server_metadata(profile: Profile, backend: Backend, issuer: str) -> Any:
    """The authorization server's metadata, checked: its issuer, PKCE and https."""
    from mcp.client.auth.utils import build_oauth_authorization_server_metadata_discovery_urls
    from mcp.shared.auth import OAuthMetadata

    found = await _first_document(
        profile,
        build_oauth_authorization_server_metadata_discovery_urls(issuer, backend.url),
        "server_metadata_unavailable",
    )
    asm = _parse(OAuthMetadata, found[0]) if found else None
    if found is None or asm is None:
        raise BackendAuthError("no_server_metadata")
    if found[1].get("issuer") != issuer:
        raise BackendAuthError("issuer_mismatch")
    if "S256" not in (asm.code_challenge_methods_supported or []):
        raise BackendAuthError("no_pkce")
    endpoints = (asm.authorization_endpoint, asm.token_endpoint, asm.registration_endpoint)
    if _REQUIRE_HTTPS and any(e is not None and e.scheme != "https" for e in endpoints):
        raise BackendAuthError("not_https")
    return asm


async def discover(profile: Profile, backend: Backend) -> Discovered:
    """Find and check the authorization server for one backend.

    Issuers are compared as the strings the documents carry, byte for byte
    (RFC 8414 3.3), never as parsed URLs that a library might normalize.
    """
    from mcp.client.auth.utils import get_client_metadata_scopes
    from mcp.shared.auth_utils import resource_url_from_server_url

    auth = backend.auth
    if auth is None:
        raise BackendAuthError("not_oauth")
    prm, issuer, asked = await _resource_metadata(profile, backend)
    if auth.issuer is not None and issuer != auth.issuer:
        raise BackendAuthError("issuer_not_pinned")
    asm = await _server_metadata(profile, backend, issuer)
    scope = (
        " ".join(auth.scopes)
        if auth.scopes
        else get_client_metadata_scopes(asked, prm, asm, _GRANT_TYPES)
    )
    return Discovered(
        resource=resource_url_from_server_url(backend.url),
        issuer=issuer,
        authorization_endpoint=str(asm.authorization_endpoint),
        token_endpoint=str(asm.token_endpoint),
        registration_endpoint=(
            str(asm.registration_endpoint) if asm.registration_endpoint is not None else None
        ),
        scopes=tuple(scope.split()) if scope else (),
        iss_required=bool(asm.authorization_response_iss_parameter_supported),
        auth_methods=tuple(asm.token_endpoint_auth_methods_supported or ["client_secret_basic"]),
    )


# ------------------------------------------------------------------ client


def _configured_client(backend: Backend, disc: Discovered) -> BackendClient | None:
    """The client the operator provisioned in the profile, if any."""
    auth = backend.auth
    if auth is None or auth.client_id is None:
        return None
    method: AuthMethod = "none"
    if auth.client_secret is not None:
        method = (
            "client_secret_post"
            if "client_secret_basic" not in disc.auth_methods
            and "client_secret_post" in disc.auth_methods
            else "client_secret_basic"
        )
    return BackendClient(
        client_id=auth.client_id,
        client_secret=auth.client_secret,
        auth_method=method,
        issuer=disc.issuer,
        token_endpoint=disc.token_endpoint,
    )


async def _client_for(
    store: BackendTokenStore, profile: Profile, name: str, backend: Backend, disc: Discovered
) -> BackendClient:
    """The provisioned client, the slot's registered one, or a new registration."""
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata

    configured = _configured_client(backend, disc)
    if configured is not None:
        return configured
    existing = await store.get_client(profile.name, name, backend)
    if (
        existing is not None
        and existing.issuer == disc.issuer
        and existing.token_endpoint == disc.token_endpoint
    ):
        return existing
    if disc.registration_endpoint is None:
        raise BackendAuthError("needs_client_id")
    method = next((m for m in _AUTH_METHODS if m in disc.auth_methods), None)
    if method is None:
        raise BackendAuthError("no_usable_auth_method")
    metadata = OAuthClientMetadata.model_validate(
        {
            "redirect_uris": [callback_url()],
            "token_endpoint_auth_method": method,
            "grant_types": _GRANT_TYPES,
            "response_types": ["code"],
            "client_name": "Trentina gateway",
            "application_type": "web",
            "scope": " ".join(disc.scopes) or None,
        }
    )
    reply = await _request(
        profile,
        "POST",
        disc.registration_endpoint,
        json_body=metadata.model_dump(mode="json", exclude_none=True),
    )
    info = _parse(OAuthClientInformationFull, reply) if reply.status in (200, 201) else None
    if info is None:
        raise BackendAuthError("registration_refused")
    granted = info.token_endpoint_auth_method or method
    if granted not in _AUTH_METHODS:
        raise BackendAuthError("no_usable_auth_method")
    if granted != "none" and not info.client_secret:
        raise BackendAuthError("registration_without_secret")
    client = BackendClient(
        client_id=info.client_id,
        client_secret=SecretStr(info.client_secret) if info.client_secret else None,
        auth_method=granted,
        issuer=disc.issuer,
        token_endpoint=disc.token_endpoint,
    )
    await store.put_client(profile.name, name, backend, client)
    return client


def _client_auth(client: BackendClient, form: dict[str, str]) -> dict[str, str]:
    """Add the client's credentials to a token request; return its headers."""
    secret = client.client_secret.get_secret_value() if client.client_secret else ""
    if client.auth_method == "client_secret_basic":
        # RFC 6749 2.3.1: each half form-urlencoded before it is joined.
        pair = f"{quote(client.client_id, safe='')}:{quote(secret, safe='')}"
        return {"Authorization": f"Basic {base64.b64encode(pair.encode()).decode()}"}
    form["client_id"] = client.client_id
    if client.auth_method == "client_secret_post":
        form["client_secret"] = secret
    return {}


async def _client_of(
    store: BackendTokenStore, profile: Profile, name: str, backend: Backend, client_id: str
) -> BackendClient | None:
    """The client a flow or grant was made with, if the slot still holds it."""
    auth = backend.auth
    if auth is not None and auth.client_id == client_id:
        stored = await store.get_client(profile.name, name, backend)
        method = stored.auth_method if stored and stored.client_id == client_id else None
        return BackendClient(
            client_id=client_id,
            client_secret=auth.client_secret,
            auth_method=method or ("client_secret_basic" if auth.client_secret else "none"),
            issuer="",
            token_endpoint="",
        )
    stored = await store.get_client(profile.name, name, backend)
    return stored if stored is not None and stored.client_id == client_id else None


# ------------------------------------------------------------------- audit


def _audit(
    profile: str,
    backend: str,
    tool: str,
    started: float,
    failure: str | None = None,
    issuer: str | None = None,
) -> None:
    """One audit row per start, completion, refresh and refusal. Never raises."""
    host = urlsplit(issuer).hostname if issuer else None
    try:
        record_gateway_call(
            profile,
            backend,
            tool,
            (Outcome.TOOL_ERROR if failure else Outcome.OK).value,
            int((time.monotonic() - started) * 1000),
            failure,
            destination=host[:MAX_DESTINATION_CHARS] if host else None,
            destination_kind=DestinationKind.OAUTH.value if host else None,
        )
    except Exception as exc:
        logger.warning("backend-oauth: audit row lost (%s)", exc_kind(exc))


# ------------------------------------------------------------------- flows


#: Each slot's live flows, oldest first, as (state key, page key).
_live_flows: dict[str, deque[tuple[str, str]]] = {}


def _require_store() -> BackendTokenStore:
    store = backend_token_store()
    if store is None:
        raise BackendAuthError("no_store")
    return store


async def _prepare(
    profile: Profile, name: str, authorized_by: Literal["self", "operator"]
) -> tuple[BackendTokenStore, Backend, Discovered, BackendClient]:
    """Everything ``start`` checks before it records anything."""
    backend = profile.backends.get(name)
    if backend is None or backend.auth is None:
        raise BackendAuthError("not_oauth")
    if authorized_by == "self" and not backend.auth.self_authorize:
        raise BackendAuthError("not_self_authorized")
    store = _require_store()
    disc = await discover(profile, backend)
    # A slot already bound to one authorization server is not quietly moved to
    # another: a backend that changes its metadata does not get to send the
    # human, or the client, somewhere new. Revoke first, or pin auth.issuer.
    for prior in (
        await store.get_grant(profile.name, name, backend),
        await store.get_client(profile.name, name, backend),
    ):
        if prior is not None and prior.issuer != disc.issuer:
            raise BackendAuthError("issuer_changed")
    return store, backend, disc, await _client_for(store, profile, name, backend, disc)


async def start(profile: Profile, name: str, *, authorized_by: Literal["self", "operator"]) -> str:
    """Begin authorizing ``profile`` to backend ``name``; return the link to send a human.

    ``authorized_by`` is required so that no caller skips the decision:
    ``"self"`` means the profile asked for its own login, which its backend
    entry must allow with ``auth.self_authorize``.
    """
    from mcp.client.auth.oauth2 import PKCEParameters

    started = time.monotonic()
    try:
        store, backend, disc, client = await _prepare(profile, name, authorized_by)
    except BackendAuthError as exc:
        _audit(profile.name, name, "oauth_start", started, exc.code)
        raise

    state = secrets.token_urlsafe(32)
    page = secrets.token_urlsafe(32)
    pkce = PKCEParameters.generate()
    params = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": callback_url(),
        "state": state,
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": "S256",
        "resource": disc.resource,
    }
    if disc.scopes:
        params["scope"] = " ".join(disc.scopes)
        if "offline_access" in disc.scopes:
            params["prompt"] = "consent"
    joiner = "&" if "?" in disc.authorization_endpoint else "?"
    flow = BackendFlow(
        profile=profile.name,
        backend=name,
        origin=backend_origin(backend.url),
        issuer=disc.issuer,
        iss_required=disc.iss_required,
        token_endpoint=disc.token_endpoint,
        authorize_url=f"{disc.authorization_endpoint}{joiner}{urlencode(params)}",
        client_id=client.client_id,
        auth_method=client.auth_method,
        verifier=SecretStr(pkce.code_verifier),
        redirect_uri=callback_url(),
        resource=disc.resource,
        scopes=disc.scopes,
        page_key=flow_key(page),
        expires_at=_now() + FLOW_TTL,
    )
    keys = (flow_key(state), flow.page_key)
    for key in keys:
        await store.put_flow(key, flow)
    live = _live_flows.setdefault(slot_key(profile.name, name), deque())
    live.append(keys)
    while len(live) > MAX_FLOWS_PER_SLOT:
        for key in live.popleft():
            await store.drop_flow(key)
    _audit(profile.name, name, "oauth_start", started, issuer=disc.issuer)
    return f"{public_base_url()}{START_PATH}?flow={page}"


def _live_backend(flow: BackendFlow) -> tuple[Profile, Backend]:
    """The flow's profile and backend as configured now, if they still match the flow."""
    from .loader import get_active_config

    active = get_active_config()
    profile = active.config.profiles.get(flow.profile) if active else None
    backend = profile.backends.get(flow.backend) if profile else None
    if profile is None or backend is None or backend.auth is None:
        raise BackendAuthError("backend_gone")
    if backend_origin(backend.url) != flow.origin:
        raise BackendAuthError("backend_moved")
    return profile, backend


def _grant_from(
    reply: _Reply,
    *,
    issuer: str,
    token_endpoint: str,
    resource: str | None,
    client: BackendClient,
    previous: BackendGrant | None = None,
    scopes: tuple[str, ...] = (),
) -> BackendGrant:
    """A grant from a token endpoint's reply; old refresh token and scopes carried forward."""
    from mcp.shared.auth import OAuthToken

    token = _parse(OAuthToken, reply) if reply.status == 200 else None
    if token is None:
        raise BackendAuthError("token_refused")
    now = _now()
    refresh = token.refresh_token or (
        previous.refresh_token.get_secret_value() if previous and previous.refresh_token else None
    )
    if token.scope:
        scopes = tuple(token.scope.split())
    elif previous is not None:
        scopes = previous.scopes
    return BackendGrant(
        access_token=SecretStr(token.access_token),
        refresh_token=SecretStr(refresh) if refresh else None,
        token_type=token.token_type,
        expires_at=now + timedelta(seconds=int(token.expires_in)) if token.expires_in else None,
        scopes=scopes,
        issuer=issuer,
        token_endpoint=token_endpoint,
        resource=resource,
        client_id=client.client_id,
        auth_method=client.auth_method,
        obtained_at=now,
    )


async def _exchange(
    store: BackendTokenStore,
    flow: BackendFlow,
    code: str | None,
    iss: str | None,
    error: str | None,
) -> None:
    """Check a callback against its flow, exchange the code, store the grant."""
    profile, backend = _live_backend(flow)
    if error is not None:
        raise BackendAuthError("authorization_denied")
    if not code:
        raise BackendAuthError("no_code")
    # RFC 9207: the response names the server that issued it, which defeats
    # a mix-up between two authorization servers this gateway talks to.
    if (iss is None and flow.iss_required) or (iss is not None and iss != flow.issuer):
        raise BackendAuthError("iss_mismatch")
    client = await _client_of(store, profile, flow.backend, backend, flow.client_id)
    if client is None:
        raise BackendAuthError("client_gone")
    client = client.model_copy(update={"auth_method": flow.auth_method})
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": flow.redirect_uri,
        "code_verifier": flow.verifier.get_secret_value(),
    }
    if flow.resource:
        form["resource"] = flow.resource
    headers = _client_auth(client, form)
    reply = await _request(profile, "POST", flow.token_endpoint, form=form, headers=headers)
    grant = _grant_from(
        reply,
        issuer=flow.issuer,
        token_endpoint=flow.token_endpoint,
        resource=flow.resource,
        client=client,
        scopes=flow.scopes,
    )
    async with store.locked(flow.profile, flow.backend):
        current = await store.get_grant(flow.profile, flow.backend, backend)
        await store.put_grant(
            flow.profile,
            flow.backend,
            backend,
            grant,
            expected_generation=current.generation if current else 0,
        )


async def complete(state: str, code: str | None, iss: str | None, error: str | None) -> None:
    """Finish the flow ``state`` names: exchange ``code`` and store the grant in its slot.

    The flow is spent first, whatever happens next: a state is good for one
    attempt, including one the authorization server answered with ``error``.
    """
    started = time.monotonic()
    store = _require_store()
    flow = await store.take_flow(flow_key(state))
    if flow is None:
        logger.info("backend-oauth: callback for no live flow (%s)", redact_source(state))
        raise BackendAuthError("state_unknown")
    await store.drop_flow(flow.page_key)
    _forget_flow(flow)
    try:
        await _exchange(store, flow, code, iss, error)
    except BackendAuthError as exc:
        _audit(flow.profile, flow.backend, "oauth_complete", started, exc.code, flow.issuer)
        raise
    _audit(flow.profile, flow.backend, "oauth_complete", started, issuer=flow.issuer)


def _forget_flow(flow: BackendFlow) -> None:
    live = _live_flows.get(slot_key(flow.profile, flow.backend))
    if live:
        for keys in list(live):
            if keys[1] == flow.page_key:
                live.remove(keys)


# ----------------------------------------------------------------- refresh


def _usable(grant: BackendGrant, stale_generation: int | None) -> bool:
    if stale_generation is not None and grant.generation == stale_generation:
        return False
    return grant.expires_at is None or grant.expires_at - _now() > REFRESH_MARGIN


def _oauth_error(reply: _Reply) -> str | None:
    document = reply.json()
    value = document.get("error") if document else None
    return value if isinstance(value, str) else None


async def fresh_grant(
    profile: Profile, name: str, *, stale_generation: int | None = None
) -> BackendGrant | None:
    """A grant the router can send now, or None: the backend needs authorizing.

    Refreshes one that is near expiry, or the one with ``stale_generation``
    that the backend just refused, against the token endpoint pinned in the
    grant. One refresh per slot at a time; a caller that waited on another's
    refresh gets its result instead of spending the refresh token again.
    """
    store = backend_token_store()
    backend = profile.backends.get(name)
    if store is None or backend is None or backend.auth is None:
        return None
    grant = await store.get_grant(profile.name, name, backend)
    if grant is None or _usable(grant, stale_generation):
        return grant
    async with store.locked(profile.name, name):
        grant = await store.get_grant(profile.name, name, backend)
        if grant is None or _usable(grant, stale_generation):
            return grant
        started = time.monotonic()
        try:
            fresh = await _refresh(store, profile, name, backend, grant)
        except BackendAuthError as exc:
            _audit(profile.name, name, "oauth_refresh", started, exc.code, grant.issuer)
            return None
        _audit(profile.name, name, "oauth_refresh", started, issuer=grant.issuer)
        return fresh


async def _refresh(
    store: BackendTokenStore, profile: Profile, name: str, backend: Backend, grant: BackendGrant
) -> BackendGrant:
    """Spend the refresh token at the pinned endpoint; store and return what comes back.

    A refusal that means the grant is dead (``invalid_grant``) drops the
    grant; one that means the registration is dead (``invalid_client``) drops
    the client too, so the next start registers again instead of looping. A
    busy or unreachable server drops nothing: the next call tries again.
    """
    client = await _client_of(store, profile, name, backend, grant.client_id)
    if grant.refresh_token is None or client is None:
        raise BackendAuthError("cannot_refresh")
    if client.issuer and client.issuer != grant.issuer:
        raise BackendAuthError("issuer_mismatch")
    client = client.model_copy(update={"auth_method": grant.auth_method})
    form = {"grant_type": "refresh_token", "refresh_token": grant.refresh_token.get_secret_value()}
    if grant.resource:
        form["resource"] = grant.resource
    headers = _client_auth(client, form)
    reply = await _request(profile, "POST", grant.token_endpoint, form=form, headers=headers)
    if reply.status == 429 or reply.status >= 500:
        raise BackendAuthError("token_endpoint_busy")
    if reply.status != 200:
        await store.delete_grant(profile.name, name)
        if _oauth_error(reply) == "invalid_client":
            await store.delete_client(profile.name, name)
        raise BackendAuthError("refresh_rejected")
    fresh = _grant_from(
        reply,
        issuer=grant.issuer,
        token_endpoint=grant.token_endpoint,
        resource=grant.resource,
        client=client,
        previous=grant,
    )
    return await store.put_grant(
        profile.name, name, backend, fresh, expected_generation=grant.generation
    )


# ------------------------------------------------------------------ routes

_REFUSED = "This sign-in link is invalid or has expired. Start again from your agent."
_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    # Nothing on these pages runs; the one link is followed by a click.
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "sandbox allow-top-navigation-by-user-activation"
    ),
}


def _page(title: str, body: str, status: int = 200) -> Response:
    """A small fixed page. ``body`` is HTML the caller built from escaped values."""
    from starlette.responses import HTMLResponse

    document = (
        '<!doctype html><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        '<body style="font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;'
        'padding:0 1rem">'
        f"{body}</body>"
    )
    return HTMLResponse(document, status_code=status, headers=_HEADERS)


def _param(request: Request, name: str) -> str | None:
    # TRUST: a query parameter on a public, unauthenticated route
    #   untrusted: every value; anyone can send this request
    #   judged-by: a length cap here; state is only ever hashed and looked up, code and
    #     iss go only to the pinned token endpoint or a string compare
    #   on-failure: fail-closed; a refused page that reflects nothing from the request
    #   owner: backend_oauth._param
    #   evidence: T2 test_backend_oauth callback-route cases
    value = request.query_params.get(name)
    if value is not None and len(value) > MAX_PARAM_CHARS:
        raise BackendAuthError("param_too_long")
    return value


async def _start_page(request: Request) -> Response:
    try:
        page = _param(request, "flow")
    except BackendAuthError:
        return _page("Sign-in link refused", f"<p>{_REFUSED}</p>", 400)
    store = backend_token_store()
    flow = await store.peek_flow(flow_key(page)) if store and page else None
    if flow is None:
        return _page("Sign-in link refused", f"<p>{_REFUSED}</p>", 400)
    backend, profile = html.escape(flow.backend), html.escape(flow.profile)
    issuer = html.escape(urlsplit(flow.issuer).hostname or flow.issuer)
    return _page(
        f"Sign in to {flow.backend}",
        f"<h1>Sign in to <b>{backend}</b></h1>"
        f"<p>This signs in the gateway profile <b>{profile}</b>: whatever account you "
        f"choose at <b>{issuer}</b> will be used for everything <b>{profile}</b> does "
        f"with <b>{backend}</b>.</p>"
        "<p>If you did not ask for this, close this tab.</p>"
        f'<p><a href="{html.escape(flow.authorize_url, quote=True)}" '
        'rel="noreferrer">Continue</a></p>',
    )


async def _callback(request: Request) -> Response:
    from starlette.responses import RedirectResponse

    state: str | None = None
    try:
        state = _param(request, "state")
        if state:
            await complete(
                state, _param(request, "code"), _param(request, "iss"), _param(request, "error")
            )
    except BackendAuthError as exc:
        logger.info("backend-oauth: callback refused (%s)", exc.code)
        state = None
    if not state:
        return _page("Sign-in failed", f"<p>{_REFUSED}</p>", 400)
    # A fresh page, so the code leaves the address bar and the history.
    return RedirectResponse(DONE_PATH, status_code=HTTPStatus.SEE_OTHER, headers=_HEADERS)


async def _done_page(_request: Request) -> Response:
    return _page("Signed in", "<p>Signed in. You can close this tab.</p>")


def register_backend_oauth_routes(mcp_server: Any) -> None:
    """Mount the confirmation page, the callback and the done page; only with a store."""
    if backend_token_store() is None:
        return
    from starlette.routing import request_response

    from .ratelimit import RateLimiter, UnauthenticatedWriteGuard, enabled

    limiter = RateLimiter(*PAGE_LIMIT, name="/oauth/backend")
    for path, handler in (
        (START_PATH, _start_page),
        (CALLBACK_PATH, _callback),
        (DONE_PATH, _done_page),
    ):
        # A plain function is wrapped by the Route itself; an ASGI app is not.
        app: Any = handler
        if enabled() and path != DONE_PATH:
            app = UnauthenticatedWriteGuard(request_response(handler), limiter=limiter)
        mcp_server.custom_route(path, methods=["GET"])(app)
    logger.info("gateway: backend OAuth pages mounted under /oauth/backend")
