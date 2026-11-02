"""Start, check and forget a profile's own login to a backend (#479).

A backend with ``auth: {type: oauth}`` is called with a grant that belongs to
the calling profile. These tools are how a profile gets one, sees whether it
has one, and drops it. Each acts on the caller's own backend of that name
and nothing else: there is no way to start, read or drop another profile's
login, and a name the caller does not hold is refused the same way whether
or not it exists elsewhere.

Starting a login is gated by the backend entry's ``auth.self_authorize``.
The operator seat is not: it is the box owner's, acting on its own backends.
Nothing here returns a token, a client secret or a PKCE verifier.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ..gateway.backend_oauth import FLOW_TTL, BackendAuthError, revoke_remote, start
from ..gateway.backend_tokens import backend_token_store
from ..gateway.errors import ScopeError
from ..gateway.scope import CallerScope, current_scope, require_caller, resolve_backend
from ..logsafe import exc_kind

if TYPE_CHECKING:
    from ..gateway.profile import Profile

logger = logging.getLogger(__name__)

#: Logins a profile may start per hour. Each one is several requests to the
#: backend and its authorization server.
STARTS_PER_HOUR = 10
_starts: dict[str, deque[float]] = {}


def _refusal(backend: str, exc: Exception) -> dict[str, Any]:
    """A refusal naming only the caller's own backends, so a miss maps nothing."""
    try:
        own = current_scope().backends
    except ScopeError:
        own = {}
    return {
        "backend": backend,
        "error": str(exc),
        "available": sorted(name for name, cfg in own.items() if cfg.auth is not None),
    }


def _own_oauth_backend(
    tool: str, backend: str, *, needs_self_authorize: bool = False
) -> tuple[CallerScope, Profile]:
    """The caller and its profile, if ``backend`` is its own OAuth backend."""
    scope = require_caller(tool)
    _url, cfg = resolve_backend(scope, backend)
    if cfg.auth is None:
        raise ScopeError(f"{tool}: backend {backend!r} does not use auth: oauth")
    if needs_self_authorize and not (scope.is_operator or cfg.auth.self_authorize):
        raise ScopeError(f"{tool}: backend {backend!r} does not allow self_authorize")
    return scope, scope.profile


def _within_rate(profile: str) -> bool:
    now = time.monotonic()
    recent = _starts.setdefault(profile, deque())
    while recent and now - recent[0] > 3600:
        recent.popleft()
    if len(recent) >= STARTS_PER_HOUR:
        return False
    recent.append(now)
    return True


async def backend_auth_start(backend: str) -> dict[str, Any]:
    """Begin this profile's login to ``backend``; return the link for a human."""
    try:
        scope, profile = _own_oauth_backend("backend_auth start", backend)
    except ScopeError as exc:
        return _refusal(backend, exc)
    if not _within_rate(profile.name):
        return {"backend": backend, "error": f"over {STARTS_PER_HOUR} logins started this hour"}
    try:
        link = await start(
            profile, backend, authorized_by="operator" if scope.is_operator else "self"
        )
    except BackendAuthError as exc:
        logger.info("backend_auth start refused: %s", exc.code)
        return {"backend": backend, "error": exc.code}
    return {
        "backend": backend,
        "link": link,
        "expires_in_minutes": int(FLOW_TTL.total_seconds() // 60),
        "next": (
            "Send this link to your human. The page it opens names this profile and "
            "this backend before it sends them to sign in."
        ),
    }


async def backend_auth_status(backend: str | None = None) -> dict[str, Any]:
    """Which of this profile's OAuth backends hold a grant. No secrets."""
    try:
        scope = require_caller("backend_auth status")
        if backend is not None:
            resolve_backend(scope, backend)
    except ScopeError as exc:
        return _refusal(backend or "", exc)
    store = backend_token_store()
    names = [backend] if backend else sorted(scope.backends)
    report = []
    for name in names:
        cfg = scope.backends[name]
        if cfg.auth is None:
            continue
        grant = await store.get_grant(scope.profile.grant_owner, name, cfg) if store else None
        report.append(
            {
                "backend": name,
                "authorized": grant is not None,
                "expires_at": grant.expires_at.isoformat() if grant and grant.expires_at else None,
                "scopes": list(grant.scopes) if grant else [],
                "issuer_host": urlsplit(grant.issuer).hostname if grant else None,
                "self_authorize": cfg.auth.self_authorize,
            }
        )
    return {"store": store is not None, "backends": report}


async def backend_auth_revoke(backend: str) -> dict[str, Any]:
    """Forget this profile's grant for ``backend``. The registration is kept.

    The authorization server is told first when it advertised an RFC 7009
    endpoint at sign-in (#499); that is best effort, and the grant is dropped
    here whatever came of it. ``remote`` carries the closed result code.
    """
    try:
        _scope, profile = _own_oauth_backend(
            "backend_auth revoke", backend, needs_self_authorize=True
        )
    except ScopeError as exc:
        return _refusal(backend, exc)
    store = backend_token_store()
    if store is None:
        return {"backend": backend, "revoked": False, "error": "no_store"}
    started = time.monotonic()
    remote: str | None = None
    try:
        # Snapshot and delete under the lock, so no refresh can rotate the tokens
        # we revoke; the network call runs after it is released.
        async with store.locked(profile.grant_owner, backend):
            cfg = profile.backends[backend]
            grant = await store.get_grant(profile.grant_owner, backend, cfg)
            revoked = await store.delete_grant(profile.grant_owner, backend)
        if grant is not None:
            remote = await revoke_remote(store, profile, backend, cfg, grant)
    except Exception as exc:
        logger.warning("backend_auth revoke failed (%s)", exc_kind(exc))
        return {"backend": backend, "revoked": False, "error": type(exc).__name__}
    from ..gateway.backend_oauth import _audit

    _audit(profile.name, backend, "oauth_revoke", started)
    result: dict[str, Any] = {"backend": backend, "revoked": revoked}
    if remote is not None:
        result["remote"] = remote
        if remote != "revoked":
            result["note"] = (
                "The grant is deleted here, but the authorization server may still honor "
                "its tokens. Revoke the app in the service's own settings."
            )
    return result
