"""Reconnect tool — recover a single backend after it restarts.

There is no persistent MCP transport to a backend (backend.py opens a fresh
streamable-http session per call), so "reconnect" here means clearing the
recovery state that a backend restart leaves stale:

1. Reset the per-URL circuit breaker (``cache_flush`` never touches it, so an
   open circuit otherwise blocks calls until the 60s cooldown probe succeeds).
2. Force a fresh probe/fetch that replaces the cached tool list and records
   breaker success/failure.
3. Invalidate the aggregates that omitted the backend while it failed: the
   caller's own for an agent, every one holding the URL for the operator.

This lets an operator recover one backend without restarting the whole gateway.

Scoped by role. An agent profile reconnects a backend it holds, and hears back
about that one: its endpoint, its circuit, and the tool count AS THAT PROFILE
SEES IT through its own allowlist. The operator reconnects a name wherever it
is configured and is told which profiles share it. A name the caller does not
hold is refused the same way whether or not it exists elsewhere, so a miss is
not a map of the rest of the gateway.

Resetting a circuit is felt by every profile on that URL — the breaker is keyed
by URL and healing it heals it for all of them. That is the point of the tool,
not a leak. An agent's aggregate rebuild is its own (#291): dropping every
profile's that held the URL moved their ``surface.built_at``, which each of
them reads in ``quarantine_stats``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ..gateway.aggregate import invalidate_profile_cache, invalidate_profile_cache_for_backend
from ..gateway.backend import refresh_backend_tools
from ..gateway.circuit import breaker
from ..gateway.compress import get_profiles
from ..gateway.decoy import served_tools
from ..gateway.errors import BackendCallError, ScopeError
from ..gateway.filter import filter_tools
from ..gateway.scope import (
    CallerScope,
    current_scope,
    require_caller,
    resolve_backend,
)
from ..logsafe import exc_kind

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..gateway.profile import Profile

logger = logging.getLogger(__name__)


def _safe_endpoint(url: str) -> str:
    """Return scheme://host:port only — never the path/query.

    A backend URL can carry an auth token in its path (e.g. Postiz's
    ``/api/mcp/<token>``) or query string, so the full URL must never be
    echoed back to the caller. The host:port is a non-secret network alias.
    """
    parts = urlsplit(url)
    # A decoy's URL says what it is, which its caller must not be told (#357).
    if not parts.netloc or parts.scheme == "decoy":
        return "(redacted)"
    return f"{parts.scheme}://{parts.netloc}"


def _configured_name(backends: Mapping[str, Any], name: str) -> str:
    """The configured key equal to ``name``, once resolution has matched it.

    ``refresh_backend_tools`` logs the name it is given. Handing it the key from
    the configuration rather than the caller's argument makes what reaches the
    log the gateway's own string by construction (#262), which is what the
    CodeQL pack's tool-arg-to-log query checks (#269).
    """
    return next(key for key in backends if key == name)


async def _grant_holder(backend: str, holders: list[Profile]) -> Profile | None:
    """The first of ``holders`` with a usable grant for ``backend`` (#479)."""
    from ..gateway.backend_oauth import fresh_grant

    for profile in holders:
        if await fresh_grant(profile, backend) is not None:
            return profile
    return None


async def _reset_one(
    backend: str,
    url: str,
    cfg: Any,
    base: dict[str, Any],
    scope: CallerScope,
    holders: list[Profile],
) -> dict[str, Any]:
    """Reset, re-probe and report one backend URL.

    ``tool_count`` is filtered through the caller's own allowlist, so the
    number is what that profile would actually see on the next tools/list —
    not the backend's raw surface, which for a shared backend is somebody
    else's view.
    """
    if cfg.is_internal:
        return {
            **base,
            "reconnected": True,
            "internal": True,
            "note": "in-process backend — nothing to reconnect",
        }
    if cfg.is_decoy:
        # As a healthy remote backend answers (#357): a caller must not learn
        # which of its backends has nothing behind it by asking to reconnect.
        return {
            **base,
            "reconnected": True,
            "tool_count": len(filter_tools(served_tools(cfg), cfg)),
            "circuit": breaker.get_state(url).value,
        }

    holder = None
    if cfg.auth is not None:
        # Fetched with a grant, so never evicted first: with no profile able
        # to refill it, an evicted list would leave every profile with none.
        holder = await _grant_holder(backend, holders)
        if holder is None:
            return {
                **base,
                "reconnected": False,
                "error": 'needs a grant: authorize with backend_auth (action="start") first',
                "circuit": breaker.get_state(url).value,
            }
    elif cfg.federated is not None and holders:
        # A federated edge authenticates with a per-request JWT whose caller is
        # the primary profile (#592 C1/C2); _credentials mints it only when a
        # profile is passed. The operator path otherwise passed none, so the
        # probe went out unauthenticated and the secondary rejected it with an
        # opaque ExceptionGroup. Hand it an owning profile so the edge re-auths.
        holder = holders[0]
    breaker.reset(url)
    try:
        # Refresh in place — never evict first. Evicting before the fetch
        # stranded the primary with no tools when the fetch then failed
        # (the list was already gone from memory and SQLite). refresh fetches
        # fresh, replaces on success, and leaves the last-good list untouched
        # on failure; the aggregate is invalidated below only after a success.
        tools = await refresh_backend_tools(backend, cfg, holder)
    except BackendCallError as exc:
        return {
            **base,
            "reconnected": False,
            "error": str(exc),
            "circuit": breaker.get_state(url).value,
        }
    if scope.is_operator:
        invalidate_profile_cache_for_backend(url)
    else:
        invalidate_profile_cache(scope.label)
    visible = tools if scope.is_operator else filter_tools(tools, cfg)
    return {
        **base,
        "reconnected": True,
        "tool_count": len(visible),
        "circuit": breaker.get_state(url).value,
    }


async def reconnect_backend(backend: str) -> dict[str, Any]:
    """Reset and re-probe a backend by name, within the caller's role.

    An agent profile reconnects the backend of that name in its own profile.
    An operator reconnects every distinct URL configured under the name — a
    name can resolve to more than one URL across profiles when the URL carries
    a per-profile token — and is told which profiles share each one.

    Args:
        backend: Backend name as it appears in the caller's profile (e.g.
            "postiz", "slack", "jira").

    Returns:
        Status dict with an overall ``reconnected`` flag and a ``targets`` list
        describing each URL that was reset. A refusal carries ``error`` and
        ``available`` — the caller's OWN backend names, so a typo is
        correctable — and nothing belonging to any other profile.
    """
    base: dict[str, Any]
    try:
        scope = require_caller("reconnect_backend")
        if not scope.is_operator:
            url, cfg = resolve_backend(scope, backend)
            base = {"endpoint": _safe_endpoint(url), "scope": scope.label}
            name = _configured_name(scope.backends, backend)
            holders = [scope.profile]
            results = [await _reset_one(name, url, cfg, base, scope, holders)]
            return {
                "backend": backend,
                "scope": scope.label,
                "reconnected": all(r["reconnected"] for r in results),
                "targets": results,
            }
    except ScopeError as exc:
        # The caller's OWN backend names, which turns a typo into a usable
        # correction. Listing the gateway's, which is what this used to do,
        # turned every typo into a directory of every other agent's backends.
        # An unbound caller has no scope to list — current_scope() refuses it.
        try:
            available = sorted(current_scope().backends)
        except ScopeError:
            available = []
        logger.warning("reconnect_backend refused: %s", exc_kind(exc))
        return {
            "backend": backend,
            "reconnected": False,
            "error": str(exc),
            "available": available,
        }

    profiles = get_profiles()
    if profiles is None:
        return {
            "backend": backend,
            "reconnected": False,
            "error": "gateway not initialized",
        }

    targets: dict[str, dict[str, Any]] = {}
    for profile in profiles.values():
        found = profile.backends.get(backend)
        if found is not None:
            name = _configured_name(profile.backends, backend)
            entry = targets.setdefault(
                found.url, {"cfg": found, "profiles": set(), "name": name, "holders": []}
            )
            entry["profiles"].add(profile.name)
            entry["holders"].append(profile)

    if not targets:
        return {
            "backend": backend,
            "reconnected": False,
            "error": "backend not found in any profile",
            "available": sorted(name for p in profiles.values() for name in p.backends),
        }

    results = []
    for url, entry in targets.items():
        base = {
            "endpoint": _safe_endpoint(url),
            "profiles": sorted(entry["profiles"]),
        }
        results.append(
            await _reset_one(entry["name"], url, entry["cfg"], base, scope, entry["holders"])
        )

    return {
        "backend": backend,
        "scope": "gateway",
        "reconnected": all(r["reconnected"] for r in results),
        "targets": results,
    }
