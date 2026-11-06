"""Cache management tool — flush backend and profile tool list caches.

Scoped by role. An agent profile drops its own aggregate and nothing else;
the operator flushes the gateway.

An agent's flush used to evict its backends' entries from the tool-list
cache and report which were still warm (``backends_flushed``). That cache was
keyed by URL and shared by every profile holding the URL, so one profile
could re-list, flush a chosen subset, and have another read the pattern back:
a bit per shared backend, per round (#263). An agent's flush therefore leaves
the shared cache alone and returns a body built from nothing another profile
can influence. A stale backend list is the operator's to flush, or
``reconnect_backend``'s to re-probe.

Since 6.1.0 that cache is keyed ``(url, owner)`` and a profile holding a
credential has a partition of its own, so the #263 channel is closed
structurally for those: an agent flushing its own partition tells a neighbour
nothing, because the neighbour reads a different row. The constant body is
kept all the same. A backend carrying NO credential still shares one row with
every profile — correctly, since its answer is the same for everyone — and
that row is exactly what the channel was made of, so letting an agent flush
and report on it would reopen #263 for the shared case while closing it for
the private one. One rule is better than a rule with a carve-out nobody can
see from the tool's output.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway.aggregate import _profile_tools_cache, invalidate_profile_cache
from ..gateway.backend import evict_backend_cache_url, flush_all_caches
from ..gateway.compress import get_profiles
from ..gateway.errors import ScopeError
from ..gateway.scope import CallerScope, require_caller, resolve_backend
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


def _flush_own(scope: CallerScope, backend: str | None) -> dict[str, Any]:
    """Agent path: the caller's own aggregate, and a constant answer.

    A named backend is still checked against the caller's own profile, so a
    typo is refused rather than silently ignored; the refusal depends only on
    that profile. Whether an aggregate was cached is not reported: it is
    rebuilt from the shared cache, so its presence is not the caller's alone.
    """
    if backend is not None:
        resolve_backend(scope, backend)
    invalidate_profile_cache(scope.label)
    return {"flushed": "profile", "scope": scope.label, "profile_cache_cleared": True}


def _flush_named_gateway_wide(backend: str) -> dict[str, Any]:
    """Operator path for one name: flush it wherever it is configured.

    Resolves through the profile registry, not through the cache keys, so a
    name means a backend somebody configured — never any URL it happens to be
    a substring of.

    Every partition of each URL, not one: an operator flushing a backend means
    the backend itself may have changed, which is true for every tenant
    holding it. ``evicted`` counts URLs, as it did before partitioning, so the
    number still answers "how many backends did I just drop".
    """
    profiles = get_profiles() or {}
    urls = {
        cfg.url
        for profile in profiles.values()
        if (cfg := profile.backends.get(backend)) is not None and cfg.is_remote
    }
    return {
        "flushed": "backend",
        "scope": "gateway",
        "backend": backend,
        "evicted": sum(evict_backend_cache_url(url) for url in urls),
        "urls_matched": len(urls),
    }


async def cache_flush(backend: str | None = None) -> dict[str, Any]:
    """Flush tool list caches, within the caller's role.

    Args:
        backend: Backend name. An agent's must be in its own profile, and
            only its own aggregate is dropped either way; an operator's is
            flushed wherever it is configured. Omit for everything in scope:
            the agent's aggregate, or every cache for an operator.

    Returns:
        What was flushed. An agent profile's result is the same every time
        for the same caller; a refusal names nothing at all.
    """
    try:
        scope = require_caller("cache_flush")
        if not scope.is_operator:
            return _flush_own(scope, backend)
    except ScopeError as exc:
        logger.warning("cache_flush refused: %s", exc_kind(exc))
        return {"flushed": "nothing", "error": str(exc)}

    if backend is not None:
        return _flush_named_gateway_wide(backend)

    count = flush_all_caches()
    _profile_tools_cache.clear()
    return {
        "flushed": "all",
        "scope": "gateway",
        "backend_caches_evicted": count,
        "profile_caches_cleared": True,
    }
