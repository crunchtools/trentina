"""The request edge of a crossing: resolve a served name, normalize its arguments.

The two pure request-side steps a ``tools/call`` takes before it reaches the
backend — turning the name a client sent back into the (backend, tool) it
routes to in this profile, and normalizing the forwarded arguments against the
backend's schema. Both ``gateway/router.py`` and ``transports/mcp.py`` run them
on the request edge, so they live here rather than inside the router the
transport is replacing. Part of PR3a (Trentina 3.0 Phase 7): make the transport
self-contained so the hand-rolled router can be retired.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .args import Normalized, normalize_arguments
from .backend import cached_tool_read_only, cached_tool_schema, loggable_tool
from .names import resolve_name

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)


def _resolve_target(profile: Profile, served_name: object) -> tuple[str, str, Backend] | None:
    """The (backend name, tool, backend) a served name routes to in this profile."""
    if not isinstance(served_name, str):
        return None
    resolved = resolve_name(profile, served_name)
    if resolved is None or not resolved[1]:
        return None
    backend_name, tool_name = resolved
    # None for an issued short name whose backend has since left the profile.
    backend = profile.backends.get(backend_name)
    return (backend_name, tool_name, backend) if backend is not None else None


def _normalize_arguments(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    forwarded: dict[str, Any],
) -> Normalized:
    """Normalize arguments against the backend's schema before a remote call (``args.py``).

    Internal tools are ours and already read an empty value as unset.
    """
    if backend.is_internal:
        return Normalized(forwarded)
    normalized = normalize_arguments(
        forwarded,
        cached_tool_schema(backend.url, tool_name),
        read_only=cached_tool_read_only(backend.url, tool_name),
    )
    if normalized.dropped:
        # How many and why, never which: a name is the caller's (#262).
        logger.info(
            "gateway: profile=%s %s/%s normalized %d arg(s): %s",
            profile.name,
            backend_name,
            loggable_tool(backend.url, tool_name),
            len(normalized.dropped),
            ",".join(sorted(set(normalized.dropped.values()))),
        )
    return normalized
