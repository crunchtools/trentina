"""Tool pins — the operator's release valve for held tools (#469).

A tool a backend newly offers, or whose definition changed, is withheld from
every profile (``gateway/tool_pins.py``). Operator only: a held tool names a
backend's surface, and approving one is a decision about the whole gateway,
since pins belong to the backend and not to a profile.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway import tool_pins
from ..gateway.aggregate import invalidate_profile_cache_for_backend
from ..gateway.compress import get_profiles
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


async def manage_tool_pins(
    action: str,
    backend: str,
    tool: str | None = None,
    hash: str | None = None,
    set_digest: str | None = None,
) -> dict[str, Any]:
    """List, approve or reject the tool definitions held under a backend name.

    Args:
        action: ``list``, ``approve``, ``reject`` or ``approve_all``.
        backend: Backend name, wherever it is configured.
        tool: The held tool, for ``approve`` and ``reject``. A rejected
            definition stays withheld and is not reported again.
        hash: Which held DEFINITION of that tool, from ``list``. Needed only
            where a tool has more than one — two profiles served different
            bytes by a backend that answers per credential. With one held
            definition it is implied.
        set_digest: For ``approve_all``: the ``digest`` ``list`` returned,
            which binds the approval to the set that was read.
    """
    try:
        require_operator(require_caller("tool_pins"), "tool_pins")
    except ScopeError as exc:
        logger.warning("tool_pins refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    url = _one_url(backend)
    if url is None:
        return {"error": "backend not found, or its name maps to more than one URL"}
    if action == "list":
        held = tool_pins.pending(url)
        return {"backend": backend, "held": held, "digest": tool_pins.pending_digest(held)}
    if action == "approve_all":
        approved, refused = tool_pins.decide_all(url, backend, set_digest=set_digest)
        if not refused:
            invalidate_profile_cache_for_backend(url)
        return (
            {"error": refused}
            if refused
            else {
                "backend": backend,
                "action": action,
                "approved": len(approved),
                "tools": approved,
            }
        )
    if action not in ("approve", "reject") or not tool:
        return {
            "error": "action is list, approve, reject or approve_all; "
            "approve and reject need a tool"
        }
    return _decide_one(url, backend, action, tool, hash)


def _one_url(backend: str) -> str | None:
    """The single remote URL that name maps to, or None.

    A name shared by different URLs is different backends: deciding for all of
    them at once could release a tool on an unrelated one.
    """
    profiles = get_profiles() or {}
    urls = {
        cfg.url
        for profile in profiles.values()
        if (cfg := profile.backends.get(backend)) is not None and cfg.is_remote
    }
    return urls.pop() if len(urls) == 1 else None


def _decide_one(
    url: str, backend: str, action: str, tool: str, definition_hash: str | None
) -> dict[str, Any]:
    """``approve`` or ``reject`` one held definition."""
    if not tool_pins.decide(
        url, tool, approve=action == "approve", definition_hash=definition_hash
    ):
        # Two tenants served different definitions is the interesting refusal:
        # there is no single thing "approve this tool" could mean then, so name
        # the hashes on offer rather than deciding one by accident.
        held = [row["hash"] for row in tool_pins.pending(url) if row["tool"] == tool]
        if definition_hash is None and len(held) > 1:
            return {
                "error": "that tool has more than one held definition; name one with hash",
                "held": held,
            }
        return {"error": "no such held tool"}
    invalidate_profile_cache_for_backend(url)
    return {"backend": backend, "tool": tool, "action": action, "hash": definition_hash}
