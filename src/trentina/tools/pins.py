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


async def manage_tool_pins(action: str, backend: str, tool: str | None = None) -> dict[str, Any]:
    """List, approve or reject the tools held under a backend name.

    Args:
        action: ``list``, ``approve`` or ``reject``.
        backend: Backend name, wherever it is configured.
        tool: The held tool, for ``approve`` and ``reject``. A rejected tool
            stays withheld and is not reported again until it changes.
    """
    try:
        require_operator(require_caller("tool_pins"), "tool_pins")
    except ScopeError as exc:
        logger.warning("tool_pins refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    profiles = get_profiles() or {}
    urls = sorted(
        {
            cfg.url
            for profile in profiles.values()
            if (cfg := profile.backends.get(backend)) is not None and cfg.is_remote
        }
    )
    if len(urls) != 1:
        # A name shared by different URLs is different backends: deciding for
        # all of them at once could release a tool on an unrelated one.
        return {"error": "backend not found, or its name maps to more than one URL"}
    if action == "list":
        return {"backend": backend, "held": tool_pins.pending(urls[0])}
    if action not in ("approve", "reject") or not tool:
        return {"error": "action is list, approve or reject; the last two need a tool"}

    if not tool_pins.decide(urls[0], tool, approve=action == "approve"):
        return {"error": "no such held tool"}
    invalidate_profile_cache_for_backend(urls[0])
    return {"backend": backend, "tool": tool, "action": action}
