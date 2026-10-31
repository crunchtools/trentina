"""Why a profile does not see a tool (#592, federation field note).

Operator field note from running federation: ``reconnect_backend``,
``cache_flush`` and ``reload_profiles`` all look like plausible fixes for a
missing tool, and none of them touches a pin hold — so a disappeared tool costs
an afternoon of guessing. This answers "why can't profile X see tool Y?" by
naming the stage that drops it, walking the real pipeline stages in order:

1. the profile has no such backend,
2. the backend does not offer the tool (or is unreachable),
3. a pin hold is withholding it (#469),
4. the allowlist or denylist excludes it,
5. the perimeter withheld its description (block mode, L3-flagged),
6. otherwise it is served, under its short name.

Read-only, and it leaves no trace: it never writes a pin (``get_pin``, never
``check_tools``) and it reads the served list as a client would — respecting,
never evicting, the shared aggregate cache, so a diagnostic cannot force every
other caller to rebuild. ``description_withheld`` therefore means the tool
passed every earlier stage but is not in the current served list: the perimeter
withheld its description, or that list is stale (``cache_flush`` rebuilds).
Reason codes are a closed set and name no caller-chosen text (#262).
"""

from __future__ import annotations

import logging
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from .. import perimeter_db
from ..logsafe import exc_kind
from . import aggregate, names
from .compress import get_profiles
from .errors import BackendCallError, ScopeError
from .filter import filter_tools
from .scope import require_caller, require_operator
from .tool_pins import backend_id

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

# Closed set of reasons; nothing here is caller-chosen text.
UNKNOWN_BACKEND = "unknown_backend"
BACKEND_UNREACHABLE = "backend_unreachable"
NOT_OFFERED = "not_offered"
HELD_PENDING_PIN = "held_pending_pin"
EXCLUDED_BY_ALLOWLIST = "excluded_by_allowlist"
EXCLUDED_BY_DENYLIST = "excluded_by_denylist"
DESCRIPTION_WITHHELD = "description_withheld"
SERVED = "served"


async def diagnose_tool_visibility(
    profile: Profile, backend_name: str, tool_name: str
) -> dict[str, Any]:
    """Report which stage drops ``tool_name`` from ``profile``'s served list.

    ``tool_name`` is the name the backend offers (the real name), not the short
    name a client sees. Returns ``{visible, reason, served_as, backend}``.
    """
    backend = profile.backends.get(backend_name)
    if backend is None:
        return {"visible": False, "reason": UNKNOWN_BACKEND, "backend": backend_name}

    # The real offered list, through the same path the aggregate uses.
    try:
        offered = await aggregate._offered_tools(backend_name, backend, profile)
    except BackendCallError:
        return {"visible": False, "reason": BACKEND_UNREACHABLE, "backend": backend_name}

    tool = next((t for t in offered if t.get("name") == tool_name), None)
    if tool is None:
        return {"visible": False, "reason": NOT_OFFERED, "backend": backend_name}

    # A pin hold withholds it (read-only: get_pin, never check_tools).
    if not (backend.is_internal or backend.is_decoy):
        row = perimeter_db.get_pin(backend_id(backend.url), tool_name)
        if row is not None and row["pending_hash"]:
            return {"visible": False, "reason": HELD_PENDING_PIN, "backend": backend_name}

    if not filter_tools([tool], backend):
        allowed = any(fnmatchcase(tool_name, pat) for pat in backend.tools_allow)
        reason = EXCLUDED_BY_DENYLIST if allowed else EXCLUDED_BY_ALLOWLIST
        return {"visible": False, "reason": reason, "backend": backend_name}

    # Rebuild fresh so a stale cache cannot mislead, then look for the tool
    # under the name it would be served as. Absent here, having passed every
    # earlier stage, means the perimeter withheld its description.
    # The served list as a client would get it: the shared cache is respected,
    # never evicted — a read-only diagnostic must not make every other caller
    # rebuild. A tool missing here, having passed every earlier stage, was
    # withheld by the perimeter (or the cache is stale; cache_flush rebuilds).
    served = await aggregate.ensure_profile_build(profile)
    serves_as = names.served_name(profile, backend_name, tool_name)
    visible = serves_as is not None and any(t.get("name") == serves_as for t in served)
    return {
        "visible": visible,
        "reason": SERVED if visible else DESCRIPTION_WITHHELD,
        "served_as": serves_as if visible else None,
        "backend": backend_name,
        # Secondary provenance (#592 A1): the origin is the backend, and whether
        # that backend is a federated secondary Trentina is part of knowing where
        # a tool came from — surfaced here, never in the agent-facing name.
        "federated": backend.federated is not None,
    }


async def diagnose_visibility(
    backend: str, tool: str, profile: str | None = None
) -> dict[str, Any]:
    """Scope-resolving entry for the operator/agent diagnostic.

    An agent diagnoses its own profile; an operator may name another with
    ``profile``. A refusal names no other profile's existence (#263).
    """
    try:
        scope = require_caller("tool_visibility")
        if profile is None or profile == scope.name:
            target: Profile = scope.profile
        else:
            require_operator(scope, "diagnosing another profile")
            found = (get_profiles() or {}).get(profile)
            if found is None:
                return {"error": "no such profile, or not visible to this caller"}
            target = found
    except ScopeError as exc:
        logger.warning("tool_visibility refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    return await diagnose_tool_visibility(target, backend, tool)
