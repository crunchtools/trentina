"""Clear session marks and cool-down windows (a1724): operator only.

A mark the profile's guards refuse on opens a cool-down on the whole profile
(#900), and marks live in memory, so until now a false positive held every
seat of that profile until its window passed or the gateway restarted. This
is the way out that is not a restart. Operator only: clearing a mark is
deciding that what the session was delivered does not count, which an agent
must not decide about itself.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..gateway import session_marks
from ..gateway.context import current_caller
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)

_SESSION = re.compile(r"[0-9a-f]{8,16}")
"""A session fingerprint (``context.session_fingerprint``), or the first eight
or more characters of one, as the log prints it."""


async def session_marks_clear(
    profile: str | None = None, session: str | None = None, all: bool = False
) -> dict[str, Any]:
    """Clear a profile's cool-down and its sessions' marks, or one session's.

    Args:
        profile: Clear this profile's window and the marks of its sessions.
        session: Clear this session's marks, and the window it owns if any:
            its fingerprint or the first eight or more characters of it.
        all: Clear every mark and window. Refused with either of the others,
            and nothing is cleared without one of the three.

    Returns:
        ``windows`` and ``sessions`` removed, or ``error`` with nothing changed.
    """
    try:
        scope = require_caller("session_marks_clear")
        require_operator(scope, "session_marks_clear")
    except ScopeError as exc:
        logger.warning("session_marks_clear refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    found: list[str] = []
    if all and (profile or session):
        refused = "all clears everything; name a profile or a session instead"
    elif not (all or profile or session):
        refused = "name a profile or a session, or pass all=true to clear everything"
    elif session and not _SESSION.fullmatch(session):
        refused = "session is a fingerprint: 8 to 16 lowercase hex characters"
    elif session and len(found := session_marks.matching_sessions(session)) != 1:
        refused = (
            "that prefix matches more than one session; give more of it"
            if found
            else "no session holds a mark or a window under that prefix"
        )
    else:
        refused = None
    if refused:
        return {"error": refused}
    full = found[0] if session else None
    result = session_marks.clear_marks(profile=profile, session=full, everything=all)
    caller = current_caller.get()
    # What was named, as constants: the arguments are the caller's text. The
    # profiles cleared are in the result, read from the gateway's own state.
    named = "all" if all else "+".join(k for k, v in (("profile", profile), ("session", full)) if v)
    logger.warning(
        "session_marks_clear by %s%s: named %s; windows=%s sessions=%s",
        scope.label,
        f" (federated {caller[0]}/{caller[1]})" if caller else "",
        named,
        result["windows"],
        result["sessions"],
    )
    return {"cleared": "all" if all else "named", **result}
