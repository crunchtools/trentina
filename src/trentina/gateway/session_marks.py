"""Which sessions have been delivered content the layers flagged (#456).

Under ``flag`` a flagged response reaches the agent with a warning attached,
and the session that read it keeps every tool it had. Guarded execution asks
whether that happened before it lets a guarded call leave, so the router
marks a session here when it delivers a warning, and the gatekeeper reads it.

Keyed by the session fingerprint (``context.current_session``), never the
session ID. Held in memory only: a restart forgets, which is the same as the
session itself, whose ID does not survive one either. A mark lasts
``MARK_TTL_SECONDS`` from the last flag, far longer than the 300-second idle
timeout that ends a session, and the table holds at most ``MAX_MARKS``, the
oldest dropped first, so a flood of sessions costs bounded memory.
"""

from __future__ import annotations

import time
from collections import OrderedDict

MARK_TTL_SECONDS = 12 * 3600
MAX_MARKS = 10_000

_marks: OrderedDict[str, float] = OrderedDict()


def mark_flagged(session: str) -> bool:
    """Record that *session* was delivered flagged or partly judged content.

    Returns True when this is the session's first live mark, so the caller
    can log the call that tainted it once rather than on every flag after.
    """
    if not session:
        return False
    first = not was_flagged(session)
    _marks[session] = time.monotonic()
    _marks.move_to_end(session)
    while len(_marks) > MAX_MARKS:
        _marks.popitem(last=False)
    return first


def was_flagged(session: str) -> bool | None:
    """Whether *session* carries a live mark. None when there is no session to ask about."""
    if not session:
        return None
    at = _marks.get(session)
    if at is None:
        return False
    if time.monotonic() - at > MARK_TTL_SECONDS:
        del _marks[session]
        return False
    return True


def clear() -> None:
    """Forget every mark. For tests."""
    _marks.clear()
