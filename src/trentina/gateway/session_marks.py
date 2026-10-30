"""Which sessions have been delivered content the layers flagged (#456).

Under ``flag`` a flagged response reaches the agent with a warning attached,
and the session that read it keeps every tool it had. Semantic request guards ask
whether that happened before it lets a guarded call leave, so the router
marks a session here when it delivers a warning, and the gatekeeper reads it.

Keyed by the session fingerprint (``context.current_session``), never the
session ID. Held in memory only: a restart forgets, which is the same as the
session itself, whose ID does not survive one either. A mark lasts
``MARK_TTL_SECONDS`` from the last flag, far longer than the 300-second idle
timeout that ends a session, and the table holds at most ``MAX_MARKS``, the
oldest dropped first, so a flood of sessions costs bounded memory.

A dropped mark must not read as a clean session, or a flood of flagged
sessions would launder an older one. So until every dropped mark would have
expired anyway, a session with no mark is unknown (None) rather than clean:
the judge is told so, and ``refuse_when_flagged`` refuses it (#457).
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..outcomes import Outcome
from ..reserved import WARNING_KEY
from .context import current_call, current_session

if TYPE_CHECKING:
    from ..core.stages import Assembled

logger = logging.getLogger(__name__)

MARK_TTL_SECONDS = 12 * 3600
MAX_MARKS = 10_000

_marks: OrderedDict[str, float] = OrderedDict()
_unknown_until = 0.0
"""Monotonic time before which an unmarked session may be one we dropped."""


def mark_flagged(session: str) -> bool:
    """Record that *session* was delivered flagged or partly judged content.

    Returns True when this is the session's first live mark, so the caller
    can log the call that tainted it once rather than on every flag after.
    """
    global _unknown_until
    if not session:
        return False
    first = was_flagged(session) is not True
    _marks[session] = time.monotonic()
    _marks.move_to_end(session)
    while len(_marks) > MAX_MARKS:
        _, at = _marks.popitem(last=False)
        if _unknown_until <= time.monotonic():
            logger.warning(
                "session marks: table full at %d, dropping the oldest; unmarked "
                "sessions read as unknown until the dropped marks expire",
                MAX_MARKS,
            )
        _unknown_until = max(_unknown_until, at + MARK_TTL_SECONDS)
    return first


def was_flagged(session: str) -> bool | None:
    """Whether *session* carries a live mark.

    None when there is no session to ask about, or when it has no mark but
    the table has dropped one recently enough that it might have been this
    session's.
    """
    if not session:
        return None
    now = time.monotonic()
    at = _marks.get(session)
    if at is not None and now - at > MARK_TTL_SECONDS:
        del _marks[session]
        at = None
    if at is not None:
        return True
    return None if now < _unknown_until else False


def clear() -> None:
    """Forget every mark. For tests."""
    global _unknown_until
    _marks.clear()
    _unknown_until = 0.0


def _mark_session(assembled: Assembled, internal: Any = None) -> None:
    """Mark the session when content it receives was flagged or partly judged (#456).

    Semantic request guards read the mark before a guarded call leaves. A refused
    response reached the agent as a refusal, not as content, so it does not
    mark. An internal tool judges its own content and says so in the result
    it returns, which is where its warning is read (``internal``).
    """
    if assembled.outcome not in (Outcome.OK, Outcome.TOOL_ERROR):
        return
    if assembled.warning is not None or (internal is not None and _carries_warning(internal)):
        session = current_session.get()
        if mark_flagged(session):
            # The taint's origin, once per session: the call_ref joins it to
            # the audit row of the response that carried the flag (#457).
            logger.info(
                "gateway: session %s… marked flagged by call_ref=%s",
                session[:8],
                current_call.get() or "?",
            )


def _carries_warning(call_result: Any) -> bool:
    """Whether an internal tool's result carries the perimeter's ``_trentina_warning``."""
    structured = call_result.structured_content
    if isinstance(structured, dict):
        return bool(structured.get(WARNING_KEY))
    for block in call_result.content or ():
        text = block.get("text") if isinstance(block, dict) else None
        if not isinstance(text, str) or WARNING_KEY not in text:
            continue
        try:
            body = json.loads(text)
        except ValueError:
            continue
        if isinstance(body, dict) and body.get(WARNING_KEY):
            return True
    return False
