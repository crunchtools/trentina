"""What each session has been delivered or done, as a closed set of labels (#456, #861).

Under ``flag`` a flagged response reaches the agent with a warning attached,
and the session that read it keeps every tool it had. Semantic guards ask
what the session has seen before a guarded call leaves or a guarded response
is delivered, so the gateway labels a session here and the gatekeeper reads it.

Every label is set by gateway code, never by a judge: content must not be
able to steer its own taint. ``SessionLabel`` is the whole set, and adding one
is a code change.

Keyed by the session fingerprint (``context.current_session``), never the
session ID. Held in memory only: a restart forgets, which is the same as the
session itself, whose ID does not survive one either. Each label lasts
``MARK_TTL_SECONDS`` from the last time it was set, far longer than the
300-second idle timeout that ends a session, and the table holds at most
``MAX_MARKS`` sessions, the oldest dropped first, so a flood of sessions
costs bounded memory.

A dropped entry must not read as a clean session, or a flood of marked
sessions would launder an older one. So until every dropped entry would have
expired anyway, a session with no entry is unknown (None) rather than clean:
the judge is told so, and ``refuse_when`` refuses it (#457).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from ..credential_shapes import kinds as credential_kinds
from ..outcomes import Outcome
from ..reserved import WARNING_KEY
from .context import current_call, current_session

if TYPE_CHECKING:
    from ..core.stages import Assembled

logger = logging.getLogger(__name__)

MARK_TTL_SECONDS = 12 * 3600
MAX_MARKS = 10_000


class SessionLabel(StrEnum):
    """What a session has been delivered or done (#861)."""

    FLAGGED_DELIVERY = "flagged_delivery"
    """Delivered content the layers flagged or only partly judged (#456)."""
    TRIPPED = "tripped"
    """Called a decoy, sent a planted credential, or tried to send a real one (#860)."""
    CREDENTIAL_SEEN = "credential_seen"
    """Delivered a response holding a credential shape (``credential_shapes``)."""


FLAG_LABELS = frozenset({SessionLabel.FLAGGED_DELIVERY, SessionLabel.TRIPPED})
"""What ``refuse_when_flagged`` and the ``session_flagged`` fact cover."""

_marks: OrderedDict[str, dict[SessionLabel, float]] = OrderedDict()
_unknown_until = 0.0
"""Monotonic time before which a session with no entry may be one we dropped."""


def mark(session: str, label: SessionLabel) -> bool:
    """Set *label* on *session*.

    Returns True when the label was not already live, so the caller can log
    the call that set it once rather than on every call after.
    """
    global _unknown_until
    if not session:
        return False
    current = labels(session)
    first = current is None or label not in current
    _marks.setdefault(session, {})[label] = time.monotonic()
    _marks.move_to_end(session)
    while len(_marks) > MAX_MARKS:
        _, dropped = _marks.popitem(last=False)
        if _unknown_until <= time.monotonic():
            logger.warning(
                "session marks: table full at %d, dropping the oldest; unmarked "
                "sessions read as unknown until the dropped marks expire",
                MAX_MARKS,
            )
        _unknown_until = max(_unknown_until, max(dropped.values()) + MARK_TTL_SECONDS)
    return first


def labels(session: str) -> frozenset[SessionLabel] | None:
    """The live labels on *session*.

    None when there is no session to ask about, or when it has no entry but
    the table has dropped one recently enough that it might have been this
    session's.
    """
    if not session:
        return None
    now = time.monotonic()
    entry = _marks.get(session)
    if entry is not None:
        for label in [lb for lb, at in entry.items() if now - at > MARK_TTL_SECONDS]:
            del entry[label]
        if entry:
            return frozenset(entry)
        # The entry outlived every label in it; an expired one is not a drop.
        del _marks[session]
        return frozenset()
    return None if now < _unknown_until else frozenset()


def was_flagged(session: str) -> bool | None:
    """Whether *session* carries a live ``FLAG_LABELS`` label, None when unknown."""
    live = labels(session)
    return None if live is None else bool(live & FLAG_LABELS)


def clear() -> None:
    """Forget every mark. For tests."""
    global _unknown_until
    _marks.clear()
    _unknown_until = 0.0


async def _mark_session(assembled: Assembled, internal: Any = None) -> None:
    """Label the session for what a delivered response carried (#456, #861).

    ``flagged_delivery`` when the content was flagged or partly judged,
    ``credential_seen`` when the text the agent receives holds a credential
    shape. A refused response reached the agent as a refusal, not as content,
    so it labels nothing. An internal tool judges its own content and says so
    in the result it returns, which is where its warning is read (``internal``).
    """
    if assembled.outcome not in (Outcome.OK, Outcome.TOOL_ERROR):
        return
    session = current_session.get()
    if not session:
        return
    if assembled.warning is not None or (internal is not None and _carries_warning(internal)):
        _log_first(session, SessionLabel.FLAGGED_DELIVERY, "")
    # Off the loop: linear, but in the response's size.
    found = await asyncio.to_thread(credential_kinds, _delivered_text(assembled.result))
    if found:
        # The kinds, never the matched text.
        _log_first(session, SessionLabel.CREDENTIAL_SEEN, ",".join(sorted(found)))


def _log_first(session: str, label: SessionLabel, detail: str) -> None:
    if mark(session, label):
        # The label's origin, once per session: the call_ref joins it to the
        # audit row of the response that set it (#457).
        logger.info(
            "gateway: session %s… labelled %s%s by call_ref=%s",
            session[:8],
            label.value,
            f" ({detail})" if detail else "",
            current_call.get() or "?",
        )


def _delivered_text(result: dict[str, Any]) -> str:
    """The text a delivered tools/call result puts in front of the agent."""
    parts: list[str] = []
    for block in result.get("content") or ():
        if not isinstance(block, dict):
            continue
        text = block.get("text")
        if isinstance(text, str):
            parts.append(text)
        resource = block.get("resource")
        if isinstance(resource, dict):
            # A URI carries a credential as readily as a body: ?token=, user:pass@.
            parts.extend(v for k in ("uri", "text") if isinstance(v := resource.get(k), str))
        if isinstance(block.get("uri"), str):
            parts.append(block["uri"])
    structured = result.get("structuredContent")
    if structured is not None:
        parts.append(json.dumps(structured, ensure_ascii=False, default=str))
    return "\n".join(parts)


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
