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

Nor may a fresh session launder a marked one (#900). An agent sheds its
labels by starting over: ``initialize`` mints a new session, and an id this
process never issued is adopted (``sessions.adopt``), and either way the
fingerprint is new and reads clean. So a mark also records when the
session's profile was last marked, the profile taken from the request that
set it (``current_session_profile``), never from a table a teardown can
empty first. For the profile's ``session_mark_cooldown_seconds`` after that
mark, a session newly minted or adopted for it (:func:`admit`) starts
unknown (None), and ``refuse_when`` refuses it until the window passes.
Sessions that already existed keep their own labels: a mark on one session
never touches another.

Admissions live in a table of their own, never in ``_marks``: a flood of
cheap ``initialize`` calls from a marked profile must not evict another
profile's marks and widen the gateway-wide unknown window. Past
``MAX_MARKS`` unknown admissions the oldest is dropped, and the window it
held moves to its profile alone (``_overflow_until``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from ..credential_shapes import kinds as credential_kinds
from ..outcomes import Outcome
from ..reserved import WARNING_KEY
from .context import current_call, current_session, current_session_profile

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


@dataclass
class _Entry:
    labels: dict[SessionLabel, float] = field(default_factory=dict)
    """Each live label and the monotonic time it was last set."""
    unknown_until: float = 0.0
    """Set when the entry was created while a dropped entry could have been
    this session's: until then the labels here are not its whole history."""


_marks: OrderedDict[str, _Entry] = OrderedDict()
_unknown_until = 0.0
"""Monotonic time before which a session with no entry may be one we dropped."""
_profile_marked: dict[str, float] = {}
"""Profile name to the monotonic time any of its sessions was last marked."""
_admitted: OrderedDict[str, tuple[str, float]] = OrderedDict()
"""Session admitted inside its profile's cool-down: (profile, unknown until)."""
_overflow_until: dict[str, float] = {}
"""Profile to the time before which a session of it with no admission entry
may be one ``_admitted`` dropped."""


def mark(session: str, label: SessionLabel, profile: str | None = None) -> bool:
    """Set *label* on *session*.

    Returns True when the label was not already live, so the caller can log
    the call that set it once rather than on every call after. *profile*
    defaults to the one the request bound (``current_session_profile``).
    """
    global _unknown_until
    if not session:
        return False
    current = labels(session)
    first = current is None or label not in current
    now = time.monotonic()
    owner = profile or current_session_profile.get()
    if owner:
        _profile_marked[owner] = now
    # A session evicted by a flood and labelled again must not read as having
    # only its new label: its dropped ones may have refused it. A window
    # already past reads as known, so it needs no special case.
    _marks.setdefault(session, _Entry(unknown_until=_unknown_until)).labels[label] = now
    _marks.move_to_end(session)
    while len(_marks) > MAX_MARKS:
        _, dropped = _marks.popitem(last=False)
        if _unknown_until <= now:
            logger.warning(
                "session marks: table full at %d, dropping the oldest; unmarked "
                "sessions read as unknown until the dropped marks expire",
                MAX_MARKS,
            )
        _unknown_until = max(_unknown_until, max(dropped.labels.values()) + MARK_TTL_SECONDS)
    return first


def admit(session: str, profile: str, cooldown_seconds: float) -> bool:
    """Register a session newly minted or adopted for *profile* (#900).

    Within *cooldown_seconds* of the last mark on any of the profile's
    sessions, the new session starts unknown until that window passes, so
    starting over does not shed a label. 0 turns it off. Returns True when
    the session starts unknown.
    """
    if not session:
        return False
    marked = _profile_marked.get(profile)
    now = time.monotonic()
    if cooldown_seconds <= 0 or marked is None or now >= marked + cooldown_seconds:
        return False
    _admitted[session] = (profile, marked + cooldown_seconds)
    _admitted.move_to_end(session)
    while _admitted and _admitted[next(iter(_admitted))][1] <= now:
        _admitted.popitem(last=False)
    while len(_admitted) > MAX_MARKS:
        _, (dropped_profile, until) = _admitted.popitem(last=False)
        _overflow_until[dropped_profile] = max(_overflow_until.get(dropped_profile, 0.0), until)
    logger.info(
        "gateway: session %s… admitted unknown for profile=%s, marked %.0fs ago (cool-down %.0fs)",
        session[:8],
        profile,
        now - marked,
        cooldown_seconds,
    )
    return True


def labels(session: str) -> frozenset[SessionLabel] | None:
    """The live labels on *session*.

    None when there is no session to ask about, or when the table has dropped
    an entry recently enough that it might have been this session's: whether
    this session has an entry since or not.
    """
    if not session:
        return None
    now = time.monotonic()
    # Inside the cool-down it was admitted in (#900), or possibly so: its
    # profile's admissions overflowed and this one may have been dropped.
    admitted = _admitted.get(session)
    if admitted is None:
        if now < _overflow_until.get(current_session_profile.get(), 0.0):
            return None
    elif now < admitted[1]:
        return None
    else:
        del _admitted[session]
    entry = _marks.get(session)
    if entry is None:
        return None if now < _unknown_until else frozenset()
    entry.labels = {lb: at for lb, at in entry.labels.items() if now - at <= MARK_TTL_SECONDS}
    known = now >= entry.unknown_until
    if known and not entry.labels:
        # The entry outlived every label in it; an expired one is not a drop.
        del _marks[session]
    return frozenset(entry.labels) if known else None


def was_flagged(session: str) -> bool | None:
    """Whether *session* carries a live ``FLAG_LABELS`` label, None when unknown."""
    live = labels(session)
    return None if live is None else bool(live & FLAG_LABELS)


def clear() -> None:
    """Forget every mark. For tests."""
    global _unknown_until
    _marks.clear()
    _profile_marked.clear()
    _admitted.clear()
    _overflow_until.clear()
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
