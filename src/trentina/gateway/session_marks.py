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

Nor may a session launder a marked one by moving to another session of the
same profile (#900): one opened beforehand, a fresh ``initialize``, or an id
this process never issued and adopts (``sessions.adopt``). So a mark the
profile's guards refuse on opens a window on its PROFILE: for
``session_mark_cooldown_seconds`` every other session of that profile, live
or new, reads unknown (None) and ``refuse_when`` refuses it. The session that
opened it owns it and keeps reading its own labels; a later refusing mark only
extends it, so no other session can take it by earning a label of its own. The
profile is the one the request bound (:func:`bind`, ``current_session_profile``),
never a per-session table a teardown or a flood could empty first, so the
state is one entry per profile and a flood of sessions costs nothing.

Only an operator takes a mark or a window back (:func:`clear_marks`, the
``session_marks_clear`` tool, a1724): a false positive otherwise held a
profile until its window passed or the gateway restarted.
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
COOLDOWN_DEFAULT = 1800.0
"""Seconds a profile's other sessions read unknown after a mark (#900)."""
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
    profile: str = ""
    """The profile bound when the entry was made, so an operator can clear a
    profile's sessions (:func:`clear_marks`). Empty when none was bound."""


_marks: OrderedDict[str, _Entry] = OrderedDict()
_unknown_until = 0.0
"""Monotonic time before which a session with no entry may be one we dropped."""
_policies: dict[str, tuple[float, frozenset[SessionLabel]]] = {}
"""Profile to its cool-down and the labels its guards refuse on, as last bound.
A profile never bound is held to the default cool-down on every label."""
_windows: dict[str, tuple[float, str]] = {}
"""Profile to (cool-down end, the session whose mark opened it). The owner is
pinned for the life of the window: a later mark extends it, never takes it."""


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
        _open_window(owner, session, label, now)
    else:
        logger.warning(
            "session marks: no profile bound for session %s… (%s); no cool-down opened",
            session[:8],
            label.value,
        )
    # A session evicted by a flood and labelled again must not read as having
    # only its new label: its dropped ones may have refused it. A window
    # already past reads as known, so it needs no special case.
    entry = _marks.setdefault(session, _Entry(unknown_until=_unknown_until, profile=owner))
    entry.labels[label] = now
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


def _open_window(profile: str, session: str, label: SessionLabel, now: float) -> None:
    """Open or extend *profile*'s cool-down for a refusing *label* (#900).

    Only a label the profile's guards refuse on opens one: a label that
    refuses nothing must neither lock every seat nor hand the window to a
    session that carries it. The first marker owns the window until it
    closes; another session's refusing mark only moves the end later.
    """
    cooldown, refusing = _policies.get(profile, (COOLDOWN_DEFAULT, frozenset(SessionLabel)))
    if cooldown <= 0 or label not in refusing:
        return
    window = _windows.get(profile)
    if window is not None and now < window[0]:
        _windows[profile] = (max(window[0], now + cooldown), window[1])
    else:
        _windows[profile] = (now + cooldown, session)


def bind(profile: str, cooldown_seconds: float, refusing: frozenset[SessionLabel]) -> None:
    """Bind the request's profile and record its cool-down policy (#900).

    Called at the gateway edge beside ``current_session``, so every mark and
    every read inside the request knows the profile without a table lookup.
    """
    current_session_profile.set(profile)
    _policies[profile] = (cooldown_seconds, refusing)


def labels(session: str) -> frozenset[SessionLabel] | None:
    """The live labels on *session*.

    None when there is no session to ask about, or when the table has dropped
    an entry recently enough that it might have been this session's: whether
    this session has an entry since or not.
    """
    if not session:
        return None
    now = time.monotonic()
    # Another session of a profile marked within its cool-down (#900): one
    # opened beforehand or since, minted or adopted, all read unknown.
    window = _windows.get(current_session_profile.get())
    if window is not None and now < window[0] and session != window[1]:
        return None
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


def matching_sessions(prefix: str) -> list[str]:
    """The sessions holding a mark or a window whose fingerprint starts with *prefix*.

    The log names a session by its first eight characters, so that is what an
    operator has to hand.
    """
    held = set(_marks) | {owner for _, owner in _windows.values()}
    return sorted(s for s in held if s.startswith(prefix))


def clear_marks(
    *, profile: str | None = None, session: str | None = None, everything: bool = False
) -> dict[str, Any]:
    """Forget marks and cool-down windows; the operator's way out of a false positive.

    *profile* drops that profile's window and the marks of every session made
    under it; *session* drops that session's marks and any window it owns;
    *everything* empties the table. Both a profile and a session clear the
    union. A session still reads unknown afterwards while a flood-dropped
    entry could have been its own (``_unknown_until``), unless *everything*
    was cleared; the result says how long that lasts.

    Returns:
        ``windows`` and ``sessions`` removed (live ones only, sessions by
        their first eight characters), and ``dropped_unknown_seconds`` when
        a flood still leaves unmarked sessions unknown.
    """
    global _unknown_until
    now = time.monotonic()
    windows = {
        p: w
        for p, w in _windows.items()
        if everything or p == profile or (session and w[1] == session)
    }
    sessions = {
        s: e
        for s, e in _marks.items()
        if everything or s == session or (profile and e.profile == profile)
    }
    for p in windows:
        del _windows[p]
    for s in sessions:
        del _marks[s]
    if everything:
        _unknown_until = 0.0
    result: dict[str, Any] = {
        "windows": [
            {"profile": p, "remaining_seconds": round(end - now), "owner": owner[:8]}
            for p, (end, owner) in sorted(windows.items())
            if now < end
        ],
        "sessions": [
            {"session": s[:8], "profile": e.profile, "labels": sorted(live)}
            for s, e in sessions.items()
            if (live := [lb.value for lb, at in e.labels.items() if now - at <= MARK_TTL_SECONDS])
        ],
    }
    if now < _unknown_until:
        result["dropped_unknown_seconds"] = round(_unknown_until - now)
    return result


def clear() -> None:
    """Forget every mark. For tests."""
    global _unknown_until
    _marks.clear()
    _policies.clear()
    _windows.clear()
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
