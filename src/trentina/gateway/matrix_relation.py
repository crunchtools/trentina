"""What a withheld Matrix event's ``m.relates_to`` may keep (#296).

A withheld event is replaced by a notice, and the notice keeps the event's
relation so a thread, reply or edit still points where it did. The relation
arrived with the event and was not judged, so it is rebuilt from an
allowlist rather than copied: a key nobody listed (``note``, an MSC's
extension, anything a sender invents) is where an injection rides past a
verdict that withheld the body. One rule for the bridge's notice
(``matrix_bridge/core.py``) and the proxy's (``matrix_proxy.py``).

Kept: ``rel_type`` from a closed set, ``event_id``, ``m.in_reply_to.event_id``
and a boolean ``is_falling_back``. Every ID must have an event ID's shape
and not read as words.
``m.annotation`` is not kept, and neither is its ``key``: a reaction key is
free text the sender chose, and a notice is not a reaction.
"""

from __future__ import annotations

import re
from typing import Any

from ..transforms.shapes import wordy

_REL_TYPES = frozenset({"m.thread", "m.reference", "m.replace"})

# One sigil, then printable ASCII with no whitespace, as long as an ID may be.
_EVENT_ID = re.compile(r"\$[\x21-\x7e]{1,254}")


def _event_id(value: Any) -> str | None:
    # The shape alone admits `$ignore.all.previous.instructions:x`; a legacy
    # ID's localpart is free text, so one that reads as words is not kept.
    if not isinstance(value, str) or not _EVENT_ID.fullmatch(value) or wordy(value[1:]):
        return None
    return value


def withheld_relation(relation: Any) -> dict[str, Any] | None:
    """The allowlisted part of ``relation``, or None when nothing survives."""
    if not isinstance(relation, dict):
        return None
    out = _typed_part(relation)
    reply = relation.get("m.in_reply_to")
    reply_to = _event_id(reply.get("event_id")) if isinstance(reply, dict) else None
    if reply_to is not None:
        out["m.in_reply_to"] = {"event_id": reply_to}
    return out or None


def _typed_part(relation: dict[str, Any]) -> dict[str, Any]:
    """``rel_type`` and its target, kept only together, with the fallback flag."""
    rel_type = relation.get("rel_type")
    target = _event_id(relation.get("event_id"))
    if not isinstance(rel_type, str) or rel_type not in _REL_TYPES or target is None:
        return {}
    kept: dict[str, Any] = {"rel_type": rel_type, "event_id": target}
    if isinstance(relation.get("is_falling_back"), bool):
        kept["is_falling_back"] = relation["is_falling_back"]
    return kept
