"""Translate the IDs inside an event's content from one side to the other.

Runs AFTER the verdict, on content that was judged as it arrived. It changes
identifiers only — event IDs in relations, user IDs in mentions, and the
agent's own ID where it appears in the text — so nothing it writes is prose
and nothing it writes was unjudged.

A relation that points at an event the other side never saw is dropped rather
than left dangling. The one exception is a reaction: it has no content of its
own, so a reaction to an unknown event means nothing and is not delivered.

The event IDs a relation points at are therefore never delivered as written:
each is replaced from the mapping table or dropped. ``judged_view`` leaves
them out of what the layers read, because an opaque ID reads to a classifier
as encoded text and withheld every reaction and reply that carried one.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, unquote

from .media import has_media, strip_media

if TYPE_CHECKING:
    from collections.abc import Mapping

# The characters carried through unescaped. '_' and '=' are the escape
# characters themselves and uppercase is folded, so neither appears here; '/'
# is legal in a localpart but escaped anyway, so no stand-in ID can carry a
# path separator into a URL.
_PLAIN = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")

_TEXT_FIELDS = ("body", "formatted_body")

# A Matrix user ID as it appears in prose, and percent-encoded as it appears
# in a matrix.to link. Linear: one character class per part, no nesting.
_USER_ID = re.compile(r"@[A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(?::[0-9]{1,5})?")
_ENCODED_USER_ID = re.compile(r"%40[A-Za-z0-9._=/+%-]+%3[Aa][A-Za-z0-9.-]+(?:%3[Aa][0-9]{1,5})?")


def escape_localpart(user_id: str) -> str:
    """A remote user ID as a localpart, per the spec's character-set mapping.

    ``_`` doubles, an uppercase letter becomes ``_`` plus its lowercase, and
    anything else is ``=`` plus the hex of each UTF-8 byte. Reversible, so two
    remote IDs never collide on one stand-in.
    """
    out: list[str] = []
    for ch in user_id.removeprefix("@"):
        if ch == "_":
            out.append("__")
        elif "A" <= ch <= "Z":
            out.append("_" + ch.lower())
        elif ch in _PLAIN:
            out.append(ch)
        else:
            out.extend(f"={byte:02x}" for byte in ch.encode("utf-8"))
    return "".join(out)


@dataclass(frozen=True)
class IdMap:
    """How to translate identifiers in one direction, resolved beforehand for
    exactly the IDs one message references (``referenced_ids``). An ID with
    no entry has no counterpart on the other side: in a relation or a
    mention it is dropped, and in text it is left as written."""

    events: Mapping[str, str]
    users: Mapping[str, str]


def referenced_ids(content: dict[str, Any]) -> tuple[set[str], set[str]]:
    """The event IDs a message relates to and the user IDs it names."""
    events: set[str] = set()
    relation = content.get("m.relates_to")
    if isinstance(relation, dict):
        if isinstance(relation.get("event_id"), str):
            events.add(relation["event_id"])
        reply = relation.get("m.in_reply_to")
        if isinstance(reply, dict) and isinstance(reply.get("event_id"), str):
            events.add(reply["event_id"])
    users = user_ids_in(content)
    for holder in (content, content.get("m.new_content")):
        mentions = holder.get("m.mentions") if isinstance(holder, dict) else None
        if isinstance(mentions, dict) and isinstance(mentions.get("user_ids"), list):
            users.update(u for u in mentions["user_ids"] if isinstance(u, str))
    return events, users


def judged_view(content: dict[str, Any]) -> dict[str, Any]:
    """``content`` as the layers read it: without the relation's event IDs.

    Leaves out exactly the IDs ``_rewrite_relation`` and ``_rewrite_reply``
    replace or drop, and only where they would: an ``event_id`` that is not a
    string is delivered as it arrived, so it stays in and is judged. The
    reaction ``key``, ``rel_type`` and every other field are judged as sent.

    Media URIs, an encrypted file's key and hashes, and thumbnails are left
    out too (#491): none crosses, and the attachment itself is judged in
    their place.
    """
    if has_media(content):
        content = strip_media(content)
    relation = content.get("m.relates_to")
    if not isinstance(relation, dict):
        return content
    seen = _without_event_id(relation)
    if isinstance(seen.get("m.in_reply_to"), dict):
        seen["m.in_reply_to"] = _without_event_id(seen["m.in_reply_to"])
    return {**content, "m.relates_to": seen}


def _without_event_id(holder: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``holder`` minus a string ``event_id``."""
    return {k: v for k, v in holder.items() if k != "event_id" or not isinstance(v, str)}


def user_ids_in(content: dict[str, Any]) -> set[str]:
    """Every user ID written in the message's text, pills included.

    Lets a caller resolve only the IDs a message actually names, instead of
    replacing against every user it has ever seen.
    """
    found: set[str] = set()
    for holder in (content, content.get("m.new_content")):
        if not isinstance(holder, dict):
            continue
        for field in _TEXT_FIELDS:
            value = holder.get(field)
            if isinstance(value, str):
                found.update(_USER_ID.findall(unquote(value)))
    return found


def rewrite_content(content: dict[str, Any], ids: IdMap) -> dict[str, Any] | None:
    """``content`` with its identifiers translated, or None if it means nothing
    on the other side."""
    out = copy.deepcopy(content)
    if not _rewrite_relation(out, ids):
        return None
    _rewrite_mentions(out, ids)
    _rewrite_text(out, ids.users)
    new_content = out.get("m.new_content")
    if isinstance(new_content, dict):
        _rewrite_mentions(new_content, ids)
        _rewrite_text(new_content, ids.users)
    return out


def _rewrite_relation(content: dict[str, Any], ids: IdMap) -> bool:
    """Translate ``m.relates_to`` in place. False means drop the event."""
    relation = content.get("m.relates_to")
    if not isinstance(relation, dict):
        content.pop("m.relates_to", None)
        return True
    rel_type = relation.get("rel_type")
    target = relation.get("event_id")
    if isinstance(target, str):
        mapped = ids.events.get(target)
        if mapped is not None:
            relation["event_id"] = mapped
        elif rel_type == "m.annotation":
            return False
        else:
            for key in ("rel_type", "event_id", "is_falling_back"):
                relation.pop(key, None)
            if rel_type == "m.replace":
                # The edit's own body ("* new text") stands as a message.
                content.pop("m.new_content", None)
    _rewrite_reply(relation, ids)
    if not relation:
        content.pop("m.relates_to")
    return True


def _rewrite_reply(relation: dict[str, Any], ids: IdMap) -> None:
    reply = relation.get("m.in_reply_to")
    if not isinstance(reply, dict) or not isinstance(reply.get("event_id"), str):
        return
    mapped = ids.events.get(reply["event_id"])
    if mapped is None:
        relation.pop("m.in_reply_to")
    else:
        reply["event_id"] = mapped


def _rewrite_mentions(content: dict[str, Any], ids: IdMap) -> None:
    mentions = content.get("m.mentions")
    if not isinstance(mentions, dict):
        return
    user_ids = mentions.get("user_ids")
    if isinstance(user_ids, list):
        mapped = [ids.users.get(u) for u in user_ids if isinstance(u, str)]
        mentions["user_ids"] = [u for u in mapped if u is not None]


def _rewrite_text(content: dict[str, Any], users: Mapping[str, str]) -> None:
    """Replace mapped user IDs in the text fields, in one pass per field."""

    def plain(match: re.Match[str]) -> str:
        return users.get(match.group(0), match.group(0))

    def encoded(match: re.Match[str]) -> str:
        mapped = users.get(unquote(match.group(0)))
        return quote(mapped, safe="") if mapped else match.group(0)

    for field in _TEXT_FIELDS:
        value = content.get(field)
        if isinstance(value, str):
            content[field] = _ENCODED_USER_ID.sub(encoded, _USER_ID.sub(plain, value))
