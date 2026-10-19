"""The RCS bridge: one agent's sender, one owner's phone, one room.

The upstream has no rooms, so the bridge makes up exactly one: the agent's
DM with the owner, announced to the gateway on every start with the owner as
its only other member (so the gateway's agent rule passes it, and openclaw's
strict two-member DM rule holds). Every message from the owner goes there;
every reply the gateway hands back from there goes to the owner's phone.

Nothing is lost inbound: the webhook writes a message to the store before
Twilio hears 200, and it leaves the store only when the gateway acks it.
Nothing is sent twice outbound: each chunk of a reply is recorded by the
gateway's ``txn_id`` as it goes.

Media (#493): an attachment from the owner is fetched from Twilio at
delivery and handed to the gateway with its event, which judges and re-hosts
it. One the agent sends arrives judged through ``/upload``; the bridge holds
it under an unguessable ID and Twilio fetches it from the public listener.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import mimetypes
import re
import secrets
import time
from typing import TYPE_CHECKING, Any

import httpx

from ..bridge.media import MAX_NAME_CHARS
from ..logsafe import exc_kind, redact_source
from .backend import BackendError, Inbound
from .store import MediaFullError
from .text import chunks, flatten
from .twilio import MAX_BODY

if TYPE_CHECKING:
    from .backend import Backend
    from .settings import RcsSettings
    from .store import RcsStore

logger = logging.getLogger(__name__)

ROOM_ANNOUNCE = "org.crunchtools.trentina.room"
ROOM_REFUSED = "refused"
_TEXT_TYPES = frozenset({"m.text", "m.notice", "m.emote"})
_MEDIA_TYPES = frozenset({"m.image", "m.file", "m.video", "m.audio"})
# The msgtype an attachment from the phone gets, by its declared type.
_MSGTYPE_BY_KIND = {"image": "m.image", "video": "m.video", "audio": "m.audio"}
_MEDIA_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,255}")
_CONTENT_TYPE_RE = re.compile(r"[A-Za-z0-9.+-]{1,127}/[A-Za-z0-9.+-]{1,127}")
_OCTET = "application/octet-stream"
# What an outbound attachment may be served as. Anything else, HTML and SVG
# above all, goes as octets: the public route is on a real origin.
_SERVED_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "video/mp4",
        "video/3gpp",
        "audio/mpeg",
        "audio/mp4",
        "audio/ogg",
        "application/pdf",
        "text/plain",
    }
)
# The event ID a dropped reaction gets: the gateway maps it like any other, so
# its later redaction comes back here and is answered as done.
DROPPED_PREFIX = "$rcs-dropped-"
EDITED_PREFIX = "(edited) "
_MAX_BACKOFF = 60.0
# The store is pruned at least this often, so a bridge that only sends still
# drops old send records.
PRUNE_EVERY = 3600.0
_GATEWAY_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)
# At most one typing indicator per this many seconds (#1533). Twilio shows
# one about 20 s, and the gateway re-sends a still-typing agent every 15 s.
TYPING_EVERY = 12.0


def _carried_text(content: dict[str, Any]) -> tuple[Any, Any]:
    """The msgtype and body a message carries: an edit's are its new
    content's, with the body marked as an edit; an edit without new content
    carries nothing."""
    relates = content.get("m.relates_to")
    if not (isinstance(relates, dict) and relates.get("rel_type") == "m.replace"):
        return content.get("msgtype"), content.get("body")
    new = content.get("m.new_content")
    if not isinstance(new, dict) or not isinstance(new.get("body"), str):
        return None, None
    return new.get("msgtype"), EDITED_PREFIX + new["body"]


def _media_holder(content: dict[str, Any]) -> dict[str, Any]:
    """The content that names an event's media: an edit's new content, else
    the content itself."""
    new = content.get("m.new_content")
    relates = content.get("m.relates_to")
    if (
        isinstance(relates, dict)
        and relates.get("rel_type") == "m.replace"
        and isinstance(new, dict)
    ):
        return new
    return content


def _placeholder_id(message: Inbound, idx: int) -> str:
    """A media ID to name an inbound attachment by: Twilio's own, when it is
    one an ``mxc://`` URI can carry."""
    media_id = message.media[idx][0].rstrip("/").rpartition("/")[2]
    return media_id if _MEDIA_ID_RE.fullmatch(media_id) else f"{message.message_id}-{idx}"


def _caption(holder: dict[str, Any]) -> str:
    """An attachment's caption: its body when a separate ``filename`` names
    the file, since otherwise the body is only the file's name."""
    body, name = holder.get("body"), holder.get("filename")
    return body if isinstance(body, str) and isinstance(name, str) and body != name else ""


class RefusedError(ValueError):
    """An event this channel has no form for. The API answers 422, which the
    gateway takes as "never" (docs/channel-bridges.md). ``reason`` is ours,
    from a closed set, and safe to log; the message text never is."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UnavailableError(RuntimeError):
    """The provider did not take a message this time. The API answers 502,
    and the gateway retries. ``reason`` as for ``RefusedError``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RcsBridge:
    """Args:
    settings: this bridge's configuration.
    backend: the RCS provider.
    store: the inbox and the sent log.
    gateway: an HTTP client for the gateway, instead of a fresh one. The
        bridge owns it, the backend and the store; ``aclose`` closes all.
    """

    def __init__(
        self,
        settings: RcsSettings,
        backend: Backend,
        store: RcsStore,
        gateway: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.backend = backend
        self.store = store
        # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
        self._gateway = gateway or httpx.AsyncClient(timeout=_GATEWAY_TIMEOUT)
        self._label = f"{settings.profile}/{settings.channel}"
        self._event_url = (
            f"{settings.gateway_url}/bridge/{settings.profile}/{settings.channel}/event"
        )
        self._wake = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._typing_at = float("-inf")
        self.ready = asyncio.Event()

    async def aclose(self) -> None:
        await self._gateway.aclose()
        await self.backend.aclose()
        self.store.close()

    # ------------------------------------------------------------ inbound

    def _room_info(self) -> dict[str, Any]:
        s = self.settings
        return {
            "name": "",
            "topic": s.room_topic,
            "is_direct": True,
            "peer": s.owner_user_id,
            "peer_displayname": s.owner_name,
        }

    async def announce(self) -> None:
        """Tell the gateway the room exists and who is in it, until it answers."""
        s = self.settings
        members = [s.owner_user_id]
        digest = hashlib.sha256("\n".join(members).encode()).hexdigest()[:16]
        outcome = await self.forward(
            {
                "room_id": s.room_id,
                "event_id": f"room:{s.room_id}:{digest}",
                "sender": s.agent_user_id,
                "type": ROOM_ANNOUNCE,
                "content": {},
                "room": self._room_info() | {"members": members},
            }
        )
        if outcome == ROOM_REFUSED:
            # Only the agent rule refuses a room, and this one holds nobody
            # but the owner: a misconfiguration, not something to carry on with.
            raise SystemExit(f"bridge[{self._label}]: the gateway refused the owner's room")
        self.ready.set()

    async def accept(self, message: Inbound) -> bool:
        """Hold one message from the owner for delivery. False: a duplicate."""
        taken = await self.store.put(message)
        if taken:
            self._wake.set()
        return taken

    def _payload(self, message: Inbound, content: dict[str, Any], idx: int = 0) -> dict[str, Any]:
        s = self.settings
        suffix = f"-{idx}" if idx else ""
        return {
            "room_id": s.room_id,
            "event_id": f"$rcs-{message.message_id}{suffix}",
            "sender": s.owner_user_id,
            "sender_displayname": s.owner_name,
            "type": "m.room.message",
            "content": content,
            "room": self._room_info(),
        }

    def _media_content(self, message: Inbound, idx: int) -> dict[str, Any]:
        """The event for one attachment. Its ``url`` only names the media for
        the gateway, which strips it and re-hosts the bytes sent alongside."""
        declared = message.media[idx][1]
        declared = declared[:MAX_NAME_CHARS] if _CONTENT_TYPE_RE.fullmatch(declared) else ""
        name = f"attachment-{idx + 1}{mimetypes.guess_extension(declared) or ''}"
        info = {"info": {"mimetype": declared}} if declared else {}
        return {
            "msgtype": _MSGTYPE_BY_KIND.get(declared.partition("/")[0], "m.file"),
            # The owner's text rides on the first attachment, as its caption.
            "body": (message.body if idx == 0 and message.body else name),
            "filename": name,
            "url": f"mxc://{self.settings.server}/{_placeholder_id(message, idx)}",
            **info,
        }

    async def _deliver(self, message: Inbound) -> None:
        """Hand one message to the gateway: its text, or one event per
        attachment, each fetched just before it goes so only one is ever
        held in memory."""
        if not message.media:
            await self.forward(self._payload(message, {"msgtype": "m.text", "body": message.body}))
            return
        for idx in range(len(message.media)):
            payload = self._payload(message, self._media_content(message, idx), idx)
            payload["media"] = await self.backend.fetch_media(message.media[idx][0])
            await self.forward(payload)

    async def run(self) -> None:
        """Announce the room, then deliver the inbox, in order, forever."""
        await self.announce()
        while True:
            self._wake.clear()
            for message in await self.store.pending():
                await self._deliver(message)
                await self.store.delivered(message.message_id)
            await self.store.prune()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), PRUNE_EVERY)

    async def forward(self, payload: dict[str, Any]) -> str:
        """POST to the gateway until it takes the event; its outcome.

        As the Matrix bridge does (``bridge/client.py``): a 4xx other than an
        auth failure or a rate limit is never going to be taken, so it is
        logged and dropped rather than stall every message behind it.
        """
        backoff = 1.0
        headers = {"Authorization": f"Bearer {self.settings.ingress_token}"}
        event_id = redact_source(str(payload.get("event_id")))
        while True:
            try:
                resp = await self._gateway.post(self._event_url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                status = 0
                why = exc_kind(exc)
            else:
                status, why = resp.status_code, str(resp.status_code)
                if status == 200:
                    try:
                        outcome = resp.json().get("outcome")
                    except (ValueError, AttributeError):
                        outcome = None
                    return outcome if isinstance(outcome, str) else ""
                if 400 <= status < 500 and status not in (401, 403, 429):
                    logger.error("bridge[%s]: gateway refused %s: %s", self._label, event_id, why)
                    return ""
            logger.warning(
                "bridge[%s]: gateway unavailable for %s (%s), retrying", self._label, event_id, why
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)

    # ----------------------------------------------------------- outbound

    async def typing(self, room_id: str, typing: bool) -> None:
        """Show the agent typing on the owner's phone (#1533). Best effort.

        Stopping is a no-op: RCS has no stop, and the reply clears the
        bubble. Starting is throttled to one indicator per ``TYPING_EVERY``.

        Raises:
            RefusedError: not the owner's room.
            UnavailableError: the provider did not take it.
        """
        if room_id != self.settings.room_id:
            raise RefusedError("not the owner's room")
        now = time.monotonic()
        if not typing or now - self._typing_at < TYPING_EVERY:
            return
        self._typing_at = now
        try:
            await self.backend.send_typing(self.settings.owner_number)
        except BackendError as exc:
            # Not shown, so the next push may try again at once.
            self._typing_at = float("-inf")
            raise UnavailableError(exc.reason) from exc

    async def upload(
        self, room_id: str, plaintext: bytes, content_type: str, _filename: str
    ) -> dict[str, str]:
        """Hold one judged attachment for Twilio to fetch; the ``mxc`` URI the
        gateway sends it under, which only this bridge resolves (#493).

        Raises:
            RefusedError: not the owner's room, or no public media URL.
            UnavailableError: ``MAX_HELD_MEDIA`` already held; try later.
        """
        if room_id != self.settings.room_id:
            raise RefusedError("not the owner's room")
        if self.settings.media_url is None:
            raise RefusedError("no public media URL configured")
        content_type = content_type.partition(";")[0].strip().lower()
        if content_type not in _SERVED_TYPES:
            content_type = _OCTET
        media_id = secrets.token_urlsafe(32)
        try:
            await self.store.hold_media(media_id, content_type, plaintext)
        except MediaFullError as exc:
            raise UnavailableError("media store full") from exc
        return {"url": f"mxc://{self.settings.server}/{media_id}"}

    async def _media_link(self, holder: dict[str, Any]) -> str:
        """The public URL Twilio fetches an uploaded attachment from.

        Raises:
            RefusedError: not media this bridge holds (expired, or never
                uploaded here).
        """
        server, _, media_id = str(holder.get("url") or "").removeprefix("mxc://").partition("/")
        if (
            server != self.settings.server
            or self.settings.media_url is None
            or not _MEDIA_ID_RE.fullmatch(media_id)
            or await self.store.held_media(media_id) is None
        ):
            raise RefusedError("attachment not held by this bridge")
        return f"{self.settings.media_url}/{media_id}"

    async def send(
        self, room_id: str, event_type: str, content: dict[str, Any], txn_id: str
    ) -> str:
        """Send one judged event to the owner's phone; the event ID it gets.

        A reaction is accepted and dropped: on RCS it would be a billed
        message that says nothing the owner needs, and refusing it would
        tell the agent, every turn, that its message was not sent. An edit
        goes out as its new text, marked as an edit, since a phone cannot
        replace a message it already has.

        At least once, per chunk: a chunk is recorded once Twilio answers, so
        one whose answer is lost (a timeout after Twilio took it) is sent
        again on the gateway's retry. Twilio's Messages API takes no
        idempotency key, so this is the strongest guarantee it allows.

        Raises:
            RefusedError: not a text or media message in the owner's room,
                empty, or media this bridge does not hold.
            UnavailableError: the provider did not take a chunk; the chunks
                that went are recorded, so the gateway's retry sends the rest.
        """
        if room_id != self.settings.room_id:
            raise RefusedError("not the owner's room")
        if event_type == "m.reaction":
            return DROPPED_PREFIX + hashlib.sha256(txn_id.encode()).hexdigest()[:32]
        async with self._send_lock:
            done = await self.store.sent(txn_id)
            # Once the media went, a retry needs only the chunks after it,
            # and must not fail because the media has since expired.
            pieces, media_link = await self._pieces(event_type, content, need_media=0 not in done)
            for idx, piece in enumerate(pieces):
                if idx in done:
                    continue
                try:
                    done[idx] = await self._send_piece(piece, media_link if idx == 0 else None)
                except BackendError as exc:
                    # Permanent even after earlier chunks went: retrying the
                    # same chunk would fail the same way, forever.
                    if exc.permanent:
                        raise RefusedError(exc.reason) from exc
                    raise UnavailableError(exc.reason) from exc
                await self.store.record(txn_id, idx, done[idx])
        return f"$rcs-{done[0]}"

    async def _pieces(
        self, event_type: str, content: dict[str, Any], *, need_media: bool = True
    ) -> tuple[list[str], str | None]:
        """The chunks a message goes as, and the attachment's public URL if
        it has one and ``need_media``.

        Raises:
            RefusedError: no RCS form for it, empty, or media not held here.
        """
        msgtype, body = _carried_text(content)
        if event_type != "m.room.message" or not isinstance(body, str):
            raise RefusedError("no RCS form for this type")
        if msgtype in _MEDIA_TYPES:
            holder = _media_holder(content)
            media_link = await self._media_link(holder) if need_media else None
            # Without a caption the media goes alone, as one empty chunk.
            return chunks(flatten("m.text", _caption(holder)), MAX_BODY) or [""], media_link
        if msgtype not in _TEXT_TYPES:
            raise RefusedError("no RCS form for this type")
        pieces = chunks(flatten(str(msgtype), body), MAX_BODY)
        if not pieces:
            raise RefusedError("empty message")
        return pieces, None

    async def _send_piece(self, piece: str, media_link: str | None) -> str:
        """One chunk to the owner, with the attachment when it carries one."""
        if media_link is None:
            return await self.backend.send_text(self.settings.owner_number, piece)
        return await self.backend.send_media(self.settings.owner_number, media_link, piece)
