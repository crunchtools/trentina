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
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from typing import TYPE_CHECKING, Any

import httpx

from ..logsafe import exc_kind, redact_source
from .backend import BackendError, Inbound
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
_MAX_BACKOFF = 60.0
# The store is pruned at least this often, so a bridge that only sends still
# drops old send records.
PRUNE_EVERY = 3600.0
_GATEWAY_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)


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

    def _payload(self, message: Inbound) -> dict[str, Any]:
        s = self.settings
        body = message.body
        if message.attachments:
            # Media is not carried yet; the agent still learns it was sent.
            note = f"[{message.attachments} attachment(s) not carried over RCS]"
            body = f"{body}\n{note}" if body else note
        return {
            "room_id": s.room_id,
            "event_id": f"$rcs-{message.message_id}",
            "sender": s.owner_user_id,
            "sender_displayname": s.owner_name,
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": body},
            "room": self._room_info(),
        }

    async def run(self) -> None:
        """Announce the room, then deliver the inbox, in order, forever."""
        await self.announce()
        while True:
            self._wake.clear()
            for message in await self.store.pending():
                await self.forward(self._payload(message))
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

    async def send(
        self, room_id: str, event_type: str, content: dict[str, Any], txn_id: str
    ) -> str:
        """Send one judged event to the owner's phone; the event ID it gets.

        At least once, per chunk: a chunk is recorded once Twilio answers, so
        one whose answer is lost (a timeout after Twilio took it) is sent
        again on the gateway's retry. Twilio's Messages API takes no
        idempotency key, so this is the strongest guarantee it allows.

        Raises:
            RefusedError: not a text message in the owner's room, or empty.
            UnavailableError: the provider did not take a chunk; the chunks
                that went are recorded, so the gateway's retry sends the rest.
        """
        if room_id != self.settings.room_id:
            raise RefusedError("not the owner's room")
        msgtype = content.get("msgtype")
        body = content.get("body")
        if (
            event_type != "m.room.message"
            or msgtype not in _TEXT_TYPES
            or not isinstance(body, str)
        ):
            raise RefusedError("no RCS form for this type")
        pieces = chunks(flatten(str(msgtype), body), MAX_BODY)
        if not pieces:
            raise RefusedError("empty message")
        async with self._send_lock:
            done = await self.store.sent(txn_id)
            for idx, piece in enumerate(pieces):
                if idx in done:
                    continue
                try:
                    done[idx] = await self.backend.send_text(self.settings.owner_number, piece)
                except BackendError as exc:
                    # Permanent even after earlier chunks went: retrying the
                    # same chunk would fail the same way, forever.
                    if exc.permanent:
                        raise RefusedError(exc.reason) from exc
                    raise UnavailableError(exc.reason) from exc
                await self.store.record(txn_id, idx, done[idx])
        return f"$rcs-{done[0]}"
