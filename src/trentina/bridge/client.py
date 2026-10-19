"""The upstream side of the bridge: one Matrix identity, its crypto, its sync.

This is the untrusted half of spec 015. It decrypts and forwards; it judges
nothing and it cannot deliver anything, because the only place it can send
plaintext is the gateway, and the gateway is the only writer into the agent's
homeserver.

Three properties the rest of the design leans on:

* **Nothing is lost.** The sync position advances only after the gateway has
  acked every event in the batch. A bridge killed mid-batch re-reads it, and
  the gateway's dedupe (by event ID) makes the repeat harmless.
* **Nothing is dropped silently.** An event whose key has not arrived is
  parked, its key requested, and retried every sync. One still undecryptable
  after ``UNDECRYPTABLE_AFTER`` is forwarded as a notice, so the agent knows a
  message exists that it cannot read.
* **Nothing goes upstream in plaintext** into an encrypted room. nio 0.26's
  ``room_send`` sends ``m.reaction`` unencrypted ("reactions don't support
  encryption"), which would hand the homeserver every reaction in the clear.
  ``send`` encrypts every type itself.
* **Only an allowed inviter opens a room** (#264). An invite from anyone not
  in ``BRIDGE_ALLOWED_INVITERS`` is rejected and forgotten, and a joined room
  that fails the rule is left and forgotten. The gateway holds the other half
  of the rule, because only it knows every bridged agent: each room's members
  go with its announcement, and a room it refuses is left the same way.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Any

import httpx
from aiohttp import ClientError
from nio import (
    AsyncClient,
    AsyncClientConfig,
    JoinResponse,
    LoginResponse,
    MegolmEvent,
    RoomForgetResponse,
    RoomLeaveResponse,
    RoomSendResponse,
    RoomTypingResponse,
    ShareGroupSessionError,
    SyncError,
    SyncResponse,
)
from nio.api import Api
from nio.exceptions import EncryptionError, LocalProtocolError
from nio.store import SqliteStore

from ..logsafe import redact_source
from . import media

if TYPE_CHECKING:
    from pathlib import Path

    from nio.rooms import MatrixRoom

    from .settings import BridgeSettings

logger = logging.getLogger(__name__)

REDACTION = "m.room.redaction"
# Not a Matrix event: the bridge's own notice that it is in a room.
ROOM_ANNOUNCE = "org.crunchtools.trentina.room"
# Nor this: the bridge is leaving a room it was in, so the gateway retires the
# agent's mirror of it (#317).
ROOM_LEFT = "org.crunchtools.trentina.room_left"
FORWARDED = frozenset({"m.room.message", "m.reaction", "m.sticker", REDACTION})
UNDECRYPTABLE_AFTER = 600.0
# The gateway's answer to a room announcement it will not relay (#264).
ROOM_REFUSED = "refused"
# Parked events held at once; past it an event is reported undecryptable at
# once. Each is one encrypted event's JSON, so this bounds memory and the
# pending file to a few megabytes.
MAX_PENDING = 1000
_SYNC_TIMEOUT_MS = 30_000
_MAX_BACKOFF = 60.0
# How long an upstream typing bubble lasts unless refreshed or cleared. The
# gateway refreshes a still-typing agent every 15 s (#1533).
TYPING_TIMEOUT_MS = 30_000
_TYPING_DEADLINE = 10.0


class SendError(RuntimeError):
    """The homeserver refused an outbound event."""


def membership_digest(members: list[str]) -> str:
    """A short digest of a room's sorted members, for its announcement ID."""
    return hashlib.sha256("\n".join(members).encode()).hexdigest()[:16]


class Bridge:
    """One profile's upstream client.

    Args:
        settings: this bridge's configuration (``BridgeSettings.from_env``).
            ``store_dir`` is created if absent and holds everything the bridge
            persists.
        client: a nio ``AsyncClient`` to drive instead of building one with
            an E2EE-enabled SQLite store in ``store_dir``. Tests pass a fake.
        gateway: the HTTP client used to hand events to the gateway, instead
            of a fresh one. Either way the bridge owns both clients and
            ``aclose`` closes them.
    """

    def __init__(
        self,
        settings: BridgeSettings,
        *,
        client: AsyncClient | None = None,
        gateway: httpx.AsyncClient | None = None,
        media: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        settings.store_dir.mkdir(parents=True, exist_ok=True)
        self.client = client or AsyncClient(
            settings.homeserver,
            settings.user_id,
            store_path=str(settings.store_dir),
            config=AsyncClientConfig(
                encryption_enabled=True,
                store=SqliteStore,
                pickle_key=settings.pickle_key,
                store_sync_tokens=False,
            ),
        )
        # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
        self._gateway = gateway or httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=5.0))
        # Upstream media (#491). Its own client: nio's session is aiohttp, and
        # this one must never follow a redirect off the homeserver.
        # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
        self._media = media or httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0))
        self._send_lock = asyncio.Lock()
        # Sync and send both drive nio's crypto state (key upload, query and
        # claim, group-session sharing, key requests), which is not safe to
        # interleave across awaits. Every such operation holds this lock.
        self._crypto_lock = asyncio.Lock()
        self._pending_dirty = False
        # Room ID -> digest of the membership last announced for it; a change
        # announces the room again, so the gateway holds the current members.
        self._announced: dict[str, str] = {}
        self._pending: dict[str, tuple[str, dict[str, Any], float]] = self._load_pending()
        # Who invited us into each room we joined, so a restart can tell an
        # allowed room from one that is not (#264).
        self._inviters: dict[str, str] = self._load_inviters()
        # Rooms that passed the inviter rule this process; rooms to leave;
        # rooms left. Nothing is forwarded from the last two.
        self._vetted: set[str] = set()
        self._evict: set[str] = set()
        self._left: set[str] = set()
        # Rooms being left that the gateway was told of, so a leave that keeps
        # failing is reported once, not every sync.
        self._reported_left: set[str] = set()
        self.ready = asyncio.Event()
        if not settings.allowed_inviters:
            logger.warning(
                "bridge[%s]: BRIDGE_ALLOWED_INVITERS is empty: every invite is refused "
                "and every joined room will be left",
                settings.profile,
            )

    # ---------------------------------------------------------- persistence

    @property
    def _session_file(self) -> Path:
        return self.settings.store_dir / "session.json"

    @property
    def _token_file(self) -> Path:
        return self.settings.store_dir / "sync_token"

    @property
    def _pending_file(self) -> Path:
        return self.settings.store_dir / "pending.json"

    def _write_private(self, path: Path, text: str) -> None:
        """Write atomically, 0600 from the first byte: the session file holds
        the upstream access token. O_EXCL refuses a planted file or symlink."""
        staged = path.with_suffix(".tmp")
        staged.unlink(missing_ok=True)
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        staged.replace(path)

    @property
    def _inviters_file(self) -> Path:
        return self.settings.store_dir / "inviters.json"

    def _load_inviters(self) -> dict[str, str]:
        try:
            raw = json.loads(self._inviters_file.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in raw.items()}
        except FileNotFoundError:
            return {}
        except (ValueError, TypeError, AttributeError) as exc:
            raise RuntimeError(f"{self._inviters_file} is not an inviter record") from exc

    async def _save_inviters(self) -> None:
        await asyncio.to_thread(
            self._write_private, self._inviters_file, json.dumps(self._inviters)
        )

    def _load_pending(self) -> dict[str, tuple[str, dict[str, Any], float]]:
        try:
            raw = json.loads(self._pending_file.read_text(encoding="utf-8"))
            return {k: (str(v[0]), dict(v[1]), float(v[2])) for k, v in raw.items()}
        except FileNotFoundError:
            return {}
        except (ValueError, TypeError, IndexError, AttributeError) as exc:
            raise RuntimeError(f"{self._pending_file} is not a pending-event record") from exc

    async def _save_pending(self) -> None:
        """Write the parked events, only when they changed since last time.

        A whole-file rewrite, off the event loop. The set is small by
        construction: an event leaves it when its key arrives or after
        ``UNDECRYPTABLE_AFTER``, whichever is first.
        """
        if not self._pending_dirty:
            return
        await asyncio.to_thread(self._write_private, self._pending_file, json.dumps(self._pending))
        self._pending_dirty = False

    # -------------------------------------------------------------- login

    async def login(self) -> None:
        """Resume the saved session, adopt the configured device, or log in.

        The saved session wins over the environment: once the bridge has a
        device, a stale BRIDGE_ACCESS_TOKEN left in the unit must not move it
        to another.
        """
        s = self.settings
        if self._session_file.exists():
            try:
                saved = json.loads(self._session_file.read_text(encoding="utf-8"))
                user_id, device_id = str(saved["user_id"]), str(saved["device_id"])
                access_token = str(saved["access_token"])
            except (ValueError, KeyError, TypeError) as exc:
                raise RuntimeError(f"{self._session_file} is not a saved session") from exc
            self.client.restore_login(user_id, device_id, access_token)
            how = "resumed"
        elif s.access_token and s.device_id:
            self.client.restore_login(s.user_id, s.device_id, s.access_token)
            self._save_session()
            how = "adopted"
        elif s.password:
            resp = await self.client.login(s.password, device_name=s.device_name)
            if not isinstance(resp, LoginResponse):
                raise RuntimeError(f"login failed: {resp}")
            self._save_session()
            how = "logged in"
        else:
            raise RuntimeError(
                "no way in: set BRIDGE_ACCESS_TOKEN + BRIDGE_DEVICE_ID, or BRIDGE_PASSWORD"
            )
        logger.warning("bridge[%s]: %s, device %s", s.profile, how, self.client.device_id)

    def _save_session(self) -> None:
        self._write_private(
            self._session_file,
            json.dumps(
                {
                    "user_id": self.client.user_id,
                    "device_id": self.client.device_id,
                    "access_token": self.client.access_token,
                }
            ),
        )

    # --------------------------------------------------------------- sync

    async def run(self) -> None:
        """Sync forever."""
        token = self._token_file.read_text().strip() if self._token_file.exists() else None
        backoff = 1.0
        while True:
            # Not under the crypto lock: this awaits a 30-second long-poll,
            # and holding the lock across it would stall every send. nio
            # applies a sync's crypto changes in receive_response, which has
            # no await in it, so they cannot interleave with an encryption.
            # Full state on the first sync of every start, not only the first
            # ever: nio keeps no room state across restarts, and a resumed sync
            # carries only what changed, which left names and members unknown.
            resp = await self.client.sync(
                timeout=_SYNC_TIMEOUT_MS, since=token, full_state=not self.ready.is_set()
            )
            if isinstance(resp, SyncError) or not isinstance(resp, SyncResponse):
                logger.warning(
                    "bridge[%s]: sync failed: %s", self.settings.profile, type(resp).__name__
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                continue
            backoff = 1.0
            token = await self.process(resp, first=token is None)

    async def process(self, resp: Any, *, first: bool) -> str:
        """Handle one sync response and return the position it reached.

        The position is written only after every event in the batch was
        taken by the gateway: ``forward`` does not return until it was.
        """
        await self.maintain_keys()
        # A left room only needs holding while nio still knows it (a failed
        # forget); otherwise every rejected invite would be kept for good.
        # Pruned before this batch, which may still carry a room left in
        # the previous one.
        self._left &= set(self.client.rooms)
        await self._join_invites(resp)
        await self._vet_rooms()
        await self._announce_rooms(resp)
        await self._evict_rooms()
        # The first sync is history. Forwarding it would replay every room
        # into the agent's new homeserver, so it only establishes position.
        if not first:
            await self._forward_batch(resp)
        await self._retry_pending()
        # Parked events are written once per batch, before the position: a
        # crash in between re-reads the batch and parks them again.
        await self._save_pending()
        token = str(resp.next_batch)
        await asyncio.to_thread(self._write_private, self._token_file, token)
        self.ready.set()
        return token

    async def maintain_keys(self) -> None:
        async with self._crypto_lock:
            await self._maintain_keys_locked()

    async def _maintain_keys_locked(self) -> None:
        c = self.client
        if c.should_upload_keys:
            await c.keys_upload()
        if c.should_query_keys:
            await c.keys_query()
        if c.should_claim_keys:
            await c.keys_claim(c.get_users_for_key_claiming())
        await c.send_to_device_messages()

    def _members(self, room: MatrixRoom | None) -> list[str]:
        """Everyone joined to or invited into ``room`` but us, sorted."""
        if room is None:
            return []
        users = set(getattr(room, "users", None) or {})
        users |= set(getattr(room, "invited_users", None) or {})
        users.discard(self.client.user_id)
        return sorted(users)

    async def _announce_rooms(self, resp: Any) -> None:
        """Tell the gateway about every joined room it has not heard of yet,
        and again whenever a room's membership changes.

        So the agent's local room exists, and the agent is in it, before the
        first message arrives. Created on the first message instead, the room
        would invite the agent at the moment the message was written, and the
        agent would join too late to read it. Every room the client knows
        and has not announced is announced, not only this sync's: a resumed
        sync omits unchanged rooms, which a restart would then never announce.
        After that a room is looked at again only when a sync carries it,
        which any membership change does. The event ID carries a digest of
        the membership, so the gateway's dedupe passes a changed room and
        swallows a repeat.

        The members ride along because the gateway decides whether a room
        holds another bridged agent (#264); a room it refuses is left.
        """
        known = set(self.client.rooms)
        touched = (known - set(self._announced)) | (known & set(resp.rooms.join))
        for room_id in sorted(touched - self._evict - self._left):
            members = self._members(self.client.rooms.get(room_id))
            digest = membership_digest(members)
            if self._announced.get(room_id) == digest:
                continue
            announcement = {
                **self._payload(room_id, {"sender": self.client.user_id}),
                "event_id": f"room:{room_id}:{digest}",
                "type": ROOM_ANNOUNCE,
                "content": {},
            }
            announcement["room"]["members"] = members
            outcome = await self.forward(announcement)
            # Remembered only once the gateway answered it. A report it
            # dropped would otherwise leave the gateway holding the old
            # members until a restart: a quiet agent that joined would stay
            # unseen, so the next sync reports again instead.
            if not outcome:
                continue
            self._announced[room_id] = digest
            if outcome == ROOM_REFUSED:
                logger.warning(
                    "bridge[%s]: the gateway refused room %s; leaving it",
                    self.settings.profile,
                    redact_source(room_id),
                )
                self._evict.add(room_id)

    def _allowed(self, user_id: str | None) -> bool:
        return bool(user_id) and user_id in self.settings.allowed_inviters

    async def _join_invites(self, resp: Any) -> None:
        """Accept every open invite from an allowed inviter; reject the rest.

        nio keeps pending invites in ``invited_rooms`` until they are joined
        or left, so a join or rejection that fails is simply tried again on
        the next sync rather than lost behind an advanced sync position.

        The inviter is the sender of our own ``invite`` membership in the
        invite's stripped state, which nio records as ``inviter``. An invite
        that does not say who sent it is rejected: an unknown inviter is not
        an allowed one.
        """
        invited = getattr(self.client, "invited_rooms", None) or {}
        recorded = len(self._inviters)
        for room_id in sorted(set(resp.rooms.invite) | set(invited)):
            inviter = getattr(invited.get(room_id), "inviter", None)
            if not self._allowed(inviter):
                await self._leave(room_id, "invite not from an allowed inviter")
                continue
            result = await self.client.join(room_id)
            if isinstance(result, JoinResponse):
                self._inviters[room_id] = str(inviter)
                self._vetted.add(room_id)
                self._left.discard(room_id)
                logger.warning("bridge[%s]: joined an invited room", self.settings.profile)
            else:
                logger.warning(
                    "bridge[%s]: join failed, retried next sync: %s",
                    self.settings.profile,
                    type(result).__name__,
                )
        # Once per batch. Before the sync position is written, so a crash in
        # between re-reads the invite and records it again.
        if len(self._inviters) != recorded:
            await self._save_inviters()

    async def _vet_rooms(self) -> None:
        """Mark every joined room that fails the inviter rule for leaving.

        A room whose inviter is recorded is vetted once: who invited the
        bridge does not change. The first sync checks every room joined
        before the start, and later syncs only a room that appeared without
        an invite this bridge accepted.

        The inviter of a room joined before #264 was never recorded, and
        nio keeps no trace of it once the invite is joined. For such a room
        the rule falls back to its audience: it stays only when everyone else
        in it, joined or invited, is an allowed inviter, so no stranger is on
        the other end. Otherwise it is left. An audience changes, so such a
        room is checked again on every batch, before anything from it is
        forwarded (#296): vetted once, a stranger invited later was on the
        other end for as long as the process ran. An allowed inviter who
        wants it back invites the bridge again, which records the inviter.
        """
        for room_id in sorted(set(self.client.rooms) - self._vetted - self._evict - self._left):
            recorded = self._inviters.get(room_id)
            if recorded is not None:
                ok = self._allowed(recorded)
            else:
                members = self._members(self.client.rooms.get(room_id))
                ok = bool(members) and all(self._allowed(m) for m in members)
            if ok:
                # The audience rule holds only as of this batch.
                if recorded is not None:
                    self._vetted.add(room_id)
                continue
            logger.warning(
                "bridge[%s]: room %s fails the inviter rule; leaving it",
                self.settings.profile,
                redact_source(room_id),
            )
            self._evict.add(room_id)

    async def _evict_rooms(self) -> None:
        for room_id in sorted(self._evict):
            await self._leave(room_id, "room refused")

    async def _leave(self, room_id: str, why: str) -> None:
        """Leave ``room_id`` (for an invite, reject it), then forget it.

        A failed leave keeps the room marked, so the next sync tries again.
        The forget is best effort: leaving is what ends the channel.

        A room the bridge was in has a mirror in the agent's homeserver, and
        the agent keeps sending into it (#317). The gateway is told first, so
        it retires the mirror and the agent's next send there fails where the
        agent sees it; told after, a crash in between would lose the notice
        for good, because a left room is never seen again. An invite being
        rejected has no mirror and is not reported.
        """
        self._evict.add(room_id)
        if room_id in self.client.rooms and room_id not in self._reported_left:
            await self.forward(
                {
                    **self._payload(room_id, {"sender": self.client.user_id}),
                    # Unique per attempt: a room left, re-joined and left
                    # again must not be swallowed by the gateway's dedupe.
                    "event_id": f"left:{room_id}:{time.time_ns()}",
                    "type": ROOM_LEFT,
                    "content": {},
                }
            )
            self._reported_left.add(room_id)
        left = await self.client.room_leave(room_id)
        if not isinstance(left, RoomLeaveResponse):
            logger.warning(
                "bridge[%s]: leaving %s (%s) failed, retried next sync: %s",
                self.settings.profile,
                redact_source(room_id),
                why,
                type(left).__name__,
            )
            return
        forgot = await self.client.room_forget(room_id)
        if not isinstance(forgot, RoomForgetResponse):
            logger.warning(
                "bridge[%s]: forgetting %s failed: %s",
                self.settings.profile,
                redact_source(room_id),
                type(forgot).__name__,
            )
        self._evict.discard(room_id)
        self._reported_left.discard(room_id)
        self._vetted.discard(room_id)
        self._announced.pop(room_id, None)
        self._left.add(room_id)
        if self._inviters.pop(room_id, None) is not None:
            await self._save_inviters()
        logger.warning(
            "bridge[%s]: left and forgot %s: %s",
            self.settings.profile,
            redact_source(room_id),
            why,
        )

    async def _forward_batch(self, resp: Any) -> None:
        for room_id, info in resp.rooms.join.items():
            if room_id in self._evict or room_id in self._left:
                continue
            for event in info.timeline.events:
                await self.handle(room_id, event)

    async def handle(self, room_id: str, event: Any) -> None:
        """Forward one timeline event, or park it until its key arrives."""
        if getattr(event, "sender", None) == self.client.user_id:
            return  # our own send, echoed back: it came from the agent
        if isinstance(event, MegolmEvent):
            await self._park(room_id, event)
            return
        await self._forward_event(
            room_id, event.source, decrypted=getattr(event, "decrypted", False)
        )

    async def _forward_event(
        self, room_id: str, source: dict[str, Any], *, decrypted: bool
    ) -> None:
        """Forward a timeline event the gateway should see.

        A redaction is honoured only when the homeserver delivered it as one.
        Inside an encrypted payload the ``type`` is whatever the sender wrote,
        so a decrypted "redaction" is any room member asking the gateway's bot
        to delete a message the homeserver never authorized them to delete.
        Real redactions are never encrypted.
        """
        event_type = source.get("type")
        if event_type not in FORWARDED:
            return
        if decrypted and event_type == REDACTION:
            logger.warning(
                "bridge[%s]: dropped an encrypted payload posing as a redaction in %s",
                self.settings.profile,
                redact_source(room_id),
            )
            return
        payload = self._payload(room_id, source)
        content = payload["content"]
        media_ref = media.media_source(event_type, content) if isinstance(content, dict) else None
        if media_ref is not None:
            payload["media"] = await media.fetch(
                self._media,
                self.settings.homeserver,
                str(self.client.access_token),
                media_ref,
                content,
            )
        await self.forward(payload)

    def _payload(self, room_id: str, source: dict[str, Any]) -> dict[str, Any]:
        room: MatrixRoom | None = self.client.rooms.get(room_id)
        sender = str(source.get("sender", ""))
        return {
            "room_id": room_id,
            "event_id": source.get("event_id"),
            "sender": sender,
            "sender_displayname": (room.user_name(sender) if room else None) or "",
            "type": source.get("type"),
            "content": source.get("content") or {},
            "redacts": source.get("redacts"),
            "room": self._room_info(room),
        }

    def _room_info(self, room: MatrixRoom | None) -> dict[str, Any]:
        """Name, topic and, for a two-member room, the other member."""
        if room is None:
            return {
                "name": "",
                "topic": "",
                "is_direct": False,
                "peer": "",
                "peer_displayname": "",
            }
        is_direct = room.member_count == 2
        peer = next((u for u in room.users if u != self.client.user_id), "") if is_direct else ""
        return {
            "name": room.name or "",
            "topic": room.topic or "",
            "is_direct": is_direct,
            "peer": peer,
            "peer_displayname": (room.user_name(peer) or "") if peer else "",
        }

    async def forward(self, payload: dict[str, Any]) -> str:
        """POST to the gateway until it takes the event, and return the
        outcome it answered ("" when it named none). A 4xx other than an
        auth failure means the gateway will never take it: logged and dropped,
        because retrying it would stall every message behind it."""
        backoff = 1.0
        url = f"{self.settings.gateway_url}/bridge/{self.settings.profile}/event"
        headers = {"Authorization": f"Bearer {self.settings.ingress_token}"}
        while True:
            try:
                resp = await self._gateway.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                status, detail = 0, str(exc)
            else:
                status, detail = resp.status_code, resp.text[:200]
                if status == 200:
                    try:
                        outcome = resp.json().get("outcome")
                    except (ValueError, AttributeError):
                        outcome = None
                    return outcome if isinstance(outcome, str) else ""
                if 400 <= status < 500 and status not in (401, 403, 429):
                    logger.error(
                        "bridge[%s]: gateway refused %s: %s %s",
                        self.settings.profile,
                        redact_source(str(payload.get("event_id"))),
                        status,
                        redact_source(detail),
                    )
                    return ""
            logger.warning(
                "bridge[%s]: gateway unavailable for %s (%s %s), retrying",
                self.settings.profile,
                redact_source(str(payload.get("event_id"))),
                status,
                redact_source(detail),
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)

    # ------------------------------------------------------ undecryptable

    async def _park(self, room_id: str, event: MegolmEvent) -> None:
        if event.event_id in self._pending:
            return
        if len(self._pending) >= MAX_PENDING:
            # Full: tell the agent now rather than hold without bound. A room
            # member who can flood undecryptable events cannot grow this.
            await self.forward(self._undecryptable(room_id, event.source))
            return
        # Raised when this session's key was already requested: nothing to do.
        async with self._crypto_lock:
            with contextlib.suppress(LocalProtocolError):
                await self.client.request_room_key(event)
        self._pending[event.event_id] = (room_id, event.source, time.time())
        self._pending_dirty = True
        logger.warning(
            "bridge[%s]: parked %s in %s awaiting key %s",
            self.settings.profile,
            redact_source(event.event_id),
            redact_source(room_id),
            redact_source(event.session_id),
        )

    def _held(self, room_id: str) -> bool:
        """Whether events from ``room_id`` may still be forwarded: the bridge
        is in it, and it is neither being left nor left."""
        return room_id in self.client.rooms and room_id not in self._evict | self._left

    async def _retry_pending(self) -> None:
        if not self._pending:
            return
        now = time.time()
        for event_id, (room_id, source, first_seen) in list(self._pending.items()):
            if not self._held(room_id):
                # Parked before the room was refused or left (#296). Not
                # forwarded, not even as an undecryptable notice: the room
                # is no longer one the agent may hear from.
                del self._pending[event_id]
                self._pending_dirty = True
                continue
            parsed = MegolmEvent.from_dict(source)
            if not isinstance(parsed, MegolmEvent):
                logger.error(
                    "bridge[%s]: dropping unparseable %s",
                    self.settings.profile,
                    redact_source(event_id),
                )
                del self._pending[event_id]
                self._pending_dirty = True
                continue
            parsed.room_id = room_id
            try:
                async with self._crypto_lock:
                    decrypted = self.client.decrypt_event(parsed)
            except EncryptionError:
                if now - first_seen < UNDECRYPTABLE_AFTER:
                    continue
                await self.forward(self._undecryptable(room_id, source))
            else:
                await self._forward_event(room_id, decrypted.source, decrypted=True)
            del self._pending[event_id]
            self._pending_dirty = True

    @staticmethod
    def _undecryptable(room_id: str, source: dict[str, Any]) -> dict[str, Any]:
        return {
            "room_id": room_id,
            "event_id": source.get("event_id"),
            "sender": source.get("sender", ""),
            "sender_displayname": "",
            "type": "m.room.message",
            "content": {
                "msgtype": "m.notice",
                "body": "[trentina] a message here could not be decrypted",
            },
            "room": {"name": "", "topic": "", "is_direct": False},
        }

    # --------------------------------------------------------------- send

    async def send(
        self, room_id: str, event_type: str, content: dict[str, Any], txn_id: str
    ) -> str:
        """Send one event upstream, encrypted whenever the room is."""
        async with self._send_lock:
            room = self.client.rooms.get(room_id)
            if room is None:
                raise SendError(f"not joined to {room_id}")
            if room.encrypted:
                event_type, content = await self._encrypt(room_id, event_type, content)
            resp = await self._put_event(room_id, event_type, content, txn_id)
        if not isinstance(resp, RoomSendResponse):
            raise SendError(str(resp))
        return str(resp.event_id)

    async def _put_event(
        self, room_id: str, event_type: str, content: dict[str, Any], txn_id: str
    ) -> Any:
        """PUT an already-final event, with no further encryption.

        ``room_send`` cannot be used for this: it re-derives whether to encrypt
        and exempts ``m.reaction``. This goes through nio's request builder and
        its private ``_send``, the one coupling to nio internals in the bridge;
        the ``bridge`` extra pins nio to 0.26.x so an upgrade that moves it is a
        deliberate one, and ``tests/test_bridge_process.py`` asserts the wire
        type of every send.
        """
        method, path, body = Api.room_send(
            self.client.access_token, room_id, event_type, content, txn_id
        )
        return await self.client._send(RoomSendResponse, method, path, body, (room_id,))

    async def _encrypt(
        self, room_id: str, event_type: str, content: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        room = self.client.rooms[room_id]
        async with self._crypto_lock:
            if not room.members_synced:
                await self.client.joined_members(room_id)
            await self._maintain_keys_locked()
            olm = self.client.olm
            if olm is None:
                raise SendError("encryption is not loaded")
            if olm.should_share_group_session(room_id):
                shared = await self.client.share_group_session(
                    room_id, ignore_unverified_devices=True
                )
                # An error comes back as a response, not an exception. Sending
                # anyway would post ciphertext its recipients hold no key for.
                if isinstance(shared, ShareGroupSessionError):
                    raise SendError(f"could not share the room key: {shared}")
            encrypted_type, encrypted = self.client.encrypt(room_id, event_type, content)
        if encrypted_type != "m.room.encrypted":
            raise SendError(f"refusing to send {event_type} unencrypted into {room_id}")
        return encrypted_type, dict(encrypted)

    async def upload(
        self, room_id: str, plaintext: bytes, content_type: str, filename: str
    ) -> dict[str, Any]:
        """Upload judged media for a send into ``room_id`` (#491): ``{"url"}``,
        or ``{"file"}`` encrypted when the room is.

        Raises:
            SendError: not now (a room not held, a 5xx, a rate limit).
            media.UploadRefusedError: never; the homeserver answered a 4xx.
        """
        room = self.client.rooms.get(room_id)
        if room is None or not self._held(room_id):
            raise SendError(f"not holding {room_id}")
        try:
            return await media.upload(
                self._media,
                self.settings.homeserver,
                str(self.client.access_token),
                plaintext,
                content_type,
                filename,
                encrypted=bool(room.encrypted),
            )
        except media.UploadError as exc:
            raise SendError(f"upload: {exc}") from exc

    async def redact(self, room_id: str, event_id: str, txn_id: str) -> None:
        """Redact upstream. ``txn_id`` makes a retried redaction the same one."""
        async with self._send_lock:
            resp = await self.client.room_redact(room_id, event_id, tx_id=txn_id)
        if not hasattr(resp, "event_id"):
            raise SendError(str(resp))

    async def typing(self, room_id: str, typing: bool) -> None:
        """Show or clear the agent's typing upstream (#1533). Best effort.

        Not under the send lock: a bubble must not wait behind a send, and
        typing is never encrypted (an EDU, not a room event).
        """
        if not self._held(room_id):
            raise SendError(f"not holding {room_id}")
        try:
            resp = await asyncio.wait_for(
                self.client.room_typing(room_id, typing, timeout=TYPING_TIMEOUT_MS),
                _TYPING_DEADLINE,
            )
        except (LocalProtocolError, ClientError, OSError, TimeoutError) as exc:
            raise SendError(type(exc).__name__) from exc
        if not isinstance(resp, RoomTypingResponse):
            raise SendError(str(resp))

    async def aclose(self) -> None:
        await self._gateway.aclose()
        await self._media.aclose()
        await self.client.close()
