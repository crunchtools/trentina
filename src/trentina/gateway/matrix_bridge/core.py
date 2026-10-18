"""One profile's bridge, gateway side: judge every event, then carry it across.

Inbound, the bridge process hands over one decrypted event at a time. The
gateway runs it through L1 ∥ L2 → L3 (``defend_json``), and only then writes
it into the agent's Conduit as the sender's stand-in — or, under ``block``,
writes a withheld notice in its place. What was judged is what is delivered:
the content, the sender's display name, and the room's name and topic.

Outbound, Conduit pushes the agent's own events to the appservice. Each is
judged the same way before the bridge encrypts and sends it upstream; a
refused one never leaves, and the agent is told so in its room.

Echo suppression is structural. Only events whose sender is the agent's local
user go outbound, so the stand-ins and the bot this module writes as never
loop back; and the bridge process drops upstream events whose sender is its
own account, which is where the agent's replies reappear.

No agent-to-agent channel (#264). Every other bridged profile's public user
is known here and nowhere else, so this is where the rule lives: an event from
one is dropped, a room announced with one in it is refused (the bridge leaves
it), and nothing is relayed into a room unless its members were reported and
none of them is another agent. That holds for a room an allowed inviter
opened too: the inviter rule is the bridge's, this one is the gateway's.

A room the bridge leaves, by either rule, is retired here (#317): the agent
is told in it and removed from it, so a send into it fails where the agent
sees it instead of being dropped where only the log does.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx

from ...database import record_gateway_call
from ...defense import defend_json
from ...httpbody import request_capped
from ...logsafe import exc_kind, redact_source
from ...modes import gaps_of, refusal_reason
from ...outcomes import Outcome
from ...reserved import WARNING_KEY, strip_reserved, with_stripped
from ...warning import build_warning
from ..context import profile_context
from ..matrix_relation import withheld_relation
from ..profile import MATRIX_CHANNEL
from .appservice import ConduitError
from .rewrite import IdMap, judged_view, referenced_ids, rewrite_content

if TYPE_CHECKING:
    from ..profile import MatrixBridgeConfig, Profile
    from .appservice import AppService
    from .mapping import BridgeMapping, Room

logger = logging.getLogger(__name__)

# Event types carried in either direction. State events are mirrored through
# the room metadata the bridge sends with each event, not replayed.
_CARRIED = frozenset({"m.room.message", "m.reaction", "m.sticker"})
_REDACTION = "m.room.redaction"
# The bridge process announcing a room it is in (bridge/client.py).
_ROOM_ANNOUNCE = "org.crunchtools.trentina.room"
# The bridge process leaving a room it was in (#317).
_ROOM_LEFT = "org.crunchtools.trentina.room_left"
_RETIRED = (
    "[trentina] this room is no longer bridged: the upstream room was left. "
    "Nothing sent here is delivered; send from a room that is still bridged."
)

# The one answer the bridge acts on: leave this room (bridge/client.py).
ROOM_REFUSED = "refused"
# Why an event was not carried, by the agent rule (#264). A closed set: these
# reach the log, the audit row and the agent's notice, and name nobody.
AGENT_SENDER = "sender is another bridged agent"
AGENT_IN_ROOM = "room shared with another bridged agent"
MEMBERS_UNREPORTED = "room members not reported"
# The audit row's backend for a bridge refusal; its tool is the direction.
_AUDIT_BACKEND = "matrix_bridge"

_BRIDGE_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)
# Wall clock for one bridge call, the reply included (#295).
_BRIDGE_DEADLINE = 90.0

# The agent's typing (#1533). Best effort: a short deadline, so a slow bridge
# costs a typing bubble and never holds the transaction behind it.
_TYPING = "m.typing"
_TYPING_DEADLINE = 5.0
# A still-typing agent is re-sent this often. Upstream indicators lapse on
# their own (RCS shows one about 20 s, the Matrix bridge sets 30 s), and the
# homeserver pushes on every refresh the agent makes (Hermes: every 2 s).
_TYPING_REFRESH = 15.0

# An event slower than this is logged at WARNING, which production runs at, so
# a stalled turn shows where its time went without turning on INFO.
_SLOW_SECONDS = 5.0


class BridgeUnavailableError(RuntimeError):
    """The bridge process did not answer, or answered "not now" (a 5xx, or
    a 401/403/408/429). Conduit retries the txn."""


class BridgeRefusedError(RuntimeError):
    """The bridge process answered that this event can never be carried: a
    type its channel has no form for, or a body it will not take (#483).
    Retrying cannot help, and holding the transaction would stall every
    reply behind it, so the event is dropped and the agent told."""

    def __init__(self, path: str, status: int) -> None:
        super().__init__(f"bridge {path} -> {status}")
        self.path = path
        self.status = status


# Client errors a bridge may answer that mean "not now" rather than "never".
_RETRYABLE_4XX = frozenset({401, 403, 408, 429})


class _Stages:
    """Wall-clock time per stage of one event, for the line that closes it."""

    def __init__(self) -> None:
        self._start = self._mark = time.monotonic()
        self._laps: list[str] = []

    def lap(self, stage: str) -> None:
        now = time.monotonic()
        self._laps.append(f"{stage}={now - self._mark:.2f}s")
        self._mark = now

    def report(self, what: str) -> None:
        total = time.monotonic() - self._start
        level = logging.WARNING if total >= _SLOW_SECONDS else logging.INFO
        if not logger.isEnabledFor(level):
            return
        # ``what`` carries upstream event IDs; escaped, one cannot forge a line.
        if not what.isprintable():
            what = repr(what)
        logger.log(level, "matrix_bridge: %s in %.2fs (%s)", what, total, " ".join(self._laps))


def _txn(prefix: str, event_id: str) -> str:
    """A transaction ID derived from the event, so a retry is idempotent."""
    return f"{prefix}{hashlib.sha256(event_id.encode()).hexdigest()[:32]}"


class ProfileBridge:
    """Everything the gateway does for one bridged profile.

    Args:
        profile: a profile whose ``matrix_bridge`` is enabled and whose
            tokens the loader has resolved; anything else is a ValueError.
            Its ``defense`` settings judge every event.
        mapping: the profile's mapping store.
        appservice: the write path into the profile's Conduit.
        client: an HTTP client for calling the bridge process, instead of a
            fresh one. ``aclose`` closes it, the appservice and the mapping.
        other_agents: the upstream user IDs of every OTHER bridged profile
            (``routes.bridged_agents``). Their events are dropped and no room
            holding one is relayed into. This profile's own ID is ignored if
            present, so one set can be handed to every bridge.
    """

    def __init__(
        self,
        profile: Profile,
        *,
        mapping: BridgeMapping,
        appservice: AppService,
        client: httpx.AsyncClient | None = None,
        other_agents: frozenset[str] = frozenset(),
        channel: str = MATRIX_CHANNEL,
    ) -> None:
        cfg = profile.channel_bridges().get(channel)
        if cfg is None or cfg.bridge_token is None:
            raise ValueError(f"profile {profile.name!r} has no enabled {channel} bridge")
        self.profile = profile
        self.channel = channel
        # What logs and audit call this bridge. The matrix channel keeps the
        # bare profile name, so alerts written before #483 still match.
        self.label = profile.name if channel == MATRIX_CHANNEL else f"{profile.name}/{channel}"
        self.cfg: MatrixBridgeConfig = cfg
        self.mapping = mapping
        self.appservice = appservice
        # nosemgrep: trentina-httpx-client-outside-egress -- operator URL
        self._client = client or httpx.AsyncClient(timeout=_BRIDGE_TIMEOUT)
        self._bridge_token = cfg.bridge_token.get_secret_value()
        self._inbound_lock = asyncio.Lock()
        self._outbound_lock = asyncio.Lock()
        # Case-folded: a Matrix ID that differs only in case is still that
        # agent as far as this rule goes, and matching more is the safe side.
        # The profile's own upstream IDs on every channel are not "another
        # agent" (#483): the same agent reached by a second path.
        self._other_agents = frozenset(a.casefold() for a in other_agents) - {
            c.public_user_id.casefold() for c in profile.channel_bridges().values()
        }
        # The agent's events refused since start, by the agent rule or the
        # judge: each is a message it believes it sent (#317). /health sums it.
        self.outbound_refused = 0
        # Per local room where the agent is typing, when that was last carried.
        self._typing: dict[str, float] = {}

    async def aclose(self) -> None:
        await self._client.aclose()
        await self.appservice.aclose()
        self.mapping.close()

    # ------------------------------------------------------------------ ids

    async def _inbound_ids(self, content: dict[str, Any]) -> IdMap:
        """Resolve the IDs one upstream message references to local ones."""
        remote_agent = self.cfg.public_user_id
        agent = self.appservice.agent_id
        event_ids, user_ids = referenced_ids(content)
        users = await self.mapping.local_users(user_ids - {remote_agent})
        users[remote_agent] = agent
        return IdMap(events=await self.mapping.local_events(event_ids), users=users)

    async def _outbound_ids(self, content: dict[str, Any]) -> IdMap:
        """Resolve the IDs one agent message references to upstream ones.

        Only the stand-ins this message names are looked up, never the whole
        user table.
        """
        remote_agent = self.cfg.public_user_id
        agent = self.appservice.agent_id
        event_ids, user_ids = referenced_ids(content)
        users = await self.mapping.remote_users(
            {u for u in user_ids if self.appservice.is_stand_in(u)}
        )
        users[agent] = remote_agent
        return IdMap(events=await self.mapping.remote_events(event_ids), users=users)

    # ---------------------------------------------------------- agent rule

    def _is_other_agent(self, user_id: str) -> bool:
        return user_id.casefold() in self._other_agents

    def _refuse(self, direction: str, reason: str, event_id: str) -> None:
        """Log and audit one refusal by the agent rule. Names nobody: the
        reason is from a closed set and the event ID is redacted (#262)."""
        logger.warning(
            "matrix_bridge: dropped %s %s for %s: %s",
            direction,
            redact_source(event_id),
            self.label,
            reason,
        )
        # As router._audit does: a failed audit write never fails the event,
        # and the refusal it would have recorded stands regardless.
        with contextlib.suppress(Exception):
            record_gateway_call(
                self.profile.name,
                _AUDIT_BACKEND if self.channel == MATRIX_CHANNEL else f"{self.channel}_bridge",
                direction,
                Outcome.DENIED_GUARD.value,
                0,
                reason,
            )

    async def _relay_refusal(self, remote_room: str) -> str | None:
        """Why nothing may be relayed into ``remote_room``, or None.

        Fails closed: a room whose members the bridge never reported is
        refused like one known to hold another agent. The bridge reports
        every room it is in on each start, so for a room it is in this lasts
        until then. A room it left is retired rather than left to refuse
        here for good (#317).
        """
        present = await self.mapping.agent_present(remote_room)
        if present is None:
            return MEMBERS_UNREPORTED
        return AGENT_IN_ROOM if present else None

    # -------------------------------------------------------------- verdict

    async def _judge(self, scanned: dict[str, Any], *, room: str, direction: str) -> Any:
        with profile_context(self.profile):
            result = await defend_json(
                scanned,
                source=f"matrix_bridge:{self.label}:{room}",
                source_type="matrix_bridge",
                defense=self.profile.defense,
                record=True,
                attribution={
                    "profile": self.profile.name,
                    "direction": direction,
                    "blocked": self.cfg.enforcement == "block",
                },
            )
        return result.verdict

    def _refusal(self, verdict: Any) -> str | None:
        """Why this event may not be delivered as-is, or None."""
        if self.cfg.enforcement != "block":
            return None
        return refusal_reason(
            verdict.flagged_by.value if verdict.flagged_by else None, gaps_of(verdict)
        )

    # -------------------------------------------------------------- inbound

    async def inbound(self, event: dict[str, Any]) -> str:
        """Judge and deliver one upstream event. Returns what happened."""
        stages = _Stages()
        async with self._inbound_lock:
            stages.lap("wait")
            outcome = await self._inbound(event, stages)
        if outcome in {"delivered", "withheld"}:
            stages.lap("deliver")
            # The sender chose the type and, in an old room, the id (#262).
            kind = event.get("type")
            stages.report(
                f"{self.label} inbound {redact_source(str(event.get('event_id')))} "
                f"{kind if isinstance(kind, str) and kind in _CARRIED else 'other'} {outcome}"
            )
        return outcome

    async def _inbound(self, event: dict[str, Any], stages: _Stages) -> str:
        event_id = str(event["event_id"])
        key = f"in:{event_id}"
        if await self.mapping.seen(key):
            return "duplicate"
        event_type = str(event["type"])
        room = event.get("room") or {}
        remote_room = str(event["room_id"])
        content = event.get("content") or {}
        # A remote sender does not get to write the gateway's markers (#265):
        # removed before the judge reads the event and before one is added.
        stripped = await asyncio.to_thread(strip_reserved, content)
        if stripped:
            logger.info(
                "matrix_bridge: stripped %d reserved key(s) from inbound %s for %s",
                stripped,
                redact_source(event_id),
                self.label,
            )

        uncarried = await self._inbound_uncarried(event, event_type, remote_room)
        if uncarried is not None:
            await self.mapping.mark(key)
            return uncarried

        scanned = {
            "sender": str(event.get("sender_displayname") or ""),
            "room_name": str(room.get("name") or ""),
            "room_topic": str(room.get("topic") or ""),
            "peer": str(room.get("peer_displayname") or ""),
            "content": judged_view(content),
        }
        verdict = await self._judge(scanned, room=remote_room, direction="inbound")
        stages.lap("judge")
        reason = self._refusal(verdict)
        local, stand_in = await self._place(event, scanned, withheld=reason is not None)

        if reason is None:
            out_type = event_type
            out = rewrite_content(content, await self._inbound_ids(content))
            warning = with_stripped(build_warning(verdict), stripped)
            if out is not None and warning is not None:
                out[WARNING_KEY] = warning
        else:
            # Event IDs are opaque; who said it and where stays out of the log.
            logger.warning(
                "matrix_bridge: withheld inbound %s for %s: %s",
                redact_source(event_id),
                self.label,
                reason,
            )
            # A withheld reaction has nothing to stand in for: it is dropped.
            out_type = "m.room.message"
            out = (
                None if event_type == "m.reaction" else await self._withheld_notice(content, reason)
            )

        if out is None:
            await self.mapping.mark(key)
            return "withheld" if reason else "skipped"
        local_event = await self.appservice.send(
            local.local_id, stand_in, out_type, out, _txn("in", event_id)
        )
        await self.mapping.put_event(event_id, local_event)
        await self.mapping.mark(key)
        return "withheld" if reason else "delivered"

    async def _inbound_uncarried(
        self, event: dict[str, Any], event_type: str, remote_room: str
    ) -> str | None:
        """The outcome of an event that is not judged and carried, or None.

        A room announcement first, because it is what reports the members the
        agent rule reads; then the agent rule, for everything else.
        """
        if event_type == _ROOM_ANNOUNCE:
            return await self._inbound_room(event, remote_room)
        if event_type == _ROOM_LEFT:
            return await self._inbound_left(remote_room)
        reason = await self._inbound_agent_refusal(str(event.get("sender") or ""), remote_room)
        if reason is not None:
            self._refuse("inbound", reason, str(event["event_id"]))
            return "dropped"
        if event_type == _REDACTION:
            return await self._inbound_redaction(event, remote_room)
        if event_type not in _CARRIED:
            return "skipped"
        return None

    async def _inbound_agent_refusal(self, sender: str, remote_room: str) -> str | None:
        """Why an upstream event may not be carried by the agent rule, or None.

        An event from another agent also marks its room, so the agent's reply
        is refused even before the bridge re-announces the room's members.
        """
        if self._is_other_agent(sender):
            await self.mapping.set_agent_present(remote_room, True)
            return AGENT_SENDER
        if await self.mapping.agent_present(remote_room):
            return AGENT_IN_ROOM
        return None

    async def _place(
        self, event: dict[str, Any], scanned: dict[str, str | Any], *, withheld: bool
    ) -> tuple[Room, str]:
        """The local room and the sender's stand-in, created as needed.

        A withheld event writes nothing it carried: not its words, not its
        sender's chosen name, not a room name or topic it tried to set.
        """
        remote_room = str(event["room_id"])
        sender = str(event["sender"])
        info = event.get("room") or {}
        peer = str(info.get("peer") or "")
        if withheld:
            known = await self.mapping.room_by_remote(remote_room)
            name, topic = (known.name, known.topic) if known else ("", "")
            displayname = await self.mapping.displayname(sender) or sender
            peer_name = await self.mapping.displayname(peer) or peer if peer else ""
        else:
            name, topic = scanned["room_name"], scanned["room_topic"]
            displayname = scanned["sender"] or sender
            peer_name = scanned["peer"] or peer
        room = await self.appservice.ensure_room(
            remote_room,
            name=name,
            topic=topic,
            is_direct=bool(info.get("is_direct")),
            peer=peer,
            peer_displayname=peer_name,
        )
        stand_in = await self.appservice.ensure_user(sender, displayname)
        await self.appservice.ensure_member(room, stand_in)
        return room, stand_in

    async def _withheld_notice(self, content: dict[str, Any], reason: str) -> dict[str, Any] | None:
        """The notice that replaces a withheld message, in its thread or reply.

        The relation is rebuilt from an allowlist, never copied: it arrived
        with the event the verdict withheld (#296).
        """
        notice: dict[str, Any] = {"msgtype": "m.notice", "body": f"[trentina] withheld: {reason}"}
        relation = withheld_relation(content.get("m.relates_to"))
        if relation is not None:
            notice["m.relates_to"] = relation
        return rewrite_content(notice, await self._inbound_ids(notice))

    async def _inbound_room(self, event: dict[str, Any], remote_room: str) -> str:
        """Create the local room for a room the bridge is in, agent invited.

        The name and topic are the only text, and they are judged like any
        other before they are written; refused, the room is created unnamed.
        """
        info = event.get("room") or {}
        members = info.get("members")
        # None: a bridge from before #264, which reports no members. The
        # room stays unreported, and outbound refuses it until one does.
        if members is not None:
            present = any(self._is_other_agent(str(m)) for m in members)
            await self.mapping.set_agent_present(remote_room, present)
            if present:
                self._refuse("room", AGENT_IN_ROOM, str(event.get("event_id")))
                return ROOM_REFUSED
        peer = str(info.get("peer") or "")
        scanned = {
            "room_name": str(info.get("name") or ""),
            "room_topic": str(info.get("topic") or ""),
            "peer": str(info.get("peer_displayname") or ""),
        }
        verdict = await self._judge(scanned, room=remote_room, direction="inbound")
        if self._refusal(verdict) is not None:
            scanned = {"room_name": "", "room_topic": "", "peer": ""}
        room = await self.appservice.ensure_room(
            remote_room,
            name=scanned["room_name"],
            topic=scanned["room_topic"],
            is_direct=bool(info.get("is_direct")),
            peer=peer,
            peer_displayname=scanned["peer"] or peer,
        )
        # Held until the agent is in, so the room's first messages (which the
        # bridge forwards next) are not written before it can read them.
        if not await self.appservice.wait_for_agent(room):
            logger.warning("matrix_bridge: %s has not joined a new room; carrying on", self.label)
        return "mapped"

    async def _inbound_left(self, remote_room: str) -> str:
        """Retire the mirror of a room the bridge is leaving (#317).

        The local room ID is logged: the agent's homeserver minted it, nobody
        upstream chose it, and it is what an operator re-points a delivery
        away from.
        """
        # TRUST: the bridge process's word that it left a room retires the mirror
        #   untrusted: which room (the bridge chooses remote_room)
        #   judged-by: nothing; the event carries no text into the agent's room
        #   on-failure: fail-closed; it can only remove the agent from a mirror,
        #     which a bridge that left or withheld the room already achieves
        #   owner: core.ProfileBridge._inbound_left
        #   evidence: T3 core module docstring (the bridge is untrusted; it can
        #     withhold, never write); T3 preprocess/base.py invariant 1
        room = await self.mapping.room_by_remote(remote_room)
        if room is None:
            return "skipped"
        await self.appservice.retire(room, _RETIRED, _txn("rt", room.local_id))
        await self.mapping.forget_room(room)
        logger.warning(
            "matrix_bridge: retired %s's room %s: the bridge left it upstream",
            self.label,
            room.local_id,
        )
        return "retired"

    async def _inbound_redaction(self, event: dict[str, Any], remote_room: str) -> str:
        """Mirror a redaction. Only removes: its reason text is not carried.

        Not judged, and not a new power for the bridge process. A redaction
        takes away an event the agent already had judged in front of it; it
        cannot put anything there. A compromised bridge that forged one could
        equally have withheld the original, so honouring it grants nothing
        the bridge did not already hold (``preprocess/base.py`` invariant 1:
        subtract, never absolve).
        """
        redacts = event.get("redacts") or (event.get("content") or {}).get("redacts")
        target = await self.mapping.local_event(str(redacts)) if redacts else None
        room = await self.mapping.room_by_remote(remote_room)
        if target is None or room is None:
            return "skipped"
        # As the room's owner: the bot in a room it created, the other
        # person's stand-in in a DM. Either holds power level 100.
        await self.appservice.redact(
            room.local_id,
            self.appservice.actor(room),
            target,
            _txn("rd", str(event["event_id"])),
        )
        return "redacted"

    # ------------------------------------------------------------- outbound

    async def outbound(self, txn_id: str, events: list[dict[str, Any]]) -> None:
        """Carry the agent's events in one appservice transaction upstream.

        Raises BridgeUnavailableError when the bridge cannot take one now, so
        the transaction is not acked and Conduit sends it again; events already
        carried are skipped on the retry. An event the bridge answers it can
        never carry (``BridgeRefusedError``) is dropped and the agent told, so
        it holds up nothing behind it.
        """
        async with self._outbound_lock:
            if await self.mapping.seen(f"txn:{txn_id}"):
                return
            for event in events:
                await self._outbound(event)
            await self.mapping.mark(f"txn:{txn_id}")

    async def _outbound(self, event: dict[str, Any]) -> None:
        if event.get("sender") != self.appservice.agent_id:
            return
        room = await self.appservice.room_for_local(str(event.get("room_id")))
        event_id = str(event.get("event_id"))
        key = f"out:{event_id}"
        if room is None or await self.mapping.seen(key):
            return
        remote_room = room.remote_id
        event_type = str(event.get("type"))
        content = event.get("content") or {}

        if event_type == _REDACTION:
            await self._outbound_redaction(event, room)
            await self.mapping.mark(key)
            return
        if event_type not in _CARRIED or await self._refused_outbound(room, event_id):
            await self.mapping.mark(key)
            return

        stages = _Stages()
        verdict = await self._judge(
            {"content": judged_view(content)}, room=remote_room, direction="outbound"
        )
        stages.lap("judge")
        reason = self._refusal(verdict)
        if reason is not None:
            self.outbound_refused += 1
            logger.warning(
                "matrix_bridge: withheld outbound %s for %s: %s",
                event_id,
                self.label,
                reason,
            )
            await self.appservice.notice(
                room,
                f"[trentina] your message was not sent: {reason}",
                _txn("wo", event_id),
            )
            await self.mapping.mark(key)
            stages.lap("notice")
            stages.report(f"{self.label} outbound {event_id} withheld")
            return

        out = rewrite_content(content, await self._outbound_ids(content))
        if out is None:
            await self.mapping.mark(key)
            return
        sent = await self._send_upstream(room, event_type, out, event_id)
        if sent is not None:
            await self.mapping.put_event(sent, event_id)
        await self.mapping.mark(key)
        stages.lap("send")
        stages.report(
            f"{self.label} outbound {event_id} {event_type} {'sent' if sent else 'refused'}"
        )

    async def _send_upstream(
        self, room: Room, event_type: str, content: dict[str, Any], event_id: str
    ) -> str | None:
        """The upstream event ID of one judged event the bridge sent, or None
        when the bridge refused it for good and the agent was told."""
        try:
            sent = await self._bridge(
                "/send",
                {
                    "room_id": room.remote_id,
                    "type": event_type,
                    "content": content,
                    "txn_id": _txn("out", event_id),
                },
            )
        except BridgeRefusedError as exc:
            logger.warning(
                "matrix_bridge: bridge %s answered %d to outbound %s for %s",
                exc.path,
                exc.status,
                event_id,
                self.label,
            )
            await self._undeliverable(room, event_id)
            return None
        return str(sent["event_id"])

    async def _outbound_redaction(self, event: dict[str, Any], room: Room) -> None:
        """Mirror the agent's redaction upstream, unless the room is refused."""
        event_id = str(event.get("event_id"))
        redacts = event.get("redacts") or (event.get("content") or {}).get("redacts")
        target = await self.mapping.remote_event(str(redacts)) if redacts else None
        if target is None or await self._refused_outbound(room, event_id):
            return
        try:
            await self._bridge(
                "/redact",
                {"room_id": room.remote_id, "event_id": target, "txn_id": _txn("rdo", event_id)},
            )
        except BridgeRefusedError as exc:
            logger.warning(
                "matrix_bridge: bridge %s answered %d to outbound %s for %s",
                exc.path,
                exc.status,
                event_id,
                self.label,
            )
            await self._undeliverable(room, event_id)

    async def _undeliverable(self, room: Room, event_id: str) -> None:
        """Tell the agent the bridge will never carry this event (#483)."""
        self.outbound_refused += 1
        await self.appservice.notice(
            room,
            f"[trentina] your message was not sent: the {self.channel} channel cannot carry it",
            _txn("wo", event_id),
        )

    async def _refused_outbound(self, room: Room, event_id: str) -> bool:
        """Refuse an event by the agent rule, telling the agent; True if so.

        Before the judge, so a refused room costs no model call.
        """
        refusal = await self._relay_refusal(room.remote_id)
        if refusal is None:
            return False
        self.outbound_refused += 1
        self._refuse("outbound", refusal, event_id)
        await self.appservice.notice(
            room, f"[trentina] your message was not sent: {refusal}", _txn("wo", event_id)
        )
        return True

    # --------------------------------------------------------------- typing

    async def typing(self, ephemeral: list[dict[str, Any]]) -> None:
        """Carry the agent's typing upstream (#1533). Never raises.

        ``ephemeral`` is a transaction's ephemeral section (MSC2409); only
        ``m.typing`` is read, and only whether the agent is in it. Nothing
        else in it reaches the bridge, so there is nothing to judge. A state
        is sent when it changes, and a still-true one every
        ``_TYPING_REFRESH`` seconds, since upstream indicators lapse.
        """
        for edu in ephemeral:
            if not isinstance(edu, dict) or edu.get("type") != _TYPING:
                continue
            local_room = edu.get("room_id")
            content = edu.get("content")
            if not isinstance(local_room, str) or not isinstance(content, dict):
                continue
            user_ids = content.get("user_ids")
            typing = isinstance(user_ids, list) and self.appservice.agent_id in user_ids
            now = time.monotonic()
            since = self._typing.get(local_room)
            # Only rooms where the agent is typing are held, so this stays as
            # small as the rooms it is typing in at once.
            if not typing and since is None:
                continue
            if typing and since is not None and now - since < _TYPING_REFRESH:
                continue
            if await self._send_typing(local_room, typing):
                if typing:
                    self._typing[local_room] = now
                else:
                    self._typing.pop(local_room, None)
            elif typing:
                # A start not carried: forget it, so the next push tries again.
                self._typing.pop(local_room, None)
            else:
                # A stop not carried: still held, and due, so the next push of
                # either kind goes at once. Upstream lapses it meanwhile.
                self._typing[local_room] = float("-inf")

    async def _send_typing(self, local_room: str, typing: bool) -> bool:
        """Ask the bridge to show or clear the agent's typing; whether it went."""
        try:
            room = await self.appservice.room_for_local(local_room)
            if room is None or await self._relay_refusal(room.remote_id) is not None:
                return False
            reply = await self._bridge(
                "/typing",
                {"room_id": room.remote_id, "typing": typing},
                deadline=_TYPING_DEADLINE,
            )
        except (BridgeRefusedError, BridgeUnavailableError, ConduitError, OSError) as exc:
            # A bridge without /typing answers 404; a bubble is not worth a
            # log line at the level production runs at.
            logger.debug("matrix_bridge: typing for %s not carried: %s", self.label, exc_kind(exc))
            return False
        return reply.get("shown") is True

    async def _bridge(
        self, path: str, body: dict[str, Any], *, deadline: float = _BRIDGE_DEADLINE
    ) -> dict[str, Any]:
        # The bridge process is untrusted: its reply is read under the #267
        # cap and a deadline (#295), and none of its text goes into the
        # error, which callers log.
        try:
            resp, raw = await request_capped(
                self._client,
                "POST",
                f"{self.cfg.bridge_url}{path}",
                deadline=deadline,
                json=body,
                headers={"Authorization": f"Bearer {self._bridge_token}"},
            )
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            raise BridgeUnavailableError(f"bridge {path}: {exc_kind(exc)}") from exc
        status = resp.status_code
        if 400 <= status < 500 and status not in _RETRYABLE_4XX:
            raise BridgeRefusedError(path, status)
        if status != 200:
            raise BridgeUnavailableError(f"bridge {path} -> {status}")
        try:
            reply = json.loads(raw)
        except ValueError as exc:
            raise BridgeUnavailableError(f"bridge {path}: not JSON") from exc
        if not isinstance(reply, dict):
            raise BridgeUnavailableError(f"bridge {path}: not a JSON object")
        return reply
