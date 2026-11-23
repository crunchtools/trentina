"""What the git transport sends back, judged (spec 027 phase 1, ``flag``).

``git_transport`` decides a request and dials the forge; this module relays
the forge's answer so that nothing reaches the agent that no layer read, or
that the agent was not told about by object id:

- **A fetch's pack** streams to the agent as it arrives, while ``git_pack``
  reads it in a worker thread and ``git_judge`` judges each object. Only the
  tail, the last pack entries and the trailer, is held, for up to
  ``TAIL_HOLD`` seconds for the judging to catch up. Then the gateway names
  what was flagged and what went unjudged on git's side band, counts in one
  line what is still pending, and delivers. Pending objects go on being
  judged in the background; their verdicts warm the cache and land as
  ``detections`` rows.
- **Forge text** is replaced, never judged: side-band channels 2 and 3 are
  dropped and the gateway writes its own progress lines from a closed
  vocabulary; an ``ERR`` line, a push's ``unpack`` reason and its ``ng``
  reasons become the gateway's wording (``git_wire``).
- **A ref listing** is buffered whole (``MAX_LISTING_BYTES``), its
  capabilities rewritten, and every name in it judged before it is listed.
  Under ``flag`` a flagged name is listed and recorded; there is no side band
  in a listing, so it is named on the side band of the repository's next
  fetch.
- **Lanes.** A profile's judged fetches run one at a time in two lanes,
  ``fetch`` and ``promisor`` (a partial clone's lazy fetches), so a
  checkout's lazy fetch never waits behind a clone. A fetch that finds its
  lane busy queues, up to ``LANE_QUEUE`` waiting, and past that is refused
  ``busy``.

Every line the gateway writes on the side band is closed words and an object
id, never a path or content: ``Trentina: flagged <kind> <oid> (<layer>,
<risk>)``, ``Trentina: unjudged <kind> <oid> (<gap>)``.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..logsafe import exc_kind, exc_where
from ..outcomes import Outcome
from ..transports.base import RefusedError
from .git_chunks import gateway_chunk_key
from .git_judge import GitJudge, flush_store
from .git_pack import Limits, PackReader, PackRefusedError
from .git_wire import (
    PACKFILE_HEADER,
    FetchResponse,
    GitRefusedError,
    PushResponse,
    progress,
    rewrite_listing,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ..transports.perimeter import InTree
    from .profile import GitGrant, Profile

logger = logging.getLogger(__name__)

TAIL_HOLD = 30.0
"""Seconds the tail of a pack is held under ``flag`` for judging to catch up."""

TAIL_BYTES = 64 * 1024
"""Pack data held back at all times, so the trailer is never sent early."""

KEEPALIVE = 60.0
"""The longest the gateway holds bytes without writing a progress line."""

LISTING_HOLD = 30.0
"""Seconds a listing waits for its names to be judged under ``flag``."""

MAX_LISTING_BYTES = 4 * 1024 * 1024
"""Largest ref listing buffered to be judged; past it, refused ``too_large``."""

MAX_NAMED = 20
"""Objects named one a line; past it, one line with the counts."""

FEED_BYTES = 1024 * 1024
"""Pack data gathered before it is handed to the reader's thread."""

LANE_QUEUE = 4
"""Judged fetches that may wait for a profile's lane."""

_OID_BYTES = {"sha1": 20, "sha256": 32}
_DEFAULT_OID_BYTES = _OID_BYTES["sha1"]


# --- lanes ---------------------------------------------------------------------


@dataclass
class _Lane:
    gate: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(1))
    waiting: int = 0


#: Per event loop: a semaphore belongs to the loop it was first used on.
_lanes: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, str], _Lane]] = (
    weakref.WeakKeyDictionary()
)


class LaneBusyError(GitRefusedError):
    def __init__(self) -> None:
        super().__init__(HTTPStatus.TOO_MANY_REQUESTS, "busy")


async def enter_lane(profile: str, promisor: bool) -> asyncio.Semaphore:
    """Wait for the profile's lane; the caller releases what is returned.

    Raises:
        GitRefusedError: ``busy`` (429) when ``LANE_QUEUE`` are already waiting.
    """
    lanes = _lanes.setdefault(asyncio.get_running_loop(), {})
    lane = lanes.setdefault((profile, "promisor" if promisor else "fetch"), _Lane())
    if lane.gate.locked():
        if lane.waiting >= LANE_QUEUE:
            raise LaneBusyError
        lane.waiting += 1
        try:
            await lane.gate.acquire()
        finally:
            lane.waiting -= 1
    else:
        await lane.gate.acquire()
    return lane.gate


# --- the chunk key -------------------------------------------------------------

_chunk_secret: bytes | None = None


def chunk_secret() -> bytes:
    """The gateway's own key for chunk boundaries, beside the perimeter store."""
    global _chunk_secret
    if _chunk_secret is None:
        config = get_config()
        config.ensure_perimeter_db_dir()
        path = Path(config.perimeter_db_path).with_name("git-chunk.key")
        _chunk_secret = gateway_chunk_key(str(path))
    return _chunk_secret


# --- ref names flagged in a listing, named on the next fetch --------------------

_FLAGGED_REFS_MAX = 1024
_flagged_refs: OrderedDict[tuple[str, str], int] = OrderedDict()


def _remember_refs(profile: str, slug: str, count: int) -> None:
    if count:
        _flagged_refs[(profile, slug)] = count
        _flagged_refs.move_to_end((profile, slug))
        while len(_flagged_refs) > _FLAGGED_REFS_MAX:
            _flagged_refs.popitem(last=False)


# --- fetch ---------------------------------------------------------------------


@dataclass
class Fetch:
    """What the route learned of one judged fetch before it dialed."""

    profile: Profile
    grant: GitGrant
    source: str
    slug: str
    v2: bool
    wants: list[str]
    object_format: str = "sha1"


def new_call_ref() -> str:
    return uuid.uuid4().hex


class _Feeder:
    """Hands pack data to the reader in a worker thread, one piece at a time,
    and each object it resolves to the judge. A reader refusal ends judging
    and leaves the rest of the pack to be named unjudged."""

    def __init__(self, reader: PackReader, judge: GitJudge) -> None:
        self._reader = reader
        self._judge = judge
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=16)
        self._task = asyncio.ensure_future(self._run())
        self._held = bytearray()
        self.refused: str | None = None
        self._ended = False
        self._finished = False

    async def feed(self, data: bytes) -> None:
        self._held += data
        if len(self._held) >= FEED_BYTES:
            await self._queue.put(bytes(self._held))
            self._held.clear()

    async def finish(self) -> None:
        """The pack has ended: read what is queued, then the trailer. Once."""
        if not self._finished:
            self._finished = True
            if self._held:
                await self._queue.put(bytes(self._held))
                self._held.clear()
            await self._queue.put(None)
        await asyncio.shield(self._task)

    def done(self) -> bool:
        return self._task.done()

    async def _drain(self) -> None:
        """Take what is still queued, so the relay never blocks on a full queue."""
        while not self._ended:
            self._ended = await self._queue.get() is None

    async def _run(self) -> None:
        try:
            while (data := await self._queue.get()) is not None:
                if self.refused is None:
                    for obj in await asyncio.to_thread(self._reader.feed, data):
                        self._judge.submit(obj)
            self._ended = True
            if self.refused is None:
                for obj in await asyncio.to_thread(self._reader.finish):
                    self._judge.submit(obj)
                self._judge.finish_pack()
        except PackRefusedError as refused:
            self.refused = refused.reason
            await self._drain()
        except Exception as exc:  # a reader that fails is an unjudged pack, never a lost one
            logger.error("git judge: pack reader failed: %s at %s", exc_kind(exc), exc_where(exc))
            self.refused = "failed"
            await self._drain()
        finally:
            self._reader.close()
            self._judge.close()


def _named(judge: GitJudge, refused: str | None, refs: int) -> list[bytes]:
    """The side-band lines naming what a fetch delivered flagged, unjudged or pending."""
    outcome = judge.outcome()
    lines: list[str] = []
    if refused is not None:
        lines.append(f"Trentina: unjudged pack ({refused})")
    if refs:
        lines.append(f"Trentina: flagged ref names in the last listing: {refs}")
    named = [
        f"Trentina: flagged {kind} {oid} ({layer}, {risk})"
        for kind, oid, layer, risk in outcome.flagged
    ] + [f"Trentina: unjudged {kind} {oid} ({gap})" for kind, oid, gap in outcome.unjudged]
    if len(named) > MAX_NAMED:
        lines.append(
            f"Trentina: flagged {len(outcome.flagged)} objects, "
            f"unjudged {len(outcome.unjudged)}; read the detections for their ids"
        )
    else:
        lines += named
    if outcome.pending:
        lines.append(f"Trentina: pending {outcome.pending} objects, judged after delivery")
    return [progress(line) for line in lines]


def _progress(judge: GitJudge) -> bytes:
    judged, seen = judge.progress()
    return progress(f"Trentina: judged {judged}/{seen} objects")


def _found(flagged: object, unjudged: object) -> str | None:
    """The row's reason for what a fetch or listing found: a flag outranks a gap."""
    return "git_flagged" if flagged else "git_unjudged" if unjudged else None


def _account(judge: GitJudge, refused: str | None) -> dict[str, str]:
    outcome = judge.outcome()
    counts = {
        "git_objects": str(outcome.total),
        "git_flagged": str(len(outcome.flagged)),
        "git_unjudged": str(len(outcome.unjudged)),
        "git_pending": str(outcome.pending),
        "git_units": str(judge.stats["units"]),
        "git_cached": str(judge.stats["cached"]),
    }
    if refused is not None:
        counts["git_pack"] = refused
    return counts


class _FetchRelay:
    """One fetch answer's state: the parser, the held tail, and the judging,
    started at the first pack byte (a v2 negotiation round carries none)."""

    def __init__(self, ctx: InTree, fetch: Fetch) -> None:
        self.ctx = ctx
        self.fetch = fetch
        self.parser = FetchResponse(v2=fetch.v2)
        self.tail: list[bytes] = []
        self.tail_bytes = 0
        self.judge: GitJudge | None = None
        self.feeder: _Feeder | None = None
        self.refs = _flagged_refs.pop((fetch.profile.name, fetch.slug), 0)

    def _start(self) -> _Feeder:
        op, fetch = self.ctx.op, self.fetch
        op.call_ref = op.call_ref or new_call_ref()
        self.judge = GitJudge(
            profile=fetch.profile,
            grant=fetch.grant,
            source=fetch.source,
            call_ref=op.call_ref,
            chunk_secret=chunk_secret(),
            wants=fetch.wants,
            oid_len=_OID_BYTES.get(fetch.object_format, _DEFAULT_OID_BYTES),
        )
        config = get_config()
        config.ensure_perimeter_db_dir()
        reader = PackReader(
            object_format=fetch.object_format,
            limits=Limits(max_arrived=fetch.grant.max_judged_pack_bytes),
            spool_dir=str(Path(config.perimeter_db_path).parent),
        )
        self.judge.start(float(fetch.grant.judge_deadline))
        self.feeder = _Feeder(reader, self.judge)
        return self.feeder

    async def take(self, piece: bytes) -> AsyncIterator[bytes]:
        """What to send on for one piece of the forge's answer."""
        out = bytearray()
        for event, value in self.parser.feed(piece):
            if event == "pass":
                out += value
            elif event == "section_start":
                out += PACKFILE_HEADER
            elif event == "pack":
                await (self.feeder or self._start()).feed(value)
                out += self._hold(value)
            elif event == "forge_error":
                out += progress("Trentina: the forge reported an error")
            elif event == "end":
                if out:
                    yield bytes(out)
                    out.clear()
                async for held in self._release():
                    yield held
                out += value
        if out:
            yield bytes(out)

    def _hold(self, pack: bytes) -> bytes:
        """Frame ``pack`` as one band-1 pkt-line, as the forge did, and keep at
        least ``TAIL_BYTES`` of the stream back; return what may go now."""
        wire = f"{len(pack) + 5:04x}".encode() + b"\x01" + pack
        self.tail.append(wire)
        self.tail_bytes += len(wire)
        sent = bytearray()
        while self.tail and self.tail_bytes - len(self.tail[0]) >= TAIL_BYTES:
            first = self.tail.pop(0)
            self.tail_bytes -= len(first)
            sent += first
        return bytes(sent)

    async def _release(self) -> AsyncIterator[bytes]:
        """The end of the pack: let the reader finish, wait up to ``TAIL_HOLD``
        for the judging, name what it found, then send the held tail. A
        progress line goes out at least every ``KEEPALIVE`` while it waits."""
        held = b"".join(self.tail)
        self.tail.clear()
        self.tail_bytes = 0
        if self.feeder is None or self.judge is None:
            yield held
            return
        finishing = asyncio.ensure_future(self.feeder.finish())
        while not finishing.done():
            yield _progress(self.judge)
            await asyncio.wait({finishing}, timeout=KEEPALIVE / 2)
        await finishing
        yield _progress(self.judge)
        await self.judge.wait(TAIL_HOLD)  # under KEEPALIVE: the line above is enough
        yield b"".join(_named(self.judge, self.feeder.refused, self.refs)) + held

    def settle(self) -> None:
        op = self.ctx.op
        if self.judge is None:
            op.settle(Outcome.OK)
            return
        refused = self.feeder.refused if self.feeder is not None else None
        op.normalized = _account(self.judge, refused)
        outcome = self.judge.outcome()
        found = _found(outcome.flagged, outcome.unjudged or refused)
        op.flag_reason = found
        op.settle(Outcome.OK, found)

    def close(self) -> None:
        """However the answer ended, the pack that arrived is still read and
        judged, in the background: a request that went away is not waited on."""
        if self.feeder is not None and not self.feeder.done():
            task = asyncio.ensure_future(self.feeder.finish())
            _CLOSING.add(task)
            task.add_done_callback(_CLOSING.discard)


async def relay_fetch(ctx: InTree, resp: Any, fetch: Fetch) -> AsyncIterator[bytes]:
    """A fetch's answer for the agent: judged as it streams, the tail held.

    A stream that fails part-way ends, and git reads a truncated pack as the
    error it is; the judging of what did arrive goes on.
    """
    op = ctx.op
    relay = _FetchRelay(ctx, fetch)
    try:
        async for piece in ctx.chunks(resp):
            op.received += len(piece)
            async for out in relay.take(piece):
                yield out
        relay.parser.finish()
        relay.settle()
    except ValueError:
        logger.warning("git transport: a fetch answer was not git's; ended it")
        op.settle(Outcome.BLOCKED_DEFENSE, "section")
    except RefusedError as failed:
        logger.warning("git transport: upstream %s mid-stream", failed.reason)
        op.settle(Outcome.BACKEND_ERROR, failed.reason)
    finally:
        relay.close()


#: Feeders finishing after their request ended, held so none is collected mid-flight.
_CLOSING: set[asyncio.Task[None]] = set()


# --- listings --------------------------------------------------------------------


async def relay_listing(
    ctx: InTree,
    resp: Any,
    *,
    protocol: str | None,
    hidden: tuple[bytes, ...],
    profile: Profile,
    grant: GitGrant,
    source: str,
    slug: str,
) -> AsyncIterator[bytes]:
    """A ref listing, buffered whole, rewritten, its names judged, then sent."""
    op = ctx.op
    held = bytearray()
    try:
        async for piece in ctx.chunks(resp):
            op.received += len(piece)
            held += piece
            if len(held) > MAX_LISTING_BYTES:
                raise GitRefusedError(HTTPStatus.BAD_GATEWAY, "too_large", Outcome.BLOCKED_DEFENSE)
        listing, names = rewrite_listing(bytes(held), protocol, hidden)
    except ValueError:
        logger.warning("git transport: a ref listing could not be filtered; ended it")
        op.settle(Outcome.BLOCKED_DEFENSE, "advertisement")
        return
    except RefusedError as failed:
        op.settle(failed.outcome or Outcome.BACKEND_ERROR, failed.reason)
        return
    flagged = await _judge_names(op, names, profile=profile, grant=grant, source=source)
    _remember_refs(profile.name, slug, flagged)
    yield listing
    unjudged = op.normalized is not None and op.normalized["git_unjudged"] != "0"
    op.settle(Outcome.OK, _found(flagged, unjudged))


async def _judge_names(
    op: Any, names: list[str], *, profile: Profile, grant: GitGrant, source: str
) -> int:
    """Judge a listing's names; the number flagged.

    The row carries a ``call_ref`` and the counts only when a name was
    flagged, unjudged or is still pending: a clean listing's row is as it was.
    """
    if not names:
        return 0
    call_ref = op.call_ref or new_call_ref()
    judge = GitJudge(
        profile=profile,
        grant=grant,
        source=source,
        call_ref=call_ref,
        chunk_secret=chunk_secret(),
    )
    judge.submit_names(names)
    judge.close()
    judge.start(float(grant.judge_deadline))
    try:
        await judge.wait(LISTING_HOLD)
    except Exception as exc:  # judging never costs the listing
        logger.warning("git judge: listing wait failed: %s at %s", exc_kind(exc), exc_where(exc))
    outcome = judge.outcome()
    if outcome.flagged or outcome.unjudged or outcome.pending:
        op.call_ref = call_ref
        op.normalized = _account(judge, None)
    flush_store()
    return len(outcome.flagged)


# --- push ------------------------------------------------------------------------


async def relay_push(ctx: InTree, resp: Any) -> AsyncIterator[bytes]:
    """A push's report, the forge's own words replaced by the gateway's."""
    op = ctx.op
    report = PushResponse()
    try:
        async for piece in ctx.chunks(resp):
            op.received += len(piece)
            if out := report.feed(piece):
                yield out
        report.finish()
        op.settle(Outcome.OK)
    except ValueError:
        logger.warning("git transport: a push report was not git's; ended it")
        op.settle(Outcome.BLOCKED_DEFENSE, "section")
    except RefusedError as failed:
        logger.warning("git transport: upstream %s mid-stream", failed.reason)
        op.settle(Outcome.BACKEND_ERROR, failed.reason)
