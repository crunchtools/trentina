"""What the git transport sends back, judged (spec 027 phase 1, ``flag``).

``git_transport`` decides a request and dials the forge; this module relays
the forge's answer so that nothing reaches the agent that no layer read, or
that the agent was not told about by object id:

- **A fetch's pack** streams to the agent as it arrives, while ``git_pack``
  reads it in a child process and ``git_judge`` judges each object. Only the
  tail, the last pack entries and the trailer, is held, for up to
  ``TAIL_HOLD`` seconds for the reading and the judging to catch up. Then the gateway names
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
import sys
import uuid
import weakref
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..logsafe import exc_kind, exc_where
from ..outcomes import Outcome
from ..transports.base import RefusedError
from ..unpack.child import environment
from ..unpack.git_pack import (
    DEFAULT_LIMITS,
    OBJ_BLOB,
    OBJ_COMMIT,
    OBJ_TAG,
    OBJ_TREE,
    PackObject,
)
from ..unpack.git_pack import REASONS as PACK_REASONS
from .git_chunks import gateway_chunk_key
from .git_judge import MAX_OBJECT_BYTES, GitJudge, flush_store
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

BUSY = "busy"
"""The unjudged-pack reason for a fetch that found no judging slot."""

SLOT_GRACE = 60.0
"""Seconds past ``judge_deadline`` a judging slot is held at most, in case what
should end it never does."""

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


# --- judging slots ------------------------------------------------------------


class _Slots:
    """The fetches being judged, counted gateway-wide and per profile.

    A judged fetch outlives its response: the reader child and the judge go on
    until the pack is read and the last unit settles, up to ``judge_deadline``.
    The lane is let go with the response, so the lane cannot count them; a slot
    is taken when judging starts and given back by ``_hold`` once both have
    ended. A fetch that finds none is delivered unjudged (``busy``), never
    refused. With ``Config.git_judges`` slots and a reader that spools at most
    ``DEFAULT_LIMITS.max_inflated`` (2 GiB) each, the spool on the perimeter
    volume is bounded by their product, and the children's memory by the
    slots times the reader's address-space limit.
    """

    def __init__(self) -> None:
        self.total = 0
        self.by_profile: dict[str, int] = {}

    def take(self, profile: str) -> bool:
        config = get_config()
        if self.total >= config.git_judges:
            return False
        if self.by_profile.get(profile, 0) >= config.git_profile_judges:
            return False
        self.total += 1
        self.by_profile[profile] = self.by_profile.get(profile, 0) + 1
        return True

    def release(self, profile: str) -> None:
        self.total = max(self.total - 1, 0)
        left = self.by_profile.get(profile, 0) - 1
        if left > 0:
            self.by_profile[profile] = left
        else:
            self.by_profile.pop(profile, None)


_slots = _Slots()


async def _hold(profile: str, judge: asyncio.Task[None], feeder: _Feeder, deadline: float) -> None:
    """Keep the profile's judging slot until the reader has ended and the judge
    task has settled, however the response ended; at the latest ``SLOT_GRACE``
    past the deadline, which bounds both."""
    try:
        async with asyncio.timeout(deadline + SLOT_GRACE):
            await feeder.over.wait()
            await asyncio.wait({judge})
    except TimeoutError:
        logger.warning("git judge: a judging slot was released at its backstop")
    finally:
        _slots.release(profile)


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


@dataclass(frozen=True)
class _Reading:
    """What the reader child is started with: numbers and a directory the
    gateway chose, never anything the forge or the agent sent."""

    object_format: str
    max_arrived: int
    max_inflated: int
    deadline: int
    spool_dir: str
    max_object: int = MAX_OBJECT_BYTES

    def argv(self) -> list[str]:
        return [
            sys.executable,
            "-m",
            "trentina.unpack.git_pack_worker",
            self.object_format,
            str(self.max_arrived),
            str(self.max_inflated),
            str(self.max_object),
            str(self.deadline),
            self.spool_dir,
        ]


class _Feeder:
    """Hands pack data to the reader child and each object it resolves to the
    judge (``unpack.git_pack_worker``).

    A refusal from the reader, a child that dies or one past the deadline ends
    the judging and leaves the rest of the pack to be named unjudged; the
    pack itself still reaches the agent, under ``flag``. Writing waits for the
    child to take each piece, so delivery runs no faster than the reading.
    """

    def __init__(self, reading: _Reading, judge: GitJudge) -> None:
        self._reading = reading
        self._judge = judge
        self._held = bytearray()
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task[None] | None = None
        self._finished = False
        self.refused: str | None = None
        #: Set once the reader child has exited and the judge has been told no more is coming.
        self.over = asyncio.Event()

    async def _started(self) -> asyncio.subprocess.Process | None:
        if self._proc is None and self.refused is None:
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *self._reading.argv(),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=environment(),
                )
            except OSError as exc:
                logger.error(
                    "git judge: pack reader not started: %s at %s", exc_kind(exc), exc_where(exc)
                )
                self.refused = "failed"
                return None
            self._task = asyncio.ensure_future(self._read(self._proc))
        return self._proc

    async def feed(self, piece: bytes) -> None:
        self._held += piece
        if len(self._held) >= FEED_BYTES:
            await self._write(bytes(self._held))
            self._held.clear()

    async def _write(self, piece: bytes) -> None:
        proc = await self._started()
        if proc is None or proc.stdin is None or self.refused is not None:
            return
        try:
            proc.stdin.write(piece)
            await proc.stdin.drain()
        except (ConnectionError, RuntimeError):
            self.refused = self.refused or "failed"  # the child ended: _read says why

    async def finish(self) -> None:
        """The pack has ended: the child reads the trailer and says so. Once."""
        if not self._finished:
            self._finished = True
            if self._held:
                await self._write(bytes(self._held))
                self._held.clear()
            proc = await self._started()
            if proc is not None and proc.stdin is not None:
                proc.stdin.close()
        if self._task is not None:
            await asyncio.shield(self._task)
        else:
            self._judge.close()
            self.over.set()

    def done(self) -> bool:
        return self._finished and (self._task is None or self._task.done())

    async def _read(self, proc: asyncio.subprocess.Process) -> None:
        try:
            async with asyncio.timeout(self._reading.deadline):
                ended = await self._objects(proc)
            if ended:
                self._judge.finish_pack()
        except TimeoutError:
            self.refused = "deadline"
        except Exception as exc:  # a reader that fails is an unjudged pack, never a lost one
            logger.error("git judge: pack reader failed: %s at %s", exc_kind(exc), exc_where(exc))
            self.refused = "failed"
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
            self._judge.close()
            self.over.set()

    async def _objects(self, proc: asyncio.subprocess.Process) -> bool:
        """Read the child's objects into the judge; True when the pack was whole.

        Every header is checked for shape and every length against the
        inflated limit before a byte of content is read.
        """
        stdout = proc.stdout
        if stdout is None:  # pragma: no cover - started with a pipe
            return False
        while header := await stdout.readline():
            words = header.decode("ascii", "replace").split()
            if words == ["end"]:
                return True
            if len(words) == 2 and words[0] == "refused":
                self.refused = words[1] if words[1] in PACK_REASONS else "failed"
                return False
            kind, oid, offset, length, over = _header(words, self._reading.max_inflated)
            if self._judge.full():
                self.refused = "too_many"
                return False
            if over:
                self._judge.submit_unread(oid, kind, "too_large")
                continue
            if length > self._reading.max_object:
                raise ValueError("an object over the limit was sent")
            content = await stdout.readexactly(length)
            await self._judge.add(PackObject(oid=oid, kind=kind, content=content, offset=offset))
        self.refused = self.refused or "failed"  # it ended without saying so
        return False


def _header(words: list[str], limit: int) -> tuple[str, str, int, int, bool]:
    """One object header from the reader child, or ValueError; the last field
    is True for an object over the limit, sent without its content."""
    over = words[4:] == ["over"]
    if len(words) != 4 + over or words[0] not in _KINDS:
        raise ValueError("not an object header")
    kind, oid, offset, length = words[:4]
    if len(oid) not in _OID_HEX or not _HEX.issuperset(oid):
        raise ValueError("not an object id")
    if not (offset.isdigit() and length.isdigit()) or int(length) > limit:
        raise ValueError("not a length")
    return kind, oid, int(offset), int(length), over


_KINDS = frozenset({OBJ_BLOB, OBJ_COMMIT, OBJ_TAG, OBJ_TREE})
_OID_HEX = frozenset({40, 64})
_HEX = frozenset("0123456789abcdef")


def _named(judge: GitJudge, refused: str | None, refs: int) -> list[bytes]:
    """The side-band lines naming what a fetch delivered flagged, unjudged or pending."""
    outcome = judge.outcome()
    lines: list[str] = []
    if refused is not None:
        lines.append(f"Trentina: unjudged pack ({refused})")
    if refs:
        lines.append(f"Trentina: flagged ref names in the last listing: {refs}")
    if len(outcome.flagged) + len(outcome.unjudged) > MAX_NAMED:
        lines.append(
            f"Trentina: flagged {len(outcome.flagged)} objects, "
            f"unjudged {len(outcome.unjudged)}; read the detections for their ids"
        )
    else:
        lines += [
            f"Trentina: flagged {kind} {oid} ({layer}, {risk})"
            for kind, oid, layer, risk in outcome.flagged
        ]
        lines += [f"Trentina: unjudged {kind} {oid} ({gap})" for kind, oid, gap in outcome.unjudged]
    if outcome.pending:
        lines.append(f"Trentina: pending {outcome.pending} objects, judged after delivery")
    return [progress(line) for line in lines]


def _unjudged(reason: str) -> bytes:
    return progress(f"Trentina: unjudged pack ({reason})")


def _progress(judge: GitJudge) -> bytes:
    judged, seen = judge.progress()
    return progress(f"Trentina: judged {judged}/{seen} objects")


def _found(flagged: object, unjudged: object) -> str | None:
    """The row's reason for what a fetch or listing found: a flag outranks a gap."""
    return "git_flagged" if flagged else "git_unjudged" if unjudged else None


_COUNTS = ("git_objects", "git_flagged", "git_unjudged", "git_pending", "git_units", "git_cached")


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
        self.tail: deque[bytes] = deque()
        self.tail_bytes = 0
        self.judge: GitJudge | None = None
        self.feeder: _Feeder | None = None
        self.refs = _flagged_refs.pop((fetch.profile.name, fetch.slug), 0)
        self.busy = False

    def _start(self) -> _Feeder | None:
        """The judging of this fetch, or None when no slot is free: the pack
        then goes on unjudged, named ``busy``."""
        op, fetch = self.ctx.op, self.fetch
        if self.busy or not _slots.take(fetch.profile.name):
            self.busy = True
            return None
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
        reading = _Reading(
            object_format=fetch.object_format,
            max_arrived=fetch.grant.max_judged_pack_bytes,
            max_inflated=DEFAULT_LIMITS.max_inflated,
            deadline=fetch.grant.judge_deadline,
            spool_dir=str(Path(config.perimeter_db_path).parent),
        )
        task = self.judge.start(float(fetch.grant.judge_deadline))
        self.feeder = _Feeder(reading, self.judge)
        hold = asyncio.ensure_future(
            _hold(fetch.profile.name, task, self.feeder, float(fetch.grant.judge_deadline))
        )
        _CLOSING.add(hold)
        hold.add_done_callback(_CLOSING.discard)
        return self.feeder

    async def _feed(self, pack: bytes) -> None:
        if feeder := self.feeder or self._start():
            await feeder.feed(pack)

    async def take(self, piece: bytes) -> AsyncIterator[bytes]:
        """What to send on for one piece of the forge's answer."""
        out = bytearray()
        for event, value in self.parser.feed(piece):
            if event == "pass":
                out += value
            elif event == "section_start":
                out += PACKFILE_HEADER
            elif event == "pack":
                await self._feed(value)
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
            first = self.tail.popleft()
            self.tail_bytes -= len(first)
            sent += first
        return bytes(sent)

    async def _release(self) -> AsyncIterator[bytes]:
        """The end of the pack: give the reader and the judging ``TAIL_HOLD``
        between them, name what they found, then send the held tail. A reader
        still going then goes on in the background, and its objects are judged
        after delivery. A progress line goes out at least every ``KEEPALIVE``."""
        held = b"".join(self.tail)
        self.tail.clear()
        self.tail_bytes = 0
        if self.busy:
            yield _unjudged(BUSY) + held
            return
        if self.feeder is None or self.judge is None:
            yield held
            return
        loop = asyncio.get_running_loop()
        until = loop.time() + TAIL_HOLD
        finishing = asyncio.ensure_future(self.feeder.finish())
        while not finishing.done() and (left := until - loop.time()) > 0:
            yield _progress(self.judge)
            await asyncio.wait({finishing}, timeout=min(KEEPALIVE / 2, left))
        yield _progress(self.judge)
        if not finishing.done():
            _CLOSING.add(finishing)
            finishing.add_done_callback(_CLOSING.discard)
            yield progress("Trentina: still reading the pack; the rest is judged after delivery")
            yield held
            return
        await finishing
        await self.judge.wait(max(until - loop.time(), 0.0))
        yield b"".join(_named(self.judge, self.feeder.refused, self.refs)) + held

    def settle(self) -> None:
        op = self.ctx.op
        if self.busy:
            op.normalized = {
                **dict.fromkeys(_COUNTS, "0"),
                "git_pack": BUSY,
            }
            op.flag_reason = "git_unjudged"
            op.settle(Outcome.OK, "git_unjudged")
            return
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
    except ValueError as exc:
        logger.warning(
            "git transport: a fetch answer was not git's (%s at %s); ended it",
            exc_kind(exc),
            exc_where(exc),
        )
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
