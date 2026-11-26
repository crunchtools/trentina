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
  ``detections`` rows. When the judging ends and has found more than the
  fetch's own row recorded, one ``fetch_judged`` row says what.
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
<risk>)``, ``Trentina: unjudged <kind> <oid> (<gap>)``, ``Trentina: unjudged tip
files (<n> want-refs not in the last listing)``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import sys
import uuid
import weakref
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
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
from .errors import ProfileConfigError
from .git_chunks import gateway_chunk_key
from .git_judge import MAX_OBJECT_BYTES, GitJudge, flush_store
from .git_wire import (
    PACKFILE_HEADER,
    FetchResponse,
    GitRefusedError,
    PushResponse,
    listed_refs,
    listed_tips,
    progress,
    rewrite_listing,
)
from .relay import Operation

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

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

FOLLOW_UP = "fetch_judged"
"""The ``tool`` of the row a fetch writes when its judging ends having found
more than the fetch's own row recorded. Rows are chained and never updated."""

COLD_PACK_OBJECTS = 1000
"""A pack declaring more objects than this is judged as a clone, whatever its
request said: ``have`` and ``filter`` lines are the client's to write, the
pack header's count is the forge's. A slot judges about 1.3M tokens in the
default 900 s ``judge_deadline`` (about 1,430 L2 tokens a second), and
trentina's own history averages about 1,200 tokens an object, so past
roughly 1,000 objects a fetch holds its slot to the deadline as a clone
does. An everyday fetch brings tens to hundreds."""

COLD_PACK_BYTES = 1536 * 1024
"""A fetch whose pack has carried more bytes than this is judged as a clone
from then on, however few objects its header declared: a few large blobs
(``git backfill``, ``fetch --deepen``) hold a slot as long as many small ones.
The same slot's 1.29M tokens (1,430 a second for 900 s), at trentina's own
packed average of about 1,585 bytes an object (19,635 objects in 30,389 KiB)
for 1,200 tokens, is about 0.76 tokens a pack byte, so about 1.7 MB of pack
fills the deadline; 1.5 MiB is the object count's 1,000 objects at that
average."""

COLD_INFLATED_BYTES = 3_861_000
"""A fetch whose reader has handed the judge more object bytes than this is
judged as a clone from then on: a small pack's deltas can inflate to
gigabytes (a few hundred KB of pack fanning out to 2 GB), which neither the
declared count nor the carried bytes show. The slot's 1.29M tokens (1,430 a
second for 900 s) at ``git_chunks.TOKEN_BYTES`` (3) bytes a token is about
3.9 MB of objects; at trentina's own 1,200 tokens an object it is the count
limit's 1,000 objects over again."""

PACK_HEADER_BYTES = 12
"""``PACK``, a version and the object count, each four bytes."""

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

    A cold fetch (no ``have``, a filtered fetch of the listed tips, a pack
    declaring more than ``COLD_PACK_OBJECTS``, or one that has carried more
    than ``COLD_PACK_BYTES``, or whose objects have inflated past
    ``COLD_INFLATED_BYTES``) takes at most ``cold_limit`` of them. A cold
    clone cannot finish judging inside ``judge_deadline`` and holds its slot
    for all of it, so without the bound two profiles cloning would leave
    every fetch after them, the cheap ones that do finish, unjudged as
    ``busy``.

    ``take`` hands out a ``_Slot`` that records whether it is counted cold,
    ``promote`` counts a running one cold, and ``release`` gives back exactly
    what the slot holds, once.
    """

    def __init__(self) -> None:
        self.total = 0
        self.cold = 0
        self.by_profile: dict[str, int] = {}

    @staticmethod
    def cold_limit() -> int:
        """Half the gateway's slots, and one where there is only one."""
        judges = get_config().git_judges
        return min(judges, max(1, judges // 2))

    def take(self, profile: str, *, cold: bool = False) -> _Slot | None:
        config = get_config()
        if self.total >= config.git_judges:
            return None
        if self.by_profile.get(profile, 0) >= config.git_profile_judges:
            return None
        if cold and self.cold >= self.cold_limit():
            return None
        self.total += 1
        self.cold += cold
        self.by_profile[profile] = self.by_profile.get(profile, 0) + 1
        return _Slot(profile, cold)

    def promote(self, slot: _Slot) -> bool:
        """Count a running slot cold; False, and nothing changed, when the cold
        ones are all taken."""
        if slot.released:
            return False
        if not slot.cold:
            if self.cold >= self.cold_limit():
                return False
            self.cold += 1
            slot.cold = True
        return True

    def release(self, slot: _Slot) -> None:
        if slot.released:
            return
        slot.released = True
        self.total = max(self.total - 1, 0)
        if slot.cold:
            self.cold = max(self.cold - 1, 0)
        left = self.by_profile.get(slot.profile, 0) - 1
        if left > 0:
            self.by_profile[slot.profile] = left
        else:
            self.by_profile.pop(slot.profile, None)


@dataclass
class _Slot:
    """One judging slot taken from ``_Slots``: whose, and whether it is counted cold."""

    profile: str
    cold: bool
    released: bool = False


_slots = _Slots()


async def _hold(
    slot: _Slot,
    judge: asyncio.Task[None],
    feeder: _Feeder,
    deadline: float,
    then: Callable[[], None] | None = None,
) -> None:
    """Keep a judging slot until the reader has ended and the judge task has
    settled, however the response ended; at the latest ``SLOT_GRACE`` past the
    deadline, which bounds both. It is released as it is then, cold if it was
    promoted on the way, and ``then``, which never raises, is told the judging
    is over."""
    try:
        async with asyncio.timeout(deadline + SLOT_GRACE):
            await feeder.over.wait()
            await asyncio.wait({judge})
    except TimeoutError:
        logger.warning("git judge: a judging slot was released at its backstop")
    finally:
        _slots.release(slot)
        if then is not None:
            then()


# --- the chunk key -------------------------------------------------------------

_chunk_secret: bytes | None = None


def chunk_secret() -> bytes:
    """The gateway's own key for chunk boundaries, in the sealed stores."""
    global _chunk_secret
    if _chunk_secret is None:
        _chunk_secret = gateway_chunk_key(legacy=_legacy_chunk_key())
    return _chunk_secret


def _legacy_chunk_key() -> Path:
    """Where the key was kept before a1706: 0600 plaintext beside the perimeter store."""
    return Path(get_config().perimeter_db_path).with_name("git-chunk.key")


def migrate_chunk_key() -> None:
    """At startup, after ``at_rest.configure``: move a plaintext key into the
    sealed store. A gateway that never had one makes none until a judged fetch
    asks; a key that cannot be moved is said so, and the start goes on."""
    if not _legacy_chunk_key().exists():
        return
    try:
        chunk_secret()
    except (OSError, ProfileConfigError) as exc:
        logger.warning("git chunk key: not moved into the sealed store: %s", exc_kind(exc))


# --- ref names flagged in a listing, named on the next fetch --------------------

_FLAGGED_REFS_MAX = 1024
_flagged_refs: OrderedDict[tuple[str, str], int] = OrderedDict()


# --- the tips a listing named, to tell a filtered clone from a lazy fetch ------

MAX_TIPS = 262_144
"""Object ids remembered across every repository's last listing; past it the
least recently listed repository is forgotten. A want that is not found
reads as a lazy fetch, and the pack's own count still applies."""

_tips: OrderedDict[tuple[str, str], tuple[frozenset[str], dict[str, str]]] = OrderedDict()
_tips_held = 0


def _weight(held: tuple[frozenset[str], dict[str, str]]) -> int:
    return len(held[0]) + len(held[1])


def remember_tips(
    profile: str, slug: str, tips: list[str], *, refs: dict[str, str] | None = None
) -> None:
    """Keep the object ids, and the ref names, ``slug``'s listing showed
    ``profile``, newest last. The bound counts both."""
    global _tips_held
    names = dict(list(refs.items())[:MAX_TIPS]) if refs else {}
    held = (frozenset(tips[: MAX_TIPS - len(names)]), names)
    _tips_held -= _weight(_tips.pop((profile, slug), (frozenset(), {})))
    _tips[(profile, slug)] = held
    _tips_held += _weight(held)
    while _tips_held > MAX_TIPS:
        _tips_held -= _weight(_tips.popitem(last=False)[1])


def at_tips(profile: str, slug: str, wants: list[str]) -> bool:
    """True when a want is a ref tip ``slug``'s last listing showed: a clone
    or a fetch of a branch, never a partial clone's lazy fetch of a blob."""
    tips = _tips.get((profile, slug), (frozenset(), {}))[0]
    return any(want in tips for want in wants)


def resolve_refs(profile: str, slug: str, names: list[str]) -> list[str]:
    """The object ids ``slug``'s last listing gave these ref names, in order;
    a name it did not show is left out."""
    refs = _tips.get((profile, slug), (frozenset(), {}))[1]
    return [refs[name] for name in names if name in refs]


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
    #: The request says clone: no ``have`` (``git_wire.is_cold_fetch``), or a
    #: filtered fetch of the listed tips. The pack header can say so too.
    cold: bool = False
    #: ``want-ref`` names the last listing did not show: their tips' whole-file
    #: pass cannot run, and the fetch says so.
    unlisted: int = 0


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
    child to take each piece, so delivery runs no faster than the reading. The
    reader ends when the judge's own deadline does: it is started later than
    the judge, and would otherwise outlive it.
    """

    def __init__(
        self,
        reading: _Reading,
        judge: GitJudge,
        inflated: Callable[[], bool] | None = None,
    ) -> None:
        self._reading = reading
        self._judge = judge
        #: Told once, when the objects handed to the judge pass ``COLD_INFLATED_BYTES``;
        #: False says the fetch may not be counted cold, and the reading stops.
        self._on_inflated = inflated
        self._inflated = 0
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
                    *self._remaining().argv(),
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

    def _expires(self) -> float | None:
        """The event-loop time the judge's deadline passes, once it has started."""
        return self._judge.expires_at

    def _remaining(self) -> _Reading:
        """The reading with the child's CPU limit cut to what is left of the judge's deadline."""
        expires = self._expires()
        if expires is None:
            return self._reading
        left = math.ceil(expires - asyncio.get_running_loop().time())
        return replace(self._reading, deadline=max(1, min(self._reading.deadline, left)))

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

    def abandon(self, reason: str) -> None:
        """Stop reading: the reader child is killed and the rest of the pack is
        left unjudged for ``reason``. ``over`` is set once it has gone."""
        self.refused = self.refused or reason
        self._finished = True
        self._held.clear()
        if self._proc is not None and self._proc.returncode is None:
            self._proc.kill()
        if self._task is None:
            self._judge.close()
            self.over.set()

    def done(self) -> bool:
        return self._finished and (self._task is None or self._task.done())

    async def _read(self, proc: asyncio.subprocess.Process) -> None:
        try:
            expires = self._expires()
            async with (
                asyncio.timeout(self._reading.deadline)
                if expires is None
                else asyncio.timeout_at(expires)
            ):
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
            if self._past_inflated(length):
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

    def _past_inflated(self, length: int) -> bool:
        """Count an object's bytes; True when that takes the fetch past
        ``COLD_INFLATED_BYTES`` and it may not be counted cold, so the reader stops."""
        before = self._inflated
        self._inflated += length
        if before > COLD_INFLATED_BYTES or self._inflated <= COLD_INFLATED_BYTES:
            return False
        return self._on_inflated is not None and not self._on_inflated()


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


def _notices(refs: int, unlisted: int) -> list[str]:
    """The lines for what the fetch's request and the last listing leave unjudged
    or flagged, whatever the pack did: ref names flagged, tips whose files no
    pass reads."""
    lines = []
    if refs:
        lines.append(f"Trentina: flagged ref names in the last listing: {refs}")
    if unlisted:
        lines.append(f"Trentina: unjudged tip files ({unlisted} want-refs not in the last listing)")
    return lines


def _named(judge: GitJudge, refused: str | None, refs: int, unlisted: int) -> list[bytes]:
    """The side-band lines naming what a fetch delivered flagged, unjudged or pending."""
    outcome = judge.outcome()
    lines: list[str] = []
    if refused is not None:
        lines.append(f"Trentina: unjudged pack ({refused})")
    lines += _notices(refs, unlisted)
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


def _account(judge: GitJudge, refused: str | None, unlisted: int = 0) -> dict[str, str]:
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
    if unlisted:
        counts["git_unlisted"] = str(unlisted)
    return counts


def _news(seen: dict[str, str], final: dict[str, str]) -> bool:
    """True when ``final`` found more than the account ``seen``: a flag, a gap
    or a pack refusal. A fetch recorded ``busy`` had the rest of its pack named
    unjudged already, so only a flag is news to it."""
    if int(final["git_flagged"]) > int(seen.get("git_flagged", 0)):
        return True
    if seen.get("git_pack") == BUSY:
        return False
    refused = final.get("git_pack")
    return int(final["git_unjudged"]) > int(seen.get("git_unjudged", 0)) or (
        refused is not None and refused != seen.get("git_pack")
    )


def _declared_objects(pack: bytes) -> int:
    """The object count a pack header declares; 0 when it is not one."""
    if len(pack) < PACK_HEADER_BYTES or not pack.startswith(b"PACK"):
        return 0
    return int.from_bytes(pack[8:PACK_HEADER_BYTES], "big")


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
        self.busy = False
        self.cold = fetch.cold
        #: The pack's first bytes, held for its header before a slot is taken.
        self.head = bytearray()
        #: Pack bytes the forge has sent, for ``COLD_PACK_BYTES``.
        self.carried = 0
        self.slot: _Slot | None = None
        #: What ``settle`` wrote on the operation's row, for the judging's end to compare with.
        self.recorded: dict[str, str] | None = None
        self.settled = False
        self.closed = False
        #: The judging has ended (``_hold`` says so).
        self.over = False

    def _take_refs(self) -> int:
        """The ref names the repository's last listing had flagged, taken at the
        point they are written on the side band: a round that names nothing
        leaves them for the next fetch."""
        return _flagged_refs.pop((self.fetch.profile.name, self.fetch.slug), 0)

    def _start(self) -> _Feeder | None:
        """The judging of this fetch, or None when no slot is free: the pack
        then goes on unjudged, named ``busy``."""
        op, fetch = self.ctx.op, self.fetch
        slot = None if self.busy else _slots.take(fetch.profile.name, cold=self.cold)
        if slot is None:
            self.busy = True
            return None
        self.slot = slot
        task: asyncio.Task[None] | None = None
        try:
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
            self.feeder = _Feeder(reading, self.judge, self._inflated)
            hold = asyncio.ensure_future(
                _hold(slot, task, self.feeder, float(fetch.grant.judge_deadline), self._ended)
            )
            _CLOSING.add(hold)
            hold.add_done_callback(_CLOSING.discard)
        except BaseException:
            # _hold gives the slot back once it runs; before that, this does.
            if task is not None:
                task.cancel()
            _slots.release(slot)
            raise
        return self.feeder

    async def _feed(self, pack: bytes, *, ended: bool = False) -> None:
        """Hand pack bytes to the judging. The first ``PACK_HEADER_BYTES`` are
        held until they are all here (or the pack ended short), so the slot is
        taken knowing how many objects the forge says it is sending."""
        if self.busy:
            return
        self.carried += len(pack)
        if self.feeder is None:
            self.head += pack
            if len(self.head) < PACK_HEADER_BYTES and not (ended and self.head):
                return
            pack = bytes(self.head)
            self.head.clear()
            self.cold = (
                self.cold
                or _declared_objects(pack) > COLD_PACK_OBJECTS
                or self.carried > COLD_PACK_BYTES
            )
            if self._start() is None:
                return
        if not self.cold and self.carried > COLD_PACK_BYTES and not self._promote():
            return
        if self.feeder is not None and pack:
            await self.feeder.feed(pack)

    def _inflated(self) -> bool:
        """The reader has handed the judge a clone's weight of objects: count
        the fetch cold, as ``_promote`` does for a pack's bytes."""
        return self.cold or self._promote()

    def _promote(self) -> bool:
        """Count this fetch cold now that its pack is a clone's size. With the
        cold slots all taken, the rest of the pack goes unjudged, named
        ``busy``: the reader stops and the slot is given back as it was."""
        self.cold = True
        if self.slot is not None and _slots.promote(self.slot):
            return True
        self.busy = True
        if self.feeder is not None:
            self.feeder.abandon(BUSY)
        if self.judge is not None:
            self.judge.abandon()
        return False

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
                await self._feed(b"", ended=True)
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
            notices = [progress(line) for line in _notices(self._take_refs(), self.fetch.unlisted)]
            yield _unjudged(BUSY) + b"".join(notices) + held
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
            yield b"".join(
                _named(self.judge, self.feeder.refused, self._take_refs(), self.fetch.unlisted)
            )
            yield progress("Trentina: still reading the pack; the rest is judged after delivery")
            yield held
            return
        await finishing
        await self.judge.wait(max(until - loop.time(), 0.0))
        named = _named(self.judge, self.feeder.refused, self._take_refs(), self.fetch.unlisted)
        yield b"".join(named) + held

    def settle(self) -> None:
        op = self.ctx.op
        self.settled = True
        if self.busy:
            op.normalized = {
                **dict.fromkeys(_COUNTS, "0"),
                "git_pack": BUSY,
                **({"git_unlisted": str(self.fetch.unlisted)} if self.fetch.unlisted else {}),
            }
            self.recorded = op.normalized
            op.flag_reason = "git_unjudged"
            op.settle(Outcome.OK, "git_unjudged")
            return
        if self.judge is None:
            op.settle(Outcome.OK)
            return
        self._account_on(op, self.judge)

    def _account_on(self, op: Operation, judge: GitJudge) -> None:
        """Write the judging's account now on ``op``, the counts and the reason."""
        refused = self.feeder.refused if self.feeder is not None else None
        op.normalized = self.recorded = _account(judge, refused, self.fetch.unlisted)
        outcome = judge.outcome()
        found = _found(outcome.flagged, outcome.unjudged or refused or self.fetch.unlisted)
        op.flag_reason = found
        op.settle(Outcome.OK, found)

    def _ended(self) -> None:
        """The judging has ended. What it found after ``settle`` wrote the
        operation's account, a late flag, the deadline, a late refusal, L3
        unavailable, is said once more. Before the response has ended there is
        nothing to compare with: ``settle`` takes the final account itself."""
        self.over = True
        if self.settled or self.closed:
            self._guarded_report()

    def _guarded_report(self) -> None:
        """``_report_late``, which never raises: a row failing is logged and nothing else."""
        try:
            self._report_late()
        except Exception as exc:
            logger.warning(
                "git judge: late findings not recorded: %s at %s", exc_kind(exc), exc_where(exc)
            )

    def _report_late(self) -> None:
        """Compare the final account with what ``settle`` recorded. The operation's
        row is amended while it is still unwritten; once written, rows are chained
        and never updated, so one ``fetch_judged`` row carries the final counts."""
        op, judge, feeder = self.ctx.op, self.judge, self.feeder
        if judge is None or feeder is None:
            return
        if not _news(self.recorded or {}, _account(judge, feeder.refused, self.fetch.unlisted)):
            return
        if self.recorded is not None and not op.finished and op.outcome is Outcome.OK:
            self._account_on(op, judge)
            return
        # Its own Operation, so the row is written as every perimeter row is.
        late = Operation(
            op.profile,
            backend=op.backend,
            tool=FOLLOW_UP,
            destination=op.destination,
            destination_kind=op.destination_kind,
            started=op.started,
            call_ref=op.call_ref,
        )
        self._account_on(late, judge)
        task = asyncio.ensure_future(late.finish())
        _CLOSING.add(task)
        task.add_done_callback(_CLOSING.discard)

    def close(self) -> None:
        """However the answer ended, the pack that arrived is still read and
        judged, in the background: a request that went away is not waited on."""
        self.closed = True
        if self.over and not self.settled:
            self._guarded_report()  # the response ended without an account of its own
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
    remember_tips(profile.name, slug, listed_tips(listing), refs=listed_refs(listing))
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
