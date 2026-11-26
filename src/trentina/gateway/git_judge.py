"""Judging what a fetch carries, object by object (spec 027, known gap 29).

``git_pack`` reads a pack as git reads it; this module decides what each
object it yields is, in the layers' terms, and keeps the bill bounded by what
is new to the profile's judge rather than by the size of a history:

- **Units.** Every object becomes units of text: a text blob its keyed chunks
  (``git_chunks``), each read behind its lead-in; a binary blob the strings a
  ``strings`` tool would show; a commit or annotated tag the whole object as
  git renders it; a tree its entry names, one unit a name; a ref listing its
  names, one unit a name. A unit is keyed by its text (and lead-in) under the
  profile's judge (``verdict_cache._cache_key``), so a second clone, a refetch
  or a second ``ls-refs`` is a cache hit, never a ``defend()``.
- **L1 and L2 on every unit; L3 on small groups.** Units new to the judge are
  screened (``defense.screen``) one by one, names packed together a couple of
  kilobytes at a time. What L1 or L2 flags is flagged, and still read by L3,
  alone: every layer reads every unit. So is a unit whose L2 score is over
  ``Config.git_suspicious``, so a borderline chunk is never diluted by its
  neighbours; the others go to L3 in groups of
  at most ``GROUP_TOKENS``, and a clean group is credited to each unit in it.
  A flagged group is debited to the pieces L3 names, and each other unit is
  judged again alone, at most ``L3_SOLO_MAX`` of them; an answer naming none,
  or leaving more, is debited to every unit (#932).
- **Files at the tip, whole.** A text blob at the tip of a wanted commit (or a
  blob wanted by id, as a partial clone's lazy fetch asks for it) of at most
  ``Config.whole_tokens`` is also judged whole at L3: the file an agent opens.
- **Background.** All of it runs in the L2 gate's background class, so a clone
  never starves a tool call, and bills L3 to the grant's ``l3_daily_quota``,
  not the profile's.

An object is flagged when any unit of it is, unjudged when any unit could
not be judged (and the gap is named), clean when every unit is clean, and
pending until then. Verdicts outlive the fetch in ``perimeter_db``'s own
bounded table; a verdict that is not complete is never kept.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import sys
import time
import weakref
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..database import record_detection
from ..defense import Screened, build_l3_briefing, judge_l3, layer_verdicts, merge_stats, screen
from ..l1.pipeline import PipelineStats
from ..logsafe import exc_kind, exc_where
from ..quarantine.classifier import background_scans
from ..quarantine.quota import git_quota
from ..unpack.child import run_unpacking
from ..unpack.git_pack import (
    OBJ_BLOB,
    OBJ_COMMIT,
    OBJ_TAG,
    OBJ_TREE,
    PackObject,
    commit_tree,
    is_binary,
    render_text,
    tag_target,
    tree_entries,
)
from ..unpack.scan import read_binary
from .context import profile_context
from .git_chunks import TOKEN_BYTES, Chunk, chunk_blob, estimate_tokens
from .service import judge_of
from .verdict_cache import _cache_key

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..quarantine.classifier import ClassifierResult
    from .profile import GitGrant, Profile

logger = logging.getLogger(__name__)

GROUP_TOKENS = 4096
"""The most tokens one L3 call reads of grouped units (spec 027)."""

L3_SOLO_MAX = 8
"""The most units a flagged group sends back to L3 alone (#932).

A group of names can hold thousands of units, so placing its finding piece
by piece is bounded: past this many unnamed units the whole group is
debited, as when L3 names no piece, and nothing more is spent on it."""

MAX_BINARY_BYTES = 16 * 1024 * 1024
"""Largest binary blob handed to the unpack stage. Past it, ``binary_unread``:
the unpack stage's own limits would refuse it anyway, after reading it."""

MAX_BACKLOG_BYTES = 256 * 1024 * 1024
"""Unit text waiting to be judged, held in memory. Past it, an object is
unjudged (``backlog``), never silently dropped."""

MAX_OBJECT_BYTES = 64 * 1024 * 1024
"""Largest object the reader child hands the gateway. Past it the object is
unjudged (``too_large``) and its bytes never leave the child."""

MAX_TIP_BYTES = 64 * 1024 * 1024
"""Small text blobs kept until the pack ends, to judge the tip's whole. A
tip file that did not fit is named unjudged (``backlog``) when the pack ends:
which blobs are the tip is known only then."""

MAX_TRACKED_OBJECTS = 1_000_000
"""Objects one fetch may have the judge track, as many as the reader accepts in
a pack. Past it the fetch stops being judged and its pack is named unjudged
(``too_many``): ``_objects`` holds one state for each, so it is the bound."""

MAX_TREE_BYTES = 64 * 1024 * 1024
"""Parsed tree entries kept until the pack ends, to find the tip, counted as
the memory they take (``_held``), not the tree objects' bytes. A tree past it is
unjudged (``backlog``) and the tip walk stops at it; its blobs are still judged
as they arrive, only not again whole."""

SCREENERS = 2
"""Units screened at once by one fetch: the L2 gate's own width."""

L3_CALLS = 4
"""L3 calls in flight for one fetch."""

VERDICT_TTL = 30 * 24 * 3600.0
"""Seconds a git verdict is kept, from its judgement, unless
``TRENTINA_VERDICT_TTL_HOURS`` asks for less (``verdict_ttl``). A chunk's key
is its content and the stamp names the judge, so a verdict holds until the
stamp changes; the cap bounds what a judge later found wanting still serves."""

READ_THREADS = 2
"""Worker threads reading objects (chunking, tree entries, rendering) for all
fetches in the gateway at once; the event loop never does that work."""

PROFILE_READ_THREADS = 1
"""Of ``READ_THREADS``, the most one profile's fetches read on at once, so a
profile running two judged fetches leaves the other thread to the rest."""

INLINE_BYTES = 4096
"""An object this small is read on the loop: a hop to a thread would cost
more than the read."""

ADD_YIELD = 512
"""Units recorded on the loop between turns given back to it."""

_MEMORY_MAX = 65536
_memory: OrderedDict[str, tuple[float, dict[str, Any] | None]] = OrderedDict()
"""Verdicts this process reached or read back, ahead of the store."""

#: Gaps an object can be left with, each a closed word on the side band.
GAPS = frozenset(
    {
        "l2_unavailable",
        "l3_unavailable",
        "l3_quota",
        "binary_unread",
        "backlog",
        "deadline",
        "too_large",
        "failed",
    }
)

CLEAN: dict[str, Any] | None = None


_POOL = ThreadPoolExecutor(READ_THREADS, thread_name_prefix="git-read")

#: Per event loop, as the lanes are: a semaphore belongs to the loop it was first used on.
_read_shares: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]] = (
    weakref.WeakKeyDictionary()
)


def _read_share(profile: str) -> asyncio.Semaphore:
    """The profile's share of ``_POOL``: ``PROFILE_READ_THREADS`` reads in flight."""
    shares = _read_shares.setdefault(asyncio.get_running_loop(), {})
    share = shares.get(profile)
    if share is None:
        share = shares[profile] = asyncio.Semaphore(PROFILE_READ_THREADS)
    return share


def verdict_ttl() -> float:
    """Seconds a git verdict is served: ``VERDICT_TTL``, or less when the
    operator set ``TRENTINA_VERDICT_TTL_HOURS``."""
    hours = get_config().git_verdict_ttl_hours
    return VERDICT_TTL if hours is None else min(VERDICT_TTL, hours * 3600.0)


def _held(value: str | bytes | None) -> int:
    """The memory a held string takes, header included: a non-ASCII ``str``
    is up to four bytes a character, and a small one mostly header."""
    return 0 if value is None else sys.getsizeof(value)


@dataclass
class Unit:
    """One piece of text judged on its own and cached on its own."""

    key: str
    text: str
    lead_in: str
    source_type: str
    oids: set[str] = field(default_factory=set)
    #: True for a tip file judged whole: L3 only, on top of its chunks.
    whole: bool = False
    screened: Screened | None = None
    #: A binary blob's bytes: read by the unpack stage before it is screened.
    binary: bytes | None = None
    #: What this unit counts against ``MAX_BACKLOG_BYTES``, fixed when queued.
    held: int = 0
    #: L1's or L2's flag, carried to L3: every layer reads the unit, and a
    #: layer's finding stands whatever the next one says.
    prior: dict[str, Any] | None = None

    @property
    def read(self) -> str:
        return f"{self.lead_in}{self.text}"

    @property
    def size(self) -> int:
        """The memory its text and bytes take, what ``MAX_BACKLOG_BYTES`` bounds."""
        return _held(self.text) + _held(self.lead_in) + _held(self.binary)


@dataclass
class ObjectState:
    """What is known of one object: its units still out, and what they found."""

    kind: str
    source_type: str
    waiting: int = 0
    flagged: tuple[str, str] | None = None  # (layer, risk)
    gap: str | None = None
    recorded: bool = False
    #: A small text blob ``MAX_TIP_BYTES`` had no room for: a gap if it is the tip.
    unheld: bool = False

    @property
    def settled(self) -> bool:
        return self.waiting == 0


@dataclass
class _Read:
    """What reading one object found: pure data, recorded later on the loop."""

    units: list[Unit]
    encoding: str | None = None
    tree: list[tuple[str, str, str]] | None = None
    tree_held: int = 0  # the memory ``tree`` takes, measured where it was parsed
    commit_tree: str | None = None
    tag_target: str | None = None
    small: bool = False  # a text blob small enough to keep for the tip's whole


@dataclass(frozen=True)
class Outcome:
    """What a fetch's objects came to, for the side band and the row."""

    flagged: list[tuple[str, str, str, str]]  # (kind, oid, layer, risk)
    unjudged: list[tuple[str, str, str]]  # (kind, oid, gap)
    pending: int
    judged: int
    total: int


class GitJudge:
    """The judging of one fetch's objects, fed as the pack is read.

    ``add`` turns an object into units (a large one in a worker thread) and
    queues those not already decided. ``start`` runs the judging as a task of
    its own, outside the request, so a fetch delivered under ``flag`` before
    its last verdict goes on being judged, its verdicts warming the cache and
    landing as ``detections`` rows. ``deadline`` bounds that task.

    Args:
        profile: whose judge, thresholds and quota the judging runs under;
            its grant owner is in every verdict key.
        grant: the git grant fetched under, for its ``l3_daily_quota``.
        source: ``git:<remote>/<owner>/<repo>``, which a detection row names
            with ``@<oid>`` after it.
        call_ref: the ``gateway_calls`` row's reference, carried by every
            detection row this judging writes.
        chunk_secret: the gateway's key for chunk boundaries
            (``git_chunks.chunk_blob``), so an author cannot place a cut.
        wants: the object ids the fetch asked for. Their trees' blobs are the
            tip, judged whole; a blob wanted by id is a lazy fetch's checkout.
        oid_len: bytes in an object id, 20 for sha1 and 32 for sha256: how
            tree entries are read.
    """

    def __init__(
        self,
        *,
        profile: Profile,
        grant: GitGrant,
        source: str,
        call_ref: str | None,
        chunk_secret: bytes,
        wants: Iterable[str] = (),
        oid_len: int = 20,
    ) -> None:
        self.profile = profile
        self.grant = grant
        self.source = source
        self.call_ref = call_ref
        self._secret = chunk_secret
        self._oid_len = oid_len
        self._judge = judge_of(profile)
        self._wants = set(wants)
        self._objects: dict[str, ObjectState] = {}
        self._units: dict[str, Unit] = {}
        self._queue: asyncio.Queue[Unit | None] = asyncio.Queue()
        self._lane = asyncio.Lock()
        self._backlog = 0
        self._trees: dict[str, list[tuple[str, str, str]]] = {}
        self._commit_trees: dict[str, str] = {}
        self._tag_targets: dict[str, str] = {}
        self._small_text: dict[str, bytes] = {}
        self._small_bytes = 0
        self._tree_bytes = 0
        self._task: asyncio.Task[None] | None = None
        self._screening = 0
        self._closed = False
        self._mark = get_config().git_suspicious
        self._settled = asyncio.Event()
        self._settled.set()
        self.stats: dict[str, int] = {
            "units": 0,
            "cached": 0,
            "screened": 0,
            "l3_groups": 0,
            "l3_alone": 0,
            "l3_whole": 0,
            "unit_tokens": 0,
        }
        #: L2 scores seen, rounded to two places: phase 1 sets the mark from them.
        self.l2_scores: dict[float, int] = {}

    # --- feeding -------------------------------------------------------------

    def submit(self, obj: PackObject) -> None:
        """Read one resolved object on the calling thread and queue its undecided units.

        For small objects and callers with no loop to spare; ``add`` is the
        feeder's way in.
        """
        if (state := self._begin(obj)) is None:
            return
        try:
            read = self._read_object(obj)
        except Exception as exc:  # a reader bug is an unjudged object, not a crash
            self._failed(state, exc)
            return
        for unit in self._take(obj, state, read):
            self._add(unit, obj.oid, state)

    async def add(self, obj: PackObject) -> None:
        """Like ``submit``, with the reading of a large object done in a worker thread.

        One object at a time per fetch (the lane), and ``READ_THREADS`` across
        the gateway, so neither a backlog nor a crowd of fetches grows the
        work; all state is recorded back on the loop, in arrival order.
        """
        if len(obj.content) <= INLINE_BYTES:
            self.submit(obj)
            await asyncio.sleep(0)  # a run of small objects still gives the loop a turn
            return
        if (state := self._begin(obj)) is None:
            return
        try:
            async with self._lane, _read_share(self.profile.name):
                read = await asyncio.get_running_loop().run_in_executor(
                    _POOL, self._read_object, obj
                )
        except asyncio.CancelledError:
            # Waiting for a thread or reading on one: either way unjudged. A
            # thread already reading finishes alone and its result is dropped.
            state.gap = "deadline"
            raise
        except Exception as exc:
            self._failed(state, exc)
            return
        for count, unit in enumerate(self._take(obj, state, read), 1):
            self._add(unit, obj.oid, state)
            if count % ADD_YIELD == 0:
                await asyncio.sleep(0)

    def _begin(self, obj: PackObject) -> ObjectState | None:
        if obj.oid in self._objects:
            return None
        state = ObjectState(obj.kind, _SOURCE_TYPE[obj.kind])
        self._objects[obj.oid] = state
        return state

    @staticmethod
    def _failed(state: ObjectState, exc: Exception) -> None:
        logger.warning("git judge: object not read: %s at %s", exc_kind(exc), exc_where(exc))
        state.gap = "failed"

    def _take(self, obj: PackObject, state: ObjectState, read: _Read) -> list[Unit]:
        """Record what reading ``obj`` found, on the loop; the units still to add."""
        if read.commit_tree is not None:
            self._commit_trees[obj.oid] = read.commit_tree
        if read.tag_target is not None:
            self._tag_targets[obj.oid] = read.tag_target
        if read.tree is not None:
            if self._tree_bytes + read.tree_held > MAX_TREE_BYTES:
                state.gap = "backlog"
                return []
            self._tree_bytes += read.tree_held
            self._trees[obj.oid] = read.tree
        if read.small:
            if self._small_bytes + (held := _held(obj.content)) <= MAX_TIP_BYTES:
                self._small_text[obj.oid] = obj.content
                self._small_bytes += held
            else:
                state.unheld = True
        if read.encoding is not None:
            # A message in an encoding the layers read one way and a tool
            # another (UTF-7, UTF-16) is flagged as that, deterministically.
            state.flagged = ("L1", "high")
            self._record(obj.oid, state, None, None)
        return read.units

    def submit_unread(self, oid: str, kind: str, gap: str) -> None:
        """An object the reader saw and did not hand over: unjudged, for ``gap``."""
        if gap not in GAPS:
            raise ValueError("not a gap")
        if oid not in self._objects:
            state = ObjectState(kind, _SOURCE_TYPE[kind])
            state.gap = gap
            self._objects[oid] = state

    def submit_names(self, names: Iterable[str], *, source_type: str = "git_refs") -> list[str]:
        """Queue ref names (and symref targets) as units; returns their ids.

        A name is its own object here, under the id ``ref:<name>``, so the
        listing's verdicts are read back like an object's.
        """
        ids = []
        for name in dict.fromkeys(names):
            oid = f"ref:{name}"
            ids.append(oid)
            if oid in self._objects:
                continue
            state = ObjectState("ref", source_type)
            self._objects[oid] = state
            self._add(self._unit(name, "", source_type), oid, state)
        return ids

    def finish_pack(self) -> None:
        """The pack is whole: judge the tip's files whole, then let go of them."""
        tips = self._tip_blobs()
        whole = get_config().whole_tokens
        for oid in tips:
            held = self._small_text.get(oid)
            if held is None:
                if (skipped := self._objects.get(oid)) is not None and skipped.unheld:
                    skipped.gap = skipped.gap or "backlog"
                continue
            text = held.decode("utf-8", "replace")
            if estimate_tokens(text) > whole:
                continue
            state = self._objects.get(oid)
            if state is None:
                continue
            unit = self._unit(text, "", "git_blob", whole=True)
            self._add(unit, oid, state)
        self._small_text.clear()
        self._small_bytes = 0
        self._trees.clear()
        self._tree_bytes = 0

    def full(self) -> bool:
        """True once ``MAX_TRACKED_OBJECTS`` are tracked: no more may be submitted."""
        return len(self._objects) >= MAX_TRACKED_OBJECTS

    def close(self) -> None:
        """No more objects: the judging task ends when its queue is empty."""
        self._closed = True
        self._queue.put_nowait(None)

    def _add(self, unit: Unit, oid: str, state: ObjectState) -> None:
        existing = self._units.get(unit.key)
        if existing is not None:
            # The same text elsewhere in this fetch: one judgement, credited to both.
            if oid not in existing.oids:
                existing.oids.add(oid)
                state.waiting += 1
            return
        cached = _memory_get(unit.key)
        if cached is not _MISS:
            self.stats["cached"] += 1
            _apply(state, cached)
            if state.flagged is not None:
                self._record(oid, state, cached, None)
            return
        if self._backlog + unit.size > MAX_BACKLOG_BYTES:
            state.gap = state.gap or "backlog"
            return
        unit.oids.add(oid)
        unit.held = unit.size
        self._units[unit.key] = unit
        self._backlog += unit.held
        state.waiting += 1
        self.stats["units"] += 1
        self.stats["unit_tokens"] += estimate_tokens(unit.read)
        self._settled.clear()
        self._queue.put_nowait(unit)

    def _unit(self, text: str, lead_in: str, source_type: str, *, whole: bool = False) -> Unit:
        kind = "git_whole" if whole else "git"
        material = f"{len(lead_in)}:{lead_in}{text}"
        return Unit(
            key=_cache_key(self.profile, kind, material, self._judge),
            text=text,
            lead_in=lead_in,
            source_type=source_type,
            whole=whole,
        )

    def _read_object(self, obj: PackObject) -> _Read:
        """An object's units and what the tip walk needs of it.

        Pure and thread-safe: it touches no judge state, only the immutable
        secret, oid width and judge, so it runs in a worker thread.
        """
        if obj.kind == OBJ_COMMIT:
            text, encoding = render_text(obj.content)
            return _Read(
                self._text_units(text, "git_commit"),
                encoding,
                commit_tree=commit_tree(obj.content),
            )
        if obj.kind == OBJ_TAG:
            text, encoding = render_text(obj.content)
            target = tag_target(obj.content)
            return _Read(
                self._text_units(text, "git_tag"),
                encoding,
                tag_target=None if target is None else target[0],
            )
        if obj.kind == OBJ_TREE:
            entries = tree_entries(obj.content, oid_len=self._oid_len)
            names = [self._unit(name, "", "git_tree") for _m, name, _o in entries]
            held = sys.getsizeof(entries) + sum(
                sys.getsizeof(entry) + sum(map(sys.getsizeof, entry)) for entry in entries
            )
            return _Read(names, tree=entries, tree_held=held)
        if is_binary(obj.content):
            # Read as anywhere else (images, PDFs, archives, office files) or
            # for its strings; keyed by its bytes, since that is what was read.
            unit = self._unit(f"binary:{_digest(obj.content)}", "", "git_blob")
            unit.binary = obj.content
            return _Read([unit])
        small = len(obj.content) <= get_config().whole_tokens * TOKEN_BYTES
        chunks = chunk_blob(obj.content, self._secret)
        return _Read([self._unit(c.text, c.lead_in, "git_blob") for c in chunks], small=small)

    def _text_units(self, text: str, source_type: str) -> list[Unit]:
        chunks: list[Chunk] = chunk_blob(text.encode("utf-8", "replace"), self._secret)
        return [self._unit(c.text, c.lead_in, source_type) for c in chunks]

    def _peel(self, oid: str) -> str:
        """A wanted id with its annotated tags taken off (a tag of a tag, bounded)."""
        for _hop in range(8):
            if oid not in self._tag_targets:
                break
            oid = self._tag_targets[oid]
        return self._commit_trees.get(oid, oid)

    def _tip_blobs(self) -> set[str]:
        """Blobs at the tip: in the trees of wanted commits and tags, or wanted by id."""
        tips: set[str] = set()
        roots: list[str] = []
        for want in self._wants:
            target = self._peel(want)
            # A tree to walk, or a blob wanted by id: a lazy fetch's checkout.
            if target in self._trees:
                roots.append(target)
            else:
                tips.add(target)
        seen: set[str] = set()
        while roots:
            tree = roots.pop()
            if tree in seen:
                continue
            seen.add(tree)
            for mode, _name, oid in self._trees.get(tree, ()):
                if mode.startswith("40"):
                    roots.append(oid)
                elif not mode.startswith("160"):  # a submodule is out of scope
                    tips.add(oid)
        return tips

    # --- judging -------------------------------------------------------------

    def start(self, deadline: float) -> asyncio.Task[None]:
        """Run the judging as its own task, bounded by ``deadline`` seconds."""
        if self._task is None:
            self._task = asyncio.ensure_future(self._run(deadline))
            _BACKGROUND.add(self._task)
            self._task.add_done_callback(_BACKGROUND.discard)
        return self._task

    async def _run(self, deadline: float) -> None:
        with (
            profile_context(self.profile),
            background_scans(),
            git_quota(self.grant.l3_daily_quota),
        ):
            try:
                async with asyncio.timeout(deadline):
                    await self._drain()
            except TimeoutError:
                self._expire("deadline")
            except Exception as exc:
                logger.error("git judge: judging failed: %s at %s", exc_kind(exc), exc_where(exc))
                self._expire("failed")
            finally:
                self._settled.set()
                flush_store()

    async def _drain(self) -> None:
        """Read the queue to its end: store, then L1 and L2, then L3 in groups."""
        screening: asyncio.Queue[Unit | None] = asyncio.Queue(maxsize=SCREENERS * 8)
        screened: asyncio.Queue[Unit | None] = asyncio.Queue()
        dispatch = _Dispatch(self)

        workers = [asyncio.ensure_future(self._collect(screening))]
        workers += [
            asyncio.ensure_future(self._screener(screening, screened)) for _ in range(SCREENERS)
        ]
        try:
            ended = 0
            while ended < SCREENERS:
                unit = await screened.get()
                if unit is None:
                    ended += 1
                elif unit.key in self._units:  # not settled by the screen (a gap)
                    dispatch.take(unit)
                idle = not self._screening and self._queue.empty() and screening.empty()
                if idle and screened.empty():
                    # Nothing more is coming soon: do not hold a group back for company.
                    dispatch.flush()
            dispatch.flush()
            await asyncio.gather(*workers)
            await dispatch.done()
        finally:
            # Past the deadline nothing spawned here screens or spends L3 any more.
            await dispatch.cancel()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    async def _collect(self, screening: asyncio.Queue[Unit | None]) -> None:
        """Queued units the store does not know, on to the screeners."""
        while (batch := await self._next_batch()) is not None:
            # On the loop: the store's connection is this thread's, and a batch
            # is one indexed read of at most 256 keys.
            for unit in self._from_store(batch):
                await screening.put(unit)
        for _ in range(SCREENERS):
            await screening.put(None)

    async def _screener(
        self, screening: asyncio.Queue[Unit | None], screened: asyncio.Queue[Unit | None]
    ) -> None:
        while (unit := await screening.get()) is not None:
            self._screening += 1
            try:
                await self._screen(unit)
            finally:
                self._screening -= 1
            await screened.put(unit)
        await screened.put(None)

    async def _next_batch(self) -> list[Unit] | None:
        """Up to 256 queued units, or None once closed and drained."""
        first = await self._queue.get()
        if first is None:
            return None
        batch = [first]
        while len(batch) < 256 and not self._queue.empty():
            unit = self._queue.get_nowait()
            if unit is None:
                self._queue.put_nowait(None)
                break
            batch.append(unit)
        return batch

    def _from_store(self, batch: list[Unit]) -> list[Unit]:
        """Settle what the store already knows; return the units still to judge."""
        from ..perimeter_db import get_git_verdicts, perimeter_stamp

        try:
            known = get_git_verdicts([unit.key for unit in batch], perimeter_stamp(), verdict_ttl())
        except Exception as exc:
            logger.warning(
                "git judge: verdict store unread: %s at %s", exc_kind(exc), exc_where(exc)
            )
            known = {}
        fresh = []
        for unit in batch:
            if unit.key in known:
                self.stats["cached"] += 1
                self._settle(unit, known[unit.key], judged=False)
            else:
                fresh.append(unit)
        return fresh

    async def _unpacked(self, unit: Unit) -> bool:
        """A binary's text, by the unpack stage; False when it could not be read."""
        blob, unit.binary = unit.binary or b"", None
        if len(blob) > MAX_BINARY_BYTES:
            return False
        view = await run_unpacking(read_binary, blob)
        unit.text = view.text
        return not view.unread

    async def _screen(self, unit: Unit) -> None:
        if unit.whole:
            return  # L3 alone reads a tip file whole; its chunks were screened
        try:
            if unit.binary is not None and not await self._unpacked(unit):
                self._settle(unit, {"gap": "binary_unread"})
                return
            screened = await screen(unit.read, source=self._source(unit))
        except Exception as exc:
            logger.warning("git judge: screen failed: %s at %s", exc_kind(exc), exc_where(exc))
            self._settle(unit, {"gap": "l2_unavailable"})
            return
        self.stats["screened"] += 1
        unit.screened = screened
        c = screened.classification
        if c is not None:
            bucket = round(c.score, 2)
            self.l2_scores[bucket] = self.l2_scores.get(bucket, 0) + 1
        if screened.unread:
            self._settle(unit, {"gap": "binary_unread"})
        elif screened.l2_flagged(self.profile.defense):
            unit.prior = _flag("L2", "high", screened, None)
        elif screened.l1_flagged():
            unit.prior = _flag("L1", screened.pipeline.stats.risk_level(), screened, None)
        elif c is None:
            self._settle(unit, {"gap": "l2_unavailable"})
        elif screened.l2_truncated:
            # Only a binary's strings can outgrow L2's budget; a chunk cannot.
            self._settle(unit, {"gap": "too_large"})

    async def _ask(self, units: list[Unit], *, whole: bool = False) -> dict[str, Any]:
        """One L3 call over ``units``; ``{"gap": ...}`` when it gave no verdict."""
        try:
            answer = await judge_l3(
                _group_text(units), self.profile.defense, self._briefing(units, whole=whole)
            )
        except Exception as exc:
            logger.warning("git judge: L3 failed: %s at %s", exc_kind(exc), exc_where(exc))
            return {"gap": "l3_unavailable"}
        if answer.get("l3_quota"):
            return {"gap": "l3_quota"}
        if answer.get("l3_unavailable"):
            return {"gap": "l3_unavailable"}
        return answer

    async def _l3(self, units: list[Unit], *, whole: bool = False) -> None:
        """Judge ``units`` together and settle each by the answer.

        A clean group is credited to each unit in it. A flagged group is
        debited to the pieces L3 names, and each piece it does not name is
        judged again alone, never cleared by the group's answer: a piece can
        name its neighbour, but not its own read (#932). An answer that names
        no piece, or one that does not exist, or that would leave more than
        ``L3_SOLO_MAX`` units to judge alone, is debited to every unit.
        """
        self.stats["l3_whole" if whole else "l3_groups" if len(units) > 1 else "l3_alone"] += 1
        answer = await self._ask(units, whole=whole)
        if len(units) == 1 and (prior := units[0].prior) is not None:
            self._settle_flagged(units[0], prior, answer)
            return
        if "gap" in answer or answer.get("injection_detected") is not True:
            for unit in units:
                self._settle(unit, answer if "gap" in answer else CLEAN)
            return
        from ..quarantine.agent import flagged_pieces
        from ..quarantine.prompts import RISK_LEVELS

        risk = answer.get("risk_level")
        risk = risk if risk in RISK_LEVELS else "high"
        named = flagged_pieces(answer, len(units)) if len(units) > 1 else None
        if named is not None and len(units) - len(named) > L3_SOLO_MAX:
            named = None
        for n, unit in enumerate(units, 1):
            if named is None or n in named:
                self._settle(unit, _flag("L3", risk, unit.screened, answer))
        if named is not None:
            # One at a time, inside this call's slot: L3_CALLS still bounds them.
            for n, unit in enumerate(units, 1):
                if n not in named:
                    await self._l3([unit])

    def _settle_flagged(self, unit: Unit, prior: dict[str, Any], answer: dict[str, Any]) -> None:
        """L1 or L2 flagged ``unit`` and L3 has read it: the flag stands."""
        if "gap" in answer:
            # A verdict L3 did not finish is not cached.
            self._settle(unit, prior, judged=False)
        elif answer.get("injection_detected") is True:
            self._settle(unit, {**prior, "l3": _l3_fields(answer)})
        else:
            self._settle(unit, prior)

    def _briefing(self, units: list[Unit], *, whole: bool) -> str:
        stats = PipelineStats()
        top: ClassifierResult | None = None
        for unit in units:
            if unit.screened is None:
                continue
            merge_stats(stats, unit.screened.pipeline.stats)
            c = unit.screened.classification
            if c is not None and (top is None or c.score > top.score):
                top = c
        note = (
            "This is one file from a git repository, whole."
            if whole
            else (
                f"These are {len(units)} pieces of content from a git repository, "
                "each shown behind the end of the piece before it. Judge each piece."
            )
        )
        return build_l3_briefing(stats, top, extra=note)

    def _source(self, unit: Unit) -> str:
        oid = next(iter(unit.oids), "")
        return f"{self.source}@{oid}"

    def _settle(self, unit: Unit, verdict: dict[str, Any] | None, *, judged: bool = True) -> None:
        """One unit is decided: credit its objects, and cache a complete verdict
        reached here (one read from the store is already the store's)."""
        if self._units.pop(unit.key, None) is None:
            return
        self._backlog -= unit.held
        if judged and (verdict is None or "gap" not in verdict):
            _memory_put(unit.key, verdict)
            _store(unit.key, verdict)
        for oid in unit.oids:
            state = self._objects.get(oid)
            if state is None:
                continue
            state.waiting -= 1
            _apply(state, verdict)
            if state.flagged is not None and not state.recorded:
                self._record(oid, state, verdict, unit.screened)
        unit.screened = None
        if not self._units:
            self._settled.set()

    def _record(
        self,
        oid: str,
        state: ObjectState,
        verdict: dict[str, Any] | None,
        screened: Screened | None,
    ) -> None:
        """One ``detections`` row per flagged object, joined by ``call_ref``."""
        if state.recorded or not self.profile.defense.audit:
            return
        state.recorded = True
        layer, risk = state.flagged or ("L3", "high")
        try:
            record_detection(
                source_type=state.source_type,
                source=f"{self.source}@{oid}",
                domain=None,
                layer1_stats=screened.pipeline.stats.to_flat_dict() if screened else {},
                risk_level=risk,
                qagent_assessment=(verdict or {}).get("l3"),
                profile=self.profile.name,
                backend=self.source.partition("/")[0],
                tool="fetch",
                direction="response",
                provenance="external",
                blocked=False,
                call_ref=self.call_ref,
                verdicts={"flagged_by": layer, "l3_risk": risk},
            )
        except Exception as exc:
            logger.error("git judge: detection row lost: %s at %s", exc_kind(exc), exc_where(exc))

    def _expire(self, gap: str) -> None:
        """Everything still out is unjudged, for ``gap``."""
        for unit in list(self._units.values()):
            self._settle(unit, {"gap": gap})

    # --- reading the outcome ---------------------------------------------------

    async def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` for every queued unit to settle; True if they did."""
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(timeout):
                await self._settled.wait()
                return True
        return not self._units

    def outcome(self) -> Outcome:
        flagged, unjudged = [], []
        pending = judged = 0
        for oid, state in self._objects.items():
            if state.flagged is not None:
                flagged.append((state.kind, oid, *state.flagged))
            elif state.gap is not None:
                unjudged.append((state.kind, oid, state.gap))
            elif not state.settled:
                pending += 1
                continue
            judged += 1
        return Outcome(flagged, unjudged, pending, judged, len(self._objects))

    def progress(self) -> tuple[int, int]:
        """(objects settled, objects seen)."""
        settled = sum(1 for state in self._objects.values() if state.settled or state.flagged)
        return settled, len(self._objects)


class _Dispatch:
    """Sends screened units to L3: whole, alone, or in groups of ``GROUP_TOKENS``."""

    def __init__(self, judge: GitJudge) -> None:
        self._judge = judge
        self._slots = asyncio.Semaphore(L3_CALLS)
        self._tasks: set[asyncio.Task[None]] = set()
        self._group: list[Unit] = []
        self._tokens = 0

    def take(self, unit: Unit) -> None:
        c = unit.screened.classification if unit.screened is not None else None
        if unit.whole:
            self._send([unit], whole=True)
        elif unit.prior is not None or (c is not None and c.score > self._judge._mark):
            # Flagged or borderline: never diluted by its neighbours.
            self._send([unit])
        else:
            tokens = estimate_tokens(unit.read)
            if self._group and self._tokens + tokens > GROUP_TOKENS:
                self.flush()
            self._group.append(unit)
            self._tokens += tokens

    def flush(self) -> None:
        if self._group:
            self._send(self._group)
            self._group, self._tokens = [], 0

    def _send(self, units: list[Unit], *, whole: bool = False) -> None:
        async def run() -> None:
            async with self._slots:
                await self._judge._l3(units, whole=whole)

        task = asyncio.ensure_future(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def cancel(self) -> None:
        """Stop every L3 call still in flight."""
        sent = list(self._tasks)
        for task in sent:
            task.cancel()
        await asyncio.gather(*sent, return_exceptions=True)
        self._tasks.difference_update(sent)

    async def done(self) -> None:
        # Drop what was gathered here: a task's discard callback runs on a later
        # turn, and gather over tasks already done returns without yielding one.
        while self._tasks:
            sent = list(self._tasks)
            await asyncio.gather(*sent)
            self._tasks.difference_update(sent)


_SOURCE_TYPE = {
    OBJ_COMMIT: "git_commit",
    OBJ_TAG: "git_tag",
    OBJ_TREE: "git_tree",
    OBJ_BLOB: "git_blob",
}

#: The judging tasks that outlive their fetch, held so none is collected mid-flight.
_BACKGROUND: set[asyncio.Task[None]] = set()

_MISS: Any = object()


def _flag(
    layer: str, risk: str, screened: Screened | None, l3: dict[str, Any] | None
) -> dict[str, Any]:
    layers = (
        {} if screened is None else {"verdicts": layer_verdicts(None, screened.classification, l3)}
    )
    return {
        "layer": layer,
        "risk": risk,
        **({} if l3 is None else {"l3": _l3_fields(l3)}),
        **layers,
    }


def _l3_fields(answer: dict[str, Any]) -> dict[str, Any]:
    """What a verdict keeps of an L3 answer: closed fields, never its prose."""
    return {k: answer[k] for k in ("injection_detected", "risk_level") if k in answer}


def _apply(state: ObjectState, verdict: dict[str, Any] | None) -> None:
    if verdict is None:
        return
    if "gap" in verdict:
        state.gap = state.gap or verdict["gap"]
    elif "layer" in verdict and state.flagged is None:
        state.flagged = (verdict["layer"], verdict.get("risk", "high"))


def _group_text(units: list[Unit]) -> str:
    pieces = (
        f"----- piece {n} of {len(units)} -----\n{unit.read}" for n, unit in enumerate(units, 1)
    )
    return units[0].read if len(units) == 1 else "\n".join(pieces)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _memory_get(key: str) -> Any:
    """A verdict this process reached, or ``_MISS``.

    It expires as the store's do (#817): counted from the judgement, not the
    last hit, and dropped once past ``verdict_ttl()``.
    """
    entry = _memory.get(key)
    if entry is None:
        return _MISS
    if not 0 <= time.time() - entry[0] < verdict_ttl():
        del _memory[key]
        return _MISS
    _memory.move_to_end(key)
    return entry[1]


def _memory_put(key: str, verdict: dict[str, Any] | None) -> None:
    """Remember a verdict this process reached, from now. A verdict read from
    the store is not kept here: its age is the store's, and the store is read
    again on the next fetch."""
    _memory[key] = (time.time(), verdict)
    _memory.move_to_end(key)
    while len(_memory) > _MEMORY_MAX:
        _memory.popitem(last=False)


_pending_writes: list[tuple[str, dict[str, Any] | None, float]] = []


def _store(key: str, verdict: dict[str, Any] | None) -> None:
    """Write a complete verdict down, a batch at a time."""
    _pending_writes.append((key, verdict, time.time()))
    if len(_pending_writes) >= 64:
        flush_store()


def flush_store() -> None:
    """Write every verdict not yet in the store. A failed write is a slower
    next fetch, never a wrong answer."""
    from ..perimeter_db import perimeter_stamp, save_git_verdicts

    rows = list(_pending_writes)
    _pending_writes.clear()
    if not rows:
        return
    try:
        save_git_verdicts(rows, perimeter_stamp())
    except Exception as exc:
        logger.warning(
            "git judge: verdict store unwritten: %s at %s", exc_kind(exc), exc_where(exc)
        )


def reset_git_verdicts() -> None:
    """Forget the in-memory verdicts (for testing)."""
    _memory.clear()
    _pending_writes.clear()
