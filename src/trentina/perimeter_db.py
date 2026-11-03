"""The perimeter's own store — what the defense pipeline CONCLUDED.

Separate from ``database.py`` on purpose, and the reason is worth stating
plainly because it is not a security boundary today.

``database.py`` holds dirty data: the blocklist, call audit, compressed
descriptions, and the tool lists backends handed us. This file holds the
opposite kind of fact — the verdict ``defend()`` reached about a piece of
content. Splitting them buys nothing on a single-uid deployment: both files
are owned by the process that reads them, and anyone who can rewrite one
can rewrite the other, the code, or the image. Anything stronger would
need the rows signed, not merely filed apart.

What the split buys is the OPTION. If these ever move to a real database,
two stores can have two owners, two grants, and two code paths; one table
next to the blocklist cannot be given any of that afterwards without
finding every caller that assumed a single connection. That is the whole
argument, and it is an argument about tomorrow.

The verdicts here are a cache. The ``tool_pins`` table (#469) is not: it holds
which tool definitions an operator approved, keyed on the backend rather than a
profile, and never expires. Losing this file costs a slow restart AND every
tool held for re-approval until an operator releases it. That is the fail-safe
direction: dark, not silently trusted.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from .config import get_config

if TYPE_CHECKING:
    from collections.abc import Collection, Iterator

logger = logging.getLogger(__name__)

_db: sqlite3.Connection | None = None
_db_path: str = ""

_local = threading.local()

# Every connection sets `PRAGMA busy_timeout=250`: SQLite's default is 0, so any
# contention raised ``database is locked`` at once (#662).

pending_pins_cached: int | None = None
"""The pending-pin count ``/health`` reports (#662). Written by the refresher
``warmup.trentina_lifespan`` owns, read by the probe, which never waits on
SQLite. None until a refresh succeeds, and again whenever the last one failed."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdict_cache (
    cache_key TEXT PRIMARY KEY,
    warning_json TEXT,
    perimeter_version TEXT NOT NULL,
    cached_at TEXT NOT NULL
);
-- One row per DEFINITION since 6.1.0, not one per tool. An approval was always
-- a decision about a definition — the hash is that definition, and the URL was
-- only ever the row's address. With tool lists partitioned per credential
-- (`backend.cache_owner`), two tenants can legitimately be served different
-- definitions of the same tool, and one row per (backend, tool) could hold only
-- one of them: the second listing overwrote the first's pending hash, an
-- approval given for one tenant's definition appeared to cover the other's, and
-- the two builds then flapped the hold and logged a detection on alternate
-- passes. Keyed by hash, both coexist, an approval covers every tenant served
-- those exact bytes, and anything else stays held.
CREATE TABLE IF NOT EXISTS tool_pins (
    backend_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (backend_id, tool, definition_hash)
);
"""

#: What a ``tool_pins.state`` may hold. ``pending`` is held awaiting an
#: operator, ``rejected`` is held permanently, ``approved`` is served.
PIN_APPROVED = "approved"
PIN_PENDING = "pending"
PIN_REJECTED = "rejected"

PERIMETER_VERSION = "22"
"""Bump whenever a change could alter what a scan CONCLUDES: a new detector, a
retuned L3 prompt, a different L2 model or threshold set. Rows stamped with any
other value are swept on load, so an older perimeter's verdict is unusable
rather than merely old.

"3" (0.23.0): petit frames before it groups, so different bytes survive
reduction. "4" (0.31.0): L2 reads the arrived bytes plus L1's normalized copy,
L3 is briefed with L2's result, and warnings carry L3's finding types.
"5" (0.55.0): L3's caveat about L2 no longer quotes Prompt Guard 2's miss
rates (#350). "6" (0.56.0): L2 reads the arrived bytes once, never L1's copy,
and L3's briefing names L1's findings by type (#359). "7" (0.57.0): every
layer reads the delivery unpacked, base64 decoded and binary labelled (#367).
"8" (0.58.0): the count-only L1 stages of #363. "9" (0.60.0): archives and
office files are read inside, and their hidden text counted (#368).
"10" (0.61.0): PDFs are read, and their invisible text counted (#369).
"11" (0.62.0): images are read by OCR, and faint text counted (#370).
"12" (1.1.1): the Matrix bridge leaves a relation's event IDs out of what the
layers read; they are replaced from the mapping table or dropped, never
delivered as written.
"13" (1.3.0): the structured transform's markers lose their bracketed
tag, which L2 read as an injected note (#411), so a listing it reduced is
judged as different text.
"14" (1.4.0): the structured transform hands a log held in a JSON string to
petit (#419), so a journal response is judged as its samples and a summary.
"15" (1.4.1): a structured listing gives its rows before its note, and the
unpack stage reads a run of decimal digits as a number, not as hex (#431).
"16" (1.5.0): the default judge is gemini-3.5-flash-lite (#397).
"19": a remote backend's new or changed tool is held until approved (#469).
"20": the default L2 model is the fine-tuned prompt-injection-guard-small-ct (#17).

The L2 model and its threshold are no longer bumped here: they are an
operator setting since 0.55.0 (#350), so :func:`perimeter_stamp` carries them."""


def perimeter_stamp() -> str:
    """``PERIMETER_VERSION`` plus the L2 model, revision, threshold, polarity, gates
    and window (#438): a model scanned in other windows scores other text.

    Switching ``CLASSIFIER_MODEL`` or ``CLASSIFIER_THRESHOLD`` changes what a
    scan concludes as surely as a code change does, so a verdict reached under
    another model is swept on load like one from an older perimeter. Read from
    the selected model's manifest, the same resolution the classifier makes,
    without loading the model; one that does not resolve stamps as absent.
    """
    from .config import get_config
    from .quarantine.classifier import resolve_model

    config = get_config()
    try:
        model = resolve_model(config.classifier_model_path, config.classifier_threshold)
    except (OSError, ValueError):
        return f"{PERIMETER_VERSION}:l2-absent"
    polarity = ",".join(str(i) for i in model.malicious)
    return (
        f"{PERIMETER_VERSION}:{model.id}@{model.revision or 'unpinned'}"
        f":{model.threshold:g}:{polarity}:gate-{model.gate}:benign-{model.benign_gate}"
        f":window-{model.window}/{model.guard}"
    )


pins_upgraded_at: float | None = None
"""``time.monotonic()`` when this process added ``tool_pins`` to an existing
store, else None (#469). The baseline window runs from here."""


def get_perimeter_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the perimeter store's connection."""
    global _db, _db_path, pins_upgraded_at
    if _db is None:
        config = get_config()
        path = db_path or config.perimeter_db_path
        config.ensure_perimeter_db_dir()
        _db = sqlite3.connect(path)
        _db_path = path
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA busy_timeout=250")
        # An existing store from before pins is an upgrade: its tools were
        # already being served, so the first pass pins them as approved. A
        # missing store is not, and holds everything.
        had_pins = _db.execute("SELECT 1 FROM sqlite_master WHERE name = 'tool_pins'").fetchone()
        had_verdicts = _db.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'verdict_cache'"
        ).fetchone()
        _rekey_pins_by_definition(_db)
        _db.executescript(SCHEMA)
        upgraded = had_pins is None and had_verdicts is not None
        pins_upgraded_at = time.monotonic() if upgraded else None
        if had_pins is None and had_verdicts is None:
            # A store with neither table is a store this gateway has never had.
            # Worth a line: every remote tool is about to be held for approval,
            # and a FEDERATED backend's whole offered set is about to be
            # approved unreviewed as a first connect (`tool_pins.check_tools`).
            # Expected on a new deployment; on an old one it means the volume
            # is missing, and the quiet version of that cost the trust it was
            # protecting.
            logger.warning(
                "gateway: the perimeter store was created empty, so this gateway holds "
                "no tool approvals and no cached verdicts. Expected on a first run. "
                "Otherwise its volume is not mounted: every remote tool will be held, "
                "and each federated peer's offered set approved as a first connect"
            )
    return _db


#: Where the pre-6.1.0 pins are kept after the re-key. Not dropped: a rollback
#: to 6.0.x finds them and re-holds nothing it had already approved, and a
#: rollback that found an empty table would hold every remote tool on this
#: gateway at once.
_LEGACY_PINS = "tool_pins_pre_6_1"


def _rekey_pins_by_definition(db: sqlite3.Connection) -> None:
    """Re-key a pre-6.1.0 ``tool_pins`` from one row per tool to one per definition.

    Runs BEFORE ``SCHEMA``, because ``CREATE TABLE IF NOT EXISTS`` would leave
    the old table in place and every read would then look for columns it does
    not have.

    Each old row becomes up to two: its approved definition, and its pending
    one — the latter as ``rejected`` when the old row's flag was set, since the
    flag described the pending definition and nothing else. An old row carried
    the rejection on the TOOL, so a rejected tool that later offered different
    bytes was still refused; now the rejection names the bytes that earned it,
    which is both narrower and what an operator was deciding about.
    """
    present = {row["name"] for row in db.execute("PRAGMA table_info(tool_pins)")}
    if not present or "definition_hash" in present:
        return
    rows = db.execute(
        "SELECT backend_id, tool, approved_hash, approved_json, pending_hash, "
        "pending_json, rejected, first_seen, last_seen FROM tool_pins"
    ).fetchall()
    db.execute("ALTER TABLE tool_pins RENAME TO tool_pins_pre_6_1")
    db.executescript(SCHEMA)
    carried = 0
    for row in rows:
        for hash_, json_, state in (
            (row["approved_hash"], row["approved_json"], PIN_APPROVED),
            (
                row["pending_hash"],
                row["pending_json"],
                PIN_REJECTED if row["rejected"] else PIN_PENDING,
            ),
        ):
            if not hash_ or not json_:
                continue
            db.execute(
                "INSERT OR REPLACE INTO tool_pins (backend_id, tool, definition_hash, "
                "state, definition_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["backend_id"],
                    row["tool"],
                    hash_,
                    state,
                    json_,
                    row["first_seen"],
                    row["last_seen"],
                ),
            )
            carried += 1
    db.commit()
    logger.info(
        "gateway: re-keyed %d tool pin(s) from %d row(s) by definition hash; the old "
        "table is kept as %s",
        carried,
        len(rows),
        _LEGACY_PINS,
    )


def opened_path() -> str:
    """The store's file, opening it (schema, migration detection) if nothing has.

    Call on the event loop, where the singleton lives; the result is what a
    worker hands ``snapshot_reader``. Mirrors ``database.opened_path``.
    """
    get_perimeter_db()
    return _db_path


@contextmanager
def snapshot_reader(path: str) -> Iterator[None]:
    """Route this thread's perimeter reads to a read-only connection of its own.

    ``database.py`` has had this since #295; this store did not, and 5.0.0 added
    a reader on a worker thread. ``quarantine_stats`` runs its aggregates under
    ``asyncio.to_thread`` because they cost seconds on a large audit table, and
    an operator's slice reaches ``federation_report.link_report`` ->
    ``tool_pins.pending`` -> ``list_pending_pins`` here. The singleton
    connection is bound to the loop's thread, so that read raised
    ``sqlite3.ProgrammingError`` and the whole tool failed for every operator on
    a gateway with a federation link.

    ``check_same_thread=False`` on the singleton would have been the short fix
    and the wrong one: it shares one connection between the loop's writes and a
    multi-second read, which serializes them. A second connection under WAL
    reads a consistent snapshot while the loop keeps writing, and read-only
    means a worker cannot write by accident.

    Args:
        path: the store's file, from ``opened_path()``.
    """
    conn = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=250")
    _local.reader = conn
    try:
        yield
    finally:
        _local.reader = None
        conn.close()


def _read_db() -> sqlite3.Connection:
    """This thread's ``snapshot_reader`` connection, else the singleton."""
    reader: sqlite3.Connection | None = getattr(_local, "reader", None)
    return reader if reader is not None else get_perimeter_db()


def get_pin(backend_id: str, tool: str, definition_hash: str) -> sqlite3.Row | None:
    """The row for ONE definition of a tool, or None when it has never been seen.

    None means held: a definition with no row is one no operator has decided
    about, which is the fail-closed direction and the whole point of the store.
    """
    row: sqlite3.Row | None = (
        _read_db()
        .execute(
            "SELECT definition_hash, state, definition_json FROM tool_pins "
            "WHERE backend_id = ? AND tool = ? AND definition_hash = ?",
            (backend_id, tool, definition_hash),
        )
        .fetchone()
    )
    return row


def last_approved(backend_id: str, tool: str) -> sqlite3.Row | None:
    """The most recently seen APPROVED definition of a tool, for diffing against.

    What a changed-definition report compares a new one to. Most recent rather
    than only: with lists partitioned per credential, a tool can have several
    approved definitions at once, and the newest is the best available answer
    to "what changed".
    """
    row: sqlite3.Row | None = (
        _read_db()
        .execute(
            "SELECT definition_hash, definition_json FROM tool_pins WHERE backend_id = ? "
            "AND tool = ? AND state = ? ORDER BY last_seen DESC LIMIT 1",
            (backend_id, tool, PIN_APPROVED),
        )
        .fetchone()
    )
    return row


def approved_by_tool(backend_id: str, tools: Collection[str]) -> dict[str, str]:
    """The most recently approved definition of each named tool, in ONE read.

    What a list of held definitions is diffed against. Per-tool it would be a
    round trip each, and ``tool_pins list`` asks about every held tool at once.
    Newest first, so the first row seen for a tool is the one kept.
    """
    wanted = sorted(set(tools))
    if not wanted:
        return {}
    # Narrowed in SQL, not in Python: a backend with a long approved history
    # would otherwise have every definition body loaded and discarded on each
    # `tool_pins list`. The tool names ride as ONE bound JSON array through
    # `json_each`, so the statement is a constant — an IN clause built from a
    # run of '?' would have needed interpolation and a lint suppression to say
    # it was harmless, and a query nobody has to take on trust is better.
    rows = (
        _read_db()
        .execute(
            "SELECT tool, definition_json FROM tool_pins WHERE backend_id = ? AND state = ? "
            "AND tool IN (SELECT value FROM json_each(?)) ORDER BY last_seen DESC",
            (backend_id, PIN_APPROVED, json.dumps(wanted)),
        )
        .fetchall()
    )
    out: dict[str, str] = {}
    for row in rows:
        out.setdefault(row["tool"], row["definition_json"])
    return out


def pending_hashes(backend_id: str, tool: str) -> list[str]:
    """Every definition of a tool now held awaiting an operator.

    More than one is possible since 6.1.0, and that is why ``tool_pins
    approve`` takes an optional hash: with two held definitions there is no
    single thing "approve this tool" could mean.
    """
    rows = (
        _read_db()
        .execute(
            "SELECT definition_hash FROM tool_pins WHERE backend_id = ? AND tool = ? "
            "AND state = ? ORDER BY last_seen DESC",
            (backend_id, tool, PIN_PENDING),
        )
        .fetchall()
    )
    return [row["definition_hash"] for row in rows]


def has_pins(backend_id: str) -> bool:
    """Whether any pin row exists for this backend yet (#592, E1b).

    A federated backend's FIRST list (no rows) is auto-approved as a unit, so a
    large peer does not trigger a per-tool approval storm; once it has rows, a
    new or changed tool is held one at a time as usual.
    """
    row = (
        _read_db()
        .execute("SELECT 1 FROM tool_pins WHERE backend_id = ? LIMIT 1", (backend_id,))
        .fetchone()
    )
    return row is not None


def pin_hold_flags(backend_id: str, tool: str) -> tuple[bool, bool] | None:
    """``(pending, rejected)`` for a TOOL, or None when it has no rows at all.

    The two flags the call gate needs, read without any definition JSON (#469).
    Still per tool rather than per definition, because the gate is asked about
    a call and a call names no definition: anything held under this tool is a
    reason to refuse it, whichever tenant's bytes earned the hold.
    """
    row = (
        _read_db()
        .execute(
            "SELECT "
            "SUM(state = ?) AS pending, SUM(state = ?) AS rejected "
            "FROM tool_pins WHERE backend_id = ? AND tool = ?",
            (PIN_PENDING, PIN_REJECTED, backend_id, tool),
        )
        .fetchone()
    )
    # SUM over no rows is NULL, which is how "this tool has no pins" reads.
    if row is None or (row["pending"] is None and row["rejected"] is None):
        return None
    return (bool(row["pending"]), bool(row["rejected"]))


#: Definitions kept per (backend, tool), least recently seen dropped. Without a
#: bound, a backend whose descriptions churn keeps every version it has ever
#: sent, JSON and all, for the life of the store.
#:
#: A plain LRU is safe because eviction is FAIL-CLOSED: a dropped row reads as
#: never seen, and never seen is held. Thirty-two is far past legitimate churn,
#: so a rejection needs that many distinct definitions to be pushed out.
MAX_DEFINITIONS_PER_TOOL = 32


def put_pin(backend_id: str, tool: str, definition_hash: str, state: str, body: str) -> None:
    """Record what one definition of a tool is: approved, pending or rejected.

    One row per definition, so writing a new one never disturbs another
    tenant's. ``last_seen`` moves on every write, which is what makes
    ``last_approved`` mean "most recent" and what orders the eviction below.
    """
    now = datetime.now(UTC).isoformat()
    db = get_perimeter_db()
    db.execute(
        "INSERT INTO tool_pins (backend_id, tool, definition_hash, state, "
        "definition_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (backend_id, tool, definition_hash) DO UPDATE SET "
        "state = excluded.state, definition_json = excluded.definition_json, "
        "last_seen = excluded.last_seen",
        (backend_id, tool, definition_hash, state, body, now, now),
    )
    db.execute(
        "DELETE FROM tool_pins WHERE backend_id = ? AND tool = ? AND definition_hash NOT IN "
        "(SELECT definition_hash FROM tool_pins WHERE backend_id = ? AND tool = ? "
        "ORDER BY last_seen DESC LIMIT ?)",
        (backend_id, tool, backend_id, tool, MAX_DEFINITIONS_PER_TOOL),
    )
    db.commit()


def set_pin_state(backend_id: str, tool: str, definition_hash: str, state: str) -> bool:
    """Move one definition to ``state``; False when there is no such row.

    An operator's decision changes nothing but the state, so it is one UPDATE
    rather than a read and a rewrite — the definition JSON it would have had to
    carry back is already in the row.
    """
    db = get_perimeter_db()
    changed = db.execute(
        "UPDATE tool_pins SET state = ?, last_seen = ? WHERE backend_id = ? "
        "AND tool = ? AND definition_hash = ?",
        (state, datetime.now(UTC).isoformat(), backend_id, tool, definition_hash),
    ).rowcount
    db.commit()
    return bool(changed)


def set_pin_states(
    backend_id: str, pairs: Collection[tuple[str, str]], state: str, *, was: str
) -> int | None:
    """Move every ``(tool, definition_hash)`` from ``was`` to ``state``, in ONE
    transaction.

    Returns how many rows moved, or None if any pair did not match a row IN
    THAT STATE — in which case nothing is committed. A batch approval is
    all-or-nothing by contract (``tool_pins.decide_all``), and a partial one
    reported as a success would be worse than a refusal: the operator would
    believe a set was released and the rows that quietly failed are the ones
    nothing has reviewed.

    ``was`` is why this is not a bare UPDATE by key. ``decide_all`` excludes
    rejected definitions from the set it approves, but with the state out of the
    WHERE clause a rejection landing between the read and the write would be
    overwritten — reversing a standing decision to keep something withheld,
    which is the one thing a batch must never do. With it, that row matches
    nothing, the count falls short, and the whole batch rolls back.

    One ``executemany`` rather than an UPDATE per definition, because the case
    this exists for is hundreds of them at once.
    """
    db = get_perimeter_db()
    now = datetime.now(UTC).isoformat()
    moved = db.executemany(
        "UPDATE tool_pins SET state = ?, last_seen = ? WHERE backend_id = ? "
        "AND tool = ? AND definition_hash = ? AND state = ?",
        [(state, now, backend_id, tool, h, was) for tool, h in pairs],
    ).rowcount
    if moved != len(pairs):
        db.rollback()
        return None
    db.commit()
    return int(moved)


def move_pins(old_backend_id: str, new_backend_id: str) -> int:
    """Re-key a backend's pins when its URL moves, returning how many moved.

    ``backend_id`` is a hash of the URL, so a trailing slash, a port or a host
    spelled differently is a DIFFERENT backend to this table — and a federated
    backend with no rows is treated as a first connect, which auto-approves the
    peer's whole offered set as a unit (#592, E1b). An operator editing a URL
    therefore re-trusted the peer wholesale without asking for it.

    Refuses to move onto an id that already has rows and returns 0: two
    backends can legitimately name one URL, and the primary key leads with
    ``backend_id``, so an UPDATE would collide on the shared definitions and
    the pins already there are not this edit's to overwrite.
    """
    db = get_perimeter_db()
    if (
        db.execute(
            "SELECT 1 FROM tool_pins WHERE backend_id = ? LIMIT 1", (new_backend_id,)
        ).fetchone()
        is not None
    ):
        return 0
    moved = db.execute(
        "UPDATE tool_pins SET backend_id = ? WHERE backend_id = ?",
        (new_backend_id, old_backend_id),
    ).rowcount
    db.commit()
    return int(moved)


def list_pending_pins(backend_id: str) -> list[sqlite3.Row]:
    """Every held definition on a backend, newest first within each tool.

    One tool can appear more than once since 6.1.0 — two tenants served
    different definitions of it — which is why each row carries its hash.
    """
    rows: list[sqlite3.Row] = (
        _read_db()
        .execute(
            "SELECT tool, definition_hash, definition_json, state FROM tool_pins "
            "WHERE backend_id = ? AND state IN (?, ?) ORDER BY tool, last_seen DESC",
            (backend_id, PIN_PENDING, PIN_REJECTED),
        )
        .fetchall()
    )
    return rows


def count_pending_pins(backend_ids: Collection[str]) -> int:
    """How many tools are held pending approval, across the backends that EXIST.

    Across every backend, so the unauthenticated ``/health`` probe can surface a
    number for Nagios without naming a profile — which backend holds what is in
    the ``tool_pins`` operator tool, not here.

    Hence the argument. A backend's id is the hash of its URL, so changing a URL,
    or removing a backend, leaves that identity's rows behind, and those rows
    hold nothing from anyone: ``tool_pins`` resolves a backend by its LIVE URL,
    so it can neither list them nor approve them. Counting them reported a held
    tool that no tool could show and nobody could release — an alert with no
    action behind it. They stay in the store rather than being swept, because a
    URL that comes back should find its approvals again instead of re-holding
    every tool it offers.
    """
    if not backend_ids:
        return 0
    live = set(backend_ids)
    # DISTINCT tool, not rows: since 6.1.0 one tool can be held under several
    # definitions, and this number is an alert threshold Nagios watches. Had it
    # counted rows, partitioning the tool lists would have moved it on its own
    # and read as a backlog appearing out of nowhere.
    rows = _read_db().execute(
        "SELECT backend_id, COUNT(DISTINCT tool) FROM tool_pins "
        "WHERE state = ? GROUP BY backend_id",
        (PIN_PENDING,),
    )
    return sum(int(count) for backend_id, count in rows if backend_id in live)


def get_all_verdicts(perimeter_version: str) -> dict[str, dict[str, Any] | None]:
    """Load the verdicts this perimeter version reached.

    Rows from any other version are deleted rather than returned: a verdict
    is only meaningful for the detector set that produced it.

    On the singleton, not ``_read_db()``, because it WRITES: a sweep and, for an
    unreadable row, a delete. It runs once at startup on the event loop. A
    reader in a worker that needed these would need the sweep moved out first.
    """
    db = get_perimeter_db()
    swept = db.execute(
        "DELETE FROM verdict_cache WHERE perimeter_version != ?",
        (perimeter_version,),
    ).rowcount
    db.commit()
    if swept > 0:
        logger.info("perimeter: swept %d verdict(s) from an older perimeter version", swept)
    rows = db.execute(
        "SELECT cache_key, warning_json FROM verdict_cache WHERE perimeter_version = ?",
        (perimeter_version,),
    ).fetchall()
    out: dict[str, dict[str, Any] | None] = {}
    unreadable: list[str] = []
    for key, blob in rows:
        try:
            out[key] = json.loads(blob) if blob is not None else None
        except json.JSONDecodeError:
            unreadable.append(key)

    if unreadable:
        # A row we cannot read is a row we rescan, and leaving it in place
        # means rescanning it on every boot forever. Delete it and say so.
        db.executemany(
            "DELETE FROM verdict_cache WHERE cache_key = ?",
            [(key,) for key in unreadable],
        )
        db.commit()
        logger.warning("perimeter: deleted %d unreadable verdict row(s)", len(unreadable))
    return out


def save_verdict(
    cache_key: str,
    warning: dict[str, Any] | None,
    perimeter_version: str,
) -> None:
    """Persist one verdict. ``warning`` is None for a clean result."""
    db = get_perimeter_db()
    db.execute(
        "INSERT OR REPLACE INTO verdict_cache "
        "(cache_key, warning_json, perimeter_version, cached_at) VALUES (?, ?, ?, ?)",
        (
            cache_key,
            None if warning is None else json.dumps(warning),
            perimeter_version,
            datetime.now(UTC).isoformat(),
        ),
    )
    db.commit()


def delete_all_verdicts() -> int:
    """Flush every persisted verdict, forcing a full rescan on next boot."""
    db = get_perimeter_db()
    count = db.execute("DELETE FROM verdict_cache").rowcount
    db.commit()
    return count
