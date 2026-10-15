"""SQLite blocklist database for trentina.

Write access is deterministic code ONLY. The Q-Agent cannot write to this database.
The Q-Agent's detection output is returned as structured JSON, parsed by the server's
deterministic code, which decides whether to record a detection.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from .config import get_config, int_env
from .outcomes import Outcome, group_of

if TYPE_CHECKING:
    from collections.abc import Iterator

_db: sqlite3.Connection | None = None
_db_path = ""  # set by get_db on every open
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source TEXT NOT NULL,
    domain TEXT,
    detected_at TEXT NOT NULL,
    layer1_stats TEXT NOT NULL,
    qagent_assessment TEXT,
    risk_level TEXT NOT NULL,
    blocked BOOLEAN DEFAULT 1,
    profile TEXT,
    backend TEXT,
    tool TEXT,
    direction TEXT,
    provenance TEXT,
    flagged_by TEXT,
    l2_label TEXT,
    l2_score REAL,
    l3_verdict TEXT,
    l3_risk TEXT,
    call_ref TEXT
);

CREATE INDEX IF NOT EXISTS idx_detections_domain ON detections(domain);
CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source);

CREATE TABLE IF NOT EXISTS gateway_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    profile TEXT NOT NULL,
    backend TEXT NOT NULL,
    tool TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    duration_ms INTEGER NOT NULL,
    error_message TEXT,
    outcome TEXT,
    bytes_arrived INTEGER,
    bytes_delivered INTEGER,
    normalized TEXT,
    destination TEXT,
    destination_kind TEXT,
    session TEXT,
    call_ref TEXT,
    content_digest TEXT
);

CREATE INDEX IF NOT EXISTS idx_gateway_calls_timestamp ON gateway_calls(timestamp);
CREATE INDEX IF NOT EXISTS idx_gateway_calls_profile_tool ON gateway_calls(profile, backend, tool);

CREATE TABLE IF NOT EXISTS tool_compressions (
    description_hash TEXT PRIMARY KEY,
    original_description TEXT NOT NULL,
    compressed_description TEXT NOT NULL,
    model TEXT NOT NULL,
    compressed_at TEXT NOT NULL,
    original_length INTEGER NOT NULL,
    compressed_length INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_names (
    profile TEXT NOT NULL,
    issued TEXT NOT NULL,
    backend TEXT NOT NULL,
    tool TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    PRIMARY KEY (profile, issued),
    UNIQUE (profile, backend, tool)
);

CREATE TABLE IF NOT EXISTS tool_list_cache (
    backend_url TEXT PRIMARY KEY,
    tools_json TEXT NOT NULL,
    cached_at TEXT NOT NULL
);

-- What a honeypot profile was delivered, whole, with every layer's verdict
-- on it (#357), and what it sent a decoy tool (#410). The one table that
-- holds content: the audit holds none.
CREATE TABLE IF NOT EXISTS honeypot_captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at REAL NOT NULL,
    profile TEXT NOT NULL,
    call_ref TEXT,
    source TEXT NOT NULL,
    flagged_by TEXT,
    l2_label TEXT,
    l2_score REAL,
    l3_verdict TEXT,
    l3_risk TEXT,
    content TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_honeypot_captures_at ON honeypot_captures(captured_at);
"""


def get_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the singleton database connection."""
    global _db, _db_path
    if _db is None:
        path = db_path or get_config().db_path
        get_config().ensure_db_dir()
        _db = sqlite3.connect(path)
        _db_path = path
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA foreign_keys=ON")
        _db.executescript(SCHEMA)
        _migrate(_db)
    return _db


def opened_path() -> str:
    """The database file, opening it (schema and migrations) if nothing has yet.

    Call on the event loop, where the singleton lives; the result is what a
    worker hands ``snapshot_reader``.
    """
    get_db()
    return _db_path


@contextmanager
def snapshot_reader(path: str) -> Iterator[None]:
    """Route this thread's stats reads to a read-only connection of its own (#295).

    The aggregates behind ``quarantine_stats`` cost about 2.7 s per million
    audit rows. On the event loop that stalled every profile; in a worker on
    the singleton connection it would trip sqlite3's thread check, and a lock
    around the singleton would make every audit write on the loop wait out
    the scan. A second connection under WAL reads a consistent snapshot while
    the singleton keeps writing.

    Args:
        path: the database file, from ``opened_path()``.
    """
    conn = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    _local.reader = conn
    try:
        yield
    finally:
        _local.reader = None
        conn.close()


def _read_db() -> sqlite3.Connection:
    """This thread's ``snapshot_reader`` connection, else the singleton."""
    reader: sqlite3.Connection | None = getattr(_local, "reader", None)
    return reader if reader is not None else get_db()


_VERDICT_COLUMNS = (
    ("flagged_by", "TEXT"),
    ("l2_label", "TEXT"),
    ("l2_score", "REAL"),
    ("l3_verdict", "TEXT"),
    ("l3_risk", "TEXT"),
)


# gateway_calls columns added after the table first shipped, in order.
_CALL_COLUMNS = (
    ("outcome", "TEXT"),
    # Response sizes as they arrived and as they were delivered. Nullable:
    # older rows, denials that never reached a backend, and internal tools
    # (which minify inside the tool) have no arrived size.
    ("bytes_arrived", "INTEGER"),
    ("bytes_delivered", "INTEGER"),
    # Arguments the gateway dropped before forwarding, as JSON (#241).
    ("normalized", "TEXT"),
    # Where the call was pointed, and which kind of destination that is
    # (#266, gateway/destination.py). NULL for older rows and for tools
    # that name no destination.
    ("destination", "TEXT"),
    ("destination_kind", "TEXT"),
    # What joins a call to the rows around it (#357): a fingerprint of the
    # MCP session, one random reference per call (detections carry the same
    # one), and a fingerprint of the delivered result. NULL for older rows,
    # for a client with no session, and for a call that delivered nothing.
    ("session", "TEXT"),
    ("call_ref", "TEXT"),
    ("content_digest", "TEXT"),
)


def _migrate(db: sqlite3.Connection) -> None:
    """Apply additive schema migrations to a database created by an older build.

    ``CREATE TABLE IF NOT EXISTS`` leaves a pre-existing table untouched, so a
    column added to SCHEMA never reaches an existing deployment without this.
    Additive only — no column is dropped and no row is rewritten.
    """
    columns = {row["name"] for row in db.execute("PRAGMA table_info(gateway_calls)")}
    for column, sql_type in _CALL_COLUMNS:
        if column not in columns:
            db.execute(f"ALTER TABLE gateway_calls ADD COLUMN {column} {sql_type}")
    # After the columns exist: an old database runs SCHEMA before them. The
    # per-profile recent-destinations read walks this, newest first.
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_calls_destination "
        "ON gateway_calls(profile, timestamp) WHERE destination IS NOT NULL"
    )
    # One session's calls in order: the read a detection is traced back along.
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_calls_session "
        "ON gateway_calls(session, id) WHERE session IS NOT NULL"
    )
    # Has this profile sent here before: the gatekeeper's first-contact fact
    # (#456), one probe per guarded call.
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_calls_sent_to "
        "ON gateway_calls(profile, destination) WHERE outcome = 'ok'"
    )
    db.commit()

    detection_columns = {row["name"] for row in db.execute("PRAGMA table_info(detections)")}
    # Gateway attribution columns (which profile, which backend and tool,
    # which direction the content was moving, and the provenance the L3
    # gate saw). Nullable — 50 web-shaped legacy rows and the standalone
    # tools carry none of this.
    # call_ref (#357) is the gateway_calls row the content arrived on.
    for column in ("profile", "backend", "tool", "direction", "provenance", "call_ref"):
        if column not in detection_columns:
            db.execute(f"ALTER TABLE detections ADD COLUMN {column} TEXT")
        db.commit()
    # Every layer's opinion on the row, not only the credited one's (#204).
    # A row credited to L2 used to say nothing about what L3 thought, so how
    # often L3 disagreed with an L2 flag could not be measured, and that is
    # the number any rule letting L3 overrule L2 has to be argued from.
    for column, sql_type in _VERDICT_COLUMNS:
        if column not in detection_columns:
            db.execute(f"ALTER TABLE detections ADD COLUMN {column} {sql_type}")
        db.commit()
    # The blocklist is keyed on (profile, source) since #263. Created here, not
    # in SCHEMA: on a table that predates the profile column, SCHEMA runs
    # before the ALTER above and an index naming the column would fail the
    # open. Rows written before #263 by the web tools carry a NULL profile and
    # are read as operator-only; nothing is rewritten.
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_detections_profile_source ON detections(profile, source)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_detections_detected_at ON detections(detected_at)")
    db.commit()


def _block_cutoff() -> str:
    """The oldest ``detected_at`` a blocklist row may carry and still count."""
    ttl = timedelta(days=get_config().blocklist_ttl_days)
    return (datetime.now(UTC) - ttl).isoformat()


_SWEEP_INTERVAL_SECONDS = 3600.0
# None until the first sweep. It was 0.0, compared with `time.monotonic()`,
# which counts from boot: on a host up less than an hour nothing was swept.
_last_sweep: float | None = None

# Rows one sweep pass deletes. The sweeps run on the event loop, inside the
# call that triggered them, so a pass is bounded rather than "everything
# expired": a month of a cheap denied-call flood is millions of rows (#295).
# A full batch leaves the sweep due, and the next call takes the next batch.
SWEEP_BATCH = 500


_SWEEP_BLOCKS = (
    "DELETE FROM detections WHERE rowid IN (SELECT rowid FROM detections "
    "WHERE blocked = 1 AND detected_at <= ? LIMIT ?)"
)
_SWEEP_CAPTURES = (
    "DELETE FROM honeypot_captures WHERE rowid IN "
    "(SELECT rowid FROM honeypot_captures WHERE captured_at <= ? LIMIT ?)"
)
_SWEEP_CALLS = (
    "DELETE FROM gateway_calls WHERE rowid IN "
    "(SELECT rowid FROM gateway_calls WHERE timestamp <= ? LIMIT ?)"
)


def _delete_batch(conn: sqlite3.Connection, statement: str, cutoff: str | float) -> int:
    cursor = conn.execute(statement, (cutoff, SWEEP_BATCH))
    conn.commit()
    return cursor.rowcount


def sweep_expired_blocks(db: sqlite3.Connection | None = None) -> int:
    """Delete up to ``SWEEP_BATCH`` blocklist rows past ``TRENTINA_BLOCKLIST_TTL_DAYS`` (#263).

    Readers filter on the cutoff themselves, so an expired row never counts
    whether or not a sweep has run; the sweep only stops the table from
    holding what no reader will use. Flag-mode observations (``blocked = 0``)
    are not blocklist rows and are kept.

    Returns:
        The number of rows removed.
    """
    return _delete_batch(db or get_db(), _SWEEP_BLOCKS, _block_cutoff())


DEFAULT_AUDIT_RETENTION_DAYS = 90


def audit_retention_days() -> int:
    """``TRENTINA_AUDIT_RETENTION_DAYS``: days an audit row is kept, 0 for ever (#295).

    The table was never pruned, and a denied call costs the caller nothing.
    """
    return int_env("TRENTINA_AUDIT_RETENTION_DAYS", DEFAULT_AUDIT_RETENTION_DAYS, minimum=0)


def sweep_old_gateway_calls(db: sqlite3.Connection | None = None) -> int:
    """Delete up to ``SWEEP_BATCH`` audit rows past ``TRENTINA_AUDIT_RETENTION_DAYS`` (#295).

    A retention of 0 keeps every row.

    Returns:
        The larger of the two tables' removals: a full batch from either
        means the sweep is not finished.
    """
    days = audit_retention_days()
    if days <= 0:
        return 0
    conn = db or get_db()
    cutoff = time.time() - days * 86400
    # A capture is kept as long as the call row it is read beside, and no longer.
    return max(
        _delete_batch(conn, _SWEEP_CALLS, cutoff), _delete_batch(conn, _SWEEP_CAPTURES, cutoff)
    )


def _maybe_sweep(db: sqlite3.Connection) -> None:
    """Both sweeps, at most hourly, until a pass comes back short of a batch.

    Run from ``is_blocked`` and ``record_gateway_call``, the first time on the
    first call after start.
    """
    global _last_sweep
    if _last_sweep is not None and time.monotonic() - _last_sweep < _SWEEP_INTERVAL_SECONDS:
        return
    removed = max(sweep_expired_blocks(db), sweep_old_gateway_calls(db))
    if removed < SWEEP_BATCH:
        _last_sweep = time.monotonic()


def is_blocked(source: str, profile: str | None, *, gateway_wide: bool = False) -> bool:
    """Whether *source* is on the blocklist as *profile* sees it (#263).

    The blocklist is keyed on ``(profile, source)``. It used to be keyed on
    the source alone, so one profile's refusal was every profile's refusal:
    profile A getting ``?slot=N`` flagged was a bit profile B could read, with
    A's timestamp attached, and rows never expired.

    Args:
        source: The URL, resolved path or content hash.
        profile: The calling agent profile. Its own rows count and nobody
            else's; rows with a NULL profile (written before #263, or by a
            standalone server) are operator-only. None with
            ``gateway_wide`` False — a live gateway with no bound caller —
            sees nothing.
        gateway_wide: Every live row, whoever wrote it. Operator and
            standalone scope only; the caller decides that, not this module.

    Returns:
        True or False and nothing else: no row, no timestamp. What a refusal
        can say is decided here, and it is one bit about the caller's own
        history.
    """
    db = get_db()
    _maybe_sweep(db)
    query = (
        "SELECT 1 FROM detections WHERE source = ? AND blocked = 1 "
        "AND detected_at > ?{profile_clause} LIMIT 1"
    )
    if gateway_wide:
        row = db.execute(query.format(profile_clause=""), (source, _block_cutoff())).fetchone()
    elif profile:
        row = db.execute(
            query.format(profile_clause=" AND profile = ?"), (source, _block_cutoff(), profile)
        ).fetchone()
    else:
        return False
    return row is not None


def record_detection(
    source_type: str,
    source: str,
    domain: str | None,
    layer1_stats: dict[str, Any],
    risk_level: str,
    qagent_assessment: dict[str, Any] | None = None,
    profile: str | None = None,
    backend: str | None = None,
    tool: str | None = None,
    direction: str | None = None,
    provenance: str | None = None,
    blocked: bool = True,
    verdicts: dict[str, Any] | None = None,
    call_ref: str | None = None,
) -> int:
    """Record a detection. Returns the detection ID.

    ``blocked`` was hardcoded 1, which was true when every caller refused
    flagged content. Flag-mode gateway rows are observations, not
    blocks, and recording them as blocks would poison both the blocklist
    semantics and step 7's calibration read.

    ``verdicts`` holds every layer's opinion whichever one is credited:
    ``flagged_by``, ``l2_label``, ``l2_score``, ``l3_verdict`` (``flagged``,
    ``clean`` or ``unavailable``) and ``l3_risk``. A missing key is NULL.

    ``call_ref`` is the reference of the gateway call the content arrived
    on; ``gateway_calls.call_ref`` carries the same one.
    """
    db = get_db()
    now = datetime.now(UTC).isoformat()
    cursor = db.execute(
        "INSERT INTO detections (source_type, source, domain, detected_at, "
        "layer1_stats, qagent_assessment, risk_level, blocked, "
        "profile, backend, tool, direction, provenance, call_ref, "
        # The last five in _VERDICT_COLUMNS order, which the values below are
        # read in; test_database pins the two orders together.
        "flagged_by, l2_label, l2_score, l3_verdict, l3_risk) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source_type,
            source,
            domain,
            now,
            json.dumps(layer1_stats),
            json.dumps(qagent_assessment) if qagent_assessment else None,
            risk_level,
            1 if blocked else 0,
            profile,
            backend,
            tool,
            direction,
            provenance,
            call_ref,
            *((verdicts or {}).get(column) for column, _ in _VERDICT_COLUMNS),
        ),
    )
    db.commit()
    return cursor.lastrowid or 0


def record_capture(
    profile: str,
    source: str,
    content: str,
    verdicts: dict[str, Any],
    call_ref: str | None = None,
) -> None:
    """Keep what a honeypot profile was delivered, with what the layers said of it (#357).

    The only place the gateway stores content a caller chose, and only for a
    profile declared ``honeypot``: reading what got past the layers is what
    such a profile is for. Never logged, and swept with the audit.

    Args:
        profile: The honeypot profile the content was delivered to.
        source: The URL, query or hash the content came from.
        content: The payload the layers were given to judge. For search that
            is the answer with its sources, of which the caller is delivered
            the answer; where the unpack stage decoded something, the layers
            read this decoded.
        verdicts: ``defense.layer_verdicts`` of the verdict; ``flagged_by`` is None when no
            layer flagged it, which is the row a miss is found in.
        call_ref: The delivering call; ``gateway_calls.call_ref`` carries it too.
    """
    db = get_db()
    db.execute(
        "INSERT INTO honeypot_captures (captured_at, profile, call_ref, source, "
        "flagged_by, l2_label, l2_score, l3_verdict, l3_risk, content) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            profile,
            call_ref,
            source,
            *(verdicts.get(column) for column, _ in _VERDICT_COLUMNS),
            content,
        ),
    )
    db.commit()


def get_blocklist_stats(profile: str | None = None) -> dict[str, Any]:
    """Get summary statistics for the live blocklist, optionally for one profile.

    Unfiltered is the gateway-wide view, for operator scope only; every agent
    caller passes its own name (``tools/stats.py``).

    The *profile* filter matters more here than the column suggests. A
    detection's ``source`` is written as ``profile:backend:tool``, so an
    unfiltered ``recent_detections`` hands the reader other agents' names, the
    backends they call and the URLs they fetched. Rows that predate the
    attribution columns have a NULL profile and belong to no one; a filtered
    query correctly leaves them out rather than crediting them to whoever asked.

    Returns:
        ``total_blocked``, ``by_risk_level``, ``recent_detections``, and
        ``profile_filter`` — the profile the numbers are for, or None for the
        whole gateway, so a reader never has to guess which it got.
    """
    db = _read_db()
    # Same idiom as get_gateway_call_stats above: fixed query templates with
    # one optional clause, the value always bound as a parameter.
    # Expired rows are off the blocklist (#263) and are not counted as on it.
    clause = " AND detected_at > ?" + (" AND profile = ?" if profile else "")
    args: tuple[Any, ...] = (_block_cutoff(), profile) if profile else (_block_cutoff(),)

    total_query = "SELECT COUNT(*) as cnt FROM detections WHERE blocked = 1{profile_clause}"
    recent_query = (
        "SELECT source_type, source, domain, detected_at, risk_level "
        "FROM detections WHERE blocked = 1{profile_clause} "
        "ORDER BY detected_at DESC LIMIT 10"
    )
    risk_query = (
        "SELECT risk_level, COUNT(*) as cnt FROM detections "
        "WHERE blocked = 1{profile_clause} GROUP BY risk_level"
    )

    total = db.execute(total_query.format(profile_clause=clause), args).fetchone()
    recent = db.execute(recent_query.format(profile_clause=clause), args).fetchall()
    by_risk = db.execute(risk_query.format(profile_clause=clause), args).fetchall()

    return {
        "total_blocked": total["cnt"] if total else 0,
        "by_risk_level": {row["risk_level"]: row["cnt"] for row in by_risk},
        "recent_detections": [dict(row) for row in recent],
        "profile_filter": profile,
    }


def record_gateway_call(
    profile: str,
    backend: str,
    tool: str,
    outcome: str,
    duration_ms: int,
    error_message: str | None = None,
    bytes_arrived: int | None = None,
    bytes_delivered: int | None = None,
    normalized: dict[str, str] | None = None,
    destination: str | None = None,
    destination_kind: str | None = None,
    session: str | None = None,
    call_ref: str | None = None,
    content_digest: str | None = None,
) -> None:
    """Record a gateway tools/call invocation.

    ``session``, ``call_ref`` and ``content_digest`` are what a reader joins
    on: the calls of one session in ``id`` order, the detections a call
    raised, and the calls that delivered the same result.

    ``destination`` is caller-chosen text (``gateway/destination.py``). It is
    stored here and nowhere else: never logged, never in an error message.

    ``success`` is derived from *outcome* rather than passed in, so the legacy
    boolean can never disagree with the taxonomy. It keeps its original
    meaning — the call returned usable content — which means a fail-closed
    defense block still reads as ``success = 0``, exactly as it did before.
    """
    db = get_db()
    _maybe_sweep(db)
    success = outcome == Outcome.OK.value
    db.execute(
        "INSERT INTO gateway_calls "
        "(timestamp, profile, backend, tool, success, duration_ms, error_message, "
        "outcome, bytes_arrived, bytes_delivered, normalized, "
        "destination, destination_kind, session, call_ref, content_digest) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            profile,
            backend,
            tool,
            success,
            duration_ms,
            error_message,
            outcome,
            bytes_arrived,
            bytes_delivered,
            json.dumps(normalized) if normalized else None,
            destination,
            destination_kind,
            session,
            call_ref,
            content_digest,
        ),
    )
    db.commit()


def reset_gateway_calls() -> int:
    """Delete every audit row. Returns the number removed.

    Deliberately not exposed as an MCP tool: erasing the audit trail is not a
    capability any consumer profile should hold. Operators run it directly.
    """
    db = get_db()
    before = db.execute("SELECT COUNT(*) AS cnt FROM gateway_calls").fetchone()["cnt"]
    db.execute("DELETE FROM gateway_calls")
    db.commit()
    return int(before)


def get_gateway_call_stats(
    profile: str | None = None,
    days: int = 30,
    *,
    trips: bool = True,
) -> dict[str, Any]:
    """Per-backend/per-tool call outcomes for allowlist tuning and health checks.

    Reports ``ok`` / ``blocked`` / ``failed`` as separate columns. A single
    "errors" number cannot be read correctly: it mixes fail-closed defense
    blocks (working as designed) with genuine breakage, which is how a tool
    that blocked 34 hostile pages came to look like a tool that was broken.
    Only ``failed`` is a health signal.

    A NULL outcome means the row predates the taxonomy. It is reported as
    "unknown" rather than guessed at: back-fitting an outcome from the old
    boolean would reintroduce the ambiguity this change removes.

    ``trips`` False leaves decoy trips (#357) out of every count and drops
    the ``tripped`` column: what an agent reading its own numbers is shown.
    A tripwire the caller can read back is one it can be told to avoid.
    """
    db = _read_db()
    cutoff = time.time() - (days * 86400)

    query = (
        "SELECT backend, tool, outcome, COUNT(*) AS cnt FROM gateway_calls "
        "WHERE timestamp > ?{profile_clause} GROUP BY backend, tool, outcome"
    )
    if profile:
        rows = db.execute(
            query.format(profile_clause=" AND profile = ?"), (cutoff, profile)
        ).fetchall()
    else:
        rows = db.execute(query.format(profile_clause=""), (cutoff,)).fetchall()

    every = ("ok", "blocked", "tripped", "failed", "unknown")
    groups = [group for group in every if trips or group != "tripped"]
    per_tool: dict[tuple[str, str], dict[str, Any]] = {}
    totals: dict[str, int] = dict.fromkeys(groups, 0)
    for row in rows:
        key = (row["backend"], row["tool"])
        raw = row["outcome"] or "legacy"
        group = group_of(raw)
        if group == "tripped" and not trips:
            continue
        entry = per_tool.setdefault(
            key,
            {
                "backend": key[0],
                "tool": key[1],
                "calls": 0,
                **dict.fromkeys(groups, 0),
                "outcomes": {},
            },
        )
        count = int(row["cnt"])
        entry["calls"] += count
        entry[group] += count
        entry["outcomes"][raw] = entry["outcomes"].get(raw, 0) + count
        totals[group] += count

    by_tool = sorted(per_tool.values(), key=lambda e: int(e["calls"]), reverse=True)

    return {
        "total_calls": sum(totals.values()),
        "days": days,
        "profile_filter": profile,
        "totals": totals,
        "by_tool": by_tool,
        "delivery": _delivery_stats(db, cutoff, profile),
    }


def _delivery_stats(db: sqlite3.Connection, cutoff: float, profile: str | None) -> dict[str, Any]:
    """Response bytes as they arrived from backends vs. as agents received them.

    Only rows carrying BOTH sizes count. An internal tool minifies inside the
    tool, so the router never saw what arrived; counting its delivered bytes
    against nothing would report a saving that was never measured.
    """
    query = (
        "SELECT backend, tool, COUNT(*) AS cnt, SUM(bytes_arrived) AS arrived, "
        "SUM(bytes_delivered) AS delivered FROM gateway_calls "
        "WHERE timestamp > ? AND bytes_arrived IS NOT NULL "
        "AND bytes_delivered IS NOT NULL{profile_clause} GROUP BY backend, tool"
    )
    if profile:
        rows = db.execute(
            query.format(profile_clause=" AND profile = ?"), (cutoff, profile)
        ).fetchall()
    else:
        rows = db.execute(query.format(profile_clause=""), (cutoff,)).fetchall()

    arrived = sum(int(r["arrived"]) for r in rows)
    delivered = sum(int(r["delivered"]) for r in rows)
    by_saving = sorted(rows, key=lambda r: int(r["arrived"]) - int(r["delivered"]), reverse=True)
    return {
        "calls_measured": sum(int(r["cnt"]) for r in rows),
        "bytes_arrived": arrived,
        "bytes_delivered": delivered,
        "savings_percent": round((1 - delivered / arrived) * 100) if arrived > 0 else 0,
        "estimated_tokens_saved": (arrived - delivered) // 4,
        "top_tools": [
            {
                "backend": r["backend"],
                "tool": r["tool"],
                "calls": int(r["cnt"]),
                "bytes_arrived": int(r["arrived"]),
                "bytes_delivered": int(r["delivered"]),
            }
            for r in by_saving[:10]
        ],
    }


#: The fan-out window: long enough to see a swarm, short enough to page on it.
FANOUT_WINDOW_SECONDS = 600

# Shared, word for word, with contrib/nagios/check_trentina_fanout, which
# cannot import this package; test_destinations pins the two together.
# A fetch destination is "<host>#<hash>" and a hostname never holds '#', so
# the host is everything before the first one. Every attempt counts, a
# denied one included: a swarm probing its allowlist is fanning out too.
FANOUT_QUERY = (
    "SELECT profile, "
    "COUNT(DISTINCT CASE WHEN destination_kind = 'fetch' "
    "THEN substr(destination, 1, instr(destination, '#') - 1) END) AS fetch_hosts, "
    "SUM(CASE WHEN destination_kind = 'param' THEN 1 ELSE 0 END) AS comms_calls "
    "FROM gateway_calls WHERE timestamp > ? AND destination_kind IS NOT NULL "
    "GROUP BY profile ORDER BY profile"
)


def get_fanout(window_seconds: int = FANOUT_WINDOW_SECONDS) -> dict[str, Any]:
    """Per profile, distinct fetch hosts and declared outbound calls in the window.

    Per-call judging cannot see a swarm: each call is fine alone. Twenty agents
    each fetching one new host, or one agent messaging forty channels in ten
    minutes, is visible only as a rate.

    Args:
        window_seconds: How far back to count, from now.

    Returns:
        ``window_seconds``, and ``profiles``: profile name to ``fetch_hosts``
        (distinct hosts fetched) and ``comms_calls`` (calls to tools a
        backend declares in ``destination_params``). A profile with no
        destination-bearing call in the window is absent.
    """
    rows = _read_db().execute(FANOUT_QUERY, (time.time() - window_seconds,)).fetchall()
    return {
        "window_seconds": window_seconds,
        "profiles": {
            row["profile"]: {
                "fetch_hosts": int(row["fetch_hosts"]),
                "comms_calls": int(row["comms_calls"]),
            }
            for row in rows
        },
    }


def has_sent_to(profile: str, destination: str, kind: str) -> bool:
    """Whether *profile* has a completed call to *destination* on record (#456).

    Completed means outcome ``ok``: a refused or failed call reached nobody.
    The audit is swept after ``TRENTINA_AUDIT_RETENTION_DAYS``, so this is
    "within retention", and a destination last used before that is a first
    contact again. One probe on ``idx_gateway_calls_sent_to``.
    """
    row = (
        _read_db()
        .execute(
            "SELECT 1 FROM gateway_calls WHERE profile = ? AND destination = ? "
            "AND destination_kind = ? AND outcome = 'ok' LIMIT 1",
            (profile, destination, kind),
        )
        .fetchone()
    )
    return row is not None


def get_recent_destinations(
    profile: str | None = None,
    limit: int = 20,
    days: int = 30,
) -> dict[str, list[dict[str, Any]]]:
    """The latest *limit* destinations per profile, newest first.

    One bounded read per profile on ``idx_gateway_calls_destination``, so the
    cost is profiles x limit rows, not the month's traffic. A single
    ``ROW_NUMBER()`` query instead ranks every row in the window first.

    Args:
        profile: One profile's rows, or None for every profile's.
        limit: Rows per profile.
        days: How far back to look.

    Returns:
        Profile name to its rows: ``at`` (ISO time), ``backend``, ``tool``,
        ``outcome``, ``kind`` (``fetch``, ``search`` or ``param``) and the
        raw ``destination``. The caller decides who may read the value.
    """
    db = _read_db()
    cutoff = time.time() - days * 86400
    if profile:
        profiles = [profile]
    else:
        profiles = [
            row["profile"]
            for row in db.execute(
                "SELECT DISTINCT profile FROM gateway_calls "
                "WHERE destination IS NOT NULL AND timestamp > ?",
                (cutoff,),
            )
        ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for name in profiles:
        rows = db.execute(
            "SELECT timestamp, backend, tool, outcome, destination, destination_kind "
            "FROM gateway_calls WHERE profile = ? AND destination IS NOT NULL "
            "AND timestamp > ? ORDER BY timestamp DESC, id DESC LIMIT ?",
            (name, cutoff, limit),
        ).fetchall()
        if rows:
            grouped[name] = [
                {
                    "at": datetime.fromtimestamp(r["timestamp"], UTC).isoformat(timespec="seconds"),
                    "backend": r["backend"],
                    "tool": r["tool"],
                    "outcome": r["outcome"],
                    "kind": r["destination_kind"],
                    "destination": r["destination"],
                }
                for r in rows
            ]
    return grouped


def get_all_compressions() -> dict[str, str]:
    """Load all cached compressions as {description_hash: compressed_description}."""
    db = get_db()
    rows = db.execute(
        "SELECT description_hash, compressed_description FROM tool_compressions"
    ).fetchall()
    return {row["description_hash"]: row["compressed_description"] for row in rows}


def save_compression(
    description_hash: str,
    original: str,
    compressed: str,
    model: str,
) -> None:
    """Persist a compressed description to SQLite."""
    db = get_db()
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO tool_compressions "
        "(description_hash, original_description, compressed_description, "
        "model, compressed_at, original_length, compressed_length) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (description_hash, original, compressed, model, now, len(original), len(compressed)),
    )
    db.commit()


def get_compression_stats() -> dict[str, Any]:
    """Aggregate compression savings from the tool_compressions table."""
    db = _read_db()
    row = db.execute(
        "SELECT COUNT(*) as cnt, "
        "COALESCE(SUM(original_length), 0) as orig, "
        "COALESCE(SUM(compressed_length), 0) as comp "
        "FROM tool_compressions"
    ).fetchone()
    total = row["cnt"] if row else 0
    orig = row["orig"] if row else 0
    comp = row["comp"] if row else 0
    savings = round((1 - comp / orig) * 100) if orig > 0 else 0
    return {
        "tools_compressed": total,
        "original_chars": orig,
        "compressed_chars": comp,
        "savings_percent": savings,
        "estimated_tokens_saved": (orig - comp) // 4,
    }


def get_all_tool_lists() -> dict[str, list[dict[str, Any]]]:
    """Load all cached tool lists as {backend_url: tools_list}."""
    db = get_db()
    rows = db.execute("SELECT backend_url, tools_json FROM tool_list_cache").fetchall()
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        result[row["backend_url"]] = json.loads(row["tools_json"])
    return result


def save_tool_list(
    backend_url: str,
    tools: list[dict[str, Any]],
) -> None:
    """Persist a tool list to SQLite."""
    db = get_db()
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO tool_list_cache "
        "(backend_url, tools_json, cached_at) VALUES (?, ?, ?)",
        (backend_url, json.dumps(tools), now),
    )
    db.commit()


def delete_tool_list(backend_url: str) -> None:
    """Delete one backend's cached tool list."""
    db = get_db()
    db.execute(
        "DELETE FROM tool_list_cache WHERE backend_url = ?",
        (backend_url,),
    )
    db.commit()


def delete_all_tool_lists() -> None:
    """Flush all cached tool lists."""
    db = get_db()
    db.execute("DELETE FROM tool_list_cache")
    db.commit()


def issued_tool_names(profile: str) -> dict[str, tuple[str, str]]:
    """Every short tool name issued to a profile: {issued: (backend, tool)}."""
    rows = (
        get_db()
        .execute("SELECT issued, backend, tool FROM tool_names WHERE profile = ?", (profile,))
        .fetchall()
    )
    return {row["issued"]: (row["backend"], row["tool"]) for row in rows}


def issued_tool_name(profile: str, issued: str) -> tuple[str, str] | None:
    """The (backend, tool) one issued name stands for, if it was issued."""
    row = (
        get_db()
        .execute(
            "SELECT backend, tool FROM tool_names WHERE profile = ? AND issued = ?",
            (profile, issued),
        )
        .fetchone()
    )
    return (row["backend"], row["tool"]) if row else None


def issue_tool_names(profile: str, names: dict[str, tuple[str, str]]) -> None:
    """Record newly issued names. An issued name is never reassigned."""
    if not names:
        return
    db = get_db()
    now = datetime.now(UTC).isoformat()
    db.executemany(
        "INSERT OR IGNORE INTO tool_names (profile, issued, backend, tool, issued_at) "
        "VALUES (?, ?, ?, ?, ?)",
        [(profile, issued, backend, tool, now) for issued, (backend, tool) in names.items()],
    )
    db.commit()
