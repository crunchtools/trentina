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

What is here is a cache and only a cache. Losing this file costs one slow
restart and nothing else.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .config import get_config

logger = logging.getLogger(__name__)

_db: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdict_cache (
    cache_key TEXT PRIMARY KEY,
    warning_json TEXT,
    perimeter_version TEXT NOT NULL,
    cached_at TEXT NOT NULL
);
"""

PERIMETER_VERSION = "19"
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
"13" (1.3.0): the structured pre-processor's markers lose their bracketed
tag, which L2 read as an injected note (#411), so a listing it reduced is
judged as different text.
"14" (1.4.0): the structured pre-processor hands a log held in a JSON string to
petit (#419), so a journal response is judged as its samples and a summary.
"15" (1.4.1): a structured listing gives its rows before its note, and the
unpack stage reads a run of decimal digits as a number, not as hex (#431).
"16" (1.5.0): the default judge is gemini-3.5-flash-lite (#397).

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


def get_perimeter_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the perimeter store's connection."""
    global _db
    if _db is None:
        config = get_config()
        path = db_path or config.perimeter_db_path
        config.ensure_perimeter_db_dir()
        _db = sqlite3.connect(path)
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.executescript(SCHEMA)
    return _db


def get_all_verdicts(perimeter_version: str) -> dict[str, dict[str, Any] | None]:
    """Load the verdicts this perimeter version reached.

    Rows from any other version are deleted rather than returned: a verdict
    is only meaningful for the detector set that produced it.
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
