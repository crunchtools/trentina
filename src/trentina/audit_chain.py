"""Hash chain over ``gateway_calls`` (#472): what it proves and how to check it.

Every audit row carries ``prev_hash`` (the previous row's ``row_hash``) and
``row_hash``, the SHA-256 of the RFC 8785 form of its audited fields. A row
altered, removed or moved breaks the link after it. The chain starts at the
newest ``audit_checkpoints`` row: ``genesis`` for rows older than the chain,
``prune`` when the retention sweep deleted a prefix, ``reset`` when an operator
wiped the table. Without an anchor held outside the file, a writer who owns
the database can still rebuild a clean chain; ``docs/audit-log.md`` says so.

This module reads and hashes. Writes happen in ``database.py``, under one
transaction with the row they chain.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from decimal import Decimal
from typing import Any
from urllib.parse import quote

GENESIS = "genesis"

# Order is the order in the digest's input only for readability: RFC 8785
# sorts the keys. A column added here changes every later row_hash, so a new
# audited column needs a version the verifier can tell apart.
CHAIN_FIELDS = (
    "id",
    "timestamp",
    "profile",
    "backend",
    "tool",
    "success",
    "duration_ms",
    "error_message",
    "outcome",
    "bytes_arrived",
    "bytes_delivered",
    "normalized",
    "destination",
    "destination_kind",
    "session",
    "call_ref",
    "content_digest",
    "detections_digest",
    "prev_hash",
)

_MAX_SAFE_INTEGER = 2**53 - 1


def _number(value: float) -> str:
    """An IEEE 754 double as ECMAScript's Number-to-string, as RFC 8785 §3.2.2.3 asks."""
    if not math.isfinite(value):
        raise ValueError("RFC 8785 has no form for NaN or infinity")
    if value == 0:
        return "0"
    parts = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(str(d) for d in parts.digits).rstrip("0")
    n = len(parts.digits) + int(parts.exponent)  # abs(value) = 0.<digits> * 10**n
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if n > 0 else '-'}{abs(n - 1)}"
    return ("-" if value < 0 else "") + body


def _write_array(items: list[Any] | tuple[Any, ...], out: list[str]) -> None:
    out.append("[")
    for index, item in enumerate(items):
        if index:
            out.append(",")
        _write(item, out)
    out.append("]")


def _write_object(members: dict[str, Any], out: list[str]) -> None:
    out.append("{")
    # UTF-16 code unit order, not code point order.
    for index, key in enumerate(sorted(members, key=lambda k: k.encode("utf-16-be"))):
        if index:
            out.append(",")
        out.append(json.dumps(key, ensure_ascii=False) + ":")
        _write(members[key], out)
    out.append("}")


def _write(value: Any, out: list[str]) -> None:
    match value:
        case None:
            out.append("null")
        case bool():
            out.append("true" if value else "false")
        case int():
            if abs(value) > _MAX_SAFE_INTEGER:
                raise ValueError("integer outside the range RFC 8785 can carry")
            out.append(str(value))
        case float():
            out.append(_number(value))
        case str():
            out.append(json.dumps(value, ensure_ascii=False))
        case list() | tuple():
            _write_array(value, out)
        case dict():
            _write_object(value, out)
        case _:
            raise TypeError(f"RFC 8785 cannot serialize {type(value).__name__}")


def canonical(value: Any) -> bytes:
    """The RFC 8785 (JCS) serialization of *value*, as UTF-8.

    Covers what the audit tables hold: null, bool, int, float, str, list and
    dict with string keys.
    """
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def digest(value: Any) -> str:
    """SHA-256 of ``canonical(value)``, hex."""
    return hashlib.sha256(canonical(value)).hexdigest()


def row_hash(row: Any) -> str:
    """The ``row_hash`` of an audit row (or a mapping of its ``CHAIN_FIELDS``)."""
    return digest({name: row[name] for name in CHAIN_FIELDS})


def detections_digest(db: sqlite3.Connection, call_ref: str | None) -> str | None:
    """Digest of the detection rows one call raised, in ``id`` order; None if none.

    Detections live on their own schedule (blocked rows expire at the
    blocklist TTL), so they are not chained themselves; the call row commits
    to them through this value.
    """
    if not call_ref:
        return None
    rows = db.execute("SELECT * FROM detections WHERE call_ref = ? ORDER BY id", (call_ref,))
    listed = [dict(zip((c[0] for c in rows.description), row, strict=True)) for row in rows]
    return digest(listed) if listed else None


def newest_checkpoint(db: sqlite3.Connection) -> Any:
    """The newest checkpoint row, (id, kind, last_id, last_row_hash), or None."""
    return db.execute(
        "SELECT id, kind, last_id, last_row_hash FROM audit_checkpoints ORDER BY id DESC LIMIT 1"
    ).fetchone()


_EXPIRED = "detections_expired"
_GENESIS_SQL = "SELECT MAX(last_id) FROM audit_checkpoints WHERE kind = 'genesis'"
# Built from CHAIN_FIELDS so the select list and the names verify() zips onto
# it cannot drift apart. Every name is a module constant, never input.
_ROWS_COLUMNS = (*CHAIN_FIELDS, "row_hash")
_ROWS_SQL = (
    "SELECT " + ", ".join(_ROWS_COLUMNS) + " FROM gateway_calls WHERE id > ? ORDER BY id"
)


def tail_hash(db: sqlite3.Connection) -> str:
    """What the next row's ``prev_hash`` must be: the newest row's hash, else the checkpoint's."""
    row = db.execute("SELECT row_hash FROM gateway_calls ORDER BY id DESC LIMIT 1").fetchone()
    if row is not None and row[0] is not None:
        return str(row[0])
    checkpoint = newest_checkpoint(db)
    return str(checkpoint[3]) if checkpoint is not None else GENESIS


def verify(
    db: sqlite3.Connection, *, ttl_seconds: float, now: float | None = None
) -> dict[str, Any]:
    """Walk the chain from the newest checkpoint and report the first break.

    Args:
        db: A connection to the audit database.
        ttl_seconds: The blocklist TTL; a call older than this may have lost
            its detection rows legitimately.
        now: Current time, for tests.

    Returns:
        ``ok``, ``checked`` (rows walked), ``first_break`` (None, or the row
        ``id`` and a closed ``reason``), ``detections_expired`` (calls whose
        detection rows are gone past the TTL: noted, not a break) and the
        ``checkpoint`` the walk started from.
    """
    cutoff = (time.time() if now is None else now) - ttl_seconds
    checkpoint = newest_checkpoint(db)
    kind, last_id, expected = (None, 0, GENESIS) if checkpoint is None else checkpoint[1:]
    genesis_last = db.execute(_GENESIS_SQL).fetchone()[0] or 0
    report: dict[str, Any] = {
        "ok": True,
        "checked": 0,
        "first_break": None,
        "detections_expired": 0,
        "checkpoint": {"kind": kind, "last_id": last_id},
    }
    # Rows at or below the genesis checkpoint predate the chain and carry no hash.
    for values in db.execute(_ROWS_SQL, (max(last_id, genesis_last),)):
        row = dict(zip(_ROWS_COLUMNS, values, strict=True))
        report["checked"] += 1
        reason = _break_reason(db, row, expected, expired=row["timestamp"] < cutoff)
        if reason == _EXPIRED:
            report["detections_expired"] += 1
        elif reason is not None:
            report.update(ok=False, first_break={"id": row["id"], "reason": reason})
            break
        expected = row["row_hash"]
    return report


def _break_reason(
    db: sqlite3.Connection, row: dict[str, Any], expected: str, *, expired: bool
) -> str | None:
    """Why *row* does not belong at this point of the chain, ``_EXPIRED`` or None."""
    if row["row_hash"] is None:
        return "unchained"
    if row["prev_hash"] != expected:
        return "prev_hash_mismatch"
    if row_hash(row) != row["row_hash"]:
        return "row_hash_mismatch"
    if row["detections_digest"] is None:
        return None
    if detections_digest(db, row["call_ref"]) == row["detections_digest"]:
        return None
    return _EXPIRED if expired else "detections_mismatch"


def main() -> int:
    """``trentina-audit-verify``: verify the configured database; 0 if the chain holds, 1 if not."""
    from .config import get_config

    config = get_config()
    db = sqlite3.connect(f"file:{quote(config.db_path)}?mode=ro", uri=True)
    try:
        report = verify(db, ttl_seconds=config.blocklist_ttl_days * 86400)
    finally:
        db.close()
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1
