"""Tests for per-call telemetry records and sinks (#556)."""

from __future__ import annotations

import io
import json
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict
from unittest.mock import patch

import pytest

from trentina import database, telemetry


@pytest.fixture(autouse=True)
def _clean_sinks() -> Iterator[None]:
    telemetry.reset_sinks()
    yield
    telemetry.reset_sinks()


def _fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(database.SCHEMA)
    return conn


_CANARY = "zqx7-caller-chosen"

_ROW = {
    "timestamp": 1700000000.0,
    "profile": "kagetora",
    "backend": "github",
    "tool": "create_issue",
    "success": 0,
    "duration_ms": 12,
    "outcome": "denied_guard",
    "bytes_arrived": 100,
    "bytes_delivered": 0,
    # Caller-chosen fields that must NEVER reach a CallRecord (#262):
    "destination": f"https://evil.example/{_CANARY}",
    "error_message": f"boom {_CANARY}",
    "normalized": json.dumps({"q": _CANARY}),
    "destination_kind": "tool",
    "session": "sess123",
    "call_ref": "ref456",
    "detections_digest": "sha256:abcd",
}


def test_from_row_takes_only_safe_fields() -> None:
    record = telemetry.from_row(_ROW)
    assert record.profile == "kagetora"
    assert record.tool == "create_issue"
    assert record.outcome == "denied_guard"
    assert record.success is False
    assert record.bytes_delivered == 0
    assert record.session == "sess123"
    # The caller-chosen fields are absent by construction.
    assert not hasattr(record, "destination")
    assert not hasattr(record, "error_message")
    assert _CANARY not in json.dumps(asdict(record))


def test_emit_fans_out_and_swallows_a_failing_sink() -> None:
    seen: list[telemetry.CallRecord] = []

    def boom(_record: telemetry.CallRecord) -> None:
        raise RuntimeError("sink boom")

    telemetry.register_sink(boom)
    telemetry.register_sink(seen.append)
    telemetry.emit(telemetry.from_row(_ROW))
    assert len(seen) == 1, "a raising sink must not stop the others or the call"


def test_install_registers_the_json_writer_only_for_json() -> None:
    telemetry.install("text")
    telemetry.emit(telemetry.from_row(_ROW))  # no sink, no output, no error
    assert telemetry._SINKS == []
    telemetry.install("json")
    assert len(telemetry._SINKS) == 1
    assert isinstance(telemetry._SINKS[0], telemetry.JsonLineWriter)


def test_json_writer_is_non_blocking_and_drops_when_full() -> None:
    writer = telemetry.JsonLineWriter(stream=io.StringIO(), maxsize=2)
    record = telemetry.from_row(_ROW)
    # Fill and overflow the queue faster than the drain thread; put never blocks.
    for _ in range(50):
        writer(record)
    writer._queue.join()
    assert writer.dropped > 0, "an overflowing queue must drop, not block the caller"
    assert writer._stream.getvalue().count("\n") >= 1


def test_json_writer_line_is_parseable_without_caller_strings() -> None:
    stream = io.StringIO()
    writer = telemetry.JsonLineWriter(stream=stream)
    writer(telemetry.from_row(_ROW))
    writer._queue.join()
    line = stream.getvalue().strip()
    parsed = json.loads(line)
    assert parsed["profile"] == "kagetora"
    assert parsed["outcome"] == "denied_guard"
    assert _CANARY not in line


def test_record_gateway_call_emits_a_record() -> None:
    conn = _fresh_db()
    seen: list[telemetry.CallRecord] = []
    telemetry.register_sink(seen.append)
    with (
        patch.object(database, "_db", conn),
        patch.object(database, "get_db", return_value=conn),
    ):
        database.record_gateway_call(
            profile="kagetora",
            backend="github",
            tool="create_issue",
            outcome="denied_guard",
            duration_ms=12,
            error_message=f"boom {_CANARY}",
            destination=f"https://evil.example/{_CANARY}",
            destination_kind="tool",
            session="sess123",
            call_ref="ref456",
        )
    assert len(seen) == 1
    assert seen[0].tool == "create_issue"
    assert seen[0].outcome == "denied_guard"
    blob = json.dumps(asdict(seen[0]))
    assert _CANARY not in blob, "no caller-chosen string reaches the record (#262)"
