"""Tests for per-call telemetry records and sinks (#556)."""

from __future__ import annotations

import argparse
import io
import json
import re
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
    writer.stop()


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
    writer.stop()


def test_stop_ends_the_writer_thread() -> None:
    writer = telemetry.JsonLineWriter(stream=io.StringIO())
    assert writer._thread.is_alive()
    writer.stop()
    assert not writer._thread.is_alive(), "stop() must end the drain thread (no leak)"


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


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "text"), ("json", "json"), ("JSON", "json"), ("TEXT", "text"), ("bogus", "text")],
)
def test_config_log_format(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: str
) -> None:
    from trentina import config as config_mod

    config_mod._config = None
    if value is None:
        monkeypatch.delenv("TRENTINA_LOG_FORMAT", raising=False)
    else:
        monkeypatch.setenv("TRENTINA_LOG_FORMAT", value)
    try:
        assert config_mod.get_config().log_format == expected
    finally:
        config_mod._config = None


def test_main_installs_telemetry_from_the_configured_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The entry point hands the configured log format to telemetry.install
    before it parses args, so JSON records turn on from startup, not only when
    install() is called directly."""
    import trentina
    from trentina import config as config_mod

    seen: list[str] = []
    monkeypatch.setattr(telemetry, "install", seen.append)

    def _exit(_self: argparse.ArgumentParser, *_a: object, **_k: object) -> None:
        raise SystemExit(0)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", _exit)
    monkeypatch.setenv("TRENTINA_LOG_FORMAT", "json")
    config_mod._config = None
    try:
        with pytest.raises(SystemExit):
            trentina.main()
        assert seen == ["json"]
    finally:
        config_mod._config = None


def test_summarize_detections_keeps_closed_sets_only() -> None:
    rows = [
        (None, "medium", "clean"),
        ("L2", "high", None),
        ("L3", "low", "flagged"),
        (f"L9{_CANARY}", f"x{_CANARY}", f"y{_CANARY}"),
    ]
    summary = telemetry.summarize_detections(rows)
    assert summary == telemetry.Detections(layer="L2", risk="high", l3_verdict="flagged")
    assert telemetry.summarize_detections([]) == telemetry.Detections()


def test_record_gateway_call_carries_the_detection_summary() -> None:
    conn = _fresh_db()
    seen: list[telemetry.CallRecord] = []
    telemetry.register_sink(seen.append)
    with (
        patch.object(database, "_db", conn),
        patch.object(database, "get_db", return_value=conn),
    ):
        database.record_detection(
            source_type="tool",
            source="s",
            domain=None,
            layer1_stats={},
            risk_level="critical",
            verdicts={"flagged_by": "L1", "l3_verdict": "flagged"},
            call_ref="ref789",
        )
        database.record_gateway_call(
            profile="kagetora",
            backend="github",
            tool="get_issue",
            outcome="blocked_defense",
            duration_ms=3,
            call_ref="ref789",
        )
    assert (seen[0].layer, seen[0].risk, seen[0].l3_verdict) == ("L1", "critical", "flagged")


def test_record_gateway_call_skips_the_record_without_sinks() -> None:
    with patch.object(telemetry, "from_row") as built:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            database.record_gateway_call(
                profile="p", backend="b", tool="t", outcome="ok", duration_ms=1
            )
    built.assert_not_called()


_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
_PARENT = "00f067aa0ba902b7"


@pytest.mark.parametrize(
    ("header", "kept"),
    [
        (f"00-{_TRACE}-{_PARENT}-01", True),
        (f" 00-{_TRACE}-{_PARENT}-00 ", True),
        (f"01-{_TRACE}-{_PARENT}-01", False),
        (f"00-{_TRACE.upper()}-{_PARENT}-01", False),
        (f"00-{'0' * 32}-{_PARENT}-01", False),
        (f"00-{_TRACE}-{'0' * 16}-01", False),
        (f"00-{_TRACE}-{_PARENT}-01-{_CANARY}", False),
        (_CANARY, False),
        (None, False),
    ],
)
def test_trace_from_headers_keeps_only_a_valid_traceparent(header: str | None, kept: bool) -> None:
    trace = telemetry.trace_from_headers(header, None)
    assert re.fullmatch(r"[0-9a-f]{32}", trace.trace_id)
    if kept:
        assert (trace.trace_id, trace.parent_span_id) == (_TRACE, _PARENT)
    else:
        assert trace.trace_id != _TRACE
        assert trace.parent_span_id is None


def test_trace_from_headers_fingerprints_the_session() -> None:
    trace = telemetry.trace_from_headers(None, f"run-{_CANARY}")
    assert trace.agent_session == telemetry.fingerprint(f"run-{_CANARY}")
    assert _CANARY not in json.dumps(asdict(trace))
    assert telemetry.trace_from_headers(None, "x" * 257).agent_session is None


def test_from_row_nests_under_the_current_trace() -> None:
    trace = telemetry.trace_from_headers(f"00-{_TRACE}-{_PARENT}-01", "run-1")
    record = telemetry.from_row(_ROW, trace=trace)
    assert (record.trace_id, record.parent_span_id) == (_TRACE, _PARENT)
    assert record.agent_session == telemetry.fingerprint("run-1")
    assert re.fullmatch(r"[0-9a-f]{16}", record.span_id or "")
    orphan = telemetry.from_row(_ROW)
    assert orphan.trace_id != _TRACE and orphan.parent_span_id is None
