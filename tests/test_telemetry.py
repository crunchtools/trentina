"""Tests for per-call telemetry records and sinks (#556)."""

from __future__ import annotations

import argparse
import http.server
import io
import json
import re
import socket
import sqlite3
import threading
import time
from collections.abc import Iterator
from dataclasses import asdict
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
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
    monkeypatch.setattr(telemetry, "install", lambda fmt, *_a, **_k: seen.append(fmt))

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


class _Collector:
    """A stdlib OTLP/HTTP collector on a free local port that keeps what it gets."""

    def __init__(self, status: int = 200) -> None:
        received: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        self.received = received

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, dict(self.headers), json.loads(body)))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *_a: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _spans(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        span
        for resource in payload["resourceSpans"]
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    ]


def _attributes(span: dict[str, Any]) -> dict[str, Any]:
    return {a["key"]: next(iter(a["value"].values())) for a in span["attributes"]}


def test_otlp_exporter_delivers_every_field_to_a_collector() -> None:
    collector = _Collector()
    trace = telemetry.trace_from_headers(f"00-{_TRACE}-{_PARENT}-01", "run-1")
    record = telemetry.from_row(
        _ROW, telemetry.Detections(layer="L2", risk="high", l3_verdict="flagged"), trace
    )
    exporter = telemetry.OtlpHttpExporter(
        collector.url + "/", {"Authorization": "Basic dTpw"}, version="9.9.9", flush_seconds=0.05
    )  # loopback: credentials over http stay on the host
    try:
        exporter(record)
        exporter.stop()
    finally:
        collector.close()
    [(path, headers, payload)] = collector.received
    assert path == "/v1/traces"
    assert headers["Authorization"] == "Basic dTpw"
    assert headers["Content-Type"] == "application/json"
    [span] = _spans(payload)
    assert (span["traceId"], span["parentSpanId"]) == (_TRACE, _PARENT)
    assert span["spanId"] == record.span_id
    assert span["name"] == "github create_issue"
    assert int(span["endTimeUnixNano"]) - int(span["startTimeUnixNano"]) == 12_000_000
    assert span["status"] == {"code": 2}
    attributes = _attributes(span)
    assert attributes == {
        "trentina.profile": "kagetora",
        "trentina.backend": "github",
        "gen_ai.tool.name": "create_issue",
        "trentina.outcome": "denied_guard",
        "trentina.success": False,
        "trentina.duration_ms": "12",
        "trentina.bytes_arrived": "100",
        "trentina.bytes_delivered": "0",
        "trentina.destination_kind": "tool",
        "trentina.mcp_session": "sess123",
        "trentina.call_ref": "ref456",
        "trentina.detections_digest": "sha256:abcd",
        "trentina.layer": "L2",
        "trentina.risk": "high",
        "trentina.l3_verdict": "flagged",
        "session.id": telemetry.fingerprint("run-1"),
    }
    resource = _attributes(payload["resourceSpans"][0]["resource"])
    assert resource == {"service.name": "trentina", "service.version": "9.9.9"}
    assert exporter.sent == 1
    assert (exporter.dropped, exporter.failed) == (0, 0)
    assert _CANARY not in json.dumps(payload), "no caller-chosen string is exported (#262)"


def test_otlp_exporter_batches_and_marks_ok_calls() -> None:
    collector = _Collector()
    exporter = telemetry.OtlpHttpExporter(collector.url, flush_seconds=0.2)
    ok = telemetry.from_row({**_ROW, "outcome": "ok", "success": 1})
    try:
        for _ in range(3):
            exporter(ok)
        exporter.stop()
    finally:
        collector.close()
    spans = [span for _, _, payload in collector.received for span in _spans(payload)]
    assert len(spans) == 3
    assert len(collector.received) == 1, "records queued together go in one request"
    assert all(span["status"] == {"code": 1} and "parentSpanId" not in span for span in spans)


def test_otlp_exporter_counts_a_refused_batch() -> None:
    collector = _Collector(status=401)
    exporter = telemetry.OtlpHttpExporter(collector.url, flush_seconds=0.05)
    try:
        exporter(telemetry.from_row(_ROW))
        exporter.stop()
    finally:
        collector.close()
    assert (exporter.sent, exporter.failed) == (0, 1)
    assert exporter.last_failure == "http_401"


def test_a_dead_collector_costs_records_not_latency() -> None:
    """Nothing listens on the port: the call path never waits on it, and what
    could not be sent or queued is counted."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{probe.getsockname()[1]}"
    exporter = telemetry.OtlpHttpExporter(dead, maxsize=10, flush_seconds=0.05)
    record = telemetry.from_row(_ROW)
    started = time.perf_counter()
    for _ in range(1000):
        exporter(record)
    elapsed = time.perf_counter() - started
    exporter.stop()
    assert elapsed < 0.5, f"1000 emits took {elapsed:.3f}s against a dead collector"
    assert exporter.dropped > 0
    assert exporter.sent == 0
    assert exporter.dropped + exporter.failed == 1000
    assert exporter.last_failure == "unreachable"


def test_otlp_exporter_refuses_a_non_http_endpoint() -> None:
    with pytest.raises(ValueError, match="http"):
        telemetry.OtlpHttpExporter("file:///etc/passwd")


def test_install_registers_the_exporter_only_with_an_endpoint() -> None:
    telemetry.install("text", None)
    assert telemetry._SINKS == []
    assert telemetry.counters() is None
    telemetry.install("json", "http://127.0.0.1:9", {"a": "b"}, version="1")
    kinds = {type(sink) for sink in telemetry._SINKS}
    assert kinds == {telemetry.JsonLineWriter, telemetry.OtlpHttpExporter}
    assert telemetry.counters() == {"sent": 0, "dropped": 0, "failed": 0, "last_failure": None}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, {}),
        ("", {}),
        ("Authorization=Basic%20dTpw", {"Authorization": "Basic dTpw"}),
        (" a = 1 ,b=x=y,novalue,=orphan", {"a": "1", "b": "x=y"}),
    ],
)
def test_parse_headers(raw: str | None, expected: dict[str, str]) -> None:
    assert telemetry.parse_headers(raw) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("http://otlp:4318", "http://otlp:4318"),
        (" https://c.example ", "https://c.example"),
        ("otlp:4318", None),
        ("file:///etc/passwd", None),
    ],
)
def test_config_otlp_endpoint(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: str | None
) -> None:
    from trentina import config as config_mod

    config_mod._config = None
    if value is None:
        monkeypatch.delenv("TRENTINA_OTLP_ENDPOINT", raising=False)
    else:
        monkeypatch.setenv("TRENTINA_OTLP_ENDPOINT", value)
    try:
        assert config_mod.get_config().otlp_endpoint == expected
    finally:
        config_mod._config = None


def test_config_otlp_headers_are_held_from_the_log(monkeypatch: pytest.MonkeyPatch) -> None:
    from trentina import config as config_mod
    from trentina import logsafe

    held = "Basic czNjcjN0LW90bHAtdG9rZW4="
    config_mod._config = None
    monkeypatch.setenv("TRENTINA_OTLP_HEADERS", f"Authorization={held}")
    try:
        assert config_mod.get_config().otlp_headers == {"Authorization": held}
        assert held not in logsafe.scrub(f"collector said {held}")
    finally:
        config_mod._config = None


@pytest.mark.parametrize(
    ("endpoint", "headers", "plaintext"),
    [
        ("http://otlp:4318", {"Authorization": "x"}, True),
        ("http://otlp:4318", {}, False),
        ("https://otlp:4318", {"Authorization": "x"}, False),
        ("http://127.0.0.1:4318", {"Authorization": "x"}, False),
        ("http://localhost:4318", {"Authorization": "x"}, False),
        ("http://[::1]:4318", {"Authorization": "x"}, False),
    ],
)
def test_plaintext_credentials(endpoint: str, headers: dict[str, str], plaintext: bool) -> None:
    assert telemetry.plaintext_credentials(endpoint, headers) is plaintext


def test_otlp_exporter_refuses_plaintext_credentials_unless_insecure() -> None:
    with pytest.raises(ValueError, match="plain http"):
        telemetry.OtlpHttpExporter("http://otlp:4318", {"Authorization": "x"})
    exporter = telemetry.OtlpHttpExporter("http://otlp:4318", {"Authorization": "x"}, insecure=True)
    exporter.stop()


@pytest.mark.parametrize(
    ("insecure", "expected"),
    [(None, None), ("false", None), ("true", "http://otlp:4318"), ("1", "http://otlp:4318")],
)
def test_config_withholds_plaintext_credentials(
    monkeypatch: pytest.MonkeyPatch, insecure: str | None, expected: str | None
) -> None:
    from trentina import config as config_mod

    config_mod._config = None
    monkeypatch.setenv("TRENTINA_OTLP_ENDPOINT", "http://otlp:4318")
    monkeypatch.setenv("TRENTINA_OTLP_HEADERS", "Authorization=Basic%20abc")
    if insecure is None:
        monkeypatch.delenv("TRENTINA_OTLP_INSECURE", raising=False)
    else:
        monkeypatch.setenv("TRENTINA_OTLP_INSECURE", insecure)
    try:
        assert config_mod.get_config().otlp_endpoint == expected
    finally:
        config_mod._config = None


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (
            httpx.HTTPStatusError("x", request=MagicMock(), response=MagicMock(status_code=503)),
            "http_503",
        ),
        (httpx.ReadTimeout("x"), "timeout"),
        (httpx.ConnectError("x"), "unreachable"),
        (RuntimeError("x"), "error"),
    ],
)
def test_failure_kind_is_a_closed_set(exc: Exception, kind: str) -> None:
    assert telemetry._failure_kind(exc) == kind


def test_a_failed_detection_read_gives_an_empty_summary(caplog: pytest.LogCaptureFixture) -> None:
    """A database whose detections cannot be read (here: no such table) gives
    an empty summary and a warning, so the record still goes out without it."""
    empty = sqlite3.connect(":memory:")
    try:
        assert database._call_detections(empty, "ref1") == telemetry.Detections()
    finally:
        empty.close()
    assert "detection summary unavailable" in caplog.text
