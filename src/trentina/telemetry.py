"""Per-call telemetry records and their sinks (#556).

A ``CallRecord`` is the server-controlled metadata of one gateway call. It
carries NO caller-chosen string (the #262 rule): not the destination, not an
error message, not an argument value — only fields the gateway itself sets
(the profile and backend from its own config, the resolved tool, the outcome
taxonomy, byte counts, the session and call fingerprints, the detections
digest, the detection layer and risk from closed sets, and the trace IDs). It
is emitted from ``database.record_gateway_call`` once per call and fanned out
to the registered sinks: the one-line-per-call JSON stream
(``TRENTINA_LOG_FORMAT=json``) and the OTLP exporter
(``TRENTINA_OTLP_ENDPOINT``). Emission never raises into the call path — a
sink that fails is swallowed.

The trace a call belongs to is ``current_trace``, set by the gateway from the
agent's W3C ``traceparent`` and ``x-session-id`` headers. Both are caller
text, so only a strictly valid ``traceparent`` is kept and the session id is
kept as a fingerprint, never raw.

This module is intentionally zero-dependency (stdlib only, like ``logsafe``),
so ``database`` can import it without a cycle.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import queue
import re
import sys
import threading
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import TextIO


@dataclass(frozen=True, slots=True)
class CallRecord:
    """The metadata of one gateway call, safe to export (#262).

    Deliberately excludes ``destination`` (caller-chosen text),
    ``error_message`` and the normalized arguments: those are the row's
    caller-controlled fields and stay in the audit DB, never in telemetry.
    """

    timestamp: float
    profile: str
    backend: str
    tool: str
    outcome: str
    success: bool
    duration_ms: int
    bytes_arrived: int | None
    bytes_delivered: int | None
    destination_kind: str | None
    session: str | None
    call_ref: str | None
    detections_digest: str | None
    layer: str | None = None
    risk: str | None = None
    l3_verdict: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    agent_session: str | None = None


_LAYERS = frozenset({"L1", "L2", "L3"})
_RISKS = ("low", "medium", "high", "critical")
_L3_VERDICTS = frozenset({"flagged", "clean", "unavailable"})


@dataclass(frozen=True, slots=True)
class Detections:
    """What a call's detection rows say, reduced to closed sets: the layer
    credited first, the highest risk, and the L3 verdict ("flagged" wins)."""

    layer: str | None = None
    risk: str | None = None
    l3_verdict: str | None = None


def summarize_detections(rows: list[tuple[Any, Any, Any]]) -> Detections:
    """Reduce ``(flagged_by, risk_level, l3_verdict)`` rows, in id order. A
    value outside its closed set is dropped rather than exported."""
    layer = next((r[0] for r in rows if r[0] in _LAYERS), None)
    risks = [_RISKS.index(r[1]) for r in rows if r[1] in _RISKS]
    verdicts = {r[2] for r in rows if r[2] in _L3_VERDICTS}
    verdict = next((v for v in ("flagged", "clean", "unavailable") if v in verdicts), None)
    return Detections(layer=layer, risk=_RISKS[max(risks)] if risks else None, l3_verdict=verdict)


@dataclass(frozen=True, slots=True)
class TraceContext:
    """The trace a call belongs to: a W3C trace id, the agent's span to nest
    under (if it sent one), and the fingerprint of its ``x-session-id``."""

    trace_id: str
    parent_span_id: str | None = None
    agent_session: str | None = None


current_trace: contextvars.ContextVar[TraceContext | None] = contextvars.ContextVar(
    "current_trace", default=None
)

_TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}")
_SESSION_MAX = 256


def new_id(nbytes: int) -> str:
    """A random lowercase-hex id of ``nbytes`` bytes (16 for a trace, 8 for a span)."""
    return os.urandom(nbytes).hex()


def fingerprint(value: str) -> str:
    """The exportable stand-in for a caller-chosen id (#262)."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def trace_from_headers(traceparent: str | None, session_id: str | None) -> TraceContext:
    """The trace for one inbound request. A ``traceparent`` that is not exactly
    version 00 with non-zero ids is ignored and a fresh trace started; an
    ``x-session-id`` is kept only as its fingerprint, and only if it is short."""
    trace_id, parent = new_id(16), None
    match = _TRACEPARENT.fullmatch(traceparent.strip()) if traceparent else None
    if match and match[1] != "0" * 32 and match[2] != "0" * 16:
        trace_id, parent = match[1], match[2]
    session = fingerprint(session_id) if session_id and len(session_id) <= _SESSION_MAX else None
    return TraceContext(trace_id=trace_id, parent_span_id=parent, agent_session=session)


TRACEPARENT_HEADER = "traceparent"
SESSION_HEADER = "x-session-id"


def trace_from_request(headers: Mapping[str, str]) -> TraceContext:
    """``trace_from_headers`` over a request's headers."""
    return trace_from_headers(headers.get(TRACEPARENT_HEADER), headers.get(SESSION_HEADER))


def from_row(
    row: dict[str, Any],
    detections: Detections | None = None,
    trace: TraceContext | None = None,
) -> CallRecord:
    """Build a record from a ``gateway_calls`` row, taking only its safe
    fields, plus the call's detection summary and the trace it ran in. A call
    outside any trace (a bridge, a startup refresh) gets a trace of its own."""
    detections = detections or Detections()
    trace = trace or TraceContext(trace_id=new_id(16))
    return CallRecord(
        timestamp=row["timestamp"],
        profile=row["profile"],
        backend=row["backend"],
        tool=row["tool"],
        outcome=row["outcome"],
        success=bool(row["success"]),
        duration_ms=row["duration_ms"],
        bytes_arrived=row["bytes_arrived"],
        bytes_delivered=row["bytes_delivered"],
        destination_kind=row["destination_kind"],
        session=row["session"],
        call_ref=row["call_ref"],
        detections_digest=row["detections_digest"],
        layer=detections.layer,
        risk=detections.risk,
        l3_verdict=detections.l3_verdict,
        trace_id=trace.trace_id,
        span_id=new_id(8),
        parent_span_id=trace.parent_span_id,
        agent_session=trace.agent_session,
    )


_SINKS: list[Callable[[CallRecord], None]] = []


def register_sink(sink: Callable[[CallRecord], None]) -> None:
    """Add a sink that every later ``emit`` fans out to."""
    _SINKS.append(sink)


def has_sinks() -> bool:
    """Whether any sink is registered, so a caller can skip building a record."""
    return bool(_SINKS)


def reset_sinks() -> None:
    """Drop every sink (startup re-wiring, and test isolation), stopping any
    writer's drain thread first so a re-install does not leak one."""
    for sink in _SINKS:
        if isinstance(sink, JsonLineWriter):
            sink.stop()
    _SINKS.clear()


def emit(record: CallRecord) -> None:
    """Fan a record out to every sink. A sink that raises is swallowed, so a
    call is never failed by its own telemetry."""
    for sink in _SINKS:
        # Swallow a sink's failure: telemetry must never break a call.
        with contextlib.suppress(Exception):
            sink(record)


TELEMETRY_QUEUE_MAX = 10_000
"""Call records the JSON writer buffers before it drops. A stalled collector
loses records (counted on ``dropped``) rather than blocking a gateway call."""


def _json_line(record: CallRecord) -> str:
    return json.dumps(asdict(record), separators=(",", ":"))


_STOP = object()
"""Sentinel put on a writer's queue to end its drain thread."""


class JsonLineWriter:
    """A non-blocking one-JSON-object-per-call stderr stream (#556).

    Calling the writer is a sink: it enqueues without blocking, so a stalled or
    backpressured stderr can never stall a gateway call; a full queue drops the
    record and counts it on ``dropped``. A daemon thread drains the queue to the
    stream, one JSON line per record, for a structured-log collector (journald
    -> a syslog collector) to pick up.
    """

    def __init__(self, stream: TextIO | None = None, maxsize: int = TELEMETRY_QUEUE_MAX) -> None:
        self._queue: queue.Queue[object] = queue.Queue(maxsize=maxsize)
        self._stream: TextIO = sys.stderr if stream is None else stream
        self.dropped = 0
        self._thread = threading.Thread(target=self._drain, name="trentina-telemetry", daemon=True)
        self._thread.start()

    def __call__(self, record: CallRecord) -> None:
        try:
            self._queue.put_nowait(_json_line(record))
        except queue.Full:
            self.dropped += 1

    def stop(self) -> None:
        """End the drain thread, so resetting sinks does not leak one."""
        self._queue.put(_STOP)
        self._thread.join(timeout=2)

    def _drain(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            # A broken stream must not kill the drain thread or block the queue.
            with contextlib.suppress(Exception):
                self._stream.write(f"{item}\n")
                self._stream.flush()
            self._queue.task_done()


def install(log_format: str) -> None:
    """Register the sinks a ``TRENTINA_LOG_FORMAT`` asks for. ``json`` adds the
    non-blocking one-line-per-call stderr stream; ``text`` adds none. Replaces
    any prior set."""
    reset_sinks()
    if log_format == "json":
        register_sink(JsonLineWriter())
