"""Per-call telemetry records and their sinks (#556).

A ``CallRecord`` is the server-controlled metadata of one gateway call. It
carries NO caller-chosen string (the #262 rule): not the destination, not an
error message, not an argument value — only fields the gateway itself sets
(the profile and backend from its own config, the resolved tool, the outcome
taxonomy, byte counts, the session and call fingerprints, the detections
digest). It is emitted from ``database.record_gateway_call`` once per call and
fanned out to the registered sinks: the one-line-per-call JSON stream today
(``TRENTINA_LOG_FORMAT=json``), an OTLP exporter later. Emission never raises
into the call path — a sink that fails is swallowed.

This module is intentionally zero-dependency (stdlib only, like ``logsafe``),
so ``database`` can import it without a cycle.
"""

from __future__ import annotations

import contextlib
import json
import queue
import sys
import threading
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
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


def from_row(row: dict[str, Any]) -> CallRecord:
    """Build a record from a ``gateway_calls`` row, taking only its safe fields."""
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
    )


_SINKS: list[Callable[[CallRecord], None]] = []


def register_sink(sink: Callable[[CallRecord], None]) -> None:
    """Add a sink that every later ``emit`` fans out to."""
    _SINKS.append(sink)


def reset_sinks() -> None:
    """Drop every sink (startup re-wiring, and test isolation)."""
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


class JsonLineWriter:
    """A non-blocking one-JSON-object-per-call stderr stream (#556).

    Calling the writer is a sink: it enqueues without blocking, so a stalled or
    backpressured stderr can never stall a gateway call; a full queue drops the
    record and counts it on ``dropped``. A daemon thread drains the queue to the
    stream, one JSON line per record, for a structured-log collector (journald
    -> the lotor syslog collector) to pick up.
    """

    def __init__(self, stream: TextIO | None = None, maxsize: int = TELEMETRY_QUEUE_MAX) -> None:
        self._queue: queue.Queue[str] = queue.Queue(maxsize=maxsize)
        self._stream: TextIO = sys.stderr if stream is None else stream
        self.dropped = 0
        threading.Thread(target=self._drain, name="trentina-telemetry", daemon=True).start()

    def __call__(self, record: CallRecord) -> None:
        try:
            self._queue.put_nowait(_json_line(record))
        except queue.Full:
            self.dropped += 1

    def _drain(self) -> None:
        while True:
            line = self._queue.get()
            # A broken stream must not kill the drain thread or block the queue.
            with contextlib.suppress(Exception):
                self._stream.write(line + "\n")
                self._stream.flush()
            self._queue.task_done()


def install(log_format: str) -> None:
    """Register the sinks a ``TRENTINA_LOG_FORMAT`` asks for. ``json`` adds the
    non-blocking one-line-per-call stderr stream; ``text`` adds none. Replaces
    any prior set."""
    reset_sinks()
    if log_format == "json":
        register_sink(JsonLineWriter())
