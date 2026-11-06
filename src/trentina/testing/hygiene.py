"""Capture every log record under the production filters — the log-hygiene
canary, shared by ``tests/test_log_hygiene.py`` and the plugin conformance suite.

The rule (#262) is that no caller-chosen string reaches a log. A plugin is a
caller too: it must not log the payload it was handed. ``capture_logs`` installs
the same filters/clamps production runs under and collects every record, so a
canary that reaches the log is visible to both the test suite and the loader's
startup conformance check.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from .. import logsafe

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Loggers that do not propagate to the root, so they are watched directly.
_DETACHED = ("fastmcp",)


class LogCapture(logging.Handler):
    """Collects every record it is handed, for inspection after the run."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def rendered(record: logging.LogRecord) -> str:
    """The record's full text: message, exception, exc_text and stack — every
    place a caller-chosen string could have landed."""
    fmt = logging.Formatter()
    parts = [record.getMessage()]
    if record.exc_info:
        parts.append(fmt.formatException(record.exc_info))
    if record.exc_text:
        parts.append(record.exc_text)
    if record.stack_info:
        parts.append(fmt.formatStack(record.stack_info))
    return "\n".join(parts)


def leaked(handler: LogCapture, needle: str) -> list[str]:
    """Every captured record whose rendered text contains ``needle`` — the
    canary strings that should never have been logged."""
    return [
        f"{r.name}:{r.levelname}: {rendered(r)[:300]}"
        for r in handler.records
        if needle in rendered(r)
    ]


@contextlib.contextmanager
def capture_logs() -> Iterator[LogCapture]:
    """Watch every log at DEBUG with the production filters and clamps installed,
    restoring levels on exit. Yields the handler for the caller to inspect."""
    watched = ["", "httpx", "httpcore", "mcp", "uvicorn.access", *_DETACHED]
    saved = {name: logging.getLogger(name).level for name in watched}
    handler = LogCapture()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    logsafe.install(logging.DEBUG)
    root.addHandler(handler)
    for name in _DETACHED:
        logging.getLogger(name).addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        for name in _DETACHED:
            logging.getLogger(name).removeHandler(handler)
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)
