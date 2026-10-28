"""``trentina.testing`` — the public conformance surface for plugin authors.

Part of the public API (with ``trentina.transforms.base`` and
``trentina.transports.base``). An author points their agent at these three
names, generates a plugin, and runs ``conformance`` / ``run_transform`` against
it before shipping. The gateway runs the load-bearing ``scan_imports`` half at
startup, so a plugin that violates the contract is refused by name at load.
"""

from __future__ import annotations

from .hygiene import LogCapture, capture_logs, leaked, rendered
from .suite import Conformance, conformance, run_transform, scan_imports

__all__ = [
    "Conformance",
    "LogCapture",
    "capture_logs",
    "conformance",
    "leaked",
    "rendered",
    "run_transform",
    "scan_imports",
]
