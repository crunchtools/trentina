"""Shared Face/Carrier recording doubles for transport-layer tests.

Lifted from ``test_orchestrator.py`` (P7.5) so the orchestrator's crossing
tests and the transport registry's conformance tests drive the same minimal
transport — a transport whose only job is to record the handoffs the crossing
makes, so a test can assert parse → carry → deliver → wrap ran in order with
each step's output fed to the next.
"""

from __future__ import annotations

from typing import Any

from trentina.transports.base import Carrier, Face


class RecordingFace(Face):
    name = "test_face"

    def __init__(self, *, parse_result: Any) -> None:
        self._parse_result = parse_result
        self.delivered: Any = None
        self.wrapped: Any = None

    async def parse(self, ctx: Any) -> Any:
        return self._parse_result

    async def deliver(self, ctx: Any, parsed: Any, carried: Any) -> Any:
        self.delivered = (parsed, carried)
        return {"delivered": carried}

    def wrap(self, ctx: Any, result: Any) -> Any:
        self.wrapped = result
        return {"wrapped": result}


class RecordingCarrier(Carrier):
    name = "test_carrier"

    def __init__(self, *, carry_result: Any) -> None:
        self._carry_result = carry_result
        self.carried: Any = None

    async def carry(self, ctx: Any, parsed: Any) -> Any:
        self.carried = parsed
        return self._carry_result
