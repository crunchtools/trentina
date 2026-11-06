"""Tests for D-Bus interface — mock D-Bus bus (no real system bus needed)."""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from trentina.dbus_interface import (
    emit_detection_event,
    emit_request_event,
)
from trentina.events import reset_event_bus
from trentina.report import Disposition


class TestEmitRequestEvent:
    """Verify emit_request_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_request_processed(self) -> None:
        from trentina.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        emit_request_event(
            tool="block_fetch",
            source="https://example.com",
            disposition=Disposition.DELIVERED.value,
            risk_level="low",
            l1_detections=0,
            l1_suspicious=0,
            l2_label="BENIGN",
            l2_score=0.02,
            input_size=5000,
            output_size=3000,
            stats={"hidden_html": 0},
        )

        assert len(received) == 1
        assert received[0]["tool"] == "block_fetch"
        assert received[0]["source"] == "https://example.com"
        assert received[0]["disposition"] == "delivered"
        assert received[0]["risk_level"] == "low"
        assert received[0]["l2_label"] == "BENIGN"
        assert received[0]["l2_score"] == 0.02
        assert received[0]["input_size"] == 5000
        assert received[0]["output_size"] == 3000

    def test_duration_calculated_from_start_time(self) -> None:
        from trentina.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        start = time.time() - 0.1

        emit_request_event(
            tool="redact_fetch",
            source="https://evil.com",
            disposition=Disposition.EXTRACTED.value,
            risk_level="high",
            l1_detections=3,
            l1_suspicious=1,
            l2_label="MALICIOUS",
            l2_score=0.95,
            input_size=10000,
            output_size=2000,
            stats={},
            start_time=start,
        )

        assert len(received) == 1
        assert received[0]["duration_ms"] >= 100


class TestEmitDetectionEvent:
    """Verify emit_detection_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_detection_occurred(self) -> None:
        from trentina.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("detection_occurred", lambda _name, data: received.append(data))

        emit_detection_event(
            layer="L2",
            source="https://evil.com",
            severity="high",
            details={"classifier_label": "MALICIOUS", "classifier_score": 0.95},
        )

        assert len(received) == 1
        assert received[0]["layer"] == "L2"
        assert received[0]["source"] == "https://evil.com"
        assert received[0]["severity"] == "high"
        assert received[0]["details"]["classifier_label"] == "MALICIOUS"


class TestDbusInterfaceMethods:
    """Test D-Bus interface method return data shapes (mocked bus)."""

    def test_build_interface_creates_object(self) -> None:
        with patch.dict(
            "sys.modules",
            {
                "dbus_fast": MagicMock(),
                "dbus_fast.service": MagicMock(),
                "dbus_fast.aio": MagicMock(),
            },
        ):
            from trentina.dbus_interface import _build_interface

            interface = _build_interface()
            assert interface is not None

    def test_on_request_processed_callback(self) -> None:
        from trentina.events import get_event_bus

        reset_event_bus()
        bus = get_event_bus()

        received: list[dict] = []
        bus.subscribe("request_processed", lambda _n, d: received.append(d))

        emit_request_event(
            tool="block_read",
            source="/tmp/test.txt",
            disposition=Disposition.DELIVERED.value,
            risk_level="low",
            l1_detections=0,
            l1_suspicious=0,
            l2_label=None,
            l2_score=None,
            input_size=100,
            output_size=100,
            stats={},
        )

        assert len(received) == 1
        assert received[0]["tool"] == "block_read"


class TestGracefulDegradation:
    """Verify D-Bus startup handles missing dbus-fast gracefully."""

    @pytest.mark.asyncio
    async def test_start_dbus_without_dbus_fast(self) -> None:
        import trentina.dbus_interface as dbi

        dbi._dbus_started = False

        with patch.object(dbi, "_has_dbus_fast", return_value=False):
            await dbi.start_dbus()

        assert not dbi._dbus_started

    @pytest.mark.asyncio
    async def test_start_dbus_connection_failure(self) -> None:
        import trentina.dbus_interface as dbi

        dbi._dbus_started = False

        mock_bus_mod = MagicMock()
        mock_msg_bus_instance = AsyncMock()
        mock_msg_bus_instance.connect = AsyncMock(side_effect=ConnectionRefusedError("no socket"))
        mock_bus_mod.MessageBus.return_value = mock_msg_bus_instance

        with (
            patch.object(dbi, "_has_dbus_fast", return_value=True),
            patch.dict(
                "sys.modules",
                {
                    "dbus_fast": MagicMock(),
                    "dbus_fast.aio": mock_bus_mod,
                },
            ),
        ):
            await dbi.start_dbus()

        assert not dbi._dbus_started

    @pytest.mark.asyncio
    async def test_a_missing_socket_logs_one_line(self, caplog: pytest.LogCaptureFixture) -> None:
        import trentina.dbus_interface as dbi

        dbi._dbus_started = False

        mock_bus_mod = MagicMock()
        mock_msg_bus_instance = AsyncMock()
        mock_msg_bus_instance.connect = AsyncMock(side_effect=FileNotFoundError("no socket"))
        mock_bus_mod.MessageBus.return_value = mock_msg_bus_instance

        with (
            caplog.at_level("WARNING", logger="trentina.dbus_interface"),
            patch.object(dbi, "_has_dbus_fast", return_value=True),
            patch.dict(
                "sys.modules",
                {
                    "dbus_fast": MagicMock(),
                    "dbus_fast.aio": mock_bus_mod,
                },
            ),
        ):
            await dbi.start_dbus()

        assert not dbi._dbus_started
        (record,) = caplog.records
        assert record.exc_info is None
        assert "no socket" in record.getMessage()


class TestEventDataShapes:
    """Verify event data contains expected fields."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_request_event_fields(self) -> None:
        from trentina.events import get_event_bus

        bus = get_event_bus()
        events_captured: list[dict] = []
        bus.subscribe("request_processed", lambda _n, d: events_captured.append(d))

        emit_request_event(
            tool="redact_search",
            source="query:test",
            disposition=Disposition.EXTRACTED.value,
            risk_level="low",
            l1_detections=1,
            l1_suspicious=0,
            l2_label="BENIGN",
            l2_score=0.01,
            input_size=500,
            output_size=400,
            stats={"directives_detected": 1},
        )

        d = events_captured[0]
        expected_keys = {
            "tool",
            "source",
            "disposition",
            "risk_level",
            "duration_ms",
            "l1_detections",
            "l1_suspicious",
            "l2_label",
            "l2_score",
            "input_size",
            "output_size",
            "stats",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_detection_event_fields(self) -> None:
        from trentina.events import get_event_bus

        bus = get_event_bus()
        events_captured: list[dict] = []
        bus.subscribe("detection_occurred", lambda _n, d: events_captured.append(d))

        emit_detection_event(
            layer="L1",
            source="https://bad.com",
            severity="critical",
        )

        d = events_captured[0]
        assert d["layer"] == "L1"
        assert d["source"] == "https://bad.com"
        assert d["severity"] == "critical"
        assert d["details"] == {}


def test_l3_status_follows_the_provider_not_the_gemini_key() -> None:
    from trentina.dbus_interface import l3_status

    config = MagicMock(has_llm=True, provider="openrouter", model="m")

    status = l3_status(config)

    assert status["active"] is True
    assert "openrouter" in status["description"]


class TestBusView:
    """Nothing a caller wrote crosses the system bus (#298)."""

    def test_source_is_a_fingerprint(self) -> None:
        from trentina.dbus_interface import bus_view

        view = bus_view({"source": "https://secret.example/token=abc", "tool": "block_fetch"})
        assert view["source"].startswith("sha256:")
        assert "secret" not in str(view)
        assert view["tool"] == "block_fetch"

    def test_l3_prose_is_reduced_to_finding_types(self) -> None:
        from trentina.dbus_interface import bus_view

        view = bus_view(
            {
                "source": "x",
                "details": {
                    "injection_detected": True,
                    "summary": "CANARY prose written by the judge",
                    "findings": [{"type": "role_reassignment", "description": "CANARY"}],
                    "hidden_html": 2,
                },
            }
        )
        assert "CANARY" not in str(view)
        assert view["details"]["finding_types"] == ["role_reassignment"]
        assert view["details"]["hidden_html"] == 2

    def test_recent_events_are_viewed(self) -> None:
        """GetRecentEvents' body, called through the real dbus-fast interface."""
        from trentina.dbus_interface import _build_interface

        reset_event_bus()
        emit_detection_event("L3", "/home/alice/secret.txt", "high", {"summary": "CANARY"})
        interface = _build_interface()
        out = type(interface).GetRecentEvents.__wrapped__(interface, 10)
        assert "secret.txt" not in out
        assert "CANARY" not in out
        assert json.loads(out)[0]["data"]["source"].startswith("sha256:")


class TestStartedOnTheServingLoop:
    """main() no longer starts D-Bus on a loop it then closes (#298)."""

    def test_main_only_requests_it(self) -> None:

        import trentina as pkg

        src = inspect.getsource(pkg.main)
        assert "new_event_loop" not in src
        assert "request_dbus()" in src

    @pytest.mark.asyncio
    async def test_the_lifespan_starts_it_on_the_running_loop(self) -> None:

        import trentina.dbus_interface as dbi
        from trentina import server

        loops: list[asyncio.AbstractEventLoop] = []

        async def fake_start() -> None:
            loops.append(asyncio.get_running_loop())

        with (
            patch.object(dbi, "_requested", True),
            patch.object(dbi, "start_dbus", fake_start),
        ):
            async with server._lifespan(server.mcp):
                pass
        assert loops == [asyncio.get_running_loop()]

    @pytest.mark.asyncio
    async def test_signals_hop_onto_the_bus_loop(self) -> None:
        """A worker thread's event is signalled from the bus's loop, viewed."""
        from trentina.dbus_interface import _build_interface

        interface = _build_interface(asyncio.get_running_loop())
        sent: list[tuple[str, int]] = []
        interface.DetectionOccurred = lambda *a: sent.append((a[1], threading.get_ident()))

        def worker() -> None:
            interface.on_detection_occurred("detection_occurred", {"source": "s", "layer": "L1"})

        await asyncio.to_thread(worker)
        await asyncio.sleep(0)
        assert sent
        assert sent[0][1] == threading.get_ident()
        assert sent[0][0].startswith("sha256:")
