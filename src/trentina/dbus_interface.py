"""D-Bus interface for trentina.

Exposes com.crunchtools.Trentina1 on the system bus with methods for
querying pipeline state and signals for live event streaming.

Uses dbus-fast (pure Python, async, no C deps). Gracefully degrades
if D-Bus socket is unavailable (e.g. container without mount).

Started from the server's lifespan, on the loop that serves (#298). It used
to be started by ``main()`` on a throwaway loop that was closed the next
line, so the bus connection died before the server began and the interface
never answered a call. Who may own the name and call it is the policy file
``dbus/com.crunchtools.Trentina1.conf``: root and the ``trentina`` group.
Whatever crosses the bus is :func:`bus_view` of an event, never the event:
sources are fingerprints and L3's assessment is reduced to its closed enum.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from .logsafe import redact_source
from .quarantine.prompts import finding_types

logger = logging.getLogger(__name__)

_dbus_started = False
_requested = False
#: Held so the connection lives as long as the process, not the function.
_bus: Any = None

#: A bus socket that accepts and never answers must not hold up serving.
CONNECT_TIMEOUT_SECONDS = 5.0


def request_dbus() -> None:
    """Ask for the interface; the lifespan starts it once the loop is serving."""
    global _requested
    _requested = True


def dbus_requested() -> bool:
    """Whether ``main()`` asked for the interface (``--no-dbus`` was absent)."""
    return _requested


def bus_view(event_data: dict[str, Any]) -> dict[str, Any]:
    """What an event may say on the system bus.

    The bus is readable by the host's operator tooling, not by the profiles
    whose calls produced the events, so a source is a fingerprint that
    correlates with the audit DB and nothing more. Detection details are L3's
    assessment or L1's counts: numbers survive, prose does not, and findings
    become their closed types.
    """
    view = dict(event_data)
    if "source" in view:
        view["source"] = redact_source(view["source"])
    details = view.get("details")
    if isinstance(details, dict):
        closed: dict[str, Any] = {
            key: value
            for key, value in details.items()
            if isinstance(value, (bool, int, float)) and not isinstance(value, str)
        }
        closed["finding_types"] = finding_types(details)
        view["details"] = closed
    return view


def _has_dbus_fast() -> bool:
    """Check if dbus-fast is importable."""
    try:
        import dbus_fast  # noqa: F401

        return True
    except ImportError:
        return False


async def start_dbus() -> None:
    """Start the D-Bus interface. Non-blocking, logs warning on failure."""
    global _dbus_started, _bus

    if _dbus_started:
        return

    if not _has_dbus_fast():
        logger.warning("dbus-fast not installed — D-Bus interface disabled")
        return

    try:
        from dbus_fast import BusType
        from dbus_fast.aio import MessageBus

        bus = await asyncio.wait_for(
            MessageBus(bus_type=BusType.SYSTEM).connect(), CONNECT_TIMEOUT_SECONDS
        )

        interface = _build_interface(asyncio.get_running_loop())
        bus.export("/com/crunchtools/Trentina1", interface)

        await bus.request_name("com.crunchtools.Trentina1")

        from .events import get_event_bus

        event_bus = get_event_bus()
        event_bus.subscribe("request_processed", interface.on_request_processed)
        event_bus.subscribe("detection_occurred", interface.on_detection_occurred)

        _bus = bus
        _dbus_started = True
        logger.info("D-Bus interface registered: com.crunchtools.Trentina1")

    except (OSError, TimeoutError) as exc:
        # No socket, or one that never answers: expected in a container, so no traceback.
        logger.warning("D-Bus unavailable — interface disabled: %r", exc)  # logsafe: ours
    except Exception:
        logger.warning("D-Bus unavailable — interface disabled", exc_info=True)  # logsafe: ours


def l3_status(config: Any) -> dict[str, Any]:
    """L3 as D-Bus reports it: live when a provider has its key, or is keyless (ollama)."""
    return {
        "active": config.has_llm,
        "description": f"Semantic judge ({config.provider})",
        "model": config.model,
    }


def _build_interface(loop: asyncio.AbstractEventLoop | None = None) -> Any:
    """Build the Trentina1 D-Bus interface object.

    ``loop`` is the one the bus connection lives on. Events are emitted from
    worker threads as well as from it, and a signal must be sent from the
    connection's own loop, so the callbacks hop onto it.
    """
    from dbus_fast.service import ServiceInterface, method, signal

    class Trentina1Interface(ServiceInterface):
        """com.crunchtools.Trentina1 D-Bus interface."""

        def __init__(self) -> None:
            super().__init__("com.crunchtools.Trentina1")
            self._loop = loop

        def _on_loop(self, fn: Any, *args: Any) -> None:
            if self._loop is None:
                fn(*args)
            else:
                self._loop.call_soon_threadsafe(fn, *args)

        @method()
        def GetStats(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON config + blocklist stats + layer status."""
            from .database import get_blocklist_stats
            from .quarantine.classifier import is_classifier_available

            # Gateway-wide on purpose: the system bus is the host operator's
            # interface, and no agent profile reaches it (#263).
            stats = get_blocklist_stats()
            from .config import get_config

            config = get_config()

            return json.dumps(
                {
                    "blocklist": stats,
                    "config": {
                        "model": config.model,
                        "require_l2": config.require_l2,
                        "require_l3": config.require_l3,
                        "admission_tokens": config.admission_tokens,
                    },
                    "layers": {
                        "l1": True,
                        "l2": is_classifier_available(),
                        "l3": l3_status(config)["active"],
                    },
                }
            )

        @method()
        def GetRecentEvents(self, count: "u") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON array of last N events from ring buffer."""
            from .events import get_event_bus

            events = get_event_bus().recent_events(count)
            return json.dumps([{**e, "data": bus_view(e.get("data", {}))} for e in events])

        @method()
        def GetLayerStatus(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON layer availability status."""
            from .config import get_config
            from .quarantine.classifier import is_classifier_available, model_info

            config = get_config()
            model = model_info() if is_classifier_available() else None
            return json.dumps(
                {
                    "l1": {"active": True, "description": "Deterministic detection"},
                    "l2": {
                        "active": model is not None,
                        "description": f"{model.id} classifier" if model else "classifier",
                    },
                    "l3": l3_status(config),
                }
            )

        @method()
        def GetTrustConfig(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON trust configuration."""
            from .config import get_config

            config = get_config()
            return json.dumps(config._trust_config)

        @signal()
        def RequestProcessed(  # noqa: N802
            self,
            tool: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            disposition: "s",  # type: ignore[name-defined]  # noqa: F821
            risk_level: "s",  # type: ignore[name-defined]  # noqa: F821
            duration_ms: "u",  # type: ignore[name-defined]  # noqa: F821
            stats_json: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when a request completes."""

        @signal()
        def DetectionOccurred(  # noqa: N802
            self,
            layer: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            severity: "s",  # type: ignore[name-defined]  # noqa: F821
            details_json: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when injection is detected."""

        def on_request_processed(self, _event: str, event_payload: dict[str, Any]) -> None:
            """EventBus callback — emit D-Bus signal."""
            view = bus_view(event_payload)
            self._on_loop(
                self.RequestProcessed,
                view.get("tool", ""),
                view.get("source", ""),
                view.get("disposition", ""),
                view.get("risk_level", ""),
                int(view.get("duration_ms", 0)),
                json.dumps(view.get("stats", {})),
            )

        def on_detection_occurred(self, _event: str, event_payload: dict[str, Any]) -> None:
            """EventBus callback — emit D-Bus signal."""
            view = bus_view(event_payload)
            self._on_loop(
                self.DetectionOccurred,
                view.get("layer", ""),
                view.get("source", ""),
                view.get("severity", ""),
                json.dumps(view.get("details", {})),
            )

    return Trentina1Interface()


def emit_request_event(
    tool: str,
    source: str,
    disposition: str,
    risk_level: str,
    l1_detections: int,
    l1_suspicious: int,
    l2_label: str | None,
    l2_score: float | None,
    input_size: int,
    output_size: int,
    stats: dict[str, int],
    start_time: float | None = None,
) -> None:
    """Emit ``request_processed``: one event per content-tool call.

    The payload is the event schema; the Cockpit plugin
    (``cockpit-trentina/trentina.js``) is its reader.

    Args:
        tool: The family and mode that ran, as ``<mode>_<family>``: ``block_fetch``
            is ``fetch_tool`` in ``block`` mode.
        source: URL, resolved path, ``sha256:`` content hash, or
            ``search:<query>``.
        disposition: A ``report.Disposition`` value — what the caller did
            with the content (``delivered``, ``annotated``, ``extracted``,
            ``refused``). It replaced ``trust_level`` in 0.30.0.
        risk_level: L1's risk level for the payload.
        l1_detections: Every L1 count, hygiene included.
        l1_suspicious: The counts that feed risk scoring.
        l2_label: ``BENIGN``/``MALICIOUS``, or None when L2 did not run.
        l2_score: L2's highest window score, or None when L2 did not run.
        input_size: Bytes that arrived.
        output_size: Bytes delivered.
        stats: L1's per-stage counts, flattened.
        start_time: ``time.time()`` at the start of the call; becomes
            ``duration_ms`` in the payload (0 when omitted).
    """
    from .events import get_event_bus

    duration_ms = int((time.time() - start_time) * 1000) if start_time else 0

    get_event_bus().emit(
        "request_processed",
        {
            "tool": tool,
            "source": source,
            "disposition": disposition,
            "risk_level": risk_level,
            "duration_ms": duration_ms,
            "l1_detections": l1_detections,
            "l1_suspicious": l1_suspicious,
            "l2_label": l2_label,
            "l2_score": l2_score,
            "input_size": input_size,
            "output_size": output_size,
            "stats": stats,
        },
    )


def emit_detection_event(
    layer: str,
    source: str,
    severity: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Convenience: emit a detection_occurred event."""
    from .events import get_event_bus

    get_event_bus().emit(
        "detection_occurred",
        {
            "layer": layer,
            "source": source,
            "severity": severity,
            "details": details or {},
        },
    )
