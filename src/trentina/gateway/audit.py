"""The one MCP tool-call audit row, and the per-call "already audited" latch.

``_audit`` is the SOLE ``record_gateway_call`` writer for the gateway's MCP
tool-call path — the lifecycle ``tests/test_perimeter_lifecycle._ALLOWED``
seals. It lived inside ``gateway/router.py`` until PR3a (Trentina 3.0 Phase 7)
lifted it here, so the MCP transport (``transports/mcp.py``) can write its one
row without importing the router that is being retired. Both the router and the
transport reference it as a module attribute (``audit._audit``), so there is a
single canonical patch point for tests: ``trentina.gateway.audit._audit``.

``_call_audited`` is the ContextVar that lets ``router._route_tools_call``
guarantee exactly one row per ``tools/call`` (#293): every path that writes a
row sets it (``_audit`` does, and the handler sets it False around the
dispatch), and the outer handler writes a ``gateway_error`` row only when
nothing inside did.
"""

from __future__ import annotations

import contextvars
import logging
import time
from typing import TYPE_CHECKING

from ..database import record_gateway_call
from ..logsafe import exc_kind
from ..outcomes import Outcome
from .context import current_call, current_session

if TYPE_CHECKING:
    from .destination import Destination

logger = logging.getLogger(__name__)

#: True once the current ``tools/call`` has written its audit row (#293). Set by
#: ``_audit`` and reset around the dispatch in ``router._route_tools_call``,
#: which reads it to decide whether the outer handler still owes a
#: ``gateway_error`` row.
_call_audited: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "trentina_call_audited", default=False
)


def _audit(
    profile: str,
    backend: str,
    tool: str,
    outcome: Outcome,
    duration_ms: int,
    error_message: str | None = None,
    *,
    bytes_arrived: int | None = None,
    bytes_delivered: int | None = None,
    normalized: dict[str, str] | None = None,
    destination: Destination | None = None,
    content_digest: str | None = None,
) -> None:
    _call_audited.set(True)
    # The audit must never fail the call it records, and sqlite3.Error is not
    # all a write can raise (a closed connection, a thread-affinity
    # ProgrammingError, a full disk surfacing as OSError). A lost row is
    # still a finding, so it is logged: the profile and the class, nothing
    # the caller chose (#262).
    try:
        record_gateway_call(
            profile,
            backend,
            tool,
            outcome.value,
            duration_ms,
            error_message,
            bytes_arrived=bytes_arrived,
            bytes_delivered=bytes_delivered,
            normalized=normalized,
            destination=destination.value if destination else None,
            destination_kind=destination.kind.value if destination else None,
            session=current_session.get() or None,
            call_ref=current_call.get() or None,
            content_digest=content_digest,
        )
    except Exception as exc:
        logger.warning("gateway: audit row lost profile=%s err=%s", profile, exc_kind(exc))


def _audit_assembly_failure(
    profile_name: str,
    backend_name: str,
    tool_name: str,
    t0: float,
    exc: Exception,
    destination: Destination | None,
) -> None:
    """The one audit row for a call whose assembly raised.

    Assembly decides the outcome, so the row is written after it; a failure in
    it would otherwise leave the call unaudited.
    """
    _audit(
        profile_name,
        backend_name,
        tool_name,
        Outcome.GATEWAY_ERROR,
        int((time.monotonic() - t0) * 1000),
        f"assembly failed: {exc_kind(exc)}",
        destination=destination,
    )
