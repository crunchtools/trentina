"""Audit chain verification tool (#472): operator only.

Walks the ``gateway_calls`` hash chain from the newest checkpoint and reports
the first break. Rows name profiles and tools, so an agent profile is refused
exactly as it is for the other gateway-wide admin tools.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from typing import Any
from urllib.parse import quote

from ..audit_chain import verify
from ..config import get_config
from ..database import opened_path
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


def _walk(path: str) -> dict[str, Any]:
    """The chain walk, on this worker's own read-only connection."""
    ttl = get_config().blocklist_ttl_days * 86400
    conn = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True)
    try:
        return verify(conn, ttl_seconds=ttl)
    finally:
        conn.close()


async def audit_verify() -> dict[str, Any]:
    """Verify the audit hash chain.

    Returns:
        ``ok``, ``checked``, ``first_break`` (None, or ``{id, reason}``),
        ``detections_expired`` and the ``checkpoint`` the walk began at. A
        refusal is ``{"error": ...}``.
    """
    try:
        require_operator(require_caller("audit_verify"), "audit_verify")
    except ScopeError as exc:
        logger.warning("audit_verify refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    # Linear in the rows kept; off the loop, like the stats aggregates (#295).
    return await asyncio.to_thread(_walk, opened_path())
