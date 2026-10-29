"""Back-compat re-exports: the JSON-RPC dispatch now lives in ``transports/mcp.py``.

PR3b (Trentina 3.0 Phase 7) moved the gateway's hand-rolled JSON-RPC surface into
the MCP transport and the ``tools/list`` aggregate into ``gateway/aggregate.py``.
This module only re-exports the names still imported from here; it is deleted
once those imports are rewired (the next commit).
"""

from __future__ import annotations

from ..transports.mcp import (
    PROTOCOL_VERSION,
    _crossing_call,
    _discovery_call,
    _negotiate_protocol_version,
    _route_tools_call,
    _route_tools_list,
    route_jsonrpc,
)
from .names import NAMESPACE_SEP

__all__ = [
    "NAMESPACE_SEP",
    "PROTOCOL_VERSION",
    "_crossing_call",
    "_discovery_call",
    "_negotiate_protocol_version",
    "_route_tools_call",
    "_route_tools_list",
    "route_jsonrpc",
]
