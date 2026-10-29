"""tools/call routing: allowlist, request guards, dispatch, one audit row.

docs/audit-log.md: "every tools/call is recorded in gateway_calls with its
outcome".
"""

from __future__ import annotations

import time
from typing import Any

from trentina.gateway.errors import BackendCallError
from trentina.gateway.guards import check_request_guards
from trentina.gateway.audit import _audit
from trentina.gateway.router import _dispatch, _err, _ok, filter_tools
from trentina.outcomes import Outcome, classify_exception

JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


async def route_tools_call(
    profile: Any, backend_name: str, tool_name: str, arguments: dict[str, Any], req_id: Any
) -> dict[str, Any]:
    """Validate routing, forward to the backend, record the outcome.

    Re-applies the allowlist on call as defense in depth: even if a consumer
    somehow learned about a tool name, calling it must still match the filter
    that produced their tools/list view.
    """
    backend = profile.backends[backend_name]

    if not filter_tools([{"name": tool_name}], backend):
        return _err(
            req_id,
            JSONRPC_INVALID_PARAMS,
            f"Tool {tool_name!r} not permitted on backend {backend_name!r}",
        )

    guard_err = check_request_guards(tool_name, arguments, backend)
    if guard_err:
        return _err(req_id, JSONRPC_INVALID_PARAMS, guard_err)

    t0 = time.monotonic()
    try:
        call_result = await _dispatch(profile, backend, backend_name, tool_name, arguments)
    except BackendCallError as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        _audit(profile.name, backend_name, tool_name, classify_exception(exc), duration_ms)
        return _err(req_id, JSONRPC_INTERNAL_ERROR, "backend call failed")

    duration_ms = int((time.monotonic() - t0) * 1000)
    outcome = Outcome.TOOL_ERROR if call_result.is_error else Outcome.OK
    _audit(profile.name, backend_name, tool_name, outcome, duration_ms)
    return _ok(req_id, {"content": call_result.content, "isError": call_result.is_error})
