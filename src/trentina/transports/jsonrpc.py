"""JSON-RPC 2.0 primitives shared by the gateway and its transports.

The wire-shape builders a crossing composes — a success envelope, an error
envelope, and the policy-refusal result the gateway returns as an ordinary tool
result rather than a protocol error. Pure functions of their inputs: they reach
into no gateway state, so both ``gateway/router.py`` and ``transports/mcp.py``
import them from here instead of the transport reaching into the router. Part
of PR3a (Trentina 3.0 Phase 7): make the transport self-contained so the
hand-rolled router can be retired.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..reserved import REFUSAL_KEY

if TYPE_CHECKING:
    from ..modes import Mode

# JSON-RPC 2.0 reserved error codes (https://www.jsonrpc.org/specification#error_object)
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(
    req_id: Any, code: int, message: str, detail: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    error: dict[str, Any] = {"code": code, "message": message}
    if detail is not None:
        error["data"] = detail
    return {"jsonrpc": "2.0", "id": req_id, "error": error}


def _refused(
    req_id: Any, refusal: dict[str, Any], text: str | None = None, **extra: Any
) -> dict[str, Any]:
    """A policy refusal: the gateway's answer, delivered as an ordinary tool result.

    Not a JSON-RPC error and not ``isError``. Stock agent clients count both
    as strikes against the server, and every tool behind the gateway shares
    one server name: three refusals in a row and hermes-agent paused all of an
    agent's tools as "unreachable" (Kagetora's weekend report, #17). A JSON-RPC
    error is kept for a request that is malformed, which is the client's bug.
    The structured refusal is under ``REFUSAL_KEY``; ``text``, the line an
    agent reads, defaults to the refusal's reason and the gateway's message.
    """
    if text is None:
        text = f"[TRENTINA] Refused ({refusal['reason']}). {refusal.get('detail', '')}".rstrip()
    return _ok(
        req_id,
        {
            "content": [{"type": "text", "text": text}],
            "isError": False,
            REFUSAL_KEY: refusal,
            **extra,
        },
    )


def _response_guard_refusal(req_id: Any, response_err: str, mode: Mode) -> dict[str, Any]:
    """A read-only tool's response a response guard forbade: refused, nothing delivered."""
    return _refused(
        req_id,
        {"reason": response_err, "mode": mode.value, "alternatives": []},
        f"[TRENTINA] Refused (response guard). {response_err} The response was not delivered.",
    )
