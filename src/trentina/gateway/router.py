"""JSON-RPC dispatch for gateway endpoints.

Implements the MCP wire-protocol surface a consumer needs from the gateway:
`initialize`, `tools/list`, `tools/call`, `ping`, and the
`notifications/initialized` no-op. Other methods return JSON-RPC error
-32601 (method not found).

For `tools/list`, aggregates across all backends in the profile and applies
the allowlist filter. Tools are served under short names (`names.py`, 0.38.0),
or as `<backend>__<tool>` when the profile turns `short_names` off.

For `tools/call`, resolves the name back into (backend, tool), verifies the
backend is in the profile, re-checks the allowlist (defense in depth), and
forwards. Only a name tools/list serves resolves: since 0.43.0 the
`<backend>__<tool>` form routes only when `short_names` is off.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
)

from .. import __version__
from ..logsafe import exc_kind, redact_source
from ..outcomes import Outcome
from ..transports.jsonrpc import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    _err,
    _ok,
)
from . import aggregate, audit, discovery, paging
from .context import current_call, current_session, profile_context
from .decoy import leaked_tokens
from .modes_policy import (
    mode_instructions,
)
from .names import (
    NAMESPACE_SEP,
)
from .request_edge import _leaked, _unknown_tool
from .sessions import session_registry
from .surface import (
    wire_bytes,
)

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

# The revision answered when a client asks for one we do not recognize. Kept
# at the SDK's own handshake ceiling rather than a literal, so trentina tracks
# the protocol registry instead of drifting behind it.
PROTOCOL_VERSION = LATEST_HANDSHAKE_VERSION

# JSON-RPC reserved error codes and the pure wire-shape builders (_ok/_err/
# _refused/_response_guard_refusal) now live in ``transports/jsonrpc.py`` and are
# imported above, so both the router and the MCP transport share one copy.


def _negotiate_protocol_version(requested: Any) -> str:
    """Answer an ``initialize`` with the revision the client asked for.

    Trentina previously replied with one hardcoded revision no matter what was
    asked, which pinned every consumer to the gateway's era and made the
    gateway the ceiling for its own fleet. Every backend measured in issue #107
    already behaves the way this does: honour the client's request when it is a
    revision we know, otherwise counter-offer our ceiling and let the client
    decide whether it can live with that.

    The known set comes from the SDK's protocol registry rather than a local
    literal, so trentina picks up new revisions when it picks up a new SDK.

    Note the gateway's surface is tools-only and hand-rolled (it does not use
    fastmcp for gateway traffic), so agreeing to a revision costs nothing
    beyond the tool methods, which are stable across every revision listed.
    """
    if isinstance(requested, str) and requested in HANDSHAKE_PROTOCOL_VERSIONS:
        return requested
    return PROTOCOL_VERSION


async def route_jsonrpc(profile: Profile, request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one JSON-RPC request against a profile.

    The response is always a JSON-RPC 2.0 body. HTTP status is 200 for any
    well-formed JSON-RPC, including error responses — the caller never
    promotes a JSON-RPC error to an HTTP non-200.

    Args:
        profile: The authenticated profile (auth was checked before dispatch).
        request: Parsed JSON-RPC 2.0 request body.

    Returns:
        JSON-RPC 2.0 response body.

    Raises:
        Exception: only what ``_route_tools_call`` re-raises after auditing
            it as a gateway_error; the caller answers it with a 500.
    """
    method = request.get("method", "")
    req_id = request.get("id")
    # Only an absent (or null) params defaults: `[]` or `0` is a malformed
    # call, and `or {}` would have quietly made it a well-formed one.
    params = request.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict) and method != "tools/call":
        # tools/call answers this itself, so the refusal is audited (#293).
        return _err(req_id, JSONRPC_INVALID_PARAMS, "params must be an object")

    if method == "initialize":
        # The mode explanation is said here once, not on every tool (#198).
        naming = (
            "Where two servers offer a tool of the same name, a server tag prefixes it."
            if profile.short_names
            else f"Tool names are namespaced as <backend>{NAMESPACE_SEP}<tool>."
        )
        instructions = " ".join(
            part
            for part in (
                f"trentina gateway, profile={profile.name}.",
                naming,
                discovery.instructions(profile),
                mode_instructions(profile),
            )
            if part
        ).rstrip()
        return _ok(
            req_id,
            {
                "protocolVersion": _negotiate_protocol_version(params.get("protocolVersion")),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {
                    "name": f"trentina-gateway:{profile.name}",
                    "version": __version__,
                },
                "instructions": instructions,
            },
        )

    if method == "ping":
        return _ok(req_id, {})

    if method == "notifications/initialized":
        return _ok(req_id, {})

    if method == "tools/list":
        return await _route_tools_list(profile, req_id)

    if method == "tools/call":
        # Everything this call judges runs on the caller's own provider and
        # key (RT #1505): unbound, L3 fell through to the global provider.
        with profile_context(profile):
            return await _route_tools_call(profile, req_id, params)

    return _err(req_id, JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}")


async def _route_tools_list(profile: Profile, req_id: Any) -> dict[str, Any]:
    """Aggregate tools/list across the profile's backends, filtered and namespaced.

    Checks the per-profile cache first. On miss, coalesces concurrent callers
    for the same profile onto a single fan-out (single-flight).
    """
    aggregated = aggregate._profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await aggregate.ensure_profile_build(profile)
    return _ok(req_id, {"tools": discovery.shape(profile, aggregated, current_session.get())})


async def _route_tools_call(profile: Profile, req_id: Any, params: Any) -> dict[str, Any]:
    """The ``tools/call`` edge, with one audit row guaranteed for every call (#293).

    Rejects a leaked-token probe and a non-mapping params, answers a discovery
    meta name, then hands the resolved call to ``_crossing_call`` (the
    orchestrator). Every path inside writes its own row. An exception that
    escapes them all is ours, so it is recorded as gateway_error before it
    propagates to the HTTP edge's 500: a probe that crashes the router is the
    probe the audit most needs to see.
    """
    # Text held for a caller who never came back does not outlive its hold.
    paging.expire()
    token = audit._call_audited.set(False)
    # Random, not the JSON-RPC id: that one is the caller's to choose.
    call = current_call.set(secrets.token_hex(8))
    t0 = time.monotonic()
    try:
        # First, on the request as sent: the params may not be a mapping and
        # the name may resolve to nothing, and it is still the alarm (#357).
        leaked = leaked_tokens(profile, params)
        if leaked:
            return _leaked(profile, req_id, params, leaked)
        if not isinstance(params, dict):
            audit._audit(profile.name, "", "", Outcome.DENIED_GUARD, 0, "params must be an object")
            return _err(req_id, JSONRPC_INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if isinstance(name, str) and name in discovery.meta_names(profile):
            arguments = params.get("arguments")
            return await _discovery_call(
                profile, req_id, name, {} if arguments is None else arguments
            )
        return await _crossing_call(profile, req_id, params)
    except Exception as exc:
        if not audit._call_audited.get():
            audit._audit(
                profile.name,
                "",
                redact_source(params.get("name") if isinstance(params, dict) else None),
                Outcome.GATEWAY_ERROR,
                int((time.monotonic() - t0) * 1000),
                f"unhandled: {exc_kind(exc)}",
            )
        raise
    except asyncio.CancelledError:
        # A BaseException: the task was cancelled mid-scan (#439), by a hang-up or a
        # shutdown. Re-raised, so the cancellation still propagates.
        if not audit._call_audited.get():
            audit._audit(
                profile.name,
                "",
                redact_source(params.get("name") if isinstance(params, dict) else None),
                Outcome.CANCELLED,
                int((time.monotonic() - t0) * 1000),
            )
        raise
    finally:
        current_call.reset(call)
        audit._call_audited.reset(token)


async def _crossing_call(profile: Profile, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    """Run one resolved ``tools/call`` through the orchestrator (Trentina 3.0).

    The one call path: ``orchestrator.crossing`` drives the MCP ``Face`` /
    ``Carrier`` (``transports.mcp``), which resolves the target, re-checks the
    allowlist, answers a decoy or ``read_part``, resolves the mode and
    preprocess switch, normalizes and guards the arguments, dispatches, and
    judges and shapes the response — writing the one audit row through
    ``transports.mcp._finish_delivery``. Reached from the ``tools/call`` route and from
    ``call_tool``'s re-entry; ``params`` is already a mapping and not a
    discovery meta name by the time it arrives.
    """
    from ..orchestrator import crossing
    from ..transports.mcp import McpCrossing
    from ..transports.registry import build_transport

    transport = build_transport("mcp")
    crossed: dict[str, Any] = await crossing(transport, McpCrossing(profile, req_id, params))
    return crossed


async def _discovery_call(
    profile: Profile, req_id: Any, name: str, arguments: Any
) -> dict[str, Any]:
    """Answer a discovery tool (#473): ``call_tool`` by routing the tool it
    names, ``find_tools`` and ``load_tools`` from the served aggregate.

    ``call_tool`` writes no row of its own: the call it carries writes the
    one row, under the real (backend, tool), through every rule a direct
    call meets. A discovery tool cannot be called through it.
    """
    if not isinstance(arguments, dict):
        message = "arguments must be an object"
        audit._audit(profile.name, "", name, Outcome.DENIED_GUARD, 0, message)
        return _err(req_id, JSONRPC_INVALID_PARAMS, message)
    if name == discovery.CALL_TOOL:
        inner = arguments.get("name", "")
        if not isinstance(inner, str) or inner in discovery.meta_names(profile):
            return _unknown_tool(profile, req_id, inner)
        return await _crossing_call(
            profile, req_id, {"name": inner, "arguments": arguments.get("arguments")}
        )
    t0 = time.monotonic()
    aggregated = aggregate._profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await aggregate.ensure_profile_build(profile)
    session = current_session.get()
    try:
        if name == discovery.FIND_TOOLS:
            result = discovery.find(profile, aggregated, arguments)
        else:
            result, grew = discovery.load(profile, aggregated, session, arguments)
            if not session_registry.holds(profile.name, session):
                # It ended while the aggregate was built, after its own
                # forget_session ran: nothing else would drop this set.
                discovery.forget_session(session)
            elif grew:
                await session_registry.notify_session(profile.name, session)
    except ValueError as exc:
        # The messages are ours and quote nothing the caller sent.
        audit._audit(profile.name, "", name, Outcome.DENIED_GUARD, 0, str(exc))
        return _err(req_id, JSONRPC_INVALID_PARAMS, str(exc))
    audit._audit(
        profile.name,
        "",
        name,
        Outcome.OK,
        int((time.monotonic() - t0) * 1000),
        bytes_delivered=wire_bytes(result),
    )
    return _ok(req_id, result)
