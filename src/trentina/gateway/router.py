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
import copy
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
from ..quarantine.limiter import Priority, l3_priority
from ..reserved import (
    reserved_sites,
    strip_reserved,
)
from ..transports.jsonrpc import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    _err,
    _ok,
)
from . import audit, discovery, paging, tool_pins
from .backend import (
    list_backend_tools,
    on_backend_cache_evict,
)
from .compress import (
    compress_tools,
    get_profiles,
    maybe_trigger_compression,
    set_on_compressed,
)
from .context import current_call, current_session, profile_context
from .decoy import leaked_tokens, served_tools
from .filter import filter_tools
from .ingress_defense import scan_tool_list
from .internal import list_internal_tools
from .modes_policy import (
    MODE_PARAM,
    insert_params,
    insert_preprocess,
    mode_instructions,
    policy_for,
    preprocess_policy_for,
    strip_params,
)
from .names import (
    NAMESPACE_SEP,
    forget_issued_names,
    serve_short_names,
)
from .request_edge import _leaked, _unknown_tool
from .schema_compact import compact_tool
from .sessions import session_registry
from .surface import (
    BackendSurface,
    Stage,
    Surface,
    forget_surface,
    record_surface,
    wire_bytes,
)

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

# The revision answered when a client asks for one we do not recognize. Kept
# at the SDK's own handshake ceiling rather than a literal, so trentina tracks
# the protocol registry instead of drifting behind it.
PROTOCOL_VERSION = LATEST_HANDSHAKE_VERSION

# JSON-RPC reserved error codes and the pure wire-shape builders (_ok/_err/
# _refused/_response_guard_refusal) now live in ``transports/jsonrpc.py`` and are
# imported above, so both the router and the MCP transport share one copy.

_profile_tools_cache: dict[str, list[dict[str, Any]]] = {}
_profile_backend_urls: dict[str, set[str]] = {}

_profile_inflight: dict[str, asyncio.Task[list[dict[str, Any]]]] = {}
# Held so the rebuild after a compression pass is not garbage-collected.
_rebuild_task: asyncio.Future[None] | None = None

# Bumped per profile by every invalidation of it. An in-flight aggregation
# built from the pre-reload Profile: its waiters still get it, but it must not
# land in the cache after the pop, where the NEXT caller would read it fresh.
# Per profile, not global (#137): one counter meant a tenant's cache_flush
# discarded every neighbour's in-flight build as well.
_cache_generation: dict[str, int] = {}


def _bump(profile_name: str) -> None:
    _cache_generation[profile_name] = _cache_generation.get(profile_name, 0) + 1


def _on_backend_evicted(url: str) -> None:
    """Clear any profile cache whose backend set includes this URL."""
    for name, urls in list(_profile_backend_urls.items()):
        if url in urls:
            _bump(name)
            _profile_tools_cache.pop(name, None)
            _profile_backend_urls.pop(name, None)


on_backend_cache_evict(_on_backend_evicted)
session_registry.on_remove(discovery.forget_session)


def _rebuild_after_compression() -> None:
    """Serve newly compressed text once it is judged, without making anyone wait.

    Each profile is rebuilt in the background, after any build already in
    flight, and the new aggregate replaces the cached one when it is done.
    Clients keep the cached list meanwhile: nothing is invalidated.
    """
    global _rebuild_task
    profiles = get_profiles()
    if profiles:
        _rebuild_task = asyncio.ensure_future(_rebuild_in_background(list(profiles.values())))


async def _rebuild_in_background(profiles: list[Profile]) -> None:
    token = l3_priority.set(Priority.BACKGROUND)
    try:
        for profile in profiles:
            # After the build in flight, which may predate the new text. A
            # failed build keeps the cached list, and the build logged why.
            inflight = _profile_inflight.get(profile.name)
            if inflight is not None:
                await asyncio.gather(inflight, return_exceptions=True)
            await asyncio.gather(ensure_profile_build(profile), return_exceptions=True)
    finally:
        l3_priority.reset(token)


set_on_compressed(_rebuild_after_compression)


def invalidate_profile_cache_for_backend(url: str) -> None:
    """Drop any profile aggregate that includes *url* so it rebuilds fresh.

    Used by the reconnect tool: after re-warming a backend's tool cache, a
    profile aggregate assembled while that backend was failing would still
    omit its tools, so it must be evicted even when the backend cache was
    already cold (in which case the eviction cascade never fired).
    """
    _on_backend_evicted(url)


def invalidate_profile_cache(profile_name: str) -> bool:
    """Drop one profile's aggregate so the next tools/list rebuilds it.

    Used by the profile reload: the aggregate was assembled from the Profile
    object that the reload just replaced, so it describes an allowlist that is
    no longer in force. Returns whether a cached aggregate was actually
    dropped — a profile nobody has listed yet has nothing to invalidate.
    """
    _bump(profile_name)
    _profile_backend_urls.pop(profile_name, None)
    forget_surface(profile_name)
    return _profile_tools_cache.pop(profile_name, None) is not None


def reset_profile_tools_cache() -> None:
    """Clear every profile aggregate (for testing).

    Covers the in-flight names too, so a build still running is disowned by
    the generation bump rather than caching into the next test.
    """
    for name in {*_profile_tools_cache, *_profile_backend_urls, *_profile_inflight}:
        invalidate_profile_cache(name)
    _profile_inflight.clear()
    forget_issued_names()
    discovery.reset()


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
    aggregated = _profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await ensure_profile_build(profile)
    return _ok(req_id, {"tools": discovery.shape(profile, aggregated, current_session.get())})


def ensure_profile_build(profile: Profile) -> asyncio.Future[list[dict[str, Any]]]:
    """The profile's aggregate build in flight, started if there is none.

    The one place a build is scheduled, so a client's tools/list and the boot
    warm-up (#216) join the same task instead of racing two.
    """
    inflight = _profile_inflight.get(profile.name)
    if inflight is None:
        # The generation is read HERE, not inside the build: a reload
        # landing between scheduling the task and its first line would
        # otherwise be invisible to it, and the stale aggregate would cache.
        inflight = asyncio.ensure_future(
            _single_flight_build(profile, _cache_generation.get(profile.name, 0))
        )
        _profile_inflight[profile.name] = inflight
    return inflight


async def _single_flight_build(profile: Profile, generation: int) -> list[dict[str, Any]]:
    """Run one aggregation and drop its in-flight slot when done."""
    try:
        return await _build_profile_tools(profile, generation)
    finally:
        _profile_inflight.pop(profile.name, None)


async def _offered_tools(
    backend_name: str, backend: Backend, profile: Profile
) -> list[dict[str, Any]]:
    """A backend's tool list as it is offered, before any filter: ours, the
    profile's own declarations for a decoy, or the remote server's."""
    if backend.is_internal:
        return await list_internal_tools()
    if backend.is_decoy:
        return served_tools(backend)
    return await list_backend_tools(backend_name, backend, profile)


def _without_held(
    backend_name: str, backend: Backend, tools: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """A remote backend's list less the tools pinning holds (#469).

    A new or changed tool is withheld from every profile, an explicit
    allowlist and "*" alike, until an operator approves it. Applied after the
    offered measure: a held tool is still what the backend offers.
    """
    if backend.is_internal or backend.is_decoy:
        return tools
    return tool_pins.check_tools(backend.url, backend_name, tools)


async def _build_profile_tools(
    profile: Profile, generation: int | None = None
) -> list[dict[str, Any]]:
    """Fan out to every backend, aggregate, and cache the assembled list.

    The aggregate is cached only when no backend hard-failed (raised). A
    backend that served a stale list counts as a success; a backend that is
    both cold and unreachable is skipped and suppresses caching, so the profile
    self-heals — the next tools/list re-aggregates and picks it up once it
    recovers. (list_backend_tools single-flights per backend, so re-aggregation
    while a backend is down stays cheap: healthy backends are cache hits and the
    down one is a fast circuit-open reject.)

    The aggregate is also discarded, rather than cached, when the profile was
    invalidated while this build was running — see ``_cache_generation``.
    ``generation`` is that counter as of when this build was SCHEDULED;
    omitting it means "as of now".
    """
    if generation is None:
        generation = _cache_generation.get(profile.name, 0)
    await maybe_trigger_compression()

    async def _fetch_one(
        backend_name: str,
        backend: Backend,
    ) -> tuple[list[dict[str, Any]], BackendSurface]:
        """Fetch, filter, compress, and namespace tools for one backend.

        Also measures the list as offered, as allowed, and as shaped, for the
        surface report (``surface.py``).
        """
        raw_tools = await _offered_tools(backend_name, backend, profile)
        offered = await asyncio.to_thread(Stage.of, raw_tools)
        raw_tools = _without_held(backend_name, backend, raw_tools)
        # An internal tool takes a mode only if it declares one: the admin
        # tools return gateway-authored data that no mode applies to. Every
        # REMOTE tool takes one, because its response crosses the perimeter.
        modal = {
            t.get("name")
            for t in raw_tools
            if not backend.is_internal
            or MODE_PARAM in ((t.get("inputSchema") or {}).get("properties") or {})
        }
        # Ours and any backend's, removed BEFORE the scan and compression and
        # re-inserted after, so gateway text is never judged as backend text.
        raw_tools = [_backend_tool_entry(t, backend) for t in raw_tools]
        filtered = filter_tools(raw_tools, backend)
        allowed = await asyncio.to_thread(Stage.of, filtered)
        pre_compress = filtered
        if backend.compresses_descriptions:
            filtered = compress_tools(filtered)
        # The perimeter, on the post-compression text — compressed
        # descriptions are LLM output and it is the OUTPUT that reaches the
        # agent. This runs whether the list came from the backend live or
        # from the persisted cache, which is what closes the poisoned-cache
        # ingress. Internal tools are included: their DESCRIPTIONS are still
        # a poisoning surface even though their responses defend themselves.
        # A decoy's text is the operator's, from the profile, as a mode's
        # instructions are the gateway's: configuration, not backend output.
        if not backend.is_decoy:
            filtered = await scan_tool_list(profile, backend_name, pre_compress, filtered)
        # After the scan, not before: compaction only deletes, so what the
        # agent reads is a subset of what was judged and no verdict changes.
        if backend.compact_schemas:
            filtered = [compact_tool(t) for t in filtered]
        namespaced: list[dict[str, Any]] = []
        for tool in filtered:
            namespaced_tool = (
                dict(
                    insert_params(
                        tool,
                        policy_for(profile, backend, tool["name"]),
                        declare=profile.declare_modes,
                    )
                )
                if tool.get("name") in modal
                else dict(tool)
            )
            namespaced_tool = dict(
                insert_preprocess(
                    namespaced_tool, preprocess_policy_for(profile, backend, tool["name"])
                )
            )
            namespaced_tool = discovery.describe(profile, backend_name, namespaced_tool)
            namespaced_tool["name"] = f"{backend_name}{NAMESPACE_SEP}{tool['name']}"
            namespaced.append(namespaced_tool)
        shaped = await asyncio.to_thread(Stage.of, namespaced)
        return namespaced, BackendSurface(offered, allowed, shaped)

    tasks = [_fetch_one(name, backend) for name, backend in profile.backends.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    aggregated: list[dict[str, Any]] = []
    measured: dict[str, BackendSurface] = {}
    any_hard_failed = False
    for (backend_name, _backend), outcome in zip(
        profile.backends.items(),
        results,
        strict=True,
    ):
        if isinstance(outcome, BaseException):
            any_hard_failed = True
            logger.warning(
                "gateway: tools/list profile=%s backend=%s skipped: %s",
                profile.name,
                backend_name,
                exc_kind(outcome),
            )
            continue
        tools, measured[backend_name] = outcome
        aggregated.extend(tools)

    aggregated = serve_short_names(profile, aggregated)
    # Measured BEFORE the generation check: an await between the check and
    # the write would let an invalidation land in between and a stale
    # surface outlive the aggregate it describes.
    served = await asyncio.to_thread(Stage.of, aggregated)
    if not any_hard_failed and generation == _cache_generation.get(profile.name, 0):
        _profile_tools_cache[profile.name] = aggregated
        record_surface(profile.name, Surface(measured, served))
        _profile_backend_urls[profile.name] = {
            b.url for b in profile.backends.values() if b.is_remote
        }
    return aggregated


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
    aggregated = _profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await ensure_profile_build(profile)
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


def _backend_tool_entry(tool: dict[str, Any], backend: Backend) -> dict[str, Any]:
    """The entry without any ``trentina_*`` param, nor, from a remote backend, reserved keys.

    A backend's own tool entry may not carry the gateway's markers (#265);
    the perimeter adds the real one after it judges the entry.
    """
    tool = strip_params(tool)
    return tool if backend.is_internal else _strip_tool(tool)


def _strip_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """A backend's tool entry without reserved keys; the same object when it had none.

    Copied before stripping: the entry may be the tool-list cache's own.
    """
    if not reserved_sites(tool):
        return tool
    copied = copy.deepcopy(tool)
    count = strip_reserved(copied)
    logger.info(
        "gateway: stripped %d reserved key(s) from tool %s",
        count,
        redact_source(str(tool.get("name"))),
    )
    return copied
