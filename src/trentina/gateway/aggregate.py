"""The per-profile ``tools/list`` aggregate and its cache.

Builds a profile's served tool list across its backends — allowlist-filtered,
namespaced, compressed, perimeter-judged — behind a per-profile single-flight
and a cache invalidated on reload, compression and backend eviction. The
hand-rolled ``gateway/router.py`` owned this; it lives here so the MCP transport
and ``tools/*``/``warmup`` reach it without the router (PR3b, Trentina 3.0
Phase 7), which this change deletes.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from typing import TYPE_CHECKING, Any

from ..logsafe import exc_kind, redact_source
from ..quarantine.limiter import Priority, l3_priority
from ..reserved import (
    reserved_sites,
    strip_reserved,
)
from . import discovery, tool_pins
from .backend import (
    _federated_held_upstream,
    list_backend_tools,
    on_backend_cache_evict,
)
from .compress import (
    compress_tools,
    get_profiles,
    maybe_trigger_compression,
    set_on_compressed,
)
from .decoy import served_tools
from .filter import filter_tools
from .internal import list_internal_tools
from .modes_policy import (
    MODE_PARAM,
    insert_params,
    insert_preprocess,
    policy_for,
    preprocess_policy_for,
    strip_params,
)
from .names import (
    NAMESPACE_SEP,
    forget_issued_names,
    serve_short_names,
)
from .schema_compact import compact_tool
from .sessions import session_registry
from .surface import (
    BackendSurface,
    Stage,
    Surface,
    forget_surface,
    record_surface,
)
from .tool_list_edge import scan_tool_list

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

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


def _held_in_allowed_slice(
    backend: Backend, offered: list[dict[str, Any]], unheld: list[dict[str, Any]]
) -> int:
    """How many HELD tools would otherwise be in this profile's allowed slice (#592, E1c).

    The surface's ``allowed`` is measured after both the hold filter and the
    allowlist, so it cannot tell a hold from an allowlist drop. This counts the
    held tools (offered minus unheld) that also pass the allowlist — the number
    a federation ingress reports to a downstream as "held upstream", scoped to
    the caller's own slice so no hold from another profile leaks.
    """
    if backend.is_internal or backend.is_decoy:
        return 0
    unheld_names = {t.get("name") for t in unheld}
    held = [t for t in offered if t.get("name") not in unheld_names]
    if not held:
        return 0
    entries = [_backend_tool_entry(t, backend) for t in held]
    return len(filter_tools(entries, backend))


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
        unheld = _without_held(backend_name, backend, raw_tools)
        held_count = _held_in_allowed_slice(backend, raw_tools, unheld)
        raw_tools = unheld
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
        return namespaced, BackendSurface(
            offered,
            allowed,
            shaped,
            held=held_count,
            held_upstream=(
                _federated_held_upstream.get(backend.url) if backend.federated else None
            ),
        )

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
