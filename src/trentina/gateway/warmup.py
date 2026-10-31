"""Boot warm-up: judge every profile's tool descriptions before anyone asks (#216).

On a cold perimeter store the first ``tools/list`` judges every tool
description through all three layers, and a client times out waiting for it
(#104). The warm-up starts that work as soon as the event loop serves,
through the same single-flight build a client's ``tools/list`` uses
(``router.ensure_profile_build``), so a client connecting mid-warm-up joins
the work in flight instead of starting its own.

Before it builds anything it refetches every tool list that was loaded from
SQLite (#335), so the aggregates, and the schemas arguments are checked
against, are what the backends list now and not what they listed before the
restart.

It runs as background L3 work: user-facing scans are granted limiter slots
first, and it may wait out a provider's throttling far longer than a user
call would, because nobody is waiting on it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Any

from ..logsafe import exc_kind, exc_where
from ..quarantine.limiter import Priority, all_limiters, l3_priority, l3_throttle_budget
from .aggregate import (
    ensure_profile_build,
    invalidate_profile_cache_for_backend,
    rebuild_profiles,
)
from .backend import revalidate_backend_tools
from .loader import get_active_config
from .verdict_cache import perimeter_counts

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

# Seconds one L3 call in the warm-up may spend waiting out 429s before the
# fallback chain moves on.
WARMUP_THROTTLE_BUDGET = 300.0

_task: asyncio.Task[None] | None = None

# The downstream federation poll (#592, F3): one shared task, started beside
# _task, that re-probes federated backends on their own cadence so an approved
# or changed upstream tool appears without a manual reconnect. It idle-ticks
# when nothing sets poll_seconds.
IDLE_TICK = 60.0
_poll_task: asyncio.Task[None] | None = None
_next_due: dict[str, float] = {}


async def warm_all() -> None:
    """Build every profile's aggregate, then log one summary line."""
    active = get_active_config()
    if active is None:
        return
    priority = l3_priority.set(Priority.BACKGROUND)
    budget = l3_throttle_budget.set(WARMUP_THROTTLE_BUDGET)
    profiles = list(active.config.profiles.values())
    try:
        await _revalidate_tool_lists(profiles)
        await _warm(profiles)
    finally:
        l3_priority.reset(priority)
        l3_throttle_budget.reset(budget)


async def _revalidate(backends: dict[str, tuple[str, Backend, Profile]]) -> list[str]:
    """Refetch each backend's tool list, once per URL, all at once; return the
    URLs whose list changed. A backend that cannot be reached keeps its cached
    list (``revalidate_backend_tools`` returns False there). The owning profile
    is passed so a federated backend can mint its edge JWT — without it the
    probe goes out unauthenticated and the upstream rejects it."""
    changed = await asyncio.gather(
        *(
            revalidate_backend_tools(name, backend, profile)
            for name, backend, profile in backends.values()
        )
    )
    return [url for url, differs in zip(backends, changed, strict=True) if differs]


async def _revalidate_tool_lists(profiles: list[Profile]) -> None:
    """Refetch every remote backend's persisted tool list at warm-up.

    A client that listed tools while this ran was served the persisted list;
    its aggregate is dropped when the backend's list turned out to differ, and
    ``_warm`` rebuilds it next.
    """
    backends: dict[str, tuple[str, Backend, Profile]] = {}
    for profile in profiles:
        for name, backend in profile.backends.items():
            if backend.is_remote:
                backends.setdefault(backend.url, (name, backend, profile))
    stale = await _revalidate(backends)
    for url in stale:
        invalidate_profile_cache_for_backend(url)
    logger.warning(
        "warm-up: revalidated the tool lists of %d backends, %d changed since they were cached",
        len(backends),
        len(stale),
    )


async def _poll_once(now: float) -> float:
    """One federation-poll tick. Re-probe the federated backends whose interval
    has elapsed, rebuild the profiles that share a changed one, and return the
    seconds to sleep before the next tick.

    ``get_active_config`` is read every call: a reload swaps the Profile
    objects, so a captured list would go stale. ``_next_due`` is seeded at
    ``now + poll_seconds`` for a URL first seen here — the warm-up just
    revalidated it — and pruned when a URL stops being polled.
    """
    active = get_active_config()
    if active is None:
        return IDLE_TICK
    profiles = list(active.config.profiles.values())
    polled: dict[str, tuple[str, Backend, Profile]] = {}
    interval: dict[str, int] = {}
    for profile in profiles:
        for name, backend in profile.backends.items():
            fed = backend.federated
            if backend.is_remote and fed is not None and fed.poll_seconds > 0:
                polled.setdefault(backend.url, (name, backend, profile))
                interval[backend.url] = fed.poll_seconds
    for url in [u for u in _next_due if u not in polled]:
        del _next_due[url]
    for url, secs in interval.items():
        _next_due.setdefault(url, now + secs)
    due = {url: nb for url, nb in polled.items() if _next_due[url] <= now}
    if due:
        stale = await _revalidate(due)
        for url in due:
            _next_due[url] = now + interval[url]
        if stale:
            stale_urls = set(stale)
            sharing = [
                p for p in profiles if any(b.url in stale_urls for b in p.backends.values())
            ]
            rebuilt = await rebuild_profiles(sharing)
            logger.warning(
                "federation poll: %d backend(s) changed, rebuilt %d profile(s)",
                len(stale),
                rebuilt,
            )
    return max(1.0, min(_next_due.values()) - now) if _next_due else IDLE_TICK


async def _poll_tool_lists() -> None:
    """The federation poll loop (#592, F3). One shared task; background L3
    priority like the warm-up, so a rebuild it triggers never competes with a
    user call. A single bad tick is logged by kind and the loop carries on.
    """
    priority = l3_priority.set(Priority.BACKGROUND)
    budget = l3_throttle_budget.set(WARMUP_THROTTLE_BUDGET)
    try:
        while True:
            try:
                sleep_for = await _poll_once(time.monotonic())
            except Exception as exc:
                logger.warning(
                    "federation poll: tick failed: %s at %s", exc_kind(exc), exc_where(exc)
                )
                sleep_for = IDLE_TICK
            await asyncio.sleep(sleep_for)
    finally:
        l3_priority.reset(priority)
        l3_throttle_budget.reset(budget)


async def _warm(profiles: list[Profile]) -> None:
    judged, hits = perimeter_counts["judged"], perimeter_counts["hits"]
    started = time.monotonic()
    # WARNING, like the startup cache line: production runs at WARNING, and
    # these two lines are what an operator reads after a cold restart.
    logger.warning("warm-up: judging tool descriptions for %d profiles", len(profiles))

    # Each build task copies this context, so its L3 calls queue as
    # background work. A client that joins one mid-flight shares that.
    results = await asyncio.gather(
        *(ensure_profile_build(p) for p in profiles), return_exceptions=True
    )
    tools = 0
    for profile, outcome in zip(profiles, results, strict=True):
        if isinstance(outcome, BaseException):
            # The kind only: a provider or backend error can carry the
            # request, a key, or a backend's own text (#262).
            logger.warning(
                "warm-up: profile=%s failed: %s at %s",
                profile.name,
                exc_kind(outcome),
                exc_where(outcome),
            )
        else:
            tools += len(outcome)

    logger.warning(
        "warm-up: done in %.1fs — profiles=%d tools=%d judged=%d cached=%d l3=%s",
        time.monotonic() - started,
        len(profiles),
        tools,
        perimeter_counts["judged"] - judged,
        perimeter_counts["hits"] - hits,
        _limiter_summary(),
    )


def _limiter_summary() -> str:
    snaps: list[dict[str, Any]] = [lim.snapshot() for lim in all_limiters()]
    if not snaps:
        return "idle"
    return ",".join(f"{s['judge']}(limit={s['limit']},throttles={s['throttles']})" for s in snaps)


@contextlib.asynccontextmanager
async def trentina_lifespan() -> AsyncIterator[dict[str, Any]]:
    """FastMCP lifespan: start the warm-up once serving begins; stop it on exit.

    Standalone (no gateway) there is nothing to warm, and this does nothing.
    FastMCP ref-counts its lifespan, but the module-level task still guards
    against a second warm-up if it is ever entered twice.
    """
    global _task, _poll_task
    started_here = False
    if get_active_config() is not None and _task is None:
        _task = asyncio.create_task(warm_all(), name="trentina-warmup")
        _poll_task = asyncio.create_task(_poll_tool_lists(), name="trentina-fed-poll")
        started_here = True
    # Warm the pinned-connection TLS context on a worker thread, so the system
    # CA bundle is loaded here at startup and never on the event loop during the
    # first /egress, /git or fetch request (egress.shared_ssl_context, #511).
    from ..reach.egress import shared_ssl_context

    await asyncio.to_thread(shared_ssl_context)

    # The client-egress listener (#442), on the loop that serves. A no-op
    # unless startup configured one.
    from . import client_egress

    await client_egress.start()
    try:
        yield {}
    finally:
        await client_egress.stop()
        # Close the pinned connection pool's long-lived clients (#511, Phase 2).
        from .upstream import close_pool

        await close_pool()
        if started_here and _task is not None:
            _task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _task
            _task = None
        if started_here and _poll_task is not None:
            _poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _poll_task
            _poll_task = None
        # The Matrix bridges' clients and mapping stores (a no-op without one).
        from .matrix_bridge.routes import close_bridges

        await close_bridges()
