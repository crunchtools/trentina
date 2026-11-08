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
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from .. import perimeter_db
from ..logsafe import exc_kind, exc_where
from ..quarantine.limiter import Priority, all_limiters, l3_priority, l3_throttle_budget
from .aggregate import (
    ensure_profile_build,
    invalidate_profile_cache_for_backend,
    rebuild_profiles,
)
from .backend import cache_owner, revalidate_backend_tools
from .loader import get_active_config
from .sessions import session_registry
from .tool_pins import backend_id
from .verdict_cache import perimeter_counts

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

# Seconds one L3 call in the warm-up may spend waiting out 429s before the
# fallback chain moves on.
WARMUP_THROTTLE_BUDGET = 300.0

_task: asyncio.Task[None] | None = None

# The tool-list poll: one shared task, started beside _task, that re-lists
# every remote backend on its own cadence so a tool a redeploy added, or an
# approved or changed secondary tool (#592, F3), appears in open sessions
# without a manual reconnect (#752). It idle-ticks when nothing is polled.
IDLE_TICK = 60.0
_poll_task: asyncio.Task[None] | None = None
_next_due: dict[str, float] = {}


# The pending-pin count `/health` reports (#662). The probe reads
# `perimeter_db.pending_pins_cached` and never waits; this task keeps it. Its
# own one-thread pool, not the default executor, which L1 and the tokenizer use:
# a wedged store would otherwise park one default-pool thread per refresh.
PINS_REFRESH_SECONDS = 15.0
PINS_TIMEOUT_SECONDS = 5.0
_pins_task: asyncio.Task[None] | None = None
_pins_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="trentina-pins")


def _count_pins(path: str, backend_ids: set[str]) -> int:
    with perimeter_db.snapshot_reader(path):
        return perimeter_db.count_pending_pins(backend_ids)


async def refresh_pending_pins(
    inflight: asyncio.Future[int] | None = None,
) -> asyncio.Future[int] | None:
    """One refresh of ``perimeter_db.pending_pins_cached``; returns the call in flight.

    Single-flight: while the previous call has not returned (a wedged store) no
    second one is submitted, and the cache reads None. Never raises.
    """
    active = get_active_config()
    if inflight is None or inflight.done():
        ids = {
            backend_id(b.url)
            for p in (active.config.profiles.values() if active else ())
            for b in p.backends.values()
        }
        try:
            path = perimeter_db.opened_path()
        except Exception as exc:
            perimeter_db.pending_pins_cached = None
            logger.warning("pending pins: refresh failed: %s", exc_kind(exc))
            return None
        inflight = asyncio.get_running_loop().run_in_executor(_pins_pool, _count_pins, path, ids)
    try:
        perimeter_db.pending_pins_cached = await asyncio.wait_for(
            asyncio.shield(inflight), PINS_TIMEOUT_SECONDS
        )
    except Exception as exc:
        perimeter_db.pending_pins_cached = None
        logger.warning("pending pins: refresh failed: %s", exc_kind(exc))
    return inflight


async def _refresh_pins_forever() -> None:
    inflight: asyncio.Future[int] | None = None
    while True:
        inflight = await refresh_pending_pins(inflight)
        await asyncio.sleep(PINS_REFRESH_SECONDS)


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
    """Refetch each backend's tool list, once per key, all at once; return the
    keys whose list changed. A backend that cannot be reached keeps its cached
    list (``revalidate_backend_tools`` returns False there). The owning profile
    is passed so a federated backend can mint its primary JWT — without it the
    probe goes out unauthenticated and the secondary rejects it."""
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
    ``_warm`` rebuilds it next. One refetch per cache partition, as the poll
    keys them: per URL alone, a header-credentialed backend was refetched as
    the first profile only and every other profile kept its pre-restart list.
    """
    backends: dict[str, tuple[str, Backend, Profile]] = {}
    for profile in profiles:
        for name, backend in profile.backends.items():
            if backend.is_remote:
                backends.setdefault(_poll_key(backend, profile), (name, backend, profile))
    stale = await _revalidate(backends)
    for key in stale:
        invalidate_profile_cache_for_backend(backends[key][1].url)
    logger.warning(
        "warm-up: revalidated the tool lists of %d backends, %d changed since they were cached",
        len(backends),
        len(stale),
    )


def _poll_interval(backend: Backend) -> int:
    """Seconds between background re-lists of ``backend``; 0 when it is not polled.

    An ``auth`` backend is never polled: there is no grant to fetch it with
    outside a call, and ``revalidate_backend_tools`` would skip it anyway.
    """
    if not backend.is_remote or backend.auth is not None:
        return 0
    if backend.federated is not None:
        return backend.federated.poll_seconds
    return backend.poll_seconds


def _poll_key(backend: Backend, profile: Profile) -> str:
    """One poll slot per cache partition, as ``backend._inflight_key`` keys a fetch.

    Keyed by URL alone, a backend carrying header credentials was re-listed as
    whichever profile came first, and every other profile's partition kept the
    list from before the redeploy.
    """
    owner = cache_owner(backend, profile)
    return f"{backend.url}#{owner}" if owner else backend.url


async def _poll_once(now: float) -> float:
    """One tool-list poll tick. Re-list the backends whose interval has
    elapsed, rebuild the profiles that read a changed list, tell their open
    sessions with ``tools/list_changed``, and return the seconds to sleep
    before the next tick.

    ``get_active_config`` is read every call: a reload swaps the Profile
    objects, so a captured list would go stale. ``_next_due`` is seeded at
    ``now + interval`` for a slot first seen here — the warm-up just
    revalidated it — and pruned when a slot stops being polled.
    """
    active = get_active_config()
    if active is None:
        return IDLE_TICK
    polled, interval, readers = _poll_slots(list(active.config.profiles.values()))
    for key in [k for k in _next_due if k not in polled]:
        del _next_due[key]
    for key, secs in interval.items():
        _next_due.setdefault(key, now + secs)
    due = {key: nb for key, nb in polled.items() if _next_due[key] <= now}
    if due:
        stale = await _revalidate(due)
        for key in due:
            _next_due[key] = now + interval[key]
        if stale:
            await _rebuild_and_notify(stale, readers)
    return max(1.0, min(_next_due.values()) - now) if _next_due else IDLE_TICK


def _poll_slots(
    profiles: list[Profile],
) -> tuple[dict[str, tuple[str, Backend, Profile]], dict[str, int], dict[str, list[Profile]]]:
    """Each poll slot's backend to re-list (with the profile to fetch it as),
    its interval — the shortest any reader asked for — and every profile that
    reads it."""
    polled: dict[str, tuple[str, Backend, Profile]] = {}
    interval: dict[str, int] = {}
    readers: dict[str, list[Profile]] = {}
    for profile in profiles:
        for name, backend in profile.backends.items():
            secs = _poll_interval(backend)
            if secs <= 0:
                continue
            key = _poll_key(backend, profile)
            polled.setdefault(key, (name, backend, profile))
            interval[key] = min(secs, interval.get(key, secs))
            readers.setdefault(key, []).append(profile)
    return polled, interval, readers


async def _rebuild_and_notify(stale: list[str], readers: dict[str, list[Profile]]) -> None:
    """Rebuild the profiles that read a changed list, then push their open
    sessions ``tools/list_changed``: a client caches its list until told, so a
    rebuilt aggregate alone reached only the next client to connect (#752)."""
    sharing = list({p.name: p for key in stale for p in readers[key]}.values())
    rebuilt = await rebuild_profiles(sharing)
    notified = 0
    for profile in sharing:
        notified += await session_registry.broadcast_tools_changed(profile.name)
    logger.warning(
        "tool-list poll: %d backend(s) changed, rebuilt %d profile(s), notified %d session(s)",
        len(stale),
        rebuilt,
        notified,
    )


async def _poll_tool_lists() -> None:
    """The tool-list poll loop (#592 F3, #752). One shared task; background L3
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
                    "tool-list poll: tick failed: %s at %s", exc_kind(exc), exc_where(exc)
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
    global _task, _poll_task, _pins_task
    started_here = False
    if get_active_config() is not None and _task is None:
        _pins_task = asyncio.create_task(_refresh_pins_forever(), name="trentina-pins")
        _task = asyncio.create_task(warm_all(), name="trentina-warmup")
        _poll_task = asyncio.create_task(_poll_tool_lists(), name="trentina-tool-poll")
        started_here = True
    # Warm the pinned-connection TLS context on a worker thread, so the system
    # CA bundle is loaded here at startup and never on the event loop during the
    # first /egress, /git or fetch request (egress.shared_ssl_context, #511).
    from ..reach.egress import shared_ssl_context

    await asyncio.to_thread(shared_ssl_context)

    # The perimeter's listeners (#442, #535), on the loop that serves. A no-op
    # unless startup configured one and a profile asked for it.
    from ..transports.registry import start_listeners, stop_listeners

    await start_listeners()
    try:
        yield {}
    finally:
        await stop_listeners()
        # Close the pinned connection pool's long-lived clients (#511, Phase 2).
        from .upstream import close_pool

        await close_pool()
        if started_here and _task is not None:
            _task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _task
            _task = None
        if started_here and _pins_task is not None:
            _pins_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _pins_task
            _pins_task = None
        if started_here and _poll_task is not None:
            _poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await _poll_task
            _poll_task = None
        # The Matrix bridges' clients and mapping stores (a no-op without one).
        from .matrix_bridge.routes import close_bridges

        await close_bridges()
