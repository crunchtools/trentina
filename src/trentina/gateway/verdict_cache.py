"""The perimeter's verdict cache and its single-flight judging.

A content-hash verdict cache keeps the perimeter's cost sane: ~210 tool
descriptions are rebuilt on every circuit-breaker flap, and agents re-read the
same tickets all day. Verdicts are cached per (defence-config, content) pair; a
cache hit re-records nothing.

Tool-description verdicts also OUTLIVE the process, in ``perimeter_db`` — a
store of its own, not a table beside the blocklist. Judging them from cold took
over five minutes, which every MCP client reports as a timeout rather than as a
warm-up. Responses stay in memory: unbounded, mostly seen once, and not what a
restart pays for.

``_single_flight`` runs one judgement per key at a time, so two clients listing
tools at the same moment do not both run the whole pipeline on the same
description. The cache and the single-flight registry live here, apart from the
edges that read them (``tool_list_edge``, the proxied-response edge), so the one
place that decides staleness and persistence is one module.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..logsafe import exc_kind, exc_where
from ..quarantine.packs import GENERIC_ID, pack_for
from .service import judge_of

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from .profile import Profile

logger = logging.getLogger(__name__)

_CACHE_MAX = 4096

# A COMPLETE verdict is a pure function of (detector set, defence config,
# content), and all three are pinned — the first by the row's version
# stamp, the other two by the cache key. So it does not go stale and does
# not expire. It used to, on a 900-second TTL, which meant fifteen quiet
# minutes re-armed a full rescan of every tool description.
_verdicts: OrderedDict[str, dict[str, Any] | None] = OrderedDict()

# Set when the store refuses a write. A read-only or full disk fails the
# same way for every subsequent verdict, and retrying 200 more times per
# boot turns one logged problem into a flood.
_persist_broken = False


def load_verdict_cache() -> int:
    """Populate the verdict cache from the perimeter store at startup.

    Without this, every restart re-judges ~210 tool descriptions through
    L1, L2 and L3 before the first ``tools/list`` can answer — measured at
    over five minutes, which every MCP client reports as a timeout rather
    than as a warm-up.

    On the trust question: the store is owned by this process's own uid, so
    an attacker able to write it can equally rewrite this dict in memory,
    the code, or the image. Re-deriving every verdict on each boot defends
    only against someone who has already won. The version stamp covers the
    case that actually happens — a row written by an older perimeter.
    """
    from ..perimeter_db import get_all_verdicts, perimeter_stamp

    global _persist_broken
    _persist_broken = False

    loaded = get_all_verdicts(perimeter_stamp())
    _verdicts.update(loaded)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)
    logger.info("perimeter: loaded %d cached verdict(s)", len(_verdicts))
    return len(_verdicts)


def reset_verdict_cache() -> None:
    """Clear the in-memory cache without touching the store (for testing)."""
    global _persist_broken
    _verdicts.clear()
    _inflight.clear()
    _persist_broken = False


def _cache_key(profile: Profile, kind: str, text: str, judge: tuple[str, str]) -> str:
    """The verdict key: what was judged, under which thresholds, by which model.

    ``profile`` supplies the thresholds — a profile's gate stays its own.
    ``judge`` is the (provider, model) L3 ran on (#137): without it, a verdict
    one model reached was served to a profile running another.

    The judge is written into the key ONLY when it differs from the env
    default. Every key persisted before #137 was judged by the env default —
    the tools/list path had no profile bound, and every lotor profile ran the
    default — so that judge keeps the old spelling and the stored verdicts
    stay reachable. Spelling it out would have cost a cold, minutes-long
    re-judgement of every description on the first boot of this version.

    The provider fallback chain can let a different model answer one call;
    that verdict is still filed under the primary judge. The chain is
    gateway-wide config, so this cannot carry a verdict across profiles.
    """
    d = profile.defense
    # Unset defers to the model's own threshold, which the store's stamp
    # carries (#350); an explicit one keeps its pre-0.55 spelling.
    pack = pack_for(judge, d.l3_prompt_pack)
    effort = get_config().reasoning_effort
    # Each part is written only when it differs from the default, so a key
    # stored before that part existed still matches. The pack is named by id
    # and text (#354): editing a prompt sweeps the verdicts it reached. How
    # long the judge thinks changes what it concludes, so that is here too.
    parts = {
        "model" if d.l2_threshold is None else f"{d.l2_threshold}": True,
        f"{judge[0]}/{judge[1]}": judge != judge_of(None),
        f"pack={pack.stamp}": pack.id != GENERIC_ID,
        f"effort={effort}": effort is not None,
    }
    cfg = ":".join(part for part, written in parts.items() if written)
    return hashlib.sha256(f"{kind}:{cfg}:{text}".encode()).hexdigest()


def _cache_get(key: str) -> tuple[bool, dict[str, Any] | None]:
    hit = key in _verdicts
    if hit:
        _verdicts.move_to_end(key)
    return hit, _verdicts.get(key)


def _cache_put(key: str, value: dict[str, Any] | None, *, persist: bool = False) -> None:
    """Remember one verdict, and for tool descriptions write it down.

    ``persist`` is set only by ``scan_tool_list``. Tool descriptions are
    what a restart pays for — a bounded set of a few hundred, judged again
    on every boot and every circuit-breaker flap. Tool RESPONSES are
    unbounded and mostly seen once, so persisting them would put a disk
    write in the hot path of every proxied call to buy a hit rate near
    zero. They stay in memory, where the LRU already bounds them.
    """
    global _persist_broken

    # A verdict reached while L3 was unavailable, or while L2 truncated its
    # input, is NOT the verdict the perimeter would reach today. Keeping it
    # would let an outage's "clean" outlive the outage. This is the one
    # thing the old TTL was really buying, and refusing the verdict outright
    # buys it without the recurring rescan.
    if value is not None and (
        value.get("l3_unavailable")
        or value.get("l3_truncated")
        or value.get("l2_truncated")
        or value.get("l2_unavailable")
        or value.get("oversize")
    ):
        return

    _verdicts[key] = value
    _verdicts.move_to_end(key)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)

    if not persist or _persist_broken:
        return
    try:
        from ..perimeter_db import perimeter_stamp, save_verdict

        save_verdict(key, value, perimeter_stamp())
    except Exception:
        # A store that cannot be written is a slow next boot, not a wrong
        # answer, and must never cost the request in front of us. Stop
        # trying: whatever broke the write breaks the next two hundred.
        _persist_broken = True
        # nosemgrep: trentina-log-exception-text -- logsafe: ours
        logger.warning(  # logsafe: ours — a sqlite write of the gateway's own rows
            "perimeter: cannot write the verdict store; verdicts will not survive this restart",
            exc_info=True,
        )


# One judgement per key in flight (#120). Two clients listing tools at the
# same moment used to miss the cache together and both run the whole pipeline
# on the same description; a backend redeploy made every profile do it at once.
_inflight: dict[str, asyncio.Task[dict[str, Any] | None]] = {}

# Descriptions judged vs. served from the verdict cache since start — read
# as a difference by the boot warm-up's summary line.
perimeter_counts: dict[str, int] = {"judged": 0, "hits": 0}


async def _single_flight(
    key: str, work: Callable[[], Coroutine[Any, Any, dict[str, Any] | None]]
) -> dict[str, Any] | None:
    """Run ``work`` once per ``key``; every concurrent caller gets its result.

    Anything that should happen once per judgement — the cache write, the
    journal line — belongs inside ``work``, not in the callers: the caller
    that started it may be long gone by the time it finishes.

    The work is its own task and each caller awaits it through ``shield``: a
    caller that disconnects or times out leaves the judgement running and its
    verdict banked, rather than cancelling it for everyone and starting over on
    the next reconnect. A failure reaches every waiter and caches nothing —
    ``_cache_put`` already refuses degraded verdicts, and an exception never
    reaches it.
    """
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(work())
        _inflight[key] = task
        task.add_done_callback(functools.partial(_settle, key))
    return await asyncio.shield(task)


def _settle(key: str, task: asyncio.Task[dict[str, Any] | None]) -> None:
    """Free the key, and surface a failure no waiter stayed to see."""
    if _inflight.get(key) is task:
        del _inflight[key]
    if not task.cancelled() and (exc := task.exception()) is not None:
        # The kind only: an exception from a provider call can carry the
        # request, which carries a key and a backend's description (#262).
        logger.warning(
            "perimeter: judgement failed for key=%s: %s at %s",
            key[:12],
            exc_kind(exc),
            exc_where(exc),
        )
