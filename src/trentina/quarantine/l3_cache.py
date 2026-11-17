"""One L3 detection per identical judgement, shared for a few minutes.

Gatehouse runs eight review agents in parallel and each sends its provider the
same diff through ``/proxy/llm``: eight identical outbound requests, so eight
identical L3 judgements and eight bills for one answer. This keeps one.

The key is a hash of exactly what L3 is handed (the content, and the briefing
built from L1's and L2's findings on it) plus the layer and the model config
that reads it: provider, model and fallback chain, as the call itself resolves
them. Two calls with one key send the same bytes to the same judge, so they get
the same verdict. ``_single_flight`` makes concurrent callers share the one call
in flight rather than race into eight; a finished verdict is kept for
``TTL_SECONDS`` in a cache of at most ``MAX_ENTRIES``.

Isolation. The key holds no profile, on purpose, and it is safe for one
reason: a hit needs the caller to already HOLD the identical bytes. No profile
can read another profile's content through this cache, only reuse a verdict on
bytes it sent itself. What a hit can tell it is that someone had those exact
bytes judged in the last ten minutes (a hit answers sooner), which needs the
whole document guessed byte for byte. The call is billed to the key of
whichever profile started the flight.

Only a complete verdict is kept. An ``l3_unavailable`` result reaches the
callers already waiting on that flight and nobody else: the next caller asks
the judge again.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..errors import QuarantineAgentError
from ..logsafe import exc_kind, exc_where
from .agent import bound_profile, resolve_profile_llm

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

logger = logging.getLogger(__name__)

#: How long a complete verdict is reused. Long enough to cover a burst of
#: parallel agents and their retries, short enough that a judge or prompt
#: change reaches every caller within minutes.
TTL_SECONDS = 600.0

#: Verdicts kept at once. A verdict is a small dict; the bound is against a
#: process lifetime of distinct content, not against one burst.
MAX_ENTRIES = 1024

_LAYER = "L3:detection"

_verdicts: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}

#: Judgements run vs. served from the cache or a shared flight, since start.
l3_counts: dict[str, int] = {"judged": 0, "shared": 0}


def judgement_key(content: str, briefing: str) -> str | None:
    """The cache key for judging ``content`` with ``briefing``, or None.

    None when the bound profile has no judge to resolve: that call is left to
    fail in ``quarantine_detect`` the way it always did, uncached.
    """
    try:
        provider, _key, model = resolve_profile_llm(bound_profile())
    except QuarantineAgentError:
        return None
    # The fallback chain is part of the model config: a verdict a fallback
    # reached is not the one a caller with no fallback would get. The key
    # itself never enters the hash; which profile pays is not what is judged.
    config = [_LAYER, provider, model or "", list(get_config().provider_fallback)]
    digest = hashlib.sha256(json.dumps(config).encode())
    for part in (briefing, content):
        digest.update(b"\0")
        digest.update(part.encode("utf-8", errors="surrogatepass"))
    return digest.hexdigest()


async def detect_once(
    content: str,
    briefing: str,
    detect: Callable[[], Coroutine[Any, Any, dict[str, Any]]],
) -> dict[str, Any]:
    """``detect()``'s verdict, from the cache, a flight in progress, or a new call.

    Each caller gets its own copy, so one caller annotating its verdict cannot
    change another's.
    """
    key = judgement_key(content, briefing)
    if key is None:
        return await detect()
    hit = _verdicts.get(key)
    if hit is not None and time.monotonic() - hit[0] < TTL_SECONDS:
        _verdicts.move_to_end(key)
        l3_counts["shared"] += 1
        return copy.deepcopy(hit[1])
    if key in _inflight:
        l3_counts["shared"] += 1
    return copy.deepcopy(await _single_flight(key, functools.partial(_judge, key, detect)))


async def _judge(
    key: str, detect: Callable[[], Coroutine[Any, Any, dict[str, Any]]]
) -> dict[str, Any]:
    """Run the judgement once and keep it if it is complete."""
    l3_counts["judged"] += 1
    verdict = await detect()
    if not verdict.get("l3_unavailable"):
        _verdicts[key] = (time.monotonic(), copy.deepcopy(verdict))
        _verdicts.move_to_end(key)
        while len(_verdicts) > MAX_ENTRIES:
            _verdicts.popitem(last=False)
    return verdict


async def _single_flight(
    key: str, work: Callable[[], Coroutine[Any, Any, dict[str, Any]]]
) -> dict[str, Any]:
    """Run ``work`` once per ``key``; every concurrent caller gets its result.

    The work is its own task and each caller awaits it through ``shield``, as
    ``gateway.verdict_cache`` does: a caller whose deadline passes leaves the
    judgement running for the others and banked for the next caller, rather
    than cancelling it for everyone.
    """
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(work())
        _inflight[key] = task
        task.add_done_callback(functools.partial(_settle, key))
    return await asyncio.shield(task)


def _settle(key: str, task: asyncio.Task[dict[str, Any]]) -> None:
    """Free the key, and surface a failure no waiter stayed to see."""
    if _inflight.get(key) is task:
        del _inflight[key]
    if not task.cancelled() and (exc := task.exception()) is not None:
        # The kind only: the exception can carry the judged content (#262).
        logger.warning(
            "l3: shared judgement failed for key=%s: %s at %s",
            key[:12],
            exc_kind(exc),
            exc_where(exc),
        )


def reset_l3_cache() -> None:
    """Forget every verdict and flight (for testing)."""
    _verdicts.clear()
    _inflight.clear()
    l3_counts.update(judged=0, shared=0)
