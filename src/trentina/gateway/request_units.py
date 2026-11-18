"""The ``/proxy/llm`` request judged a message at a time, each message once.

Gatehouse sends up to two dozen review calls at once, each the same diff behind
its own reviewer prompt. Judged as one document, every call was a different
document: L2 read the identical diff once per call, two scans at a time behind
``TRENTINA_L2_CONCURRENCY`` on cores those two already filled. A burst of 18
finished four scans in 20 s and timed the other 14 out unjudged (a341). A
conversation agent pays the same way across turns: every turn re-reads the
messages the last turn already judged.

So the request is cut into units (``request_units``): the frame (method, path,
headers and the body with its conversation emptied) and each conversation
message. Each unit is judged on its own through ``judge_outbound``; identical
units in flight share one judgement, and a finished one is kept for
``TTL_SECONDS``, refreshed on use. The request's verdict is the units' verdicts
merged: refused, flagged or unjudged if any unit is.

What is kept. Only a complete verdict that was not refused: a clean unit, or
one flag delivered with a warning. Anything unjudged (a timeout, a failed
judge, a truncation) or refused is judged again next time. A flagged request
still reaches the caller's audit row through ``flag_reason``; only the
detection row is written once per kept verdict rather than once per request.

Each unit is judged whole under the admission cap, as each part of a paged
response is (``gateway/paging.py``): the cap bounds what one judgement reads,
and a unit over it is ``oversize`` like any payload.

Isolation. The key holds the profile's grant owner and name, the mode, the
profile's defense settings and the judge identity, as ``quarantine/l3_cache``
does, plus ``perimeter_stamp`` for L2's model and L1/L2's version: no verdict
crosses tenants, and a changed threshold, model or judge is a miss.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..logsafe import exc_kind, exc_where
from ..modes import Mode
from ..orchestrator import OutboundVerdict, judge_outbound

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from .profile import Profile

logger = logging.getLogger(__name__)

#: Body fields that hold the conversation, one unit per element: ``messages``
#: (Anthropic, OpenAI, OpenRouter), ``contents`` (Gemini), ``input`` (OpenAI
#: Responses and embeddings, when it is a list).
CONVERSATION_FIELDS = ("messages", "contents", "input")

#: How long a kept verdict is reused after its last use. Covers a burst and a
#: conversation's next turn; a judge or threshold change is in the key anyway.
TTL_SECONDS = 600.0

#: Verdicts kept at once. Each is a small frozen dataclass.
MAX_ENTRIES = 4096

#: Gaps that say the judge did not answer, so the next request asks again.
_TRANSIENT_GAPS = frozenset({"l2_unavailable", "l3_unavailable"})

_RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_verdicts: OrderedDict[str, tuple[float, OutboundVerdict]] = OrderedDict()
_inflight: dict[str, asyncio.Task[OutboundVerdict]] = {}

#: Units judged vs. served from the cache or a shared flight, since start.
unit_counts: dict[str, int] = {"judged": 0, "shared": 0}


def request_units(head: str, body: str | None) -> list[str]:
    """The frame, then each conversation message, as the texts the layers read.

    ``head`` is the method, path, query and forwarded headers; ``body`` the
    body as ``outbound.body_text`` renders it. A body that is not a JSON object
    is one unit with the head, as the whole request was before. Together the
    units carry every field of the body, so nothing sent goes unjudged.
    """
    if body is None:
        return [head]
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        return [f"{head}\n{body}"]
    messages: list[str] = []
    frame = dict(parsed)
    for name in CONVERSATION_FIELDS:
        value = frame.get(name)
        if isinstance(value, list):
            messages.extend(json.dumps(item, ensure_ascii=False) for item in value)
            frame[name] = []
    return [f"{head}\n{json.dumps(frame, ensure_ascii=False)}", *messages]


def _key(unit: str, profile: Profile, mode: Mode, source_type: str) -> str:
    """Everything that can change a unit's verdict, hashed; never a secret."""
    # Lazy: the gateway service imports this module's caller on its way in.
    from ..perimeter_db import perimeter_stamp
    from .service import judge_stamp

    config = [
        profile.grant_owner,
        profile.name,
        mode.value,
        source_type,
        judge_stamp(profile),
        perimeter_stamp(),
        profile.defense.model_dump_json(),
    ]
    digest = hashlib.sha256()
    # Length-prefixed, so no two (config, unit) pairs spell the same input.
    for part in (json.dumps(config), unit):
        encoded = part.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _keepable(verdict: OutboundVerdict) -> bool:
    """True for a complete verdict that delivered: nothing missing, nothing refused."""
    return not (verdict.unjudged or verdict.refused or _TRANSIENT_GAPS.intersection(verdict.gaps))


async def judge_units(
    units: list[str],
    *,
    source: str,
    source_type: str,
    backend: str,
    profile: Profile,
    mode: Mode,
    deadline: float,
) -> OutboundVerdict:
    """Judge each unit once and merge the verdicts into the request's.

    The arguments are ``judge_outbound``'s, with ``units`` for its document.
    Each unit's judgement runs under ``deadline`` from when it started, so a
    caller that joins a flight in progress waits no longer than its own.
    """
    run = functools.partial(
        judge_outbound,
        source=source,
        source_type=source_type,
        backend=backend,
        profile=profile,
        mode=mode,
        deadline=deadline,
    )
    verdicts = await asyncio.gather(
        *(
            _judge_once(
                _key(unit, profile, mode, source_type),
                functools.partial(run, unit),
                deadline=deadline,
                refused=mode is Mode.BLOCK,
            )
            for unit in units
        )
    )
    return merge(verdicts)


async def _judge_once(
    key: str,
    judge: Callable[[], Coroutine[Any, Any, OutboundVerdict]],
    *,
    deadline: float,
    refused: bool,
) -> OutboundVerdict:
    """The unit's kept verdict, a flight in progress, or a new judgement.

    A caller that joins a flight started earlier waits no longer than its own
    ``deadline``; past it the unit is unjudged for that caller (``refused``
    under block, as ``judge_outbound`` answers a timeout), and the flight goes
    on for the others.
    """
    hit = _verdicts.get(key)
    if hit is not None and time.monotonic() - hit[0] < TTL_SECONDS:
        _verdicts[key] = (time.monotonic(), hit[1])
        _verdicts.move_to_end(key)
        unit_counts["shared"] += 1
        return hit[1]
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(_judge(key, judge))
        _inflight[key] = task
        task.add_done_callback(functools.partial(_settle, key))
    else:
        unit_counts["shared"] += 1
    # A caller cancelled from above, or out of time, leaves the judgement to the others.
    try:
        async with asyncio.timeout(deadline):
            return await asyncio.shield(task)
    except TimeoutError:
        return OutboundVerdict(refused=refused)


async def _judge(
    key: str, judge: Callable[[], Coroutine[Any, Any, OutboundVerdict]]
) -> OutboundVerdict:
    """Run the judgement, and keep it if the next would say the same."""
    unit_counts["judged"] += 1
    verdict = await judge()
    if _keepable(verdict):
        _verdicts[key] = (time.monotonic(), verdict)
        _verdicts.move_to_end(key)
        while len(_verdicts) > MAX_ENTRIES:
            _verdicts.popitem(last=False)
    return verdict


def _settle(key: str, task: asyncio.Task[OutboundVerdict]) -> None:
    """Free the key, and surface a failure no waiter stayed to see."""
    if _inflight.get(key) is task:
        del _inflight[key]
    if not task.cancelled() and (exc := task.exception()) is not None:
        # The kind only: the exception can carry the judged content (#262).
        logger.warning(
            "request_units: shared judgement failed for key=%s: %s at %s",
            key[:12],
            exc_kind(exc),
            exc_where(exc),
        )


def merge(verdicts: list[OutboundVerdict]) -> OutboundVerdict:
    """One request's verdict from its units': any unit's finding is the request's."""
    flagged = [v for v in verdicts if v.flagged]
    worst = max(flagged or verdicts, key=lambda v: _RISK_RANK.get(v.risk, 0))
    return OutboundVerdict(
        refused=any(v.refused for v in verdicts),
        kinds=list(dict.fromkeys(k for v in verdicts for k in v.kinds)),
        flagged=bool(flagged),
        flagged_by=worst.flagged_by if flagged else None,
        unjudged=any(v.unjudged for v in verdicts),
        gaps=list(dict.fromkeys(g for v in verdicts for g in v.gaps)),
        risk=worst.risk,
    )


def reset_request_units() -> None:
    """Forget every verdict and flight (for testing)."""
    _verdicts.clear()
    _inflight.clear()
    unit_counts.update(judged=0, shared=0)
