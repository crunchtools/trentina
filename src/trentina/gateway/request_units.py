"""The ``/proxy/llm`` request judged a message at a time, each message once.

Gatehouse sends up to two dozen review calls at once, each the same diff behind
its own reviewer prompt. Judged as one document, every call was a different
document: L2 read the identical diff once per call, two scans at a time behind
``TRENTINA_L2_CONCURRENCY`` on cores those two already filled. A burst of 18
finished four scans in 20 s and timed the other 14 out unjudged (a341).

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

The admission cap is one cap on the whole request. A request over it is
judged whole, as before: ``block`` refuses it as ``oversize`` and ``flag``
reads its head. Only a request under the cap is cut.

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
from ..orchestrator import OutboundVerdict, judge_outbound, outbound_trip
from .outbound import detect_credentials

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from .profile import Profile

logger = logging.getLogger(__name__)

#: Body fields that hold the conversation, one unit per element: ``messages``
#: (Anthropic, OpenAI, OpenRouter), ``contents`` (Gemini), ``input`` (OpenAI
#: Responses). Only a list of objects is cut: an embeddings ``input`` is a list
#: of strings, one batch, and stays in the frame (gap 34).
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
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            messages.extend(json.dumps(item, ensure_ascii=False) for item in value)
            frame[name] = []
    return [f"{head}\n{json.dumps(frame, ensure_ascii=False)}", *messages]


#: Whole conversation entries that answer a call: OpenAI chat ``role: tool``
#: (by ``tool_call_id``) and Responses outputs (by ``call_id``), Codex's
#: freeform and ``apply_patch`` results among them.
_RESULT_ITEMS = frozenset({"function_call_output", "custom_tool_call_output"})
_CALL_ITEMS = frozenset({"function_call", "custom_tool_call"})


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _calls(entry: dict[str, Any]) -> set[str]:
    """The ids of the calls ``entry`` makes, in every API shape."""
    ids = {_text(call.get("id")) for call in _dicts(entry.get("tool_calls"))}
    if _text(entry.get("type")) in _CALL_ITEMS:
        ids.add(_text(entry.get("call_id")))
    for block in _dicts(entry.get("content")):
        if block.get("type") == "tool_use":
            ids.add(_text(block.get("id")))
    for part in _dicts(entry.get("parts")):
        call = part.get("functionCall")
        if isinstance(call, dict):
            # Gemini's id is optional; without one the name is all a response carries.
            ids.add(_text(call.get("id")) or _text(call.get("name")))
    return {i for i in ids if i}


def _answers(entry: dict[str, Any], called: set[str]) -> bool:
    """Whether ``entry`` is, whole, a result answering one of ``called``."""
    match entry:
        case {"role": "tool", "tool_call_id": str(ref)}:
            return ref in called
        case {"type": str(kind), "call_id": str(ref)} if kind in _RESULT_ITEMS:
            return ref in called
        case _:
            return False


def _block_answers(block: dict[str, Any], called: set[str]) -> bool:
    """Whether ``block`` of a user entry is a result answering one of ``called``."""
    response = block.get("functionResponse")
    ref = (
        _text(response.get("id")) or _text(response.get("name"))
        if isinstance(response, dict)
        else _text(block.get("tool_use_id"))
        if block.get("type") == "tool_result"
        else None
    )
    return ref is not None and ref in called


def _without_answers(entry: dict[str, Any], called: set[str]) -> dict[str, Any]:
    """A user entry without its result blocks that answer ``called``."""
    kept = dict(entry)
    for name in ("content", "parts"):
        if isinstance(entry.get(name), list):
            kept[name] = [
                block
                for block in entry[name]
                if not (isinstance(block, dict) and _block_answers(block, called))
            ]
    return kept


def agent_written(units: list[str]) -> list[str]:
    """The units with every delivered tool result cut: what the agent wrote,
    one piece a unit, for the trip check.

    A conversation carries the tool results the agent was DELIVERED. One that
    holds a planted credential is the agent reading the decoy, not sending it,
    and checking it would refuse every later turn of the session. A result is
    cut only where its API puts it, and only when it answers a call made
    EARLIER in the same request: an OpenAI ``role: tool`` entry by its
    ``tool_call_id``, a Responses ``function_call_output`` or
    ``custom_tool_call_output`` by its ``call_id``, an Anthropic ``tool_result``
    block of a ``user`` entry by its ``tool_use_id``, a Gemini
    ``functionResponse`` part of a ``user`` or ``function`` entry by its id or
    name. A result anywhere else, or
    answering no call, stays checked. Each unit ends in one line of JSON
    (``request_units``); a unit that does not is kept whole.
    """
    called: set[str] = set()
    pieces: list[str] = []
    for unit in units:
        head, sep, last = unit.rpartition("\n")
        try:
            entry = json.loads(last)
        except ValueError:
            entry = None
        if not isinstance(entry, dict):
            pieces.append(unit)
        elif not _answers(entry, called):
            # Results come back in the caller's turn: Gemini also names it ``function``.
            answering = entry.get("role") in ("user", "function")
            kept = _without_answers(entry, called) if answering else entry
            pieces.append(f"{head}{sep}{json.dumps(kept, ensure_ascii=False)}")
        if isinstance(entry, dict):
            called |= _calls(entry)
    return pieces


def _key(unit: str, profile: Profile, mode: Mode, source_type: str) -> str:
    """Everything that can change a unit's verdict, hashed; never a secret."""
    # Lazy: the gateway service imports this module's caller on its way in.
    from ..config import get_config
    from ..perimeter_db import perimeter_stamp
    from .service import judge_stamp

    settings = get_config()
    config = [
        profile.grant_owner,
        profile.name,
        mode.value,
        source_type,
        judge_stamp(profile),
        # As in ``l3_cache.judgement_key``: a fallback reaches another judge,
        # and the effort only when set, as the call sends none unset.
        list(settings.provider_fallback),
        *([f"effort={settings.reasoning_effort}"] if settings.reasoning_effort else []),
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
    Counting the request against the cap and judging its units share one
    ``deadline``; a caller that joins a flight in progress waits no longer
    than what is left of its own. A count past the deadline is unjudged, as
    ``judge_outbound`` answers a scan past it.
    """
    # First, before the count can run out its deadline and before any cached
    # verdict is reused: neither may let a planted credential leave (#865).
    if (trip := await outbound_trip(profile, backend, agent_written(units))) is not None:
        return trip
    loop = asyncio.get_running_loop()
    started = loop.time()
    if len(units) > 1:
        try:
            async with asyncio.timeout(deadline):
                units = await _one_cap(units)
        except TimeoutError as exc:
            _log_scan_failed(backend, source_type, exc)
            kinds = list(dict.fromkeys(k for unit in units for k in detect_credentials(unit)))
            return OutboundVerdict(refused=mode is Mode.BLOCK, kinds=kinds)
        deadline = max(deadline - (loop.time() - started), 0.001)
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
                backend=backend,
                source_type=source_type,
            )
            for unit in units
        )
    )
    return merge(verdicts)


async def _one_cap(units: list[str]) -> list[str]:
    """``units``, or the whole request as one unit when it is over the cap.

    The admission cap is one cap on what a request carries, counted before
    any inference; only a response is delivered in parts. A request over it
    is judged whole, as before the request was cut: ``block`` refuses it as
    ``oversize`` and ``flag`` reads its head.
    """
    from ..defense import admission  # heavy; deferred like judge_outbound's

    whole = "\n".join(units)
    tokens, cap = await admission(whole)
    return [whole] if tokens > cap else units


async def _judge_once(
    key: str,
    judge: Callable[[], Coroutine[Any, Any, OutboundVerdict]],
    *,
    deadline: float,
    refused: bool,
    backend: str,
    source_type: str,
) -> OutboundVerdict:
    """The unit's kept verdict, a flight in progress, or a new judgement.

    A caller that joins a flight started earlier waits no longer than its own
    ``deadline``; past it the unit is unjudged for that caller (``refused``
    under block, as ``judge_outbound`` answers a timeout), and the flight goes
    on for the others. Logged as ``judge_outbound`` logs a scan past its
    deadline, so one syslog count covers both.
    """
    hit = _verdicts.get(key)
    if hit is not None and time.monotonic() - hit[0] < TTL_SECONDS:
        _verdicts[key] = (time.monotonic(), hit[1])
        _verdicts.move_to_end(key)
        return hit[1]
    task = _inflight.get(key)
    if task is None:
        task = asyncio.ensure_future(_judge(key, judge))
        _inflight[key] = task
        task.add_done_callback(functools.partial(_settle, key))
        # The flight runs under this caller's own deadline already. A caller
        # cancelled from above leaves the judgement to the others.
        return await asyncio.shield(task)
    try:
        async with asyncio.timeout(deadline):
            return await asyncio.shield(task)
    except TimeoutError as exc:
        _log_scan_failed(backend, source_type, exc, level=logging.WARNING)
        return OutboundVerdict(refused=refused)


def _log_scan_failed(
    backend: str, source_type: str, exc: BaseException, *, level: int = logging.ERROR
) -> None:
    """``judge_outbound``'s line for a scan with no verdict, word for word."""
    logger.log(  # backend is server-configured (#262-safe)
        level,
        "outbound: request scan failed backend=%s source_type=%s: %s at %s",
        backend,
        source_type,
        exc_kind(exc),
        exc_where(exc),
    )


async def _judge(
    key: str, judge: Callable[[], Coroutine[Any, Any, OutboundVerdict]]
) -> OutboundVerdict:
    """Run the judgement, and keep it if the next would say the same."""
    verdict = await judge()
    # Only a complete verdict that delivered: nothing missing, nothing refused.
    if not (verdict.unjudged or verdict.refused or _TRANSIENT_GAPS.intersection(verdict.gaps)):
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
