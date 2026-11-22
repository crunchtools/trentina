"""Adaptive concurrency for L3: send as fast as the provider will take (#216).

One ``AdaptiveLimiter`` per judge — the (provider, model) a request actually
goes to — and per API key, shared by everything that calls it on that key:
user-facing scans, the perimeter, compression, the boot warm-up. The key is in
the limiter's identity because a provider throttles per key (#291): keyed by
judge alone, one profile driving its own key into 429s paused, then refused,
every other profile's L3 on that model, and block refused their content.
Foreground work is granted a slot before background work, so a warm-up
judging hundreds of tool descriptions never makes a user's ``tools/call`` wait
behind it. Within a priority each profile queues FIFO and a freed slot goes to
the next profile in rotation (#867), as ``classifier.FairGate`` does for L2:
profiles sharing a key no longer wait behind one profile's backlog.

The limit is found, not configured, by the rule TCP uses for the same
problem (AIMD):

- slow start: until the provider first throttles, double per window;
- then add one per window of successful completions;
- on a 429, halve — once per congestion epoch, so a burst of 429s from
  requests that were all in flight together counts as one signal, not
  thirty-two — and pause every new request for the provider's Retry-After.

A window is ``limit`` completions, about one round trip at that concurrency.
A request that failed for any other reason neither grows nor shrinks the
limit: an outage is not a capacity signal, and the fallback chain owns it.
"""

from __future__ import annotations

import asyncio
import collections
import contextvars
import enum
import logging
import secrets
from typing import TYPE_CHECKING, Any

from ..config import int_env
from ..errors import QuarantineAgentError

if TYPE_CHECKING:
    from .providers.base import Provider, ProviderResult

logger = logging.getLogger(__name__)

THROTTLE_STATUS = 429

# A provider that answers 429 with no Retry-After, or with 0, still gets a
# pause: re-sending immediately is how a throttle becomes a ban.
_MIN_PAUSE = 0.25
_DEFAULT_PAUSE = 1.0
_MAX_PAUSE = 30.0
_JITTER = secrets.SystemRandom()
DEFAULT_THROTTLE_BUDGET = 20


class Priority(enum.Enum):
    """Who is waiting for a slot. Foreground is always served first."""

    FOREGROUND = "foreground"
    BACKGROUND = "background"


class Outcome(enum.Enum):
    """What a finished request tells the limiter."""

    OK = "ok"
    THROTTLED = "throttled"
    FAILED = "failed"


l3_priority: contextvars.ContextVar[Priority] = contextvars.ContextVar(
    "l3_priority", default=Priority.FOREGROUND
)

# How long one L3 call may keep waiting out 429s on the same provider before
# the fallback chain moves on. None means TRENTINA_L3_THROTTLE_BUDGET: short,
# because a user is waiting. The boot warm-up sets a long one — nobody is.
l3_throttle_budget: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "l3_throttle_budget", default=None
)


def throttle_budget() -> float:
    """Seconds this context may spend waiting out throttles per L3 call."""
    budget = l3_throttle_budget.get()
    if budget is not None:
        return budget
    return float(int_env("TRENTINA_L3_THROTTLE_BUDGET", DEFAULT_THROTTLE_BUDGET, minimum=0))


class AdaptiveLimiter:
    """A fair queue in front of one judge, with an AIMD concurrency limit."""

    def __init__(self, judge: tuple[str, str], start: int, ceiling: int) -> None:
        """Create the limiter for one judge.

        Args:
            judge: The (provider, model) every request through this limiter
                goes to.
            start: Requests allowed in flight before anything is learned;
                slow start grows it from here. Clamped to 1..ceiling.
            ceiling: The most requests ever allowed in flight at once.
        """
        self.judge = judge
        self.name = "/".join(map(str, judge))
        self.ceiling = max(1, ceiling)
        self.limit = float(min(max(1, start), self.ceiling))
        self.in_flight = 0
        self.epoch = 0
        self.slow_start = True
        self.throttles = 0
        self._window = 0
        self._backoff = 0.0
        self._pause_until = 0.0
        self._timer: asyncio.TimerHandle | None = None
        # Per priority, one FIFO per profile, in the order their turns come.
        self._waiters: dict[
            Priority,
            collections.OrderedDict[str | None, collections.deque[asyncio.Future[int]]],
        ] = {p: collections.OrderedDict() for p in Priority}
        # Each queued caller's throttle budget, so a pause that begins while
        # it waits can refuse it rather than hold it past what it allowed.
        self._budgets: dict[asyncio.Future[int], float] = {}

    def _cap(self) -> int:
        return max(1, int(self.limit))

    def _queued(self) -> bool:
        return any(self._waiters[p] for p in Priority)

    def resume_in(self) -> float:
        """Seconds until the current throttle pause ends; 0 when not paused."""
        return max(0.0, self._pause_until - asyncio.get_running_loop().time())

    async def acquire(self) -> int:
        """Wait for a slot; return the congestion epoch it was granted in."""
        if not self._queued() and self.in_flight < self._cap() and self.resume_in() == 0:
            self.in_flight += 1
            return self.epoch
        fut: asyncio.Future[int] = asyncio.get_running_loop().create_future()
        # Imported here: the gateway package imports this one on its way in.
        from ..gateway.context import get_current_profile
        from ..gateway.errors import ScopeError

        try:
            # By grant owner, as the judge's key and the L3 quota are (#898):
            # a derived -federation ingress shares its profile's turn.
            key: str | None = get_current_profile().grant_owner
        except ScopeError:
            # The boot warm-up and other gateway-side work run with no
            # profile bound; they share one turn rather than being refused.
            key = None
        turns = self._waiters[l3_priority.get()]
        queue = turns.setdefault(key, collections.deque())
        queue.append(fut)
        self._budgets[fut] = throttle_budget()
        self._pump()
        try:
            return await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                # Granted a slot in the same tick the caller was cancelled.
                self.release(fut.result(), Outcome.FAILED)
            elif fut in queue:
                queue.remove(fut)
                if not queue and turns.get(key) is queue:
                    del turns[key]
            raise
        finally:
            self._budgets.pop(fut, None)

    def release(self, epoch: int, outcome: Outcome, retry_after: float | None = None) -> None:
        """Return a slot and adjust the limit by what the request learned.

        Args:
            epoch: What ``acquire`` returned — the congestion epoch the slot
                was granted in. A result from before the last halving does
                not move the limit again.
            outcome: ``OK`` counts toward growth, ``THROTTLED`` halves the
                limit and pauses new requests, ``FAILED`` only frees the slot.
            retry_after: For ``THROTTLED``, the provider's requested wait in
                seconds; None means back off by the limiter's own schedule.
        """
        self.in_flight -= 1
        if outcome is Outcome.OK and epoch == self.epoch:
            # A success that started before the last halving says nothing
            # about the new limit, so only current-epoch completions count.
            self._backoff = 0.0
            self._window += 1
            if self._window >= self._cap():
                self._window = 0
                grown = self.limit * 2 if self.slow_start else self.limit + 1
                self.limit = min(float(self.ceiling), grown)
        elif outcome is Outcome.THROTTLED:
            self._throttle(epoch, retry_after)
        self._pump()

    def _throttle(self, epoch: int, retry_after: float | None) -> None:
        self.throttles += 1
        paused_until = self._pause_until
        now = asyncio.get_running_loop().time()
        if retry_after is not None:
            self._pause_until = max(self._pause_until, now + max(_MIN_PAUSE, retry_after))
        # Only a result from the current epoch is a new congestion signal;
        # one that started before the last decrease is already accounted for,
        # though its Retry-After still counts.
        if epoch == self.epoch:
            self.epoch += 1
            self.slow_start = False
            self._window = 0
            self.limit = max(1.0, self.limit / 2)
            if retry_after is None:
                self._backoff = min(_MAX_PAUSE, max(_DEFAULT_PAUSE, self._backoff * 2))
                pause = self._backoff * _JITTER.uniform(1.0, 1.25)
                self._pause_until = max(self._pause_until, now + pause)
            logger.warning(
                "l3 limiter: %s throttled — limit now %d, pausing %.1fs",
                self.name,
                self._cap(),
                self.resume_in(),
            )
        # Queued callers are re-checked only when the pause got longer: that
        # is the only change that can put one past its budget, and it keeps a
        # burst of 429s from re-scanning the queue once per response.
        if self._pause_until > paused_until:
            self._refuse_waiters_past_budget()

    def _refuse_waiters_past_budget(self) -> None:
        """Fail queued callers whose budget the current pause outlasts."""
        pause = self.resume_in()
        refused = {fut for fut, budget in self._budgets.items() if pause > budget}
        if not refused:
            return
        for fut in refused:
            if not fut.done():
                fut.set_exception(
                    QuarantineAgentError(
                        f"{self.name} paused for throttling",
                        status_code=THROTTLE_STATUS,
                        retry_after=pause,
                    )
                )
        # One pass per queue, so a long pause cannot pile up dead futures.
        for turns in self._waiters.values():
            for key in list(turns):
                kept = collections.deque(f for f in turns[key] if f not in refused)
                if kept:
                    turns[key] = kept
                else:
                    del turns[key]

    def _pump(self) -> None:
        """Grant queued waiters the free slots, foreground first."""
        wait = self.resume_in()
        if wait > 0:
            if self._timer is None and self._queued():
                self._timer = asyncio.get_running_loop().call_later(wait, self._wake)
            return
        while self.in_flight < self._cap():
            fut = self._next_waiter()
            if fut is None:
                return
            self.in_flight += 1
            fut.set_result(self.epoch)

    def _wake(self) -> None:
        self._timer = None
        self._pump()

    def _next_waiter(self) -> asyncio.Future[int] | None:
        """The next live waiter: highest priority, then the next profile's turn."""
        for priority in Priority:
            turns = self._waiters[priority]
            while turns:
                key, queue = next(iter(turns.items()))
                fut = queue.popleft()
                if queue:
                    turns.move_to_end(key)
                else:
                    del turns[key]
                if not fut.done():
                    return fut
        return None

    def snapshot(self) -> dict[str, Any]:
        """The state an operator reads in the warm-up summary."""
        return {
            "judge": self.name,
            "limit": self._cap(),
            "in_flight": self.in_flight,
            "throttles": self.throttles,
        }


_limiters: dict[tuple[str, str, str], AdaptiveLimiter] = {}


def limiter_for(judge: tuple[str, str], key_ordinal: str = "global") -> AdaptiveLimiter:
    """The one limiter for this (provider, model) on this key, created on first use.

    ``key_ordinal`` is ``Provider.key_ordinal``: an ordinal, never
    the key nor anything derived from it. Two profiles holding the same key
    share a limiter, as they share the provider's quota for it.
    """
    slot = (*judge, key_ordinal)
    limiter = _limiters.get(slot)
    if limiter is None:
        limiter = AdaptiveLimiter(
            judge,
            start=int_env("TRENTINA_L3_CONCURRENCY_START", 4, minimum=1),
            ceiling=int_env("TRENTINA_L3_CONCURRENCY_MAX", 64, minimum=1),
        )
        _limiters[slot] = limiter
    return limiter


def all_limiters() -> list[AdaptiveLimiter]:
    """Every limiter created so far."""
    return list(_limiters.values())


def reset_limiters() -> None:
    """Forget every limiter. Tests only — a limiter is bound to one event loop."""
    for limiter in _limiters.values():
        if limiter._timer is not None:
            limiter._timer.cancel()
    _limiters.clear()


async def limited_generate(provider: Provider, **kwargs: Any) -> ProviderResult:
    """``provider.generate`` behind that judge's limiter.

    Args:
        provider: The driver to call; its ``judge`` and ``key_ordinal``
            pick the limiter.
        **kwargs: Passed to ``provider.generate`` unchanged.

    Returns:
        What ``provider.generate`` returned.

    Raises:
        QuarantineAgentError: whatever the provider raised. On a 429 its
            ``retry_after`` is rewritten to how long the limiter will
            actually hold new requests, which is what a caller deciding
            between waiting and falling back needs. A call made while the
            limiter is paused for longer than this context's throttle budget
            is refused the same way without being sent, so a long
            Retry-After cannot hold a user's call past its budget.
    """
    limiter = limiter_for(provider.judge, provider.key_ordinal)
    if limiter.resume_in() > throttle_budget():
        raise QuarantineAgentError(
            f"{limiter.name} paused for throttling",
            status_code=THROTTLE_STATUS,
            retry_after=limiter.resume_in(),
        )
    epoch = await limiter.acquire()
    try:
        result = await provider.generate(**kwargs)
    except QuarantineAgentError as exc:
        if exc.status_code != THROTTLE_STATUS:
            limiter.release(epoch, Outcome.FAILED)
            raise
        limiter.release(epoch, Outcome.THROTTLED, exc.retry_after)
        exc.retry_after = limiter.resume_in()
        raise
    except BaseException:
        limiter.release(epoch, Outcome.FAILED)
        raise
    limiter.release(epoch, Outcome.OK)
    return result
