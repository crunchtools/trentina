"""A per-profile daily cap on L3 judgements (#891).

A looping agent re-reading the same pages runs one L3 judgement per miss, on
its own key. Fair rotation (#867) stops it starving the profiles that share
that key; this stops it spending the key. The cap is per profile and never
shared: a profile that spends its own leaves every other profile's intact.

What is counted is a judgement that actually runs: a miss in
``quarantine/l3_cache.py``, once per scan however many providers the fallback
chain then tries. One that comes back unanswered (``l3_unavailable``) or
raises is refunded, so retries through a provider outage do not spend the
day. The count is kept by ``grant_owner``, as the judge's key and the L3
cache are: a derived ``<profile>-federation`` ingress spends its profile's
cap, not a second one. A verdict-cache hit, an L3-cache hit and a caller sharing a
flight in progress are free. Background work (the boot warm-up and the tool
aggregate) is the gateway's, not the agent's, and is not counted.

At the cap L3 is not asked. The verdict carries the ``l3_quota`` gap, told
apart from ``l3_unavailable`` so "you spent your cap" is not read as "the
provider is down"; block and redact refuse on it, flag delivers with it. The
count is kept in memory, by UTC day: it starts again at midnight UTC and when
the gateway restarts.

Git judging (spec 027) spends a separate counter, ``charge_git``, against the
git grant's ``l3_daily_quota`` and never the profile's. ``git_quota`` marks
the calls that do; ``charge_for_call`` and ``refund_for_call`` pick the
counter, so ``defense`` swaps two names and knows nothing of git. A git call is
counted even in background work, which is the point of the cap: the profile's
own counter skips background work, git judging is all of it.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from .limiter import Priority, l3_priority

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..gateway.profile import Profile

logger = logging.getLogger(__name__)

#: Grant owner -> (UTC day, judgements run that day).
_usage: dict[str, tuple[str, int]] = {}

#: Grant owner -> the UTC day it was last logged as spent, so the line is said
#: once a day and the map holds one entry per owner, not one per day.
_spent_logged: dict[str, str] = {}


#: The clock the day is read from; tests move it.
_clock = functools.partial(datetime.now, UTC)


def _used(name: str, day: str) -> int:
    entry = _usage.get(name)
    return entry[1] if entry is not None and entry[0] == day else 0


def charge(profile: Profile) -> str | None:
    """Count one L3 judgement against ``profile``; None when its cap is spent.

    Otherwise the UTC day it was counted on, for ``refund``. Background work
    is not counted. A profile without ``defense.l3_daily_quota`` is counted
    and never refused.
    """
    day = _clock().date().isoformat()
    if l3_priority.get() is Priority.BACKGROUND:
        return day
    owner = profile.grant_owner
    used = _used(owner, day)
    limit = profile.defense.l3_daily_quota
    if limit is not None and used >= limit:
        if _spent_logged.get(owner) != day:
            _spent_logged[owner] = day
            logger.warning(
                "L3 daily quota spent for profile %r (%d judgements, UTC day %s): "
                "verdicts report l3_quota until midnight UTC, and block and redact refuse on it",
                owner,
                limit,
                day,
            )
        return None
    _usage[owner] = (day, used + 1)
    return day


def refund(profile: Profile, day: str) -> None:
    """Give back a judgement ``charge`` counted on ``day`` that L3 did not answer.

    A charge from a day that has since ended is gone with that day: refunding
    it from today's count would hand out one judgement more than the cap.
    Called in the task that charged, so background work, never counted, is
    never refunded.
    """
    if l3_priority.get() is Priority.BACKGROUND:
        return
    owner = profile.grant_owner
    used = _used(owner, day)
    if used:
        _usage[owner] = (day, used - 1)


#: Profile grant owner -> (UTC day, git judgements run that day). Kept apart from
#: ``_usage`` so a clone spends the git grant's cap and not the agent's own.
_git_usage: dict[str, tuple[str, int]] = {}

GIT_QUOTA: contextvars.ContextVar[int | Literal[False] | None] = contextvars.ContextVar(
    "trentina_git_quota", default=False
)
"""False outside git judging. Inside it, the git grant's ``l3_daily_quota``
(None for no cap); see :func:`git_quota`."""


@contextlib.contextmanager
def git_quota(cap: int | None) -> Iterator[None]:
    """Count the L3 calls inside against the git counter, capped at ``cap`` (None: no cap)."""
    token = GIT_QUOTA.set(cap)
    try:
        yield
    finally:
        GIT_QUOTA.reset(token)


def charge_git(profile: Profile, cap: int | None) -> str | None:
    """Count one git L3 judgement against ``profile``; None when ``cap`` is spent.

    The same day semantics as :func:`charge`, in a counter of its own. Not
    skipped for background work: git judging is background work.
    """
    day = _clock().date().isoformat()
    owner = profile.grant_owner
    entry = _git_usage.get(owner)
    used = entry[1] if entry is not None and entry[0] == day else 0
    if cap is not None and used >= cap:
        key = f"git:{owner}"
        if _spent_logged.get(key) != day:
            _spent_logged[key] = day
            logger.warning(
                "L3 daily git quota spent for profile %r (%d judgements, UTC day %s): "
                "git objects judged after this report l3_quota until midnight UTC",
                owner,
                cap,
                day,
            )
        return None
    _git_usage[owner] = (day, used + 1)
    return day


def refund_git(profile: Profile, day: str) -> None:
    """Give back a git judgement ``charge_git`` counted on ``day`` that L3 did not answer."""
    owner = profile.grant_owner
    entry = _git_usage.get(owner)
    if entry is not None and entry[0] == day and entry[1]:
        _git_usage[owner] = (day, entry[1] - 1)


def charge_for_call(profile: Profile) -> str | None:
    """:func:`charge`, or :func:`charge_git` inside :func:`git_quota`."""
    cap = GIT_QUOTA.get()
    if cap is False:
        return charge(profile)
    return charge_git(profile, cap)


def refund_for_call(profile: Profile, day: str) -> None:
    """:func:`refund`, or :func:`refund_git` inside :func:`git_quota`."""
    if GIT_QUOTA.get() is False:
        refund(profile, day)
    else:
        refund_git(profile, day)


def snapshot(profile: Profile) -> dict[str, Any]:
    """``profile``'s cap, today's count and when it resets, for quarantine_stats."""
    now = _clock()
    used = _used(profile.grant_owner, now.date().isoformat())
    limit = profile.defense.l3_daily_quota
    midnight = datetime.combine(now.date() + timedelta(days=1), datetime.min.time(), UTC)
    return {
        "limit": limit,
        "used": used,
        "remaining": None if limit is None else max(0, limit - used),
        "resets_at": midnight.isoformat(),
    }


def reset() -> None:
    """Forget every count. For tests."""
    _usage.clear()
    _git_usage.clear()
    _spent_logged.clear()
