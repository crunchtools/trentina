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
"""

from __future__ import annotations

import functools
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from .limiter import Priority, l3_priority

if TYPE_CHECKING:
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


def charge(profile: Profile) -> bool:
    """Count one L3 judgement against ``profile``; False when its cap is spent.

    A profile without ``defense.l3_daily_quota`` is counted and never refused.
    """
    if l3_priority.get() is Priority.BACKGROUND:
        return True
    owner = profile.grant_owner
    day = _clock().date().isoformat()
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
        return False
    _usage[owner] = (day, used + 1)
    return True


def refund(profile: Profile) -> None:
    """Give back a judgement ``charge`` took that L3 did not answer.

    Called in the same task as the charge, so a background caller, which was
    never charged, is never refunded. A charge from a day that has since
    ended is gone with that day.
    """
    if l3_priority.get() is Priority.BACKGROUND:
        return
    owner = profile.grant_owner
    day = _clock().date().isoformat()
    used = _used(owner, day)
    if used:
        _usage[owner] = (day, used - 1)


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
    _spent_logged.clear()
