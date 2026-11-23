"""The git L3 counter (spec 027): its own cap, its own day, not the profile's."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.quarantine import quota
from trentina.quarantine.limiter import Priority, l3_priority

from .judge_key import with_judge_key


@pytest.fixture(autouse=True)
def _fresh() -> Iterator[None]:
    quota.reset()
    yield
    quota.reset()


def _profile(name: str = "alpha", limit: int | None = None) -> Profile:
    p = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(l3_daily_quota=limit),
        backends={},
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return with_judge_key(p)


def test_git_cap_refuses_at_the_cap_and_refund_gives_one_back() -> None:
    p = _profile()
    day = quota.charge_git(p, 2)
    assert day is not None
    assert quota.charge_git(p, 2) is not None
    assert quota.charge_git(p, 2) is None
    quota.refund_git(p, day)
    assert quota.charge_git(p, 2) is not None


def test_no_cap_counts_and_never_refuses() -> None:
    p = _profile()
    assert all(quota.charge_git(p, None) is not None for _ in range(50))


def test_git_and_profile_counters_are_separate() -> None:
    p = _profile(limit=1)
    assert quota.charge_git(p, 1) is not None
    assert quota.charge_git(p, 1) is None
    assert quota.charge(p) is not None, "the profile's own cap is untouched"
    assert quota.charge(p) is None
    assert quota.snapshot(p)["used"] == 1


def test_git_charge_is_counted_in_background_work() -> None:
    p = _profile()
    token = l3_priority.set(Priority.BACKGROUND)
    try:
        assert quota.charge_git(p, 1) is not None
        assert quota.charge_git(p, 1) is None
    finally:
        l3_priority.reset(token)


def test_a_stale_day_refund_is_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    p = _profile()
    t0 = datetime(2026, 11, 23, 12, tzinfo=UTC)
    monkeypatch.setattr(quota, "_clock", lambda: t0)
    old = quota.charge_git(p, 1)
    assert old is not None
    monkeypatch.setattr(quota, "_clock", lambda: t0 + timedelta(days=1))
    assert quota.charge_git(p, 1) is not None
    quota.refund_git(p, old)
    assert quota.charge_git(p, 1) is None, "yesterday's refund must not reopen today"


def test_dispatch_follows_the_context_var() -> None:
    p = _profile(limit=1)
    assert quota.GIT_QUOTA.get() is False
    with quota.git_quota(1):
        day = quota.charge_for_call(p)
        assert day is not None
        assert quota.charge_for_call(p) is None
        quota.refund_for_call(p, day)
        assert quota.charge_for_call(p) is not None
    assert quota.GIT_QUOTA.get() is False
    assert quota.charge_for_call(p) is not None, "outside git_quota: the profile's counter"
    assert quota.charge_for_call(p) is None


def test_git_quota_none_is_uncapped_git_not_a_profile_call() -> None:
    p = _profile(limit=1)
    with quota.git_quota(None):
        assert all(quota.charge_for_call(p) is not None for _ in range(5))
    assert quota.snapshot(p)["used"] == 0
