"""The per-profile daily L3 quota (#891): charge, snapshot, the gap, and the stats."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr, ValidationError

from trentina.defense import defend
from trentina.gateway import compress
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.modes import Gaps, gaps_of, refusal_reason
from trentina.quarantine import quota
from trentina.quarantine.classifier import ClassifierResult
from trentina.quarantine.limiter import Priority, l3_priority
from trentina.tools.stats import get_trentina_stats
from trentina.warning import build_warning

from .judge_key import with_judge_key

_D = "trentina.defense"
BENIGN_LOW = ClassifierResult(label="BENIGN", score=0.05, latency_ms=1.0)


@pytest.fixture(autouse=True)
def _fresh_quota() -> Iterator[None]:
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


def _on_day(monkeypatch: pytest.MonkeyPatch, *ymd: int) -> None:
    monkeypatch.setattr(quota, "_clock", lambda: datetime(*ymd, 10, 30, tzinfo=UTC))


class TestCharge:
    def test_an_unlimited_profile_is_counted_and_never_refused(self) -> None:
        p = _profile()
        assert all(quota.charge(p) for _ in range(50))
        assert quota.snapshot(p)["used"] == 50

    def test_the_limit_allows_n_and_refuses_the_next(self) -> None:
        p = _profile(limit=3)
        assert [quota.charge(p) for _ in range(5)] == [True, True, True, False, False]
        # A refusal is not a judgement: it does not count.
        assert quota.snapshot(p)["used"] == 3

    def test_the_next_utc_day_starts_again(self, monkeypatch: pytest.MonkeyPatch) -> None:
        p = _profile(limit=1)
        _on_day(monkeypatch, 2026, 11, 22)
        assert quota.charge(p)
        assert not quota.charge(p)
        _on_day(monkeypatch, 2026, 11, 23)
        assert quota.charge(p)
        assert quota.snapshot(p)["used"] == 1

    def test_background_work_is_not_charged(self) -> None:
        p = _profile(limit=1)
        token = l3_priority.set(Priority.BACKGROUND)
        try:
            assert all(quota.charge(p) for _ in range(5))
        finally:
            l3_priority.reset(token)
        assert quota.snapshot(p)["used"] == 0
        assert quota.charge(p)

    def test_the_spent_line_is_logged_once_per_profile_per_day(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        p = _profile(limit=1)
        _on_day(monkeypatch, 2026, 11, 22)
        with caplog.at_level(logging.WARNING, logger=quota.logger.name):
            quota.charge(p)
            for _ in range(4):
                quota.charge(p)
            assert len([r for r in caplog.records if "quota spent" in r.message]) == 1
            _on_day(monkeypatch, 2026, 11, 23)
            quota.charge(p)
            quota.charge(p)
        assert len([r for r in caplog.records if "quota spent" in r.message]) == 2

    def test_profiles_are_independent(self) -> None:
        a, b = _profile("alpha", 1), _profile("beta", 1)
        assert quota.charge(a)
        assert not quota.charge(a)
        assert quota.charge(b)
        assert quota.snapshot(b)["used"] == 1


class TestSnapshot:
    def test_the_numbers_and_the_next_utc_midnight(self, monkeypatch: pytest.MonkeyPatch) -> None:
        p = _profile(limit=5)
        _on_day(monkeypatch, 2026, 12, 31)
        quota.charge(p)
        quota.charge(p)
        assert quota.snapshot(p) == {
            "limit": 5,
            "used": 2,
            "remaining": 3,
            "resets_at": "2027-01-01T00:00:00+00:00",
        }

    def test_remaining_is_none_when_unlimited(self) -> None:
        p = _profile()
        quota.charge(p)
        snap = quota.snapshot(p)
        assert (snap["limit"], snap["used"], snap["remaining"]) == (None, 1, None)

    def test_a_spent_cap_has_nothing_remaining(self) -> None:
        p = _profile(limit=1)
        quota.charge(p)
        quota.charge(p)
        assert quota.snapshot(p)["remaining"] == 0


class TestConfig:
    @pytest.mark.parametrize("bad", [0, -1])
    def test_a_non_positive_quota_is_refused(self, bad: int) -> None:
        with pytest.raises(ValidationError):
            DefenseConfig(l3_daily_quota=bad)

    def test_unset_is_unlimited(self) -> None:
        assert DefenseConfig().l3_daily_quota is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("standalone_l3")
class TestThroughDefend:
    async def _defend(self, p: Profile, content: str = "hello world") -> tuple:
        with (
            patch(f"{_D}.classify_async", return_value=BENIGN_LOW),
            patch(f"{_D}.record_detection"),
            patch(f"{_D}.emit_detection_event"),
            patch(
                f"{_D}.quarantine_detect",
                new_callable=AsyncMock,
                return_value={"injection_detected": False},
            ) as detect,
            profile_context(p),
        ):
            verdict = await defend(
                content, source="https://example.com", source_type="url", defense=p.defense
            )
        return verdict, detect

    async def test_under_the_cap_l3_runs(self) -> None:
        verdict, detect = await self._defend(_profile(limit=2))
        detect.assert_awaited_once()
        gaps = gaps_of(verdict)
        assert not gaps.l3_quota
        assert not gaps.l3_unavailable

    async def test_over_the_cap_l3_is_not_asked_and_the_gap_is_the_quota(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_L3", "false")
        from trentina import config as config_mod

        config_mod._config = None
        p = _profile(limit=1)
        await self._defend(p, "first page")
        verdict, detect = await self._defend(p, "second page")

        detect.assert_not_awaited()
        gaps = gaps_of(verdict)
        assert gaps.l3_quota is True
        assert gaps.l3_unavailable is False
        # The cap is the operator's own limit: require_l3 off excuses nothing.
        assert gaps.blocking() is True
        assert "quota" in (refusal_reason(None, gaps) or "")
        warning = build_warning(verdict)
        assert warning is not None
        assert warning["l3_quota"] is True
        assert "l3_unavailable" not in warning

    async def test_a_cache_hit_is_free(self) -> None:
        p = _profile(limit=1)
        _, first = await self._defend(p, "same page")
        verdict, second = await self._defend(p, "same page")
        first.assert_awaited_once()
        second.assert_not_awaited()
        assert quota.snapshot(p)["used"] == 1
        assert not gaps_of(verdict).l3_quota

    async def test_an_unlimited_profile_never_hits_the_gap(self) -> None:
        p = _profile()
        for i in range(4):
            verdict, _ = await self._defend(p, f"page {i}")
            assert not gaps_of(verdict).l3_quota
        assert quota.snapshot(p)["used"] == 4


class TestGapsInIsolation:
    def test_the_quota_is_blocking_and_not_redactable_only(self) -> None:
        gaps = Gaps(l3_quota=True)
        assert gaps.any
        assert not gaps.redactable_only()


YAML = """\
profiles:
  alpha:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      jira:
        url: http://jira:1/mcp
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    defense:
      l3_daily_quota: 4
    backends:
      wiki:
        url: http://wiki:1/mcp
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "trentina.db"))
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield config.profiles
    compress._profiles = None


@pytest.mark.asyncio
class TestStats:
    async def test_the_agent_slice_carries_its_own_quota(self, gateway: dict) -> None:
        beta = gateway["beta"]
        quota.charge(beta)
        quota.charge(beta)
        with profile_context(beta):
            result = await get_trentina_stats()

        assert result["config"]["l3_daily_quota"] == 4
        assert result["l3_quota"]["limit"] == 4
        assert result["l3_quota"]["used"] == 2
        assert result["l3_quota"]["remaining"] == 2
        assert result["l3_quota"]["resets_at"].endswith("T00:00:00+00:00")

    async def test_the_operator_sees_capped_or_active_profiles_only(self, gateway: dict) -> None:
        quota.charge(gateway["beta"])
        with profile_context(gateway["alpha"]):
            result = await get_trentina_stats()

        assert set(result["l3_quota"]) == {"beta"}
        assert result["l3_quota"]["beta"]["used"] == 1
