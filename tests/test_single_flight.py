"""One judgement per tool description in flight (#120).

Two clients that list tools at the same moment used to both miss the verdict
cache and both run the full pipeline over the same text. These tests pin the
fix and its two easy-to-get-wrong requirements: the work outlives a caller
that leaves, and a failure reaches every waiter and caches nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from trentina import orchestrator as orch
from trentina.gateway import tool_list_edge as ing
from trentina.gateway import verdict_cache as vc
from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.gateway.service import judge_of

TOOLS = [
    {"name": "a", "description": "Lists things."},
    {"name": "b", "description": "Counts things."},
]


def _profile(name: str, l2_threshold: float = 0.5) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="T"),
        defense=DefenseConfig(l2_threshold=l2_threshold),
    )


def _key(profile: Profile, tool: dict[str, Any]) -> str:
    return ing._cache_key(profile, "tool:external", ing._tool_surface_text(tool), judge_of(None))


class _GatedDefend:
    """A defend() that blocks until released and counts its calls."""

    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self.attributed: list[str] = []
        self.gate = asyncio.Event()
        self.fail = fail

    async def __call__(self, *_a: Any, **kwargs: Any) -> Any:
        self.calls += 1
        self.attributed.append(kwargs["attribution"]["profile"])
        await self.gate.wait()
        if self.fail:
            raise RuntimeError("L3 fell over")
        return MagicMock(flagged=False)


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


class TestCoalescing:
    async def test_two_profiles_listing_together_each_judge_their_own(self) -> None:
        """6.1.0: two profiles no longer share one judgement.

        They used to coalesce onto a single run per description, which is what
        made one tenant's key pay for another's tool list and the verdict
        shareable. The key now carries the grant owner, so the single-flight
        unit is per tenant — and that is the point, not a regression: Scott,
        "Everything that a user's account touches should be done by its own
        key."

        Within ONE profile the coalescing is intact; the test below holds it.
        """
        defend = _GatedDefend()
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            first = asyncio.create_task(ing.scan_tool_list(_profile("alpha"), "b", TOOLS, TOOLS))
            second = asyncio.create_task(ing.scan_tool_list(_profile("beta"), "b", TOOLS, TOOLS))
            await _settle()
            defend.gate.set()
            await asyncio.gather(first, second)

        assert defend.calls == len(TOOLS) * 2
        # Each judgement is attributed to the profile that ran it, and each
        # profile ran its own.
        assert sorted(defend.attributed) == sorted(["alpha", "beta"] * len(TOOLS))

    async def test_one_profile_listing_twice_judges_each_description_once(self) -> None:
        """The coalescing that remains, and the reason the single-flight map is
        still there: two clients on the SAME profile join one judgement."""
        defend = _GatedDefend()
        profile = _profile("alpha")
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            first = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS, TOOLS))
            second = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS, TOOLS))
            await _settle()
            defend.gate.set()
            await asyncio.gather(first, second)

        assert defend.calls == len(TOOLS)
        assert defend.attributed == ["alpha"] * len(TOOLS)

    async def test_different_thresholds_are_different_judgements(self) -> None:
        """The key is the coalescing unit: a stricter gate is its own verdict."""
        defend = _GatedDefend()
        defend.gate.set()
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            await asyncio.gather(
                ing.scan_tool_list(_profile("alpha"), "b", TOOLS[:1], TOOLS[:1]),
                ing.scan_tool_list(_profile("beta", 0.2), "b", TOOLS[:1], TOOLS[:1]),
            )

        assert defend.calls == 2


class TestAFlagReachesEveryone:
    async def test_every_caller_gets_the_flag_and_the_journal_gets_one_line(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        defend = _GatedDefend()
        # One profile, two clients: since 6.1.0 two PROFILES no longer join one
        # judgement, so the joining this test is about is within a tenant.
        profile = _profile("alpha")
        flag = {"flagged_by": "L2", "risk_level": "high"}
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=dict(flag)),
            patch.object(ing, "effective_mode", return_value=ing.Mode.FLAG),
        ):
            first = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            second = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            await _settle()
            first.cancel()  # the starter leaves; the line must still be written
            defend.gate.set()
            results = await asyncio.gather(first, second, return_exceptions=True)

        assert isinstance(results[0], asyncio.CancelledError)
        assert results[1][0]["_trentina_warning"]["flagged_by"] == "L2"
        flagged = [r for r in caplog.records if "tool description flagged" in r.getMessage()]
        assert len(flagged) == 1


class TestDifferentJudges:
    async def test_the_same_thresholds_under_different_judges_are_not_shared(self) -> None:
        """A verdict one model reached must not reach a list judged by another
        (#137). The judge is the LISTING profile's own since 6.1.0, so two
        profiles running different models key apart for that reason as well as
        for their owners."""
        defend = _GatedDefend()
        judge_a = _profile("alpha").model_copy(update={"defense": DefenseConfig(model="judge-a")})
        judge_b = _profile("beta").model_copy(update={"defense": DefenseConfig(model="judge-b")})
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            first = asyncio.create_task(ing.scan_tool_list(judge_a, "b", TOOLS[:1], TOOLS[:1]))
            second = asyncio.create_task(ing.scan_tool_list(judge_b, "b", TOOLS[:1], TOOLS[:1]))
            await _settle()
            defend.gate.set()
            await asyncio.gather(first, second)

        assert defend.calls == 2


class TestTheWorkOutlivesTheCaller:
    async def test_a_cancelled_caller_leaves_the_verdict_banked(self) -> None:
        defend = _GatedDefend()
        profile = _profile("alpha")
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            caller = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            await _settle()
            caller.cancel()
            with pytest.raises(asyncio.CancelledError):
                await caller

            defend.gate.set()
            await _settle()

        assert _key(profile, TOOLS[0]) in vc._descriptions
        assert vc._inflight == {}


class TestFailure:
    async def test_every_waiter_sees_the_failure_and_nothing_is_cached(self) -> None:
        defend = _GatedDefend(fail=True)
        profile = _profile("alpha")
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            first = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            second = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            await _settle()
            defend.gate.set()
            results = await asyncio.gather(first, second, return_exceptions=True)

        assert all(isinstance(r, RuntimeError) for r in results)
        assert defend.calls == 1
        assert _key(profile, TOOLS[0]) not in vc._descriptions
        # The key is free again: the next caller retries rather than joining a corpse.
        assert vc._inflight == {}

    async def test_a_failure_nobody_waited_for_is_logged_and_retried(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        defend = _GatedDefend(fail=True)
        profile = _profile("alpha")
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            caller = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1]))
            await _settle()
            caller.cancel()
            defend.gate.set()
            await _settle()

            assert vc._inflight == {}
            assert _key(profile, TOOLS[0]) not in vc._descriptions
            assert any("judgement failed" in r.getMessage() for r in caplog.records)

            defend.fail = False
            await ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1])

        assert defend.calls == 2
        assert _key(profile, TOOLS[0]) in vc._descriptions

    async def test_the_failure_line_is_scrubbed(self, caplog: pytest.LogCaptureFixture) -> None:
        async def leaky(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("HTTP 400 for https://x/?key=AIzaSECRET123")

        with (
            patch.object(orch, "defend", leaky),
            patch.object(ing, "build_warning", return_value=None),
            pytest.raises(RuntimeError),
        ):
            await ing.scan_tool_list(_profile("alpha"), "b", TOOLS[:1], TOOLS[:1])

        await _settle()
        lines = [r.getMessage() for r in caplog.records if "judgement failed" in r.getMessage()]
        assert lines
        assert "AIzaSECRET123" not in lines[0]
