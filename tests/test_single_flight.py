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
    async def test_two_profiles_listing_together_judge_each_description_once(self) -> None:
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

        assert defend.calls == len(TOOLS)
        # The detection row names the profile that started each judgement.
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
        flag = {"flagged_by": "L2", "risk_level": "high"}
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=dict(flag)),
            patch.object(ing, "effective_mode", return_value=ing.Mode.FLAG),
        ):
            first = asyncio.create_task(
                ing.scan_tool_list(_profile("alpha"), "b", TOOLS[:1], TOOLS[:1])
            )
            second = asyncio.create_task(
                ing.scan_tool_list(_profile("beta"), "b", TOOLS[:1], TOOLS[:1])
            )
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
        """A verdict one model reached must not reach a list judged by another (#137)."""
        defend = _GatedDefend()
        judge_a = _profile("ops").model_copy(update={"defense": DefenseConfig(model="judge-a")})
        judge_b = _profile("ops").model_copy(update={"defense": DefenseConfig(model="judge-b")})
        with (
            patch.object(ing, "service_profile", side_effect=[judge_a, judge_b]),
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            first = asyncio.create_task(
                ing.scan_tool_list(_profile("alpha"), "b", TOOLS[:1], TOOLS[:1])
            )
            second = asyncio.create_task(
                ing.scan_tool_list(_profile("beta"), "b", TOOLS[:1], TOOLS[:1])
            )
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

        assert _key(profile, TOOLS[0]) in vc._verdicts
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
            second = asyncio.create_task(
                ing.scan_tool_list(_profile("beta"), "b", TOOLS[:1], TOOLS[:1])
            )
            await _settle()
            defend.gate.set()
            results = await asyncio.gather(first, second, return_exceptions=True)

        assert all(isinstance(r, RuntimeError) for r in results)
        assert defend.calls == 1
        assert _key(profile, TOOLS[0]) not in vc._verdicts
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
            assert _key(profile, TOOLS[0]) not in vc._verdicts
            assert any("judgement failed" in r.getMessage() for r in caplog.records)

            defend.fail = False
            await ing.scan_tool_list(profile, "b", TOOLS[:1], TOOLS[:1])

        assert defend.calls == 2
        assert _key(profile, TOOLS[0]) in vc._verdicts

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
