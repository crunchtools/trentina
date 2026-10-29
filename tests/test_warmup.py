"""Boot warm-up and concurrent description judging (#216).

A cold perimeter store used to make the first tools/list judge every tool
description one at a time, after a client had already asked. These tests pin
the two halves of the fix: descriptions are judged together, and the warm-up
starts that work at boot through the same single-flight build a client joins.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from trentina import orchestrator as orch
from trentina.gateway import ingress_defense as ing
from trentina.gateway import router, warmup
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.quarantine.limiter import (
    Priority,
    l3_priority,
    l3_throttle_budget,
)

TOOLS = [{"name": f"t{n}", "description": f"Does thing number {n}."} for n in range(6)]


def _profile(name: str) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="T"),
        defense=DefenseConfig(),
    )


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


class _GatedDefend:
    def __init__(self) -> None:
        self.started = 0
        self.gate = asyncio.Event()

    async def __call__(self, *_a: Any, **_kw: Any) -> Any:
        self.started += 1
        await self.gate.wait()
        return MagicMock(flagged=False)


class TestDescriptionsJudgedTogether:
    async def test_every_description_is_in_flight_at_once(self) -> None:
        defend = _GatedDefend()
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            scan = asyncio.create_task(ing.scan_tool_list(_profile("a"), "b", TOOLS, TOOLS))
            await _settle()
            # Sequential judging would have exactly one waiting here.
            assert defend.started == len(TOOLS)
            defend.gate.set()
            result = await scan

        assert [t["name"] for t in result] == [t["name"] for t in TOOLS]

    async def test_withholding_keeps_the_original_order(self) -> None:
        flagged = {"t1", "t4"}

        def warning_for(verdict: Any) -> dict[str, Any] | None:
            return verdict

        async def defend(surface: str, **_kw: Any) -> Any:
            await asyncio.sleep(0.001 * (hash(surface) % 3))
            name = next(t["name"] for t in TOOLS if t["description"] in surface)
            return {"flagged_by": "L2", "risk_level": "high"} if name in flagged else None

        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", side_effect=warning_for),
            patch.object(ing, "effective_mode", return_value=ing.Mode.BLOCK),
        ):
            result = await ing.scan_tool_list(_profile("a"), "b", TOOLS, TOOLS)

        assert [t["name"] for t in result] == ["t0", "t2", "t3", "t5"]

    async def test_counts_judged_and_cached(self) -> None:
        before = dict(ing.perimeter_counts)
        defend = _GatedDefend()
        defend.gate.set()
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            await ing.scan_tool_list(_profile("a"), "b", TOOLS, TOOLS)
            await ing.scan_tool_list(_profile("a"), "b", TOOLS, TOOLS)

        assert ing.perimeter_counts["judged"] - before["judged"] == len(TOOLS)
        assert ing.perimeter_counts["hits"] - before["hits"] == len(TOOLS)


def _active(*profiles: Profile) -> MagicMock:
    active = MagicMock()
    active.config.profiles = {p.name: p for p in profiles}
    return active


class TestWarmUp:
    async def test_a_client_mid_warmup_joins_the_build(self) -> None:
        gate = asyncio.Event()
        builds: list[str] = []

        async def build(profile: Profile, _generation: int | None = None) -> list[dict[str, Any]]:
            builds.append(profile.name)
            await gate.wait()
            return [{"name": "x"}]

        profile = _profile("alpha")
        with (
            patch.object(warmup, "get_active_config", return_value=_active(profile)),
            patch.object(router, "_build_profile_tools", build),
        ):
            warm = asyncio.create_task(warmup.warm_all())
            await _settle()
            client = asyncio.create_task(router._route_tools_list(profile, 1))
            await _settle()
            gate.set()
            await warm
            response = await client

        assert builds == ["alpha"]
        assert response["result"]["tools"] == [{"name": "x"}]

    async def test_runs_as_background_l3_work(self) -> None:
        seen: dict[str, Any] = {}

        async def build(_profile: Profile, _generation: int | None = None) -> list[Any]:
            seen["priority"] = l3_priority.get()
            seen["budget"] = l3_throttle_budget.get()
            return []

        with (
            patch.object(warmup, "get_active_config", return_value=_active(_profile("a"))),
            patch.object(router, "_build_profile_tools", build),
        ):
            await warmup.warm_all()

        assert seen == {
            "priority": Priority.BACKGROUND,
            "budget": warmup.WARMUP_THROTTLE_BUDGET,
        }
        # The warm-up's context does not leak into the caller's.
        assert l3_priority.get() is Priority.FOREGROUND

    async def test_one_failing_profile_does_not_stop_the_rest(self) -> None:
        async def build(profile: Profile, _generation: int | None = None) -> list[Any]:
            if profile.name == "bad":
                raise RuntimeError("backend fell over")
            return [{"name": "x"}]

        with (
            patch.object(
                warmup, "get_active_config", return_value=_active(_profile("bad"), _profile("ok"))
            ),
            patch.object(router, "_build_profile_tools", build),
        ):
            await warmup.warm_all()

        assert router._profile_inflight == {}


class TestPersistedListsAreRevalidated:
    """Boot refetches what SQLite remembered, before anything is built (#335)."""

    @staticmethod
    def _sharing(name: str) -> Profile:
        profile = _profile(name)
        profile.backends = {
            "feeds": Backend(url="http://feeds:8000/mcp"),
            "wiki": Backend(url="http://wiki:8000/mcp"),
            "web": Backend(url="internal://web"),
        }
        return profile

    async def test_each_url_once_and_changed_ones_are_invalidated(self) -> None:
        order: list[str] = []

        async def revalidate(name: str, _backend: Backend) -> bool:
            order.append(name)
            return name == "feeds"

        async def build(profile: Profile, _generation: int | None = None) -> list[Any]:
            order.append(f"build:{profile.name}")
            return []

        with (
            patch.object(
                warmup,
                "get_active_config",
                return_value=_active(self._sharing("a"), self._sharing("b")),
            ),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "invalidate_profile_cache_for_backend") as invalidate,
            patch.object(router, "_build_profile_tools", build),
        ):
            await warmup.warm_all()

        # Two profiles share both URLs; the internal backend has no list to refetch.
        assert order == ["feeds", "wiki", "build:a", "build:b"]
        invalidate.assert_called_once_with("http://feeds:8000/mcp")

    async def test_nothing_changed_invalidates_nothing(self) -> None:
        async def revalidate(_name: str, _backend: Backend) -> bool:
            return False

        async def build(_profile: Profile, _generation: int | None = None) -> list[Any]:
            return []

        with (
            patch.object(warmup, "get_active_config", return_value=_active(self._sharing("a"))),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "invalidate_profile_cache_for_backend") as invalidate,
            patch.object(router, "_build_profile_tools", build),
        ):
            await warmup.warm_all()

        invalidate.assert_not_called()


class TestLifespan:
    async def test_standalone_starts_nothing(self) -> None:
        with patch.object(warmup, "get_active_config", return_value=None):
            async with warmup.trentina_lifespan():
                assert warmup._task is None

    async def test_gateway_starts_one_warmup_and_cancels_it_on_exit(self) -> None:
        gate = asyncio.Event()

        async def build(_profile: Profile, _generation: int | None = None) -> list[Any]:
            await gate.wait()
            return []

        with (
            patch.object(warmup, "get_active_config", return_value=_active(_profile("a"))),
            patch.object(router, "_build_profile_tools", build),
        ):
            async with warmup.trentina_lifespan():
                task = warmup._task
                assert task is not None
                async with warmup.trentina_lifespan():
                    assert warmup._task is task  # re-entry starts no second warm-up
                await _settle()
                assert not task.done()
            assert task.cancelled()
            assert warmup._task is None

    async def test_fastmcp_runs_it_at_http_startup(self) -> None:
        from trentina.server import mcp

        started = asyncio.Event()

        async def warm() -> None:
            started.set()

        app = mcp.http_app()
        with (
            patch.object(warmup, "get_active_config", return_value=_active()),
            patch.object(warmup, "warm_all", warm),
        ):
            async with app.router.lifespan_context(app):
                await asyncio.wait_for(started.wait(), timeout=2.0)


class TestAFailedJudgement:
    async def test_fails_the_list_and_the_others_still_bank(self) -> None:
        gate = asyncio.Event()

        async def defend(surface: str, **_kw: Any) -> Any:
            if "number 0" in surface:
                raise RuntimeError("L3 fell over")
            await gate.wait()
            return MagicMock(flagged=False)

        profile = _profile("a")
        with (
            patch.object(orch, "defend", defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            scan = asyncio.create_task(ing.scan_tool_list(profile, "b", TOOLS, TOOLS))
            await _settle()
            gate.set()
            with pytest.raises(RuntimeError, match="L3 fell over"):
                await scan
            await _settle()
            # The rest were single-flight tasks: they finished and banked.
            before = ing.perimeter_counts["hits"]
            with patch.object(orch, "defend", side_effect=AssertionError("re-judged")):
                result = await ing.scan_tool_list(profile, "b", TOOLS[1:], TOOLS[1:])

        assert len(result) == len(TOOLS) - 1
        assert ing.perimeter_counts["hits"] - before == len(TOOLS) - 1
