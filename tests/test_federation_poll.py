"""Primary federation poll (#592, F3).

A federated secondary's newly approved or changed tool should appear primary
without a hand-run reconnect. ``warmup._poll_once`` re-probes the federated
backends whose interval has elapsed and rebuilds the profiles that share a
changed one, under background L3 priority. These drive ``_poll_once`` directly
(no real timer) and pin the config validators.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from trentina.gateway import warmup
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile
from trentina.quarantine.limiter import Priority, l3_priority


def _active(*profiles: Profile) -> MagicMock:
    active = MagicMock()
    active.config.profiles = {p.name: p for p in profiles}
    return active


def _profile(name: str, backends: dict[str, Backend]) -> Profile:
    return Profile(name=name, auth=AuthConfig(bearer_token_env="T"), backends=backends)


def _fed(url: str, poll_seconds: int = 300) -> Backend:
    return Backend(url=url, federated=FederatedConfig(poll_seconds=poll_seconds))


@pytest.fixture(autouse=True)
def _clear_next_due() -> Any:
    warmup._next_due.clear()
    yield
    warmup._next_due.clear()


UP = "http://up:8000/mcp"


@pytest.mark.asyncio
class TestPollOnce:
    async def test_due_backend_revalidated_and_sharing_profiles_rebuilt(self) -> None:
        a = _profile("a", {"up": _fed(UP, 30)})
        b = _profile("b", {"up": _fed(UP, 30)})
        c = _profile("c", {"other": Backend(url="http://other:8000/mcp")})
        warmup._next_due[UP] = 0.0  # already due
        got_profiles: list[Any] = []

        async def revalidate(_name: str, _backend: Backend, profile: Any = None) -> bool:
            got_profiles.append(profile)
            return True  # the list changed

        rebuilt: list[list[str]] = []

        async def spy_rebuild(profiles: list[Profile]) -> int:
            rebuilt.append([p.name for p in profiles])
            return len(profiles)

        with (
            patch.object(warmup, "get_active_config", return_value=_active(a, b, c)),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "rebuild_profiles", spy_rebuild),
        ):
            sleep_for = await warmup._poll_once(100.0)

        # Exactly the two profiles sharing the changed URL are rebuilt; "c" is not.
        assert rebuilt == [["a", "b"]]
        # The owning profile is passed so a federated backend can mint its edge JWT.
        assert got_profiles and got_profiles[0].name == "a"
        assert warmup._next_due[UP] == 130.0  # re-seeded now + poll_seconds
        assert sleep_for == pytest.approx(30.0)

    async def test_not_due_backend_is_not_probed(self) -> None:
        a = _profile("a", {"up": _fed(UP, 300)})
        warmup._next_due[UP] = 500.0  # due in the future

        async def revalidate(_name: str, _backend: Backend, _profile: Any = None) -> bool:
            raise AssertionError("revalidate must not run before a backend is due")

        with (
            patch.object(warmup, "get_active_config", return_value=_active(a)),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "rebuild_profiles") as rebuild,
        ):
            sleep_for = await warmup._poll_once(100.0)

        rebuild.assert_not_called()
        assert sleep_for == pytest.approx(400.0)

    async def test_non_federated_backend_is_not_polled(self) -> None:
        a = _profile("a", {"plain": Backend(url="http://plain:8000/mcp")})

        async def revalidate(_name: str, _backend: Backend, _profile: Any = None) -> bool:
            raise AssertionError("a non-federated backend must not be polled")

        with (
            patch.object(warmup, "get_active_config", return_value=_active(a)),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "rebuild_profiles") as rebuild,
        ):
            sleep_for = await warmup._poll_once(100.0)

        rebuild.assert_not_called()
        assert sleep_for == warmup.IDLE_TICK
        assert warmup._next_due == {}

    async def test_unchanged_or_errored_backend_skips_rebuild(self) -> None:
        a = _profile("a", {"up": _fed(UP, 30)})
        warmup._next_due[UP] = 0.0

        async def revalidate(_name: str, _backend: Backend, _profile: Any = None) -> bool:
            return False  # unchanged, or unreachable (revalidate_backend_tools swallows the error)

        with (
            patch.object(warmup, "get_active_config", return_value=_active(a)),
            patch.object(warmup, "revalidate_backend_tools", revalidate),
            patch.object(warmup, "rebuild_profiles") as rebuild,
        ):
            await warmup._poll_once(100.0)

        rebuild.assert_not_called()
        assert warmup._next_due[UP] == 130.0  # still re-seeded — it was probed

    async def test_dropped_backend_is_pruned_from_next_due(self) -> None:
        warmup._next_due["http://gone:8000/mcp"] = 0.0
        a = _profile("a", {"plain": Backend(url="http://plain:8000/mcp")})
        with patch.object(warmup, "get_active_config", return_value=_active(a)):
            await warmup._poll_once(100.0)
        assert "http://gone:8000/mcp" not in warmup._next_due

    async def test_no_active_config_idle_ticks(self) -> None:
        with patch.object(warmup, "get_active_config", return_value=None):
            assert await warmup._poll_once(100.0) == warmup.IDLE_TICK


@pytest.mark.asyncio
class TestPollLoop:
    async def test_a_raising_tick_does_not_end_the_loop(self) -> None:
        calls = {"n": 0}

        async def poll_once(_now: float) -> float:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("one bad tick")
            return 0.0

        async def no_sleep(_s: float) -> None:
            if calls["n"] >= 3:
                raise asyncio.CancelledError

        with (
            patch.object(warmup, "_poll_once", poll_once),
            patch.object(warmup.asyncio, "sleep", no_sleep),
            pytest.raises(asyncio.CancelledError),
        ):
            await warmup._poll_tool_lists()

        assert calls["n"] >= 3  # survived the raise and kept ticking

    async def test_loop_runs_at_background_priority(self) -> None:
        seen: dict[str, Any] = {}

        async def poll_once(_now: float) -> float:
            seen["priority"] = l3_priority.get()
            raise asyncio.CancelledError

        with (
            patch.object(warmup, "_poll_once", poll_once),
            pytest.raises(asyncio.CancelledError),
        ):
            await warmup._poll_tool_lists()

        assert seen["priority"] is Priority.BACKGROUND
        assert l3_priority.get() is Priority.FOREGROUND  # context restored


class TestPollSecondsConfig:
    def test_default_is_300(self) -> None:
        assert FederatedConfig().poll_seconds == 300

    def test_zero_disables(self) -> None:
        assert FederatedConfig(poll_seconds=0).poll_seconds == 0

    def test_below_30_fails_load(self) -> None:
        with pytest.raises(ValidationError, match=r"0 .off. or at least 30"):
            FederatedConfig(poll_seconds=3)

    def test_poll_with_auth_is_rejected(self) -> None:
        from trentina.gateway.profile import BackendAuth

        with pytest.raises(ValidationError, match="cannot also use auth"):
            Backend(
                url=UP,
                federated=FederatedConfig(poll_seconds=30),
                auth=BackendAuth(type="oauth", issuer="https://idp.example"),
            )
