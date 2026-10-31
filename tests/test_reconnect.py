"""Tests for tools/reconnect.py — per-backend circuit reset and re-probe.

Patches the transport layer (_do_list_tools) so the real reconnect_backend
runs its breaker reset, cache eviction, fresh fetch, and profile-cache
invalidation end to end. Profiles are registered via set_profiles and reset
to None after each test (the autouse conftest fixture does not manage them).

The class below registers no ActiveConfig, so it runs in the standalone scope
— one tenant, full reach, which is the operator path. ``TestAgentScope`` is
the multi-tenant half: a live gateway, a bound agent profile, and a backend it
does not hold.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from mcp.types import ListToolsResult, Tool

from trentina.gateway import compress
from trentina.gateway.aggregate import (
    _profile_backend_urls,
    _profile_tools_cache,
)
from trentina.gateway.backend import _tool_list_cache
from trentina.gateway.circuit import State, breaker
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import (
    GatewayConfig,
    register_active_config,
)
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.tools.reconnect import _safe_endpoint, reconnect_backend

POSTIZ_URL = "http://mcp-postiz:5000/api/mcp/token-a"


def _unset_profiles() -> None:
    """Clear the profile registry to simulate an un-started gateway."""
    compress._profiles = None


# Real SDK models rather than hand-rolled stand-ins -- a fake with its own
# attribute names cannot notice an SDK field rename, which is how camelCase
# reads survived the move to snake_case with the suite still green.
def _tools_result(names: list[str]) -> ListToolsResult:
    return ListToolsResult(tools=[Tool(name=n, description="", input_schema={}) for n in names])


def _profile(name: str, backends: dict[str, Backend]) -> Profile:
    return Profile(name=name, auth=AuthConfig(bearer_token_env="TEST"), backends=backends)


@pytest.fixture(autouse=True)
def _clear_profiles() -> Iterator[None]:
    """Reset the profile registry around each test (conftest does not)."""
    yield
    _unset_profiles()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://mcp-postiz:5000/api/mcp/token-a", "http://mcp-postiz:5000"),
        ("http://mcp-rotv:8000/mcp?token=secret", "http://mcp-rotv:8000"),
        ("https://example.com", "https://example.com"),
        ("internal://web", "internal://web"),
        ("garbage-no-scheme", "(redacted)"),
        ("", "(redacted)"),
    ],
)
def test_safe_endpoint_strips_path_and_query(url: str, expected: str) -> None:
    """host:port survives; any path/query (where tokens hide) is dropped."""
    result = _safe_endpoint(url)
    assert result == expected
    assert "token" not in result
    assert "secret" not in result


@pytest.mark.asyncio
class TestReconnectBackend:
    async def test_reset_closes_open_circuit_and_rewarms_cache(self) -> None:
        """An open circuit is forced closed and the tool cache is re-warmed."""
        set_profiles({"agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})})
        for _ in range(3):
            breaker.record_failure(POSTIZ_URL)
        assert breaker.get_state(POSTIZ_URL) is State.OPEN

        async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
            return _tools_result(["integrationList", "listPostsTool"])

        with patch("trentina.gateway.backend._do_list_tools", side_effect=ok):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is True
        assert result["targets"][0]["tool_count"] == 2
        assert result["targets"][0]["circuit"] == "closed"
        assert result["targets"][0]["endpoint"] == "http://mcp-postiz:5000"
        assert "token-a" not in str(result)
        assert breaker.get_state(POSTIZ_URL) is State.CLOSED
        assert _tool_list_cache[POSTIZ_URL]

    async def test_unknown_backend_reports_available(self) -> None:
        """A name in no profile returns reconnected False with the known names."""
        set_profiles({"agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})})
        result = await reconnect_backend("nope")

        assert result["reconnected"] is False
        assert result["error"] == "backend not found in any profile"
        assert result["available"] == ["postiz"]

    async def test_failing_backend_reports_failure(self) -> None:
        """A backend that still can't be reached reports reconnected False."""
        set_profiles({"agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})})

        async def boom(_url: str, _headers: Any, *_: Any) -> Any:
            raise ConnectionRefusedError("still down")

        with patch("trentina.gateway.backend._do_list_tools", side_effect=boom):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert "error" in result["targets"][0]
        assert POSTIZ_URL not in _tool_list_cache

    async def test_failed_operator_reconnect_keeps_the_last_good_list(self) -> None:
        """A failed operator reconnect must not strand the primary: the
        last-good list survives in memory and SQLite, and the error names the
        real leaf, not the SDK task group (F1 + F2)."""
        import httpx

        from trentina.database import save_tool_list
        from trentina.gateway.backend import load_tool_list_cache

        set_profiles({"agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})})
        good = [{"name": "integrationList"}, {"name": "listPostsTool"}]
        _tool_list_cache[POSTIZ_URL] = good
        save_tool_list(POSTIZ_URL, good)

        async def grouped_connect_error(_url: str, _headers: Any, *_: Any) -> Any:
            raise ExceptionGroup(
                "unhandled errors in a TaskGroup", [httpx.ConnectError("boom")]
            )

        with patch(
            "trentina.gateway.backend._do_list_tools", side_effect=grouped_connect_error
        ):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        error = str(result["targets"][0]["error"])
        assert "ConnectError" in error
        assert "ExceptionGroup" not in error
        # Untouched in memory ...
        assert _tool_list_cache[POSTIZ_URL] == good
        # ... and still on disk: reload from SQLite and confirm it returns.
        _tool_list_cache.clear()
        load_tool_list_cache()
        assert _tool_list_cache.get(POSTIZ_URL) == good

    async def test_operator_reconnect_of_a_federated_backend_passes_the_profile(self) -> None:
        """A federated edge mints its JWT from the caller profile (#592 C1/C2);
        the operator reconnect must pass one, or the probe goes out with no auth
        and the secondary rejects it (surfacing as an opaque ExceptionGroup)."""
        from trentina.gateway.profile import FederatedConfig

        fed = Backend(
            url="https://up.example/gateway/fed-x/mcp",
            federated=FederatedConfig(primary_key_env="X_EDGE_KEY"),
        )
        set_profiles({"josui": _profile("josui", {"up": fed})})
        captured: dict[str, Any] = {}

        async def spy_refresh(_name: str, _backend: Backend, profile: Any = None) -> Any:
            captured["profile"] = profile
            return [{"name": "t"}]

        with patch("trentina.tools.reconnect.refresh_backend_tools", side_effect=spy_refresh):
            result = await reconnect_backend("up")

        assert result["reconnected"] is True
        assert captured["profile"] is not None
        assert captured["profile"].name == "josui"

    async def test_internal_backend_is_noop(self) -> None:
        """An internal:// backend needs no transport reconnect."""
        set_profiles({"agent2": _profile("agent2", {"web": Backend(url="internal://web")})})
        result = await reconnect_backend("web")

        assert result["reconnected"] is True
        assert result["targets"][0]["internal"] is True

    async def test_distinct_urls_across_profiles_all_reset(self) -> None:
        """The same name with different URLs across profiles resets each URL."""
        url_b = "http://mcp-postiz:5000/api/mcp/token-b"
        set_profiles(
            {
                "agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)}),
                "agent3": _profile("agent3", {"postiz": Backend(url=url_b)}),
            }
        )

        async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
            return _tools_result(["integrationList"])

        with patch("trentina.gateway.backend._do_list_tools", side_effect=ok):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is True
        assert len(result["targets"]) == 2
        profiles_seen = {frozenset(t["profiles"]) for t in result["targets"]}
        assert profiles_seen == {frozenset({"agent2"}), frozenset({"agent3"})}
        assert "token-" not in str(result)

    async def test_reconnect_invalidates_stale_profile_cache(self) -> None:
        """A profile aggregate that omitted the backend is dropped on reconnect."""
        set_profiles({"agent2": _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})})
        _profile_tools_cache["agent2"] = [{"name": "other__tool"}]
        _profile_backend_urls["agent2"] = {POSTIZ_URL}

        async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
            return _tools_result(["integrationList"])

        with patch("trentina.gateway.backend._do_list_tools", side_effect=ok):
            await reconnect_backend("postiz")

        assert "agent2" not in _profile_tools_cache

    async def test_gateway_not_initialized(self) -> None:
        """With no profiles loaded, reconnect reports the gateway is down."""
        _unset_profiles()
        result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert result["error"] == "gateway not initialized"


@pytest.mark.asyncio
class TestAgentScope:
    """A live gateway, and a caller that is not the operator."""

    @staticmethod
    def _live(profiles: dict[str, Profile], tmp_path: Any) -> None:
        set_profiles(profiles)
        register_active_config(tmp_path / "profiles.yaml", GatewayConfig(profiles=profiles), {})

    async def test_a_backend_in_another_profile_is_refused(self, tmp_path: Any) -> None:
        """Reconnecting what you cannot call is not yours to do."""
        agent2 = _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})
        agent3 = _profile("agent3", {"wiki": Backend(url="http://wiki:1/mcp")})
        self._live({"agent2": agent2, "agent3": agent3}, tmp_path)

        with profile_context(agent3):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert "not in this profile" in result["error"]
        assert breaker.get_state(POSTIZ_URL) is State.CLOSED

    async def test_a_miss_lists_only_the_callers_own_backends(self, tmp_path: Any) -> None:
        """The directory of every profile's backends used to come back here."""
        agent2 = _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})
        agent3 = _profile("agent3", {"wiki": Backend(url="http://wiki:1/mcp")})
        self._live({"agent2": agent2, "agent3": agent3}, tmp_path)

        with profile_context(agent3):
            result = await reconnect_backend("nope")

        assert result["available"] == ["wiki"]
        assert "postiz" not in str(result)

    async def test_the_tool_count_is_what_the_caller_would_see(self, tmp_path: Any) -> None:
        """A shared backend's raw surface is somebody else's view of it."""
        agent3 = _profile(
            "agent3",
            {"postiz": Backend(url=POSTIZ_URL, tools_allow=["integrationList"])},
        )
        self._live({"agent3": agent3}, tmp_path)

        async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
            return _tools_result(["integrationList", "deletePostTool"])

        with (
            profile_context(agent3),
            patch("trentina.gateway.backend._do_list_tools", side_effect=ok),
        ):
            result = await reconnect_backend("postiz")

        assert result["targets"][0]["tool_count"] == 1
        assert "profiles" not in result["targets"][0]

    async def test_no_bound_caller_on_a_live_gateway_is_refused(self, tmp_path: Any) -> None:
        agent2 = _profile("agent2", {"postiz": Backend(url=POSTIZ_URL)})
        self._live({"agent2": agent2}, tmp_path)

        result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert "no calling profile bound" in result["error"]
