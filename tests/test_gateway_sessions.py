"""Tests for gateway/sessions.py — session registry lifecycle and notifications."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest

from trentina.gateway.sessions import (
    REASON_CLIENT_DELETE,
    REASON_EVICTED,
    REASON_TTL_EXPIRED,
    TOMBSTONE_MAXSIZE,
    SessionRegistry,
)


@pytest.fixture
def registry() -> SessionRegistry:
    return SessionRegistry(session_ttl=5.0, max_sessions_per_profile=3)


class TestSessionLifecycle:
    def test_create_returns_session_id(self, registry: SessionRegistry) -> None:
        sid = registry.create_session("alice")
        assert isinstance(sid, str)
        assert len(sid) == 32

    def test_get_session_returns_session(self, registry: SessionRegistry) -> None:
        sid = registry.create_session("alice")
        session = registry.get_session(sid)
        assert session is not None
        assert session.session_id == sid
        assert session.profile_name == "alice"

    def test_get_unknown_session_returns_none(self, registry: SessionRegistry) -> None:
        assert registry.get_session("nonexistent") is None

    def test_delete_session(self, registry: SessionRegistry) -> None:
        sid = registry.create_session("alice")
        assert registry.delete_session(sid) is True
        assert registry.get_session(sid) is None

    def test_delete_unknown_returns_false(self, registry: SessionRegistry) -> None:
        assert registry.delete_session("nonexistent") is False

    def test_active_count(self, registry: SessionRegistry) -> None:
        registry.create_session("alice")
        registry.create_session("alice")
        registry.create_session("bob")
        assert registry.active_count == 3

    def test_reset_clears_all(self, registry: SessionRegistry) -> None:
        registry.create_session("alice")
        registry.create_session("bob")
        registry.reset()
        assert registry.active_count == 0

    def test_get_sessions_for_profile(self, registry: SessionRegistry) -> None:
        registry.create_session("alice")
        registry.create_session("alice")
        registry.create_session("bob")
        alice_sessions = registry.get_sessions_for_profile("alice")
        assert len(alice_sessions) == 2
        assert all(s.profile_name == "alice" for s in alice_sessions)

    def test_get_updates_last_access(self, registry: SessionRegistry) -> None:
        sid = registry.create_session("alice")
        session = registry.get_session(sid)
        assert session is not None
        first_access = session.last_access
        time.sleep(0.01)
        session = registry.get_session(sid)
        assert session is not None
        assert session.last_access > first_access


class TestSessionTTL:
    def test_expired_session_not_returned(self) -> None:
        registry = SessionRegistry(session_ttl=0.01, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        time.sleep(0.02)
        assert registry.get_session(sid) is None

    def test_expired_session_cleaned_from_count(self) -> None:
        registry = SessionRegistry(session_ttl=0.01, max_sessions_per_profile=10)
        registry.create_session("alice")
        time.sleep(0.02)
        assert registry.active_count == 0


class TestMaxSessions:
    def test_oldest_evicted_when_limit_reached(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=2)
        first = registry.create_session("alice")
        time.sleep(0.01)
        registry.create_session("alice")
        time.sleep(0.01)
        registry.create_session("alice")
        assert registry.get_session(first) is None
        assert len(registry.get_sessions_for_profile("alice")) == 2

    def test_max_sessions_per_profile_not_global(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=2)
        registry.create_session("alice")
        registry.create_session("alice")
        registry.create_session("bob")
        assert len(registry.get_sessions_for_profile("alice")) == 2
        assert len(registry.get_sessions_for_profile("bob")) == 1
        assert registry.active_count == 3


class TestProfileLookup:
    def test_profiles_for_backend_url(self, registry: SessionRegistry) -> None:
        from pydantic import SecretStr

        from trentina.gateway.profile import (
            AuthConfig,
            Backend,
            Profile,
        )

        p1 = Profile(
            name="alice",
            auth=AuthConfig(bearer_token_env="A"),
            backends={"slack": Backend(url="http://slack:8005/mcp")},
        )
        p1.auth.bearer_token = SecretStr("t")
        p2 = Profile(
            name="bob",
            auth=AuthConfig(bearer_token_env="B"),
            backends={"jira": Backend(url="http://jira:8006/mcp")},
        )
        p2.auth.bearer_token = SecretStr("t")

        profiles = {"alice": p1, "bob": p2}
        affected = registry.profiles_for_backend_url("http://slack:8005/mcp", profiles)
        assert affected == ["alice"]

    def test_no_profiles_for_unknown_url(self, registry: SessionRegistry) -> None:
        affected = registry.profiles_for_backend_url("http://unknown/mcp", {})
        assert affected == []


class TestBroadcast:
    @pytest.mark.asyncio
    async def test_broadcast_calls_callback(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        callback = AsyncMock()
        registry.set_notification_callback(callback)

        registry.create_session("alice")
        registry.create_session("alice")

        count = await registry.broadcast_tools_changed("alice")
        assert count == 2
        assert callback.call_count == 2

        for call in callback.call_args_list:
            notification = call.args[1]
            assert notification["method"] == "notifications/tools/list_changed"

    @pytest.mark.asyncio
    async def test_broadcast_to_empty_profile_returns_zero(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        count = await registry.broadcast_tools_changed("nobody")
        assert count == 0

    @pytest.mark.asyncio
    async def test_broadcast_without_callback(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        registry.create_session("alice")
        count = await registry.broadcast_tools_changed("alice")
        assert count == 0

    @pytest.mark.asyncio
    async def test_broadcast_survives_callback_error(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        callback = AsyncMock(side_effect=[Exception("boom"), None])
        registry.set_notification_callback(callback)

        registry.create_session("alice")
        registry.create_session("alice")

        count = await registry.broadcast_tools_changed("alice")
        assert count == 1


class TestSubscribers:
    @pytest.mark.asyncio
    async def test_broadcast_delivers_to_subscriber_queue(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        queue = registry.subscribe(sid)

        count = await registry.broadcast_tools_changed("alice")
        assert count == 1

        notification = queue.get_nowait()
        assert notification["method"] == "notifications/tools/list_changed"
        assert notification["jsonrpc"] == "2.0"

    @pytest.mark.asyncio
    async def test_broadcast_delivers_to_all_subscribers_of_session(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        q1 = registry.subscribe(sid)
        q2 = registry.subscribe(sid)

        count = await registry.broadcast_tools_changed("alice")
        assert count == 1
        assert q1.get_nowait()["method"] == "notifications/tools/list_changed"
        assert q2.get_nowait()["method"] == "notifications/tools/list_changed"

    @pytest.mark.asyncio
    async def test_broadcast_only_targets_matching_profile(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        alice_sid = registry.create_session("alice")
        bob_sid = registry.create_session("bob")
        alice_q = registry.subscribe(alice_sid)
        bob_q = registry.subscribe(bob_sid)

        count = await registry.broadcast_tools_changed("alice")
        assert count == 1
        assert not alice_q.empty()
        assert bob_q.empty()

    @pytest.mark.asyncio
    async def test_unsubscribe_stops_delivery(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        queue = registry.subscribe(sid)
        assert registry.subscriber_count(sid) == 1

        registry.unsubscribe(sid, queue)
        assert registry.subscriber_count(sid) == 0

        count = await registry.broadcast_tools_changed("alice")
        assert count == 0
        assert queue.empty()

    @pytest.mark.asyncio
    async def test_callback_and_subscriber_count_session_once(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        callback = AsyncMock()
        registry.set_notification_callback(callback)
        sid = registry.create_session("alice")
        queue = registry.subscribe(sid)

        count = await registry.broadcast_tools_changed("alice")
        assert count == 1
        assert callback.call_count == 1
        assert not queue.empty()

    def test_delete_session_drops_subscribers(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        registry.subscribe(sid)
        registry.delete_session(sid)
        assert registry.subscriber_count(sid) == 0

    def test_reset_clears_subscribers(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        registry.subscribe(sid)
        registry.reset()
        assert registry.subscriber_count(sid) == 0


class TestDisconnectDiagnostics:
    def test_expired_session_is_explained_as_ttl(self) -> None:
        registry = SessionRegistry(session_ttl=0.01, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        time.sleep(0.02)
        assert registry.get_session(sid) is None
        assert REASON_TTL_EXPIRED in registry.explain_missing(sid, None)

    def test_evicted_session_is_explained_as_eviction(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=2)
        first = registry.create_session("alice")
        time.sleep(0.01)
        registry.create_session("alice")
        time.sleep(0.01)
        registry.create_session("alice")
        assert registry.get_session(first) is None
        assert REASON_EVICTED in registry.explain_missing(first, None)

    def test_ttl_and_eviction_are_distinguishable(self) -> None:
        """The whole point: a 404 must name which limit killed the session."""
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=1)
        evicted = registry.create_session("alice")
        registry.create_session("alice")

        idle = SessionRegistry(session_ttl=0.01, max_sessions_per_profile=10)
        expired = idle.create_session("bob")
        time.sleep(0.02)
        idle.get_session(expired)

        assert REASON_EVICTED in registry.explain_missing(evicted, None)
        assert REASON_TTL_EXPIRED in idle.explain_missing(expired, None)

    def test_client_delete_is_explained(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = registry.create_session("alice")
        registry.delete_session(sid)
        assert REASON_CLIENT_DELETE in registry.explain_missing(sid, None)

    def test_unknown_session_reports_never_issued(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        assert "never issued" in registry.explain_missing("deadbeef" * 4, None)

    def test_tombstones_are_bounded(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=1)
        for _ in range(TOMBSTONE_MAXSIZE + 25):
            registry.create_session("alice")
        assert len(registry._tombstones) <= TOMBSTONE_MAXSIZE

    def test_census_counts_live_sessions_per_profile(self) -> None:
        registry = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        registry.create_session("alice")
        registry.create_session("alice")
        registry.create_session("bob")
        assert registry.census() == {"alice": 2, "bob": 1}
