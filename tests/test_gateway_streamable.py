"""Tests for Streamable HTTP gateway features — circuit callbacks, app endpoints."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
)
from pydantic import SecretStr
from starlette.requests import Request
from starlette.testclient import TestClient

from trentina import _wire_circuit_notifications
from trentina.gateway.app import (
    MCP_SESSION_ID_HEADER,
    SSE_RETRY_MS,
    _handle_get,
    _sse_event_stream,
    gateway_app,
)
from trentina.gateway.circuit import CircuitBreaker, State
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.sessions import REASON_CLIENT_DELETE, SessionRegistry
from trentina.transports.mcp import _negotiate_protocol_version

TEST_TOKEN = "alice-token"


def _make_profile(name: str = "alice", token: str = TEST_TOKEN) -> Profile:
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8000/mcp")},
    )
    profile.auth.bearer_token = SecretStr(token)
    return profile


def _make_registry_and_client(
    session_ttl: float = 300.0,
) -> tuple[SessionRegistry, TestClient]:
    profile = _make_profile()
    sessions = SessionRegistry(session_ttl=session_ttl, max_sessions_per_profile=10)
    app = gateway_app({"alice": profile}, sessions=sessions)
    return sessions, TestClient(app)


AUTH = {"Authorization": "Bearer alice-token"}


class TestCircuitBreakerCallbacks:
    def test_callback_on_open(self) -> None:
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        assert changes == []

        cb.record_failure("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.CLOSED, State.OPEN)

    def test_callback_on_close_after_probe(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        changes.clear()

        cb.allow("http://test/mcp")
        assert any(s == State.HALF_OPEN for _, _, s in changes)

        changes.clear()
        cb.record_success("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.HALF_OPEN, State.CLOSED)

    def test_callback_on_reopen_after_failed_probe(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        cb.allow("http://test/mcp")
        changes.clear()

        cb.record_failure("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.HALF_OPEN, State.OPEN)

    def test_callback_exception_does_not_propagate(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        cb.on_state_change(lambda url, old, new: (_ for _ in ()).throw(RuntimeError("boom")))
        # record_failure must not raise even though the callback does, and the
        # breaker's own state transition must still have happened.
        cb.record_failure("http://test/mcp")
        assert cb.get_state("http://test/mcp") is State.OPEN


class TestStreamableHTTPPost:
    def test_initialize_returns_session_id(self) -> None:
        sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        assert resp.status_code == 200
        session_id = resp.headers.get(MCP_SESSION_ID_HEADER)
        assert session_id is not None
        assert len(session_id) == 32
        assert sessions.active_count == 1

    def test_post_with_session_id_succeeds(self) -> None:
        _sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 200
        assert resp2.headers.get(MCP_SESSION_ID_HEADER) == session_id

    def test_post_with_expired_session_returns_404(self) -> None:
        _sessions, client = _make_registry_and_client(session_ttl=0.001)
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        time.sleep(0.01)
        resp2 = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 404

    def test_a_stale_session_404_is_a_json_rpc_error(self) -> None:
        """#104: the 404 says what happened and what to do, as JSON-RPC.

        Carried by a malformed id since #775: a well-formed one this process
        never issued is adopted rather than refused, so a refusal now needs an
        id adoption will not take.
        """
        _sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: "not-a-session-id"},
        )

        assert resp.status_code == 404
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert body["id"] == 7
        assert body["error"]["code"] == -32001
        assert "never issued by this gateway process" in body["error"]["message"]
        assert "Re-initialize" in body["error"]["message"]

    def test_initialize_over_a_stale_session_starts_a_new_one(self) -> None:
        """A client recovering from a restart must not be refused for its old header."""
        sessions, client = _make_registry_and_client()
        stale = "deadbeef" * 4
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: stale},
        )

        assert resp.status_code == 200
        fresh = resp.headers[MCP_SESSION_ID_HEADER]
        assert fresh != stale
        assert sessions.get_session(fresh) is not None

    def test_another_profiles_session_is_not_named_in_the_404(self) -> None:
        """The scoped explanation (#137): no owner, no lifetime, for a foreign session."""
        sessions, client = _make_registry_and_client()
        foreign = sessions.create_session("bob")
        sessions.delete_session(foreign)

        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: foreign},
        )

        assert resp.status_code == 404
        assert "bob" not in resp.text
        assert "never issued" in resp.json()["error"]["message"]

    def test_post_without_session_id_still_works(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers=AUTH,
        )
        assert resp.status_code == 200

    def test_post_with_wrong_profile_session_returns_403(self) -> None:
        bob = _make_profile(name="bob", token="bob-token")
        alice = _make_profile()
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        app = gateway_app({"alice": alice, "bob": bob}, sessions=sessions)
        client = TestClient(app)

        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"Authorization": "Bearer alice-token"},
        )
        alice_session = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.post(
            "/bob/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={
                "Authorization": "Bearer bob-token",
                MCP_SESSION_ID_HEADER: alice_session,
            },
        )
        assert resp2.status_code == 403

    def test_initialize_advertises_list_changed(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        result = resp.json()["result"]
        assert result["capabilities"]["tools"]["listChanged"] is True

    def test_initialize_without_a_requested_version_answers_our_ceiling(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        result = resp.json()["result"]
        assert result["protocolVersion"] == LATEST_HANDSHAKE_VERSION


class TestProtocolVersionNegotiation:
    """The frontend half of issue #107: accept clients of any protocol era.

    Trentina used to answer every ``initialize`` with one hardcoded revision
    regardless of what was asked, which made the gateway the protocol ceiling
    for every consumer behind it. It now behaves the way the backend fleet
    measured in #107 already did: honour a known request, counter-offer
    otherwise.

    Parametrized over the SDK's own registry rather than a literal list, so a
    new revision arriving with a future SDK is covered without editing this
    test.
    """

    @pytest.mark.parametrize("requested", HANDSHAKE_PROTOCOL_VERSIONS)
    def test_known_revision_is_echoed_back(self, requested: str) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": requested},
            },
            headers=AUTH,
        )
        assert resp.json()["result"]["protocolVersion"] == requested

    @pytest.mark.parametrize(
        "requested",
        [
            "2026-07-28",  # the modern per-request-envelope era: real, not a
            # handshake revision, so not reachable this way
            "1999-01-01",
            "",
            None,
            {"not": "a string"},
        ],
    )
    def test_unknown_revision_gets_our_ceiling(self, requested: object) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": requested},
            },
            headers=AUTH,
        )
        assert resp.json()["result"]["protocolVersion"] == LATEST_HANDSHAKE_VERSION

    def test_answer_is_always_something_a_real_client_accepts(self) -> None:
        """An SDK client rejects any reply outside HANDSHAKE_PROTOCOL_VERSIONS.

        ``ClientSession.initialize`` raises RuntimeError on an unrecognized
        server version, so every branch of the negotiation must land inside the
        registry or the gateway becomes undialable.
        """
        for requested in (*HANDSHAKE_PROTOCOL_VERSIONS, "2026-07-28", "nonsense"):
            assert _negotiate_protocol_version(requested) in HANDSHAKE_PROTOCOL_VERSIONS


class TestStreamableHTTPDelete:
    def test_delete_tears_down_session(self) -> None:
        sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.delete(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 204
        assert sessions.active_count == 0

    def test_delete_without_session_returns_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete("/alice/mcp", headers=AUTH)
        assert resp.status_code == 400

    def test_delete_unknown_session_returns_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: "nonexistent"},
        )
        assert resp.status_code == 404

    def test_delete_without_auth_returns_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete(
            "/alice/mcp",
            headers={MCP_SESSION_ID_HEADER: "some-id"},
        )
        assert resp.status_code == 401


class TestStreamableHTTPGet:
    def test_get_without_session_returns_405(self) -> None:
        """405, not 400. The streamable-HTTP spec reserves 405 for "no
        standalone SSE stream here", which is what a GET with no session is
        asking for and not getting; 400 claimed the client sent something
        malformed and sent readers hunting a bug that was not there. See #156.
        """
        _, client = _make_registry_and_client()
        resp = client.get("/alice/mcp", headers=AUTH)
        assert resp.status_code == 405

    def test_the_405_names_the_methods_that_do_work(self) -> None:
        """RFC 9110 §15.5.6 requires Allow on a 405, and a client that reads it
        learns the endpoint is alive rather than broken."""
        _, client = _make_registry_and_client()
        resp = client.get("/alice/mcp", headers=AUTH)
        assert resp.headers["allow"] == "POST, DELETE"

    def test_get_with_unknown_session_returns_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.get(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: "nonexistent"},
        )
        assert resp.status_code == 404

    def test_get_without_auth_returns_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.get(
            "/alice/mcp",
            headers={MCP_SESSION_ID_HEADER: "some-id"},
        )
        assert resp.status_code == 401

    def test_get_with_valid_session_accepted(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")

        session = sessions.get_session(sid)
        assert session is not None
        assert session.profile_name == "alice"


class TestAdoptionOverTheWire:
    """#775: a restart used to leave a long-lived seat retrying a dead stream.

    Claude Code re-initializes on a 404 to a POST and deliberately does not on
    a 404 to the standalone SSE GET, so from 2.0.0 — which gave every such seat
    a GET stream — a restart stranded it. Adoption mints the id it already
    holds against the profile its bearer token authenticated as.
    """

    FOREIGN = "a" * 32
    """Well-formed (the uuid4().hex shape) but issued by a previous process."""

    @staticmethod
    async def _get(sessions: SessionRegistry, session_id: str, *, token: str = TEST_TOKEN) -> Any:
        """Drive ``_handle_get`` directly, as TestSSEEventStream drives the
        generator.

        Neither TestClient nor httpx's ASGI transport can be used here: both
        wait on the response body, and the standalone SSE stream never ends.
        Calling the handler returns the response without iterating it.
        """
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/alice/mcp",
                "raw_path": b"/alice/mcp",
                "query_string": b"",
                "scheme": "http",
                "http_version": "1.1",
                "root_path": "",
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 4242),
                "state": {},
                "headers": [
                    (b"authorization", f"Bearer {token}".encode()),
                    (b"mcp-session-id", session_id.encode()),
                    (b"user-agent", b"claude-code/test"),
                ],
                "path_params": {"profile": "alice"},
            }
        )
        return await _handle_get(request, {"alice": _make_profile()}, sessions)

    @pytest.mark.asyncio
    async def test_the_sse_get_adopts_instead_of_404ing(self) -> None:
        """The path that matters: this client never recovers from the 404."""
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)

        resp = await self._get(sessions, self.FOREIGN)
        assert resp.status_code == 200
        assert resp.headers[MCP_SESSION_ID_HEADER] == self.FOREIGN

        session = sessions.get_session(self.FOREIGN)
        assert session is not None
        assert session.profile_name == "alice"

    @pytest.mark.asyncio
    async def test_the_adopted_sessions_first_stream_carries_a_list_changed(self) -> None:
        """An adopted client may still hold a tools/list from the previous
        process, including names load_tools added — which did not survive it.

        The adopting request has no subscriber of its own, so the notification
        waits for the first stream, and is not repeated on the next one.
        """
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        assert sessions.adopt(self.FOREIGN, "alice") is not None

        stream = _sse_event_stream(sessions, self.FOREIGN, keepalive_seconds=5.0)
        try:
            assert await stream.__anext__() == f"retry: {SSE_RETRY_MS}\n\n"
            frame = await stream.__anext__()
            assert "notifications/tools/list_changed" in frame
        finally:
            await stream.aclose()

        again = _sse_event_stream(sessions, self.FOREIGN, keepalive_seconds=0.01)
        try:
            assert await again.__anext__() == f"retry: {SSE_RETRY_MS}\n\n"
            assert await again.__anext__() == ": keepalive\n\n"
        finally:
            await again.aclose()

    @pytest.mark.asyncio
    async def test_a_created_sessions_stream_carries_no_list_changed(self) -> None:
        """The frame is adoption's, not every stream's: sending it on each open
        would double every seat's startup tools/list."""
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            assert await stream.__anext__() == f"retry: {SSE_RETRY_MS}\n\n"
            assert await stream.__anext__() == ": keepalive\n\n"
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_a_malformed_id_is_refused_on_the_get_too(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        resp = await self._get(sessions, "not-a-session-id")
        assert resp.status_code == 404
        assert sessions.active_count == 0

    @pytest.mark.asyncio
    async def test_the_get_adopts_only_after_the_token_is_checked(self) -> None:
        """The whole security argument: _authorize runs first, so the session id
        is a correlation handle and not a credential."""
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        resp = await self._get(sessions, self.FOREIGN, token="wrong")
        assert resp.status_code == 401
        assert sessions.active_count == 0

    def test_an_adopted_session_serves_tool_calls(self) -> None:
        """What the seat actually needs: work, without re-initializing."""
        sessions, client = _make_registry_and_client()
        mock_route = AsyncMock(
            return_value={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
            }
        )
        with patch("trentina.gateway.app.route_jsonrpc", mock_route):
            resp = client.post(
                "/alice/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {},
                    },
                },
                headers={**AUTH, MCP_SESSION_ID_HEADER: self.FOREIGN},
            )
        assert resp.status_code == 200
        assert resp.json()["result"]["isError"] is False
        assert mock_route.await_count == 1
        assert sessions.active("alice") == 1

    def test_adoption_does_not_hand_a_reinitializing_client_its_dead_id(self) -> None:
        """The initialize branch runs first (#104), so self-recovery still wins."""
        sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: self.FOREIGN},
        )
        assert resp.status_code == 200
        assert resp.headers[MCP_SESSION_ID_HEADER] != self.FOREIGN
        assert sessions.get_session(self.FOREIGN) is None

    @pytest.mark.parametrize(
        "bad",
        ["nonexistent", "a" * 31, "a" * 33, "A" * 32],
        ids=["text", "short", "long", "upper-hex"],
    )
    def test_a_malformed_session_id_is_still_refused(self, bad: str) -> None:
        """An adopted id is caller-supplied, so only the shape we issue reaches
        the registry, the journal and the audit session column."""
        sessions, client = _make_registry_and_client()
        headers = {**AUTH, MCP_SESSION_ID_HEADER: bad}
        assert client.get("/alice/mcp", headers=headers).status_code == 404
        assert (
            client.post(
                "/alice/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers=headers,
            ).status_code
            == 404
        )
        assert sessions.active_count == 0

    def test_a_client_deleted_session_is_still_refused(self) -> None:
        """A teardown ended on purpose in this process, and must stay ended, or
        the TTL and the per-profile cap stop meaning anything."""
        sessions, client = _make_registry_and_client()
        ended = sessions.create_session("alice")
        sessions.delete_session(ended)

        headers = {**AUTH, MCP_SESSION_ID_HEADER: ended}
        assert client.get("/alice/mcp", headers=headers).status_code == 404
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers=headers,
        )
        assert resp.status_code == 404
        assert REASON_CLIENT_DELETE in resp.json()["error"]["message"]

    def test_an_expired_session_is_still_refused(self) -> None:
        sessions, client = _make_registry_and_client(session_ttl=0.001)
        expired = sessions.create_session("alice")
        time.sleep(0.01)
        resp = client.get("/alice/mcp", headers={**AUTH, MCP_SESSION_ID_HEADER: expired})
        assert resp.status_code == 404

    def test_another_profiles_live_session_is_still_403(self) -> None:
        """Unchanged: the session exists, so adoption never runs."""
        bob = _make_profile(name="bob", token="bob-token")
        alice = _make_profile()
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        client = TestClient(gateway_app({"alice": alice, "bob": bob}, sessions=sessions))
        alice_session = sessions.create_session("alice")

        resp = client.post(
            "/bob/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={
                "Authorization": "Bearer bob-token",
                MCP_SESSION_ID_HEADER: alice_session,
            },
        )
        assert resp.status_code == 403

    def test_another_profiles_tombstone_is_not_adoptable(self) -> None:
        """Deliberately not scoped the way explain_missing is: resurrecting a
        session another profile ended would make the cap a suggestion."""
        bob = _make_profile(name="bob", token="bob-token")
        alice = _make_profile()
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        client = TestClient(gateway_app({"alice": alice, "bob": bob}, sessions=sessions))
        foreign = sessions.create_session("bob")
        sessions.delete_session(foreign)

        resp = client.get("/alice/mcp", headers={**AUTH, MCP_SESSION_ID_HEADER: foreign})
        assert resp.status_code == 404
        assert "bob" not in resp.text

    def test_adoption_still_needs_the_bearer_token(self) -> None:
        """The whole security argument: _authorize runs before any of this, so
        the session id is a correlation handle and not a credential."""
        sessions, client = _make_registry_and_client()
        headers = {"Authorization": "Bearer wrong", MCP_SESSION_ID_HEADER: self.FOREIGN}
        assert client.get("/alice/mcp", headers=headers).status_code == 401
        assert (
            client.post(
                "/alice/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers=headers,
            ).status_code
            == 401
        )
        assert sessions.active_count == 0

    def test_the_per_profile_cap_applies_to_adoption(self) -> None:
        """Admitted on the same terms as a created session, eviction included."""
        sessions, client = _make_registry_and_client()
        sessions.max_sessions_per_profile = 2
        held = [sessions.create_session("alice") for _ in range(2)]

        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: self.FOREIGN},
        )
        assert resp.status_code == 200
        assert sessions.active("alice") == 2
        assert sessions.get_session(held[0]) is None  # the least recently used
        assert sessions.get_session(self.FOREIGN) is not None


class TestSSEEventStream:
    """The long-lived SSE stream that carries server-push notifications."""

    @pytest.mark.asyncio
    async def test_first_frame_is_retry_hint(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            first = await stream.__anext__()
            assert first == f"retry: {SSE_RETRY_MS}\n\n"
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_subscribes_on_open(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            await stream.__anext__()  # retry frame; subscription is now live
            assert sessions.subscriber_count(sid) == 1
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_broadcast_delivers_message_frame(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            await stream.__anext__()  # drain retry frame, register subscription

            count = await sessions.broadcast_tools_changed("alice")
            assert count == 1

            frame = await stream.__anext__()
            assert frame.startswith("event: message\ndata: ")
            payload = json.loads(frame.split("data: ", 1)[1].strip())
            assert payload["method"] == "notifications/tools/list_changed"
            assert "event: endpoint" not in frame
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_keepalive_on_idle(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            frame = await stream.__anext__()  # nothing queued → keepalive
            assert frame == ": keepalive\n\n"
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_closes_when_session_removed(self) -> None:
        """An orphaned stream must terminate, not keepalive into the void."""
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            assert await stream.__anext__() == ": keepalive\n\n"

            sessions.delete_session(sid)

            with pytest.raises(StopAsyncIteration):
                await stream.__anext__()
            assert sessions.subscriber_count(sid) == 0
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_closes_when_session_expires(self) -> None:
        """TTL expiry reaches the stream too, not just explicit teardown."""
        sessions = SessionRegistry(session_ttl=0.02, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.05)
        try:
            await stream.__anext__()  # retry frame
            with pytest.raises(StopAsyncIteration):
                await stream.__anext__()
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_keepalive_does_not_extend_session_lifetime(self) -> None:
        """The liveness poll must not refresh last_access.

        If it did, any client holding an SSE stream would become immortal and
        TTL expiry could never fire for it.
        """
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        session = sessions.get_session(sid)
        assert session is not None
        before = session.last_access

        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            await stream.__anext__()  # keepalive → liveness poll runs
            await stream.__anext__()  # and again
            assert session.last_access == before
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_close_unsubscribes(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        await stream.__anext__()
        assert sessions.subscriber_count(sid) == 1
        await stream.aclose()
        assert sessions.subscriber_count(sid) == 0


class TestCircuitToSSEDelivery:
    """End-to-end: a circuit trip reaches a subscribed session's queue."""

    @pytest.mark.asyncio
    async def test_circuit_open_delivers_listchanged(self) -> None:
        backend_url = "http://mcp-slack:8000/mcp"
        profile = _make_profile()
        profiles = {"alice": profile}
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)

        _wire_circuit_notifications(cb, sessions, profiles)

        sid = sessions.create_session("alice")
        queue = sessions.subscribe(sid)

        cb.record_failure(backend_url)
        cb.record_failure(backend_url)

        for _ in range(50):
            if not queue.empty():
                break
            await asyncio.sleep(0.01)

        assert not queue.empty()
        notification = queue.get_nowait()
        assert notification["method"] == "notifications/tools/list_changed"

    @pytest.mark.asyncio
    async def test_unaffected_profile_not_notified(self) -> None:
        profile = _make_profile()  # backend http://mcp-slack:8000/mcp
        profiles = {"alice": profile}
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)

        _wire_circuit_notifications(cb, sessions, profiles)

        sid = sessions.create_session("alice")
        queue = sessions.subscribe(sid)

        cb.record_failure("http://other:9000/mcp")
        cb.record_failure("http://other:9000/mcp")

        for _ in range(10):
            await asyncio.sleep(0.01)

        assert queue.empty()


class TestBackwardsCompatibility:
    """Phase 1 behaviour must still work for stateless POST clients."""

    def test_post_unknown_profile_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post("/missing/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 404

    def test_post_missing_auth_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post("/alice/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401

    def test_post_empty_body_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            content=b"",
            headers={**AUTH, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_post_invalid_json_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            content=b"{not json",
            headers={**AUTH, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_tools_call_dispatch(self) -> None:
        mock_route = AsyncMock(
            return_value={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
            }
        )
        with patch(
            "trentina.gateway.app.route_jsonrpc",
            mock_route,
        ):
            _, client = _make_registry_and_client()
            resp = client.post(
                "/alice/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {},
                    },
                },
                headers=AUTH,
            )
            assert resp.status_code == 200


class TestCircuitInvalidatesOnlyHolders:
    """A backend's flap rebuilds the profiles that hold it, not everyone (#137)."""

    @pytest.mark.asyncio
    async def test_unaffected_profiles_aggregate_survives(self) -> None:
        from trentina.gateway import aggregate

        holder = _make_profile()  # backend http://mcp-slack:8000/mcp
        bystander = holder.model_copy(update={"name": "bob", "backends": {}})
        profiles = {"alice": holder, "bob": bystander}
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)
        _wire_circuit_notifications(cb, sessions, profiles)
        aggregate._profile_tools_cache["alice"] = []
        aggregate._profile_tools_cache["bob"] = []

        cb.record_failure("http://mcp-slack:8000/mcp")
        cb.record_failure("http://mcp-slack:8000/mcp")

        assert "alice" not in aggregate._profile_tools_cache
        assert "bob" in aggregate._profile_tools_cache
