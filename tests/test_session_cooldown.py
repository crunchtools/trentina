"""Starting over does not shed a session's labels (#900).

An agent whose session is labelled could send ``initialize`` with no or a
stale session header and get a fresh, clean one, or present any well-formed
id and have it adopted. Within the profile's ``session_mark_cooldown_seconds``
of a mark on any of its sessions, a session newly minted or adopted for it
starts unknown, which ``refuse_when`` refuses.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr, ValidationError
from starlette.requests import Request
from starlette.testclient import TestClient

from trentina.gateway import session_marks
from trentina.gateway.app import MCP_SESSION_ID_HEADER, _handle_get, gateway_app
from trentina.gateway.context import current_session_profile, session_fingerprint
from trentina.gateway.profile import (
    SESSION_MARK_COOLDOWN_DEFAULT,
    SESSION_MARK_COOLDOWN_MAX,
    AuthConfig,
    Backend,
    Profile,
)
from trentina.gateway.session_marks import SessionLabel as L
from trentina.gateway.sessions import SessionRegistry

WINDOW = 1800.0
T0 = 1000.0
FOREIGN = "ab" * 16


def _at(t: float) -> Any:
    return patch.object(session_marks.time, "monotonic", return_value=t)


def _profile(name: str = "alice", cooldown: float | None = None) -> Profile:
    extra = {} if cooldown is None else {"session_mark_cooldown_seconds": cooldown}
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8000/mcp")},
        **extra,
    )
    profile.auth.bearer_token = SecretStr(f"{name}-token")
    return profile


def _marked(profile: str = "alice", at: float = T0) -> str:
    """A session of *profile*, admitted and then labelled at *at*."""
    fp = f"fp-marked-{profile}"
    with _at(at):
        session_marks.admit(fp, profile, WINDOW)
        session_marks.mark(fp, L.FLAGGED_DELIVERY, profile)
    return fp


class TestAdmit:
    def test_a_session_minted_in_the_window_is_unknown(self) -> None:
        _marked()
        with _at(T0 + 60):
            assert session_marks.admit("fp-new", "alice", WINDOW) is True
            assert session_marks.labels("fp-new") is None
            assert session_marks.was_flagged("fp-new") is None

    def test_after_the_window_it_reads_clean(self) -> None:
        _marked()
        with _at(T0 + 60):
            session_marks.admit("fp-new", "alice", WINDOW)
        with _at(T0 + WINDOW):
            assert session_marks.labels("fp-new") == frozenset()

    def test_a_session_admitted_after_the_window_is_clean(self) -> None:
        _marked()
        with _at(T0 + WINDOW + 1):
            assert session_marks.admit("fp-new", "alice", WINDOW) is False
            assert session_marks.labels("fp-new") == frozenset()

    def test_another_profile_is_unaffected(self) -> None:
        _marked("alice")
        with _at(T0 + 60):
            assert session_marks.admit("fp-bob", "bob", WINDOW) is False
            assert session_marks.labels("fp-bob") == frozenset()

    def test_an_existing_session_is_unaffected(self) -> None:
        with _at(T0 - 10):
            session_marks.admit("fp-old", "alice", WINDOW)
        marked = _marked()
        with _at(T0 + 60):
            assert session_marks.labels("fp-old") == frozenset()
            # The marked session keeps its own label; nothing else inherits it.
            assert session_marks.labels(marked) == {L.FLAGGED_DELIVERY}

    def test_a_later_mark_extends_the_window_for_later_sessions(self) -> None:
        marked = _marked()
        with _at(T0 + 1000):
            session_marks.mark(marked, L.CREDENTIAL_SEEN, "alice")
        with _at(T0 + WINDOW + 10):
            assert session_marks.admit("fp-new", "alice", WINDOW) is True
            assert session_marks.labels("fp-new") is None

    def test_zero_turns_it_off(self) -> None:
        _marked()
        with _at(T0 + 60):
            assert session_marks.admit("fp-new", "alice", 0) is False
            assert session_marks.labels("fp-new") == frozenset()

    def test_a_mark_takes_its_profile_from_the_request(self) -> None:
        """Review finding 2: a DELETE racing the flagged response emptied the
        owner table, so the mark started no window. The request's own binding
        cannot be torn down under it."""
        token = current_session_profile.set("alice")
        try:
            with _at(T0):
                session_marks.mark("fp-deleted-mid-call", L.TRIPPED)
        finally:
            current_session_profile.reset(token)
        with _at(T0 + 1):
            assert session_marks.admit("fp-new", "alice", WINDOW) is True
            assert session_marks.labels("fp-new") is None

    def test_a_flood_of_admissions_reaches_no_other_profile(self) -> None:
        """Review finding 3: unknown admissions lived in ``_marks``, so a flood
        of initializes from a marked profile widened the gateway-wide window
        and every other profile's clean session read None."""
        _marked("alice")
        with _at(T0 + 60):
            session_marks.admit("fp-bob", "bob", WINDOW)
            session_marks.mark("fp-carol", L.CREDENTIAL_SEEN, "carol")
            with patch.object(session_marks, "MAX_MARKS", 3):
                for i in range(10):
                    session_marks.admit(f"fp-flood-{i}", "alice", WINDOW)
            assert session_marks.labels("fp-bob") == frozenset()
            assert session_marks.labels("fp-carol") == {L.CREDENTIAL_SEEN}
            assert session_marks.labels("fp-marked-alice") == {L.FLAGGED_DELIVERY}

    def test_an_admission_dropped_by_a_flood_stays_unknown_for_its_profile(self) -> None:
        _marked("alice")
        with _at(T0 + 60), patch.object(session_marks, "MAX_MARKS", 3):
            for i in range(10):
                session_marks.admit(f"fp-flood-{i}", "alice", WINDOW)
            assert "fp-flood-0" not in session_marks._admitted
            token = current_session_profile.set("alice")
            try:
                assert session_marks.labels("fp-flood-0") is None
            finally:
                current_session_profile.reset(token)
            token = current_session_profile.set("bob")
            try:
                assert session_marks.labels("fp-bob-unrelated") == frozenset()
            finally:
                current_session_profile.reset(token)


def _client(profile: Profile) -> tuple[SessionRegistry, TestClient]:
    sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
    return sessions, TestClient(gateway_app({profile.name: profile}, sessions=sessions))


def _auth(profile: Profile) -> dict[str, str]:
    return {"Authorization": f"Bearer {profile.name}-token"}


_OK = {"jsonrpc": "2.0", "id": 1, "result": {}}


class TestGatewayAdmits:
    """Every way a session comes into being passes through ``admit``."""

    def _initialize(self, client: TestClient, profile: Profile, **headers: str) -> str:
        with patch("trentina.gateway.app.route_jsonrpc", AsyncMock(return_value=_OK)):
            resp = client.post(
                f"/{profile.name}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                headers={**_auth(profile), **headers},
            )
        assert resp.status_code == 200
        return str(resp.headers[MCP_SESSION_ID_HEADER])

    def test_initialize_in_the_window_is_unknown(self) -> None:
        profile = _profile()
        _sessions, client = _client(profile)
        old = self._initialize(client, profile)
        session_marks.mark(session_fingerprint(old), L.TRIPPED, "alice")

        new = self._initialize(client, profile)
        assert session_marks.labels(session_fingerprint(new)) is None
        # Re-initializing over a stale header is the same mint.
        again = self._initialize(client, profile, **{MCP_SESSION_ID_HEADER: "cd" * 16})
        assert session_marks.labels(session_fingerprint(again)) is None

    def test_initialize_with_no_mark_is_clean(self) -> None:
        profile = _profile()
        _sessions, client = _client(profile)
        new = self._initialize(client, profile)
        assert session_marks.labels(session_fingerprint(new)) == frozenset()

    def test_initialize_with_the_cooldown_off_is_clean(self) -> None:
        profile = _profile(cooldown=0)
        _sessions, client = _client(profile)
        old = self._initialize(client, profile)
        session_marks.mark(session_fingerprint(old), L.TRIPPED, "alice")
        new = self._initialize(client, profile)
        assert session_marks.labels(session_fingerprint(new)) == frozenset()

    def test_an_existing_session_keeps_reading_clean(self) -> None:
        profile = _profile()
        _sessions, client = _client(profile)
        bystander = self._initialize(client, profile)
        marked = self._initialize(client, profile)
        session_marks.mark(session_fingerprint(marked), L.FLAGGED_DELIVERY, "alice")
        assert session_marks.labels(session_fingerprint(bystander)) == frozenset()

    def test_another_profile_initializes_clean(self) -> None:
        alice, bob = _profile("alice"), _profile("bob")
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        client = TestClient(gateway_app({"alice": alice, "bob": bob}, sessions=sessions))
        marked = self._initialize(client, alice)
        session_marks.mark(session_fingerprint(marked), L.TRIPPED, "alice")
        assert session_marks.labels(session_fingerprint(self._initialize(client, bob))) == (
            frozenset()
        )

    def test_a_call_binds_its_sessions_profile(self) -> None:
        """What finding 2's fix stands on: every mark inside a request knows
        the profile without asking a table a DELETE can empty."""
        profile = _profile()
        _sessions, client = _client(profile)
        sid = self._initialize(client, profile)
        seen: list[str] = []

        async def route(_profile: Profile, _body: dict[str, Any]) -> dict[str, Any]:
            seen.append(current_session_profile.get())
            return _OK

        with patch("trentina.gateway.app.route_jsonrpc", route):
            client.post(
                "/alice/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers={**_auth(profile), MCP_SESSION_ID_HEADER: sid},
            )
        assert seen == ["alice"]

    def test_a_post_adoption_in_the_window_is_unknown(self) -> None:
        profile = _profile()
        sessions, client = _client(profile)
        marked = self._initialize(client, profile)
        session_marks.mark(session_fingerprint(marked), L.CREDENTIAL_SEEN, "alice")
        with patch("trentina.gateway.app.route_jsonrpc", AsyncMock(return_value=_OK)):
            resp = client.post(
                "/alice/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers={**_auth(profile), MCP_SESSION_ID_HEADER: FOREIGN},
            )
        assert resp.status_code == 200
        assert sessions.get_session(FOREIGN) is not None
        assert session_marks.labels(session_fingerprint(FOREIGN)) is None

    @pytest.mark.asyncio
    async def test_a_get_adoption_in_the_window_is_unknown(self) -> None:
        profile = _profile()
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        marked = sessions.create_session("alice")
        session_marks.admit(session_fingerprint(marked), "alice", WINDOW)
        session_marks.mark(session_fingerprint(marked), L.TRIPPED, "alice")
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
                    (b"authorization", b"Bearer alice-token"),
                    (b"mcp-session-id", FOREIGN.encode()),
                ],
                "path_params": {"profile": "alice"},
            }
        )
        resp = await _handle_get(request, {"alice": profile}, sessions)
        assert resp.status_code == 200
        assert session_marks.labels(session_fingerprint(FOREIGN)) is None


class TestConfig:
    def test_default_is_thirty_minutes(self) -> None:
        assert _profile().session_mark_cooldown_seconds == SESSION_MARK_COOLDOWN_DEFAULT == 1800

    def test_zero_is_accepted(self) -> None:
        assert _profile(cooldown=0).session_mark_cooldown_seconds == 0

    @pytest.mark.parametrize("bad", [-1, SESSION_MARK_COOLDOWN_MAX + 1])
    def test_out_of_range_is_refused(self, bad: float) -> None:
        with pytest.raises(ValidationError):
            _profile(cooldown=bad)
