"""Moving to another session does not shed a session's labels (#900).

An agent whose session is labelled could carry on in a session it opened
beforehand, send ``initialize`` for a fresh one, or present any well-formed id
and have it adopted. For the profile's ``session_mark_cooldown_seconds`` after
a mark, every other session of the profile reads unknown, which
``refuse_when`` refuses (Scott's ruling on #942).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError
from starlette.testclient import TestClient

from trentina.gateway import session_marks
from trentina.gateway.app import MCP_SESSION_ID_HEADER, gateway_app
from trentina.gateway.context import (
    current_session,
    current_session_profile,
    session_fingerprint,
)
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


@contextmanager
def _as(profile: str, cooldown: float = WINDOW) -> Iterator[None]:
    """Inside a request of *profile*, as the gateway edge binds one."""
    token = current_session_profile.set("")
    try:
        session_marks.bind(profile, cooldown)
        yield
    finally:
        current_session_profile.reset(token)


class TestWindow:
    def test_a_session_opened_before_the_mark_is_cooled_down(self) -> None:
        """Review finding 1: admit A and B, mark A, and B read clean."""
        with _as("alice"), _at(T0):
            session_marks.mark("fp-a", L.FLAGGED_DELIVERY)
            assert session_marks.labels("fp-b") is None
            assert session_marks.was_flagged("fp-b") is None
            # The marked session keeps reading its own labels.
            assert session_marks.labels("fp-a") == {L.FLAGGED_DELIVERY}

    def test_a_session_minted_in_the_window_is_unknown(self) -> None:
        with _as("alice"):
            with _at(T0):
                session_marks.mark("fp-a", L.TRIPPED)
            with _at(T0 + 60):
                assert session_marks.labels("fp-new") is None

    def test_after_the_window_every_session_reads_clean(self) -> None:
        with _as("alice"):
            with _at(T0):
                session_marks.mark("fp-a", L.TRIPPED)
            with _at(T0 + WINDOW):
                assert session_marks.labels("fp-b") == frozenset()
                assert session_marks.labels("fp-a") == {L.TRIPPED}

    def test_another_profile_is_unaffected(self) -> None:
        with _as("alice"), _at(T0):
            session_marks.mark("fp-a", L.TRIPPED)
        with _as("bob"), _at(T0 + 60):
            assert session_marks.labels("fp-bob") == frozenset()

    def test_a_later_mark_moves_the_window_to_its_session(self) -> None:
        with _as("alice"):
            with _at(T0):
                session_marks.mark("fp-a", L.CREDENTIAL_SEEN)
            with _at(T0 + 1000):
                session_marks.mark("fp-b", L.CREDENTIAL_SEEN)
            with _at(T0 + WINDOW + 10):
                assert session_marks.labels("fp-a") is None
                assert session_marks.labels("fp-b") == {L.CREDENTIAL_SEEN}
                assert session_marks.labels("fp-c") is None

    def test_zero_turns_it_off(self) -> None:
        with _as("alice", cooldown=0), _at(T0):
            session_marks.mark("fp-a", L.TRIPPED)
            assert session_marks.labels("fp-b") == frozenset()

    def test_a_session_deleted_mid_call_still_opens_the_window(self) -> None:
        """Review finding 2: a DELETE racing the flagged response emptied the
        owner table, so the mark opened no window. The request's own binding
        cannot be torn down under it."""
        with _as("alice"), _at(T0):
            session_marks.mark("fp-deleted-mid-call", L.TRIPPED)
        with _as("alice"), _at(T0 + 1):
            assert session_marks.labels("fp-d") is None

    def test_a_flood_of_sessions_costs_nothing(self) -> None:
        """Review finding 3: unknown admissions filled ``_marks``, so a flood of
        initializes from a marked profile widened the gateway-wide window and
        every other profile's clean session read None. The window is one entry
        per profile, and another session reading it stores nothing."""
        with _as("carol"), _at(T0):
            session_marks.mark("fp-carol", L.CREDENTIAL_SEEN)
        with _as("alice"), _at(T0):
            session_marks.mark("fp-a", L.TRIPPED)
            with patch.object(session_marks, "MAX_MARKS", 3):
                for i in range(10):
                    assert session_marks.labels(f"fp-flood-{i}") is None
        assert len(session_marks._marks) == 2
        with _as("bob"), _at(T0 + 60):
            assert session_marks.labels("fp-bob") == frozenset()
        with _as("carol"), _at(T0 + 60):
            assert session_marks.labels("fp-carol") == {L.CREDENTIAL_SEEN}


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


_OK = {"jsonrpc": "2.0", "id": 1, "result": {}}


class TestThroughTheGateway:
    """What the gatekeeper sees: the labels read inside a real request."""

    @staticmethod
    def _client(*profiles: Profile) -> TestClient:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        return TestClient(gateway_app({p.name: p for p in profiles}, sessions=sessions))

    @staticmethod
    def _call(client: TestClient, profile: Profile, sid: str | None = None) -> Any:
        """One call; the session id, and the profile and labels it read."""
        seen: list[Any] = []

        async def route(_bound: Profile, _body: dict[str, Any]) -> dict[str, Any]:
            seen.append(
                (current_session_profile.get(), session_marks.labels(current_session.get()))
            )
            return _OK

        headers = {"Authorization": f"Bearer {profile.name}-token"}
        if sid is not None:
            headers[MCP_SESSION_ID_HEADER] = sid
        method = "initialize" if sid is None else "tools/list"
        with patch("trentina.gateway.app.route_jsonrpc", route):
            resp = client.post(
                f"/{profile.name}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": method},
                headers=headers,
            )
        assert resp.status_code == 200
        return resp.headers.get(MCP_SESSION_ID_HEADER, sid), seen[0]

    def _marked(self, client: TestClient, profile: Profile) -> None:
        sid, _ = self._call(client, profile)
        session_marks.mark(session_fingerprint(sid), L.TRIPPED, profile.name)

    def test_the_request_binds_its_profile(self) -> None:
        alice = _profile()
        client = self._client(alice)
        sid, _ = self._call(client, alice)
        _, (bound, read) = self._call(client, alice, sid)
        assert bound == "alice"
        assert read == frozenset()

    def test_a_pre_opened_session_is_cooled_down(self) -> None:
        alice = _profile()
        client = self._client(alice)
        spare, _ = self._call(client, alice)
        self._marked(client, alice)
        _, (_, read) = self._call(client, alice, spare)
        assert read is None

    def test_a_fresh_initialize_is_cooled_down(self) -> None:
        alice = _profile()
        client = self._client(alice)
        self._marked(client, alice)
        fresh, _ = self._call(client, alice)
        _, (_, read) = self._call(client, alice, fresh)
        assert read is None

    def test_an_adopted_id_is_cooled_down(self) -> None:
        alice = _profile()
        client = self._client(alice)
        self._marked(client, alice)
        _, (_, read) = self._call(client, alice, FOREIGN)
        assert read is None

    def test_another_profile_is_unaffected(self) -> None:
        alice, bob = _profile("alice"), _profile("bob")
        client = self._client(alice, bob)
        self._marked(client, alice)
        sid, _ = self._call(client, bob)
        _, (_, read) = self._call(client, bob, sid)
        assert read == frozenset()

    def test_with_the_cooldown_off_nothing_else_is_affected(self) -> None:
        alice = _profile(cooldown=0)
        client = self._client(alice)
        spare, _ = self._call(client, alice)
        self._marked(client, alice)
        _, (_, read) = self._call(client, alice, spare)
        assert read == frozenset()


class TestConfig:
    def test_default_is_thirty_minutes(self) -> None:
        assert _profile().session_mark_cooldown_seconds == SESSION_MARK_COOLDOWN_DEFAULT == 1800

    def test_zero_is_accepted(self) -> None:
        assert _profile(cooldown=0).session_mark_cooldown_seconds == 0

    @pytest.mark.parametrize("bad", [-1, SESSION_MARK_COOLDOWN_MAX + 1])
    def test_out_of_range_is_refused(self, bad: float) -> None:
        with pytest.raises(ValidationError):
            _profile(cooldown=bad)
