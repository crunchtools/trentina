"""An operator clears session marks and cool-down windows (a1724).

A false positive on the operator's own memory search labelled its session
under 6.32.0, and the profile's cool-down (#900) then refused its memory
writes. Marks live in memory, so a restart was the only way out.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import pytest

from trentina.gateway import session_marks
from trentina.gateway.context import current_session_profile, profile_context
from trentina.gateway.profile import Profile
from trentina.gateway.session_marks import SessionLabel as L
from trentina.tools.marks import session_marks_clear

WINDOW = 1800.0
T0 = 1000.0
ALL = frozenset(L)
A1, A2, B1 = "aaaaaaaa11111111", "aaaaaaaa22222222", "bbbbbbbb11111111"


def _at(t: float) -> Any:
    return patch.object(session_marks.time, "monotonic", return_value=t)


@contextmanager
def _as(profile: str) -> Iterator[None]:
    """Inside a request of *profile*, as the gateway edge binds one."""
    token = current_session_profile.set("")
    try:
        session_marks.bind(profile, WINDOW, ALL)
        yield
    finally:
        current_session_profile.reset(token)


_AUTH = {"auth": {"bearer_token_env": "A"}, "backends": {}}
OPERATOR = Profile.model_validate({"name": "op", "role": "operator", **_AUTH})
AGENT = Profile.model_validate({"name": "alice", **_AUTH})


async def _clear(caller: Profile = OPERATOR, **kwargs: Any) -> dict[str, Any]:
    with profile_context(caller):
        return await session_marks_clear(**kwargs)


@pytest.fixture
def marked() -> None:
    """alice's A1 opened a window that cools A2 down; bob's B1 opened bob's."""
    with _at(T0):
        with _as("alice"):
            session_marks.mark(A1, L.FLAGGED_DELIVERY)
            session_marks.mark(A2, L.TRIPPED)
        with _as("bob"):
            session_marks.mark(B1, L.TRIPPED)


def _read(profile: str, session: str, t: float = T0 + 60) -> frozenset[L] | None:
    with _as(profile), _at(t):
        return session_marks.labels(session)


@pytest.mark.usefixtures("marked")
class TestOperatorClears:
    async def test_a_profile_window_and_its_sessions_marks(self) -> None:
        assert _read("alice", "aaaaaaaa33333333") is None
        with _at(T0 + 60):
            result = await _clear(profile="alice")
        assert result["windows"] == [
            {"profile": "alice", "remaining_seconds": WINDOW - 60, "owner": A1[:8]}
        ]
        assert {(s["session"], tuple(s["labels"])) for s in result["sessions"]} == {
            (A1[:8], ("flagged_delivery",)),
            (A2[:8], ("tripped",)),
        }
        assert _read("alice", "aaaaaaaa33333333") == frozenset()
        assert _read("alice", A1) == frozenset()
        assert _read("alice", A2) == frozenset()

    async def test_one_sessions_marks_and_the_window_it_owns(self) -> None:
        with _at(T0 + 60):
            result = await _clear(session=A1)
        assert [w["profile"] for w in result["windows"]] == ["alice"]
        assert [s["session"] for s in result["sessions"]] == [A1[:8]]
        assert _read("alice", A1) == frozenset()
        # A2's own label is still its own.
        assert _read("alice", A2) == {L.TRIPPED}

    async def test_a_session_that_owns_no_window_leaves_the_window(self) -> None:
        with _at(T0 + 60):
            result = await _clear(session=A2)
        assert result["windows"] == []
        assert _read("alice", A2) is None  # still cooled down by A1's window

    async def test_a_partial_clear_leaves_other_profiles_intact(self) -> None:
        with _at(T0 + 60):
            await _clear(profile="alice")
        assert _read("bob", B1) == {L.TRIPPED}
        assert _read("bob", "bbbbbbbb22222222") is None
        assert "bob" in session_marks._windows

    async def test_all_clears_everything(self) -> None:
        with _at(T0 + 60):
            result = await _clear(all=True)
        assert {w["profile"] for w in result["windows"]} == {"alice", "bob"}
        assert session_marks._marks == {}
        assert session_marks._windows == {}

    async def test_a_fresh_refusing_mark_opens_a_new_window(self) -> None:
        with _at(T0 + 60):
            await _clear(profile="alice")
        with _as("alice"), _at(T0 + 120):
            session_marks.mark(A2, L.TRIPPED)
        assert session_marks._windows["alice"] == (T0 + 120 + WINDOW, A2)
        assert _read("alice", A1, T0 + 130) is None
        assert _read("alice", A2, T0 + 130) == {L.TRIPPED}

    async def test_the_audit_line_names_who_and_what(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with _at(T0 + 60), caplog.at_level("WARNING"):
            await _clear(profile="alice")
        line = next(r.getMessage() for r in caplog.records if "session_marks_clear by" in r.message)
        assert line.startswith("session_marks_clear by op:")
        assert "profile=alice" in line
        assert "flagged_delivery" in line
        assert "tripped" in line
        assert "'remaining_seconds': 1740" in line


@pytest.mark.usefixtures("marked")
class TestRefusals:
    async def test_an_agent_is_refused_and_nothing_changes(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        before = (dict(session_marks._marks), dict(session_marks._windows))
        result = await _clear(AGENT, profile="alice")
        assert "operator" in result["error"]
        assert (dict(session_marks._marks), dict(session_marks._windows)) == before
        assert "session_marks_clear by" not in caplog.text

    @pytest.mark.parametrize(
        ("kwargs", "says"),
        [
            ({}, "all=true"),
            ({"all": True, "profile": "alice"}, "all clears everything"),
            ({"session": "AAAAAAAA"}, "hex"),
            ({"session": "aaaa"}, "hex"),
            ({"session": "cccccccc"}, "no session"),
            ({"session": "aaaaaaaa"}, "more than one"),
            ({"session": "cccccccc", "profile": "alice"}, "no session"),
        ],
    )
    async def test_nothing_is_cleared_without_a_clear_target(
        self, kwargs: dict[str, Any], says: str
    ) -> None:
        before = (dict(session_marks._marks), dict(session_marks._windows))
        result = await _clear(**kwargs)
        assert says in result["error"]
        assert (dict(session_marks._marks), dict(session_marks._windows)) == before


async def test_a_flood_drop_is_reported_and_only_all_resets_it() -> None:
    with _as("alice"), _at(T0), patch.object(session_marks, "MAX_MARKS", 1):
        session_marks.mark(A1, L.TRIPPED)
        session_marks.mark(A2, L.TRIPPED)
    with _at(T0 + 60):
        assert "dropped_unknown_seconds" in await _clear(profile="alice")
        assert "dropped_unknown_seconds" not in await _clear(all=True)
