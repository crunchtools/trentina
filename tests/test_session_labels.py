"""A session carries a closed set of labels, and a guard refuses on any of them (#861).

``flagged_delivery`` is the old mark, ``tripped`` is what #860 set through it,
and ``credential_seen`` is new: a delivered response that held a credential.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from tests.test_credential_guard import GITHUB
from tests.test_credential_guard import _call as _credential_call
from tests.test_gatekeeper import _ARGS, _DEST, _judge_response, _response_profile
from tests.test_gatekeeper import _judge as _judge_call
from tests.test_gatekeeper import _profile as _guarded_profile
from tests.test_gateway_decoy import _rpc as _decoy_rpc
from trentina import orchestrator
from trentina.core.stages import Assembled
from trentina.gateway import gatekeeper, session_marks
from trentina.gateway.context import current_session
from trentina.gateway.session_marks import SessionLabel as L
from trentina.outcomes import Outcome

SESSION = "fp-861"


@pytest.fixture
def session() -> Iterator[str]:
    session_marks.clear()
    token = current_session.set(SESSION)
    try:
        yield SESSION
    finally:
        current_session.reset(token)
        session_marks.clear()


@pytest.fixture
def asked() -> Iterator[list[AsyncMock]]:
    defend, generate = AsyncMock(), AsyncMock()
    with (
        patch.object(orchestrator, "defend", defend),
        patch.object(gatekeeper, "quarantine_generate", generate),
    ):
        yield [defend, generate]


def _delivered(text: str, outcome: Outcome = Outcome.OK) -> Assembled:
    return Assembled(result={"content": [{"type": "text", "text": text}]}, outcome=outcome)


class TestLabels:
    def test_each_label_is_its_own(self, session: str) -> None:
        assert session_marks.mark(session, L.CREDENTIAL_SEEN) is True
        assert session_marks.mark(session, L.CREDENTIAL_SEEN) is False
        assert session_marks.mark(session, L.TRIPPED) is True
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN, L.TRIPPED}
        # A credential seen is not a flag; a trip is.
        assert session_marks.was_flagged(session) is True

    def test_credential_seen_alone_is_not_flagged(self, session: str) -> None:
        session_marks.mark(session, L.CREDENTIAL_SEEN)
        assert session_marks.was_flagged(session) is False

    def test_each_label_expires_on_its_own(self, session: str) -> None:
        with patch.object(session_marks.time, "monotonic", return_value=1000.0):
            session_marks.mark(session, L.FLAGGED_DELIVERY)
        later = 1000.0 + session_marks.MARK_TTL_SECONDS
        with patch.object(session_marks.time, "monotonic", return_value=later):
            session_marks.mark(session, L.CREDENTIAL_SEEN)
        with patch.object(session_marks.time, "monotonic", return_value=later + 1):
            assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}
        gone = later + session_marks.MARK_TTL_SECONDS + 1
        with patch.object(session_marks.time, "monotonic", return_value=gone):
            assert session_marks.labels(session) == frozenset()
            assert session not in session_marks._marks

    def test_a_dropped_entry_leaves_unmarked_sessions_unknown(
        self, session: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(session_marks, "MAX_MARKS", 1)
        session_marks.mark("first", L.CREDENTIAL_SEEN)
        session_marks.mark("second", L.TRIPPED)
        assert session_marks.labels("first") is None
        assert session_marks.labels("never-seen") is None
        assert session_marks.labels("second") == {L.TRIPPED}

    def test_the_unknown_window_follows_the_latest_dropped_label(
        self, session: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(session_marks, "MAX_MARKS", 1)
        ttl = session_marks.MARK_TTL_SECONDS
        clock = patch.object(session_marks.time, "monotonic")
        with clock as now:
            now.return_value = 1000.0
            session_marks.mark("first", L.FLAGGED_DELIVERY)
            now.return_value = 5000.0
            session_marks.mark("first", L.CREDENTIAL_SEEN)
            session_marks.mark("second", L.TRIPPED)
            now.return_value = 1000.0 + ttl + 1
            assert session_marks.labels("unseen") is None
            now.return_value = 5000.0 + ttl + 1
            assert session_marks.labels("unseen") == frozenset()

    def test_no_session_is_unknown(self) -> None:
        assert session_marks.labels("") is None
        assert session_marks.mark("", L.TRIPPED) is False


class TestCredentialSeen:
    async def test_a_delivered_credential_labels_the_session(self, session: str) -> None:
        await session_marks._mark_session(_delivered("token: " + GITHUB))
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}

    async def test_a_tool_error_that_carries_one_labels_it_too(self, session: str) -> None:
        await session_marks._mark_session(_delivered(GITHUB, Outcome.TOOL_ERROR))
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}

    @pytest.mark.parametrize(
        "outcome", [Outcome.BLOCKED_DEFENSE, Outcome.DENIED_RESPONSE_GATEKEEPER]
    )
    async def test_a_refused_response_labels_nothing(self, session: str, outcome: Outcome) -> None:
        await session_marks._mark_session(_delivered(GITHUB, outcome))
        assert session_marks.labels(session) == frozenset()

    async def test_structured_content_and_resources_are_read(self, session: str) -> None:
        result = {
            "content": [{"type": "resource", "resource": {"uri": "x", "text": "clean"}}],
            "structuredContent": {"key": GITHUB},
        }
        await session_marks._mark_session(Assembled(result=result, outcome=Outcome.OK))
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}

    async def test_a_resource_uri_is_read(self, session: str) -> None:
        uri = "https://api.example/v1?token=" + GITHUB
        result = {"content": [{"type": "resource_link", "uri": uri, "name": "x"}]}
        await session_marks._mark_session(Assembled(result=result, outcome=Outcome.OK))
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}

    async def test_a_clean_response_labels_nothing(self, session: str) -> None:
        await session_marks._mark_session(_delivered("nothing secret here"))
        assert session_marks.labels(session) == frozenset()

    async def test_the_log_names_the_kind_never_the_value(
        self, session: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("INFO", logger="trentina.gateway.session_marks"):
            await session_marks._mark_session(_delivered(GITHUB))
        assert "credential_seen (github_token)" in caplog.text
        assert GITHUB not in caplog.text

    async def test_a_real_backend_reply_labels_the_session(
        self, tmp_path: Any, session: str
    ) -> None:
        await _credential_call(tmp_path, {"text": "hello"}, reply="here: " + GITHUB)
        assert session_marks.labels(session) == {L.CREDENTIAL_SEEN}


class TestEarlyRefusalsStillLabel:
    """A credential sent with a call refused before the credential check (#892 review)."""

    async def test_non_object_arguments(self, session: str) -> None:
        from trentina.gateway import request_edge
        from trentina.gateway.profile import Backend

        backend = Backend(url="http://luna:8000/mcp", tools_allow=["*"])
        assert await request_edge.mark_refused_credentials(backend, "echo", ["tok " + GITHUB])
        assert session_marks.labels(session) == {L.TRIPPED}

    async def test_a_refused_mode(self, tmp_path: Any, session: str) -> None:
        _, seen, row = await _credential_call(tmp_path, {"text": "tok " + GITHUB}, mode="nope")
        assert seen == []
        assert "credential" not in row["error_message"]
        assert "trentina_mode" in row["error_message"]
        assert session_marks.labels(session) == {L.TRIPPED}

    async def test_a_held_tool(self, tmp_path: Any, session: str) -> None:
        with patch("trentina.transports.mcp.tool_pins.held", return_value=True):
            _, seen, row = await _credential_call(tmp_path, {"text": "tok " + GITHUB})
        assert seen == []
        assert "held pending operator approval" in row["error_message"]
        assert session_marks.labels(session) == {L.TRIPPED}


class TestRefuseWhen:
    def test_refuse_when_flagged_covers_the_flag_labels(self) -> None:
        cfg = _guarded_profile(refuse_when_flagged=True).semantic_request_guards
        assert cfg is not None
        assert cfg.refusing_labels == {L.FLAGGED_DELIVERY, L.TRIPPED}

    def test_both_keys_add_up(self) -> None:
        cfg = _guarded_profile(
            refuse_when_flagged=True, refuse_when=["credential_seen"]
        ).semantic_request_guards
        assert cfg is not None
        assert cfg.refusing_labels == {L.FLAGGED_DELIVERY, L.TRIPPED, L.CREDENTIAL_SEEN}

    def test_an_unknown_or_repeated_label_fails_to_load(self) -> None:
        with pytest.raises(ValidationError):
            _guarded_profile(refuse_when=["private_source"])
        with pytest.raises(ValidationError):
            _guarded_profile(refuse_when=["tripped", "tripped"])

    async def test_a_guarded_call_after_a_credential_read_is_refused_unasked(
        self, session: str, asked: list[AsyncMock]
    ) -> None:
        await session_marks._mark_session(_delivered(GITHUB))
        refusal = await _judge_call(_guarded_profile(refuse_when=["credential_seen"]))
        assert refusal is not None
        assert refusal.reason == gatekeeper.SESSION_CREDENTIAL_SEEN
        assert refusal.audit.endswith("session_flagged=no credential_seen=yes")
        assert not any(mock.await_count for mock in asked)

    async def test_a_guarded_response_after_a_credential_read_is_refused_unasked(
        self, session: str, asked: list[AsyncMock]
    ) -> None:
        await session_marks._mark_session(_delivered(GITHUB))
        refusal = await _judge_response(_response_profile(refuse_when=["credential_seen"]))
        assert refusal is not None
        assert refusal.reason == gatekeeper.SESSION_CREDENTIAL_SEEN
        assert not any(mock.await_count for mock in asked)

    async def test_refuse_when_flagged_alone_ignores_a_credential_read(self, session: str) -> None:
        await session_marks._mark_session(_delivered(GITHUB))
        facts = gatekeeper.gather_facts(_guarded_profile(), "mail", "send_message", _DEST)
        cfg = _guarded_profile(refuse_when_flagged=True).semantic_request_guards
        assert cfg is not None
        assert gatekeeper.session_refusal(cfg, facts) is None
        assert "this session was delivered a credential: yes" in facts.briefing()

    async def test_only_the_listed_label_refuses(self, session: str) -> None:
        session_marks.mark(session, L.FLAGGED_DELIVERY)
        cfg = _guarded_profile(refuse_when=["credential_seen"]).semantic_request_guards
        assert cfg is not None
        facts = gatekeeper.gather_facts(_guarded_profile(), "mail", "send_message", _DEST)
        assert gatekeeper.session_refusal(cfg, facts) is None
        cfg = _guarded_profile(refuse_when=["flagged_delivery"]).semantic_request_guards
        assert cfg is not None
        assert gatekeeper.session_refusal(cfg, facts) == gatekeeper.SESSION_FLAGGED

    async def test_an_unidentified_session_is_refused(self, asked: list[AsyncMock]) -> None:
        session_marks.clear()
        refusal = await _judge_call(_guarded_profile(refuse_when=["credential_seen"]))
        assert refusal is not None
        assert refusal.reason == gatekeeper.SESSION_FLAGGED

    async def test_a_trip_is_tripped_not_flagged_delivery(self, session: str) -> None:
        with patch.object(orchestrator, "defend", AsyncMock()):
            await _decoy_rpc("tools/call", {"name": "host__send_email", "arguments": dict(_ARGS)})
        assert session_marks.labels(session) == {L.TRIPPED}


class TestEgress:
    async def test_refuse_when_does_not_apply_to_egress(self) -> None:
        profile = _guarded_profile(refuse_when=["credential_seen"])
        cfg = profile.semantic_request_guards
        assert cfg is not None
        session_marks.clear()
        with patch.object(gatekeeper, "_ask", AsyncMock(return_value=None)) as ask:
            refusal = await gatekeeper.judge_egress(
                profile, cfg, backend="http:gh", method="POST", destination=_DEST, document="x"
            )
        assert refusal is None
        ask.assert_awaited_once()
