"""A decoy trip or a refused credential marks the session (#860).

Both are the agent itself misbehaving, and ``refuse_when_flagged`` and the
gatekeeper's judge read the same mark delivered flagged content sets.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from tests.test_credential_guard import GITHUB
from tests.test_credential_guard import _call as _credential_call
from tests.test_gatekeeper import _profile as _guarded_profile
from tests.test_gateway_decoy import PLANTED
from tests.test_gateway_decoy import _rpc as _decoy_rpc
from trentina.gateway import gatekeeper, session_marks
from trentina.gateway.context import current_session
from trentina.gateway.decoy import record_trip

SESSION = "fp-860"


@pytest.fixture
def session() -> Iterator[str]:
    session_marks.clear()
    token = current_session.set(SESSION)
    try:
        yield SESSION
    finally:
        current_session.reset(token)
        session_marks.clear()


@pytest.mark.usefixtures("env")
class TestDecoyTrips:
    async def test_a_decoy_call_marks_the_session(self, session: str) -> None:
        await _decoy_rpc("tools/call", {"name": "host__send_email", "arguments": {"to": "a@b.c"}})
        assert session_marks.was_flagged(session) is True

    async def test_a_planted_credential_bound_for_a_real_backend_marks_it(
        self, session: str
    ) -> None:
        arguments = {"body": f"key is {PLANTED}"}
        await _decoy_rpc("tools/call", {"name": "tickets__comment", "arguments": arguments})
        assert session_marks.was_flagged(session) is True

    def test_a_trip_with_no_session_marks_nothing(self) -> None:
        # /proxy/http and /proxy/llm trip with no MCP session to mark.
        session_marks.clear()
        record_trip("kage", "", "request", "honeytoken:aws-key")
        assert session_marks._marks == {}

    async def test_the_judge_and_refuse_when_flagged_see_the_trip(self, session: str) -> None:
        await _decoy_rpc("tools/call", {"name": "host__send_email", "arguments": {"to": "a@b.c"}})
        facts = gatekeeper.gather_facts(_guarded_profile(), "mail", "send_message", None)
        assert facts.session_flagged is True
        assert "tripped a decoy or tried to send a credential: yes" in facts.briefing()


class TestCredentialRefusals:
    async def test_a_refused_credential_marks_the_session(
        self, tmp_path: Any, session: str
    ) -> None:
        _, seen, _ = await _credential_call(tmp_path, {"text": "tok " + GITHUB})
        assert seen == []
        assert session_marks.was_flagged(session) is True

    async def test_an_allowed_kind_does_not(self, tmp_path: Any, session: str) -> None:
        from tests.test_credential_guard import _backend
        from trentina.credential_shapes import CredentialKind as K

        backend = _backend(credentials_allowed={"echo": [K.GITHUB_TOKEN.value]})
        _, seen, _ = await _credential_call(tmp_path, {"text": GITHUB}, backend)
        assert seen == [{"text": GITHUB}]
        assert session_marks.was_flagged(session) is False

    async def test_a_clean_call_does_not(self, tmp_path: Any, session: str) -> None:
        await _credential_call(tmp_path, {"text": "hello"})
        assert session_marks.was_flagged(session) is False
