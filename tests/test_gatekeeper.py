"""Guarded execution (#456): a gatekeeper judges a profile's guarded calls."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr, ValidationError

from trentina.database import has_sent_to, record_gateway_call
from trentina.errors import QuarantineAgentError
from trentina.gateway import gatekeeper, session_marks
from trentina.gateway.backend import BackendCall
from trentina.gateway.context import current_session
from trentina.gateway.destination import Destination, DestinationKind
from trentina.gateway.loader import ProfileConfigError, load_profiles
from trentina.gateway.profile import AuthConfig, Backend, GuardedExecutionConfig, Profile
from trentina.gateway.profile_lint import check_guarded_destinations
from trentina.gateway.router import NAMESPACE_SEP, Assembled, _mark_session, route_jsonrpc
from trentina.outcomes import BLOCKED_OUTCOMES, Outcome

POLICY = "Mail leaves only to example.com addresses. No customer data in bulk."


def _profile(**guarded: Any) -> Profile:
    p = Profile(
        short_names=False,
        name="clerk",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mail": Backend(
                url="http://mail:8000/mcp",
                tools_allow=["*"],
                destination_params={"send_message": "to"},
            ),
            "wiki": Backend(url="http://wiki:8000/mcp", tools_allow=["*"]),
        },
        guarded_execution=GuardedExecutionConfig(
            policy=POLICY, tools={"mail": ["send_message"]}, **guarded
        ),
    )
    p.auth.bearer_token = SecretStr("x")
    return p


def _verdict(*, flagged: bool = False) -> SimpleNamespace:
    return SimpleNamespace(flagged=flagged)


def _gaps(*, blocking: bool = False) -> SimpleNamespace:
    return SimpleNamespace(blocking=lambda: blocking)


class _Judge:
    """Patches the three things the gatekeeper asks: the layers, the gaps, the judge."""

    def __init__(
        self,
        answer: dict[str, Any] | BaseException | None = None,
        *,
        flagged: bool = False,
        blocking: bool = False,
        llm: bool = True,
    ) -> None:
        self.answer = {"decision": "allow", "reason": "within_policy"} if answer is None else answer
        self.defend = AsyncMock(return_value=_verdict(flagged=flagged))
        self.generate = AsyncMock(side_effect=self._generate)
        self._patches = [
            patch.object(gatekeeper, "defend", self.defend),
            patch.object(gatekeeper, "gaps_of", lambda _v: _gaps(blocking=blocking)),
            patch.object(gatekeeper, "quarantine_generate", self.generate),
            patch.object(gatekeeper, "llm_available", lambda: llm),
            patch.object(gatekeeper, "gather_facts", self._facts),
        ]
        self.first_contact: bool | None = True

    async def _generate(self, *_a: Any, **_k: Any) -> dict[str, Any]:
        if isinstance(self.answer, BaseException):
            raise self.answer
        return dict(self.answer)

    def _facts(
        self, profile: Profile, backend: str, tool: str, dest: Destination | None
    ) -> gatekeeper.CallFacts:
        return gatekeeper.CallFacts(
            backend=backend,
            tool=tool,
            destination=dest.value if dest else None,
            destination_kind=dest.kind.value if dest else None,
            first_contact=self.first_contact,
            session_flagged=False,
        )

    def __enter__(self) -> _Judge:
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(self._patches):
            p.stop()


_DEST = Destination("ceo@other.example", DestinationKind.PARAM)
_ARGS = {"to": "ceo@other.example", "body": "the weekly export"}


async def _judge(profile: Profile, tool: str = "send_message", backend: str = "mail") -> Any:
    return await gatekeeper.judge_call(
        profile, profile.backends[backend], backend, tool, dict(_ARGS), _DEST
    )


class TestWhatIsJudged:
    async def test_a_tool_that_is_not_guarded_costs_nothing(self) -> None:
        with _Judge() as judge:
            assert await _judge(_profile(), tool="list_messages") is None
            assert await _judge(_profile(), tool="send_message", backend="wiki") is None
        judge.defend.assert_not_awaited()
        judge.generate.assert_not_awaited()

    async def test_a_profile_without_the_block_is_never_judged(self) -> None:
        p = _profile()
        p.guarded_execution = None
        with _Judge() as judge:
            assert await _judge(p) is None
        judge.defend.assert_not_awaited()

    async def test_an_explicit_allow_lets_the_call_go(self) -> None:
        with _Judge() as judge:
            assert await _judge(_profile()) is None
        judge.defend.assert_awaited_once()
        judge.generate.assert_awaited_once()

    async def test_the_judge_is_told_the_policy_the_facts_and_the_arguments_as_data(self) -> None:
        with _Judge() as judge:
            await _judge(_profile())
        content = judge.generate.await_args.args[0]
        kwargs = judge.generate.await_args.kwargs
        assert POLICY in kwargs["system_prompt"]
        assert "ceo@other.example (param)" in kwargs["user_prompt"]
        assert "first contact with this destination: yes" in kwargs["user_prompt"]
        assert '"body": "the weekly export"' in content
        assert POLICY not in content
        schema = kwargs["response_schema"]["properties"]
        assert schema["decision"]["enum"] == ["allow", "refuse"]

    async def test_the_arguments_cross_the_layers_as_model_output(self) -> None:
        with _Judge() as judge:
            await _judge(_profile())
        kwargs = judge.defend.await_args.kwargs
        assert kwargs["source"] == "clerk:mail:send_message:arguments"
        assert kwargs["source_type"] == "tool_arguments"
        assert kwargs["provenance"].value == "model_output"
        assert kwargs["attribution"]["direction"] == "arguments"


class TestRefusals:
    @pytest.mark.parametrize(
        "reason",
        ["policy_violation", "unfamiliar_destination", "bulk_private_data", "credential_material"],
    )
    async def test_the_judges_reason_is_the_code(self, reason: str) -> None:
        with _Judge({"decision": "refuse", "reason": reason}):
            refusal = await _judge(_profile())
        assert refusal.reason == reason
        assert refusal.message == f"Refused by guarded execution: {reason}"

    async def test_flagged_arguments_refuse_without_asking_the_judge(self) -> None:
        with _Judge(flagged=True) as judge:
            refusal = await _judge(_profile())
        assert refusal.reason == gatekeeper.ARGUMENTS_FLAGGED
        judge.generate.assert_not_awaited()

    async def test_arguments_the_layers_could_not_finish_refuse(self) -> None:
        with _Judge(blocking=True) as judge:
            refusal = await _judge(_profile())
        assert refusal.reason == gatekeeper.ARGUMENTS_UNJUDGED
        judge.generate.assert_not_awaited()

    @pytest.mark.parametrize(
        "answer",
        [
            {"decision": "refuse", "reason": "within_policy"},
            {"decision": "allow", "reason": "credential_material"},
            {"decision": "allow", "reason": "made_up"},
            {"decision": "allow"},
            {"decision": "refuse", "reason": "made_up"},
            {"decision": "maybe", "reason": "within_policy"},
            {"reason": "within_policy"},
            {},
        ],
    )
    async def test_anything_but_an_explicit_allow_refuses(self, answer: dict[str, Any]) -> None:
        with _Judge(answer):
            refusal = await _judge(_profile())
        assert refusal is not None
        assert refusal.reason == "other"

    async def test_the_refusal_names_no_policy_and_no_prose(self) -> None:
        with _Judge({"decision": "refuse", "reason": "policy_violation"}):
            refusal = await _judge(_profile())
        assert POLICY not in refusal.message
        assert POLICY not in refusal.audit
        assert refusal.audit.endswith("first_contact=yes session_flagged=no")


class TestFailsClosed:
    async def test_no_judge_configured(self) -> None:
        with _Judge(llm=False):
            refusal = await _judge(_profile())
        assert refusal.reason == gatekeeper.GATEKEEPER_UNAVAILABLE

    @pytest.mark.parametrize(
        "error",
        [
            QuarantineAgentError("all providers exhausted"),
            QuarantineAgentError("SECURITY: canary token leaked in response"),
        ],
    )
    async def test_a_judge_that_fails_or_leaks_refuses(self, error: Exception) -> None:
        with _Judge(error):
            refusal = await _judge(_profile())
        assert refusal.reason == gatekeeper.GATEKEEPER_UNAVAILABLE

    async def test_a_slow_judge_refuses(self) -> None:
        p = _profile()
        assert p.guarded_execution is not None
        p.guarded_execution.timeout_seconds = 0.01
        with _Judge() as judge:

            async def slow(*_a: Any, **_k: Any) -> dict[str, Any]:
                await asyncio.sleep(1)
                return {"decision": "allow", "reason": "within_policy"}

            judge.generate.side_effect = slow
            refusal = await _judge(p)
        assert refusal.reason == gatekeeper.GATEKEEPER_UNAVAILABLE


class TestFacts:
    def test_first_contact_counts_only_completed_calls(self, env: Path) -> None:
        record_gateway_call(
            "clerk",
            "mail",
            "send_message",
            "denied_gatekeeper",
            0,
            destination="a@x",
            destination_kind="param",
        )
        assert has_sent_to("clerk", "a@x", "param") is False
        record_gateway_call(
            "clerk", "mail", "send_message", "ok", 3, destination="a@x", destination_kind="param"
        )
        assert has_sent_to("clerk", "a@x", "param") is True
        assert has_sent_to("other", "a@x", "param") is False
        assert has_sent_to("clerk", "a@x", "fetch") is False

    def test_facts_read_the_audit_and_the_session(self, env: Path) -> None:
        record_gateway_call(
            "clerk", "mail", "send_message", "ok", 3, destination="a@x", destination_kind="param"
        )
        session_marks.clear()
        session_marks.mark_flagged("s1")
        token = current_session.set("s1")
        try:
            known = gatekeeper.gather_facts(
                _profile(), "mail", "send_message", Destination("a@x", DestinationKind.PARAM)
            )
            new = gatekeeper.gather_facts(
                _profile(), "mail", "send_message", Destination("b@x", DestinationKind.PARAM)
            )
            blind = gatekeeper.gather_facts(_profile(), "mail", "send_message", None)
        finally:
            current_session.reset(token)
        assert (known.first_contact, known.session_flagged) == (False, True)
        assert new.first_contact is True
        assert blind.first_contact is None
        assert "destination: not declared for this tool" in blind.briefing()

    def test_an_unreadable_audit_reads_as_a_first_contact(self) -> None:
        with patch("trentina.database.has_sent_to", side_effect=RuntimeError("locked")):
            facts = gatekeeper.gather_facts(_profile(), "mail", "send_message", _DEST)
        assert facts.first_contact is True


class TestSessionMarks:
    def setup_method(self) -> None:
        session_marks.clear()

    def test_no_session_is_unknown_and_is_never_marked(self) -> None:
        session_marks.mark_flagged("")
        assert session_marks.was_flagged("") is None

    def test_a_mark_lasts_its_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        now = [1000.0]
        monkeypatch.setattr(session_marks.time, "monotonic", lambda: now[0])
        session_marks.mark_flagged("s")
        assert session_marks.was_flagged("s") is True
        assert session_marks.was_flagged("t") is False
        now[0] += session_marks.MARK_TTL_SECONDS + 1
        assert session_marks.was_flagged("s") is False

    def test_the_table_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(session_marks, "MAX_MARKS", 2)
        for s in ("a", "b", "c"):
            session_marks.mark_flagged(s)
        assert session_marks.was_flagged("a") is False
        assert session_marks.was_flagged("c") is True

    @pytest.mark.parametrize(
        ("outcome", "warning", "marked"),
        [
            (Outcome.OK, {"flagged_by": "L2"}, True),
            (Outcome.OK, {"l3_unavailable": True}, True),
            (Outcome.TOOL_ERROR, {"flagged_by": "L3"}, True),
            (Outcome.OK, None, False),
            (Outcome.BLOCKED_DEFENSE, {"flagged_by": "L2"}, False),
        ],
    )
    def test_a_delivered_warning_marks_the_session(
        self, outcome: Outcome, warning: dict[str, Any] | None, marked: bool
    ) -> None:
        token = current_session.set("s")
        try:
            _mark_session(Assembled(result={}, outcome=outcome, warning=warning))
        finally:
            current_session.reset(token)
        assert session_marks.was_flagged("s") is marked

    def test_an_internal_tools_own_warning_marks_the_session(self) -> None:
        call = BackendCall(
            content=[
                {
                    "type": "text",
                    "text": '{"content": "x", "_trentina_warning": {"flagged_by": "L3"}}',
                }
            ],
            is_error=False,
            structured_content=None,
        )
        token = current_session.set("s")
        try:
            _mark_session(Assembled(result={}, outcome=Outcome.OK), call)
        finally:
            current_session.reset(token)
        assert session_marks.was_flagged("s") is True


def _call(tool: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": f"mail{NAMESPACE_SEP}{tool}", "arguments": dict(_ARGS)},
    }


class TestRouter:
    async def test_a_refused_call_never_reaches_the_backend(self) -> None:
        backend = AsyncMock()
        audits: list[tuple[Any, ...]] = []
        with (
            _Judge({"decision": "refuse", "reason": "bulk_private_data"}),
            patch("trentina.gateway.router.call_backend_tool", backend),
            patch("trentina.gateway.router._audit", lambda *a, **k: audits.append((a, k))),
        ):
            resp = await route_jsonrpc(_profile(), _call("send_message"))
        backend.assert_not_awaited()
        assert resp["error"]["code"] == -32602
        assert resp["error"]["message"] == "Refused by guarded execution: bulk_private_data"
        ((args, kwargs),) = audits
        assert args[3] is Outcome.DENIED_GATEKEEPER
        assert "first_contact=yes" in args[5]
        assert kwargs["destination"] == _DEST

    async def test_an_allowed_call_is_forwarded(self) -> None:
        backend = AsyncMock(
            return_value=BackendCall(
                content=[{"type": "text", "text": "sent"}], is_error=False, structured_content=None
            )
        )
        with (
            _Judge(),
            patch("trentina.gateway.router.call_backend_tool", backend),
            patch("trentina.gateway.router._audit"),
            patch(
                "trentina.gateway.router.scan_tool_response",
                AsyncMock(
                    return_value=SimpleNamespace(
                        warning=None, blocked=False, refusal=None, extraction=None
                    )
                ),
            ),
        ):
            await route_jsonrpc(_profile(), _call("send_message"))
        backend.assert_awaited_once()

    async def test_a_parameter_guard_speaks_before_the_judge(self) -> None:
        p = _profile()
        from trentina.gateway.profile import ParameterConstraint

        p.backends["mail"].parameter_guards = {
            "send_message": {"to": ParameterConstraint(allow=["*@example.com"])}
        }
        with (
            _Judge() as judge,
            patch("trentina.gateway.router._audit"),
        ):
            resp = await route_jsonrpc(p, _call("send_message"))
        assert "not in allow list" in resp["error"]["message"]
        judge.defend.assert_not_awaited()

    async def test_a_flagged_delivery_marks_the_session_the_next_call_reads(self) -> None:
        session_marks.clear()
        backend = AsyncMock(
            return_value=BackendCall(
                content=[{"type": "text", "text": "a mail"}],
                is_error=False,
                structured_content=None,
            )
        )
        scanned = SimpleNamespace(
            warning={"flagged_by": "L2"}, blocked=False, refusal=None, extraction=None
        )
        token = current_session.set("fp-1")
        try:
            with (
                patch("trentina.gateway.router.call_backend_tool", backend),
                patch("trentina.gateway.router._audit"),
                patch(
                    "trentina.gateway.router.scan_tool_response", AsyncMock(return_value=scanned)
                ),
            ):
                await route_jsonrpc(_profile(), _call("get_message"))
            facts = gatekeeper.gather_facts(_profile(), "mail", "send_message", None)
        finally:
            current_session.reset(token)
        assert facts.session_flagged is True

    def test_the_outcome_is_a_policy_outcome(self) -> None:
        assert Outcome.DENIED_GATEKEEPER in BLOCKED_OUTCOMES


class TestConfig:
    @pytest.mark.parametrize(
        ("fields", "message"),
        [
            ({"policy": "   ", "tools": {"mail": ["send_message"]}}, "policy is empty"),
            ({"policy": POLICY, "tools": {"mail": ["send_*"]}}, "not exact tool names"),
            ({"policy": POLICY, "tools": {"mail": []}}, "names no tool"),
            ({"policy": POLICY, "tools": {"mail": ["a", "a"]}}, "lists a tool twice"),
            ({"policy": POLICY, "tools": {}}, "at least 1"),
            ({"policy": POLICY, "tools": {"mail": ["a"]}, "timeout_seconds": 1}, "greater than"),
            ({"policy": POLICY, "tools": {"mail": ["a"]}, "extra": 1}, "Extra inputs"),
        ],
    )
    def test_a_malformed_block_is_refused(self, fields: dict[str, Any], message: str) -> None:
        with pytest.raises(ValidationError, match=message):
            GuardedExecutionConfig(**fields)

    def test_a_guarded_backend_must_exist_and_be_real(self) -> None:
        with pytest.raises(ValidationError, match="no such backend"):
            Profile(
                name="p",
                auth=AuthConfig(bearer_token_env="T"),
                backends={"mail": Backend(url="http://mail:1/mcp", tools_allow=["*"])},
                guarded_execution={"policy": POLICY, "tools": {"post": ["send"]}},
            )
        with pytest.raises(ValidationError, match="decoy backend is not judged"):
            Profile(
                name="p",
                auth=AuthConfig(bearer_token_env="T"),
                backends={
                    "trap": Backend(
                        url="decoy://trap",
                        tools_allow=["send"],
                        decoys={"send": {"description": "sends", "result": "ok"}},
                    )
                },
                guarded_execution={"policy": POLICY, "tools": {"trap": ["send"]}},
            )

    def test_a_guarded_tool_the_allowlist_never_serves_fails_the_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("T", "secret")
        path = tmp_path / "profiles.yaml"
        path.write_text(
            "profiles:\n"
            "  p:\n"
            "    auth:\n      bearer_token_env: T\n"
            "    backends:\n"
            "      mail:\n        url: http://mail:1/mcp\n        tools_allow: [list_*]\n"
            "    guarded_execution:\n"
            "      policy: mail stays inside\n"
            "      tools:\n        mail: [send_message]\n",
            encoding="utf-8",
        )
        with pytest.raises(ProfileConfigError, match="send_message: the tool is not allowed"):
            load_profiles(path)

    def test_a_honeypot_has_no_guarded_execution(self) -> None:
        with pytest.raises(ValidationError, match="guarded_execution does not apply"):
            Profile(
                name="p",
                honeypot=True,
                auth=AuthConfig(bearer_token_env="T"),
                defense={"enforcement": "flag"},
                backends={"web": Backend(url="internal://web", tools_allow=["fetch_tool"])},
                guarded_execution={"policy": POLICY, "tools": {"web": ["fetch_tool"]}},
            )


class TestLint:
    def test_a_guarded_tool_with_no_destination_is_reported(self) -> None:
        file = {
            "profiles": {
                "p": {
                    "backends": {
                        "mail": {"destination_params": {"send_message": "to"}},
                        "chat": {},
                    },
                    "guarded_execution": {
                        "policy": "x",
                        "tools": {"mail": ["send_message"], "chat": ["post_message"]},
                    },
                }
            }
        }
        findings = check_guarded_destinations(file)
        assert [f.code for f in findings] == ["guarded-tool-no-destination"]
        assert "chat/post_message" in findings[0].message

    def test_a_profile_without_the_block_is_clean(self) -> None:
        assert check_guarded_destinations({"profiles": {"p": {"backends": {}}}}) == []
