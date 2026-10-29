"""Phase 4: the orchestrator is the one MCP ``tools/call`` path.

Every profile's ``tools/call`` runs through ``orchestrator.crossing`` and the MCP
``Face``/``Carrier`` (``transports.mcp``); the hand-rolled ``router._tools_call``
path is gone. These tests drive one request per branch of the call path through
``route_jsonrpc`` and assert the orchestrated response directly — a clean
delivery, a flag warning, a defense block, a redact extraction, a required-
transform failure, a backend error, an unknown tool, non-object arguments, a
disallowed mode, an allowlist denial, the two guard branches that gate dispatch,
and the response guard. (The byte-identical-to-the-old-path parity checks these
replace retired with the dual path they guarded.) The ``crossing`` driver itself
is unit-tested for its short-circuit on an ``Early`` and its edge ordering.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from tests.refusal_shape import refused
from trentina.gateway.backend import BackendCall
from trentina.gateway.errors import BackendCallError
from trentina.gateway.ingress_defense import IngressDecision
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.orchestrator import crossing
from trentina.outcomes import Outcome
from trentina.reserved import REFUSAL_KEY, WARNING_KEY
from trentina.transports.base import Carrier, Early, Face, Transport

ROUTER = "trentina.gateway.router"
AUDIT = "trentina.gateway.audit"
MCP = "trentina.transports.mcp"
ORCH = "trentina.orchestrator"
RESULTS = "trentina.gateway.results"


def _profile(
    *,
    enforcement: str = "flag",
    modes: list[str] | None = None,
    tools_deny: list[str] | None = None,
) -> Profile:
    p = Profile(
        name="agent",
        short_names=False,  # calls use <backend>__<tool>
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement=enforcement, modes=modes or [enforcement]),
        backends={"rt": Backend(url="http://rt:8000/mcp", tools_deny=tools_deny or [])},
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


def _request(*, name: str = "search", arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": f"rt{NAMESPACE_SEP}{name}", "arguments": arguments or {}},
    }


def _reply() -> BackendCall:
    return BackendCall(
        content=[{"type": "text", "text": json.dumps({"issues": [{"key": "RT-1"}]})}],
        is_error=False,
        structured_content=None,
    )


async def _run(
    profile: Profile,
    request: dict[str, Any],
    *,
    reply: BackendCall | None = None,
    decision: IngressDecision | None = None,
    exc: Exception | None = None,
) -> dict[str, Any]:
    """Route one request with the backend call and the scan patched to fixed values.

    ``scan_tool_response`` is patched in BOTH the router and the orchestrator
    namespace — the non-paged response edge reaches it as
    ``orchestrator.scan_tool_response`` (via ``judge_response``) and the paged
    path as ``router.scan_tool_response`` (which imported the name).
    """
    call = AsyncMock(side_effect=exc) if exc is not None else AsyncMock(return_value=reply)
    verdict = decision if decision is not None else IngressDecision(warning=None)
    scan = AsyncMock(return_value=verdict)
    with (
        patch(f"{ROUTER}.call_backend_tool", call),
        patch(f"{ROUTER}.scan_tool_response", scan),
        patch(f"{ORCH}.scan_tool_response", scan),
        patch(f"{AUDIT}._audit", MagicMock()),
    ):
        return await route_jsonrpc(profile, request)


# --- Every delivery verdict -------------------------------------------------


@pytest.mark.asyncio
async def test_clean_delivery() -> None:
    resp = await _run(
        _profile(), _request(), reply=_reply(), decision=IngressDecision(warning=None)
    )
    assert "result" in resp
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"]  # the backend's content was delivered


@pytest.mark.asyncio
async def test_flag_warning_attached() -> None:
    decision = IngressDecision(warning={"flagged_by": "l2", "risk_level": "high"})
    resp = await _run(_profile(), _request(), reply=_reply(), decision=decision)
    assert "result" in resp
    assert resp["result"][WARNING_KEY]["flagged_by"] == "l2"


@pytest.mark.asyncio
async def test_redact_extraction_replaces_content() -> None:
    decision = IngressDecision(warning=None, extraction="the gist of the response")
    resp = await _run(_profile(), _request(), reply=_reply(), decision=decision)
    assert "result" in resp
    assert resp["result"]["content"] == [{"type": "text", "text": "the gist of the response"}]


@pytest.mark.asyncio
async def test_block_refusal() -> None:
    decision = IngressDecision(
        warning={"flagged_by": "l2", "risk_level": "high"},
        blocked=True,
        refusal={"reason": "flagged by l2", "mode": "block", "alternatives": []},
    )
    resp = await _run(_profile(enforcement="block"), _request(), reply=_reply(), decision=decision)
    assert "result" in resp
    assert resp["result"][REFUSAL_KEY]["reason"] == "flagged by l2"
    # `search` is not annotated read-only, so the block reads as executed-withheld.
    assert resp["result"][REFUSAL_KEY]["executed"] is True


@pytest.mark.asyncio
async def test_required_transform_failure() -> None:
    # A required processor that cannot run: assembly delivers the preprocess
    # refusal in place of the response (results._preprocess_refusal).
    from trentina.gateway.transform import TransformOutcome

    failed = TransformOutcome(content_blocks=_reply().content, failed="required processor failed")
    transform = AsyncMock(return_value=failed)
    with (
        patch(f"{ROUTER}.call_backend_tool", AsyncMock(return_value=_reply())),
        patch(f"{MCP}.transform_response", transform),
        patch(f"{AUDIT}._audit", MagicMock()),
    ):
        resp = await route_jsonrpc(_profile(), _request())
    assert resp["result"][REFUSAL_KEY]["reason"] == "preprocess_failed"


# --- Every early-return branch ----------------------------------------------


@pytest.mark.asyncio
async def test_backend_error() -> None:
    # A transport failure (backend unreachable) is a genuine failed call: a
    # JSON-RPC error, not a policy refusal-as-result.
    resp = await _run(_profile(), _request(), exc=BackendCallError("backend unreachable"))
    assert "error" in resp


@pytest.mark.asyncio
async def test_unknown_tool() -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": f"ghost{NAMESPACE_SEP}tool", "arguments": {}},
    }
    resp = await _run(_profile(), req, reply=_reply())
    assert "error" in resp


@pytest.mark.asyncio
async def test_non_object_arguments() -> None:
    req = _request()
    req["params"]["arguments"] = ["not", "an", "object"]
    resp = await _run(_profile(), req, reply=_reply())
    assert "error" in resp


@pytest.mark.asyncio
async def test_disallowed_mode() -> None:
    # flag-only profile; a call asking for block is refused, delivered as a result (#549).
    resp = await _run(_profile(), _request(arguments={"trentina_mode": "block"}), reply=_reply())
    assert refused(resp)


@pytest.mark.asyncio
async def test_allowlist_denied() -> None:
    resp = await _run(_profile(tools_deny=["search"]), _request(), reply=_reply())
    assert "error" in resp


# --- The guard branches that gate dispatch and delivery ---------------------


async def _run_capture(
    profile: Profile,
    request: dict[str, Any],
    *,
    reply: BackendCall,
    guard_err: str | None = None,
    may_act: bool | None = None,
    refuse: tuple[Outcome, str, str] | None = None,
) -> tuple[dict[str, Any], AsyncMock]:
    """Route one request, returning the backend mock so a test can assert it was
    (not) dispatched. Patches the shared collaborators a guard branch rides.

    ``scan_tool_response`` is patched as ``router.*`` (the paged path) and
    ``orchestrator.*`` (the non-paged edge, via ``judge_response``);
    ``check_response_guards`` is reached as ``transports.mcp.*``; ``_refuse_call``
    is reached as ``router.*`` and ``_may_have_acted`` as ``results.*`` on the
    orchestrated path, so one patch covers each.
    """
    call = AsyncMock(return_value=reply)
    scan = AsyncMock(return_value=IngressDecision(warning=None))
    patches = [
        patch(f"{ROUTER}.call_backend_tool", call),
        patch(f"{ROUTER}.scan_tool_response", scan),
        patch(f"{ORCH}.scan_tool_response", scan),
        patch(f"{AUDIT}._audit", MagicMock()),
    ]
    if guard_err is not None:
        patches.append(patch(f"{MCP}.check_response_guards", MagicMock(return_value=guard_err)))
    if may_act is not None:
        patches.append(patch(f"{RESULTS}._may_have_acted", MagicMock(return_value=may_act)))
    if refuse is not None:
        patches.append(patch(f"{ROUTER}._refuse_call", AsyncMock(return_value=refuse)))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        resp = await route_jsonrpc(profile, request)
    return resp, call


@pytest.mark.asyncio
async def test_disallowed_preprocess_not_dispatched() -> None:
    # An invalid trentina_preprocess raises TransformNotPermittedError in
    # resolve_preprocess: refuse before the backend is reached.
    req = _request(arguments={"trentina_preprocess": "maybe"})
    resp, call = await _run_capture(_profile(), req, reply=_reply())
    assert refused(resp)
    call.assert_not_called()


@pytest.mark.asyncio
async def test_post_normalization_refusal_not_dispatched() -> None:
    # _refuse_call rejects a normalized argument: refuse, never reach the backend.
    refuse = (Outcome.DENIED_GUARD, "value not permitted for argument", "guard: q")
    resp, call = await _run_capture(_profile(), _request(), reply=_reply(), refuse=refuse)
    assert refused(resp)
    call.assert_not_called()


@pytest.mark.asyncio
async def test_response_guard_read_tool_refused() -> None:
    # A read tool whose response the guard refuses is refused as a result (#549,
    # _response_guard_refusal); the backend was dispatched (the guard runs on it).
    resp, call = await _run_capture(
        _profile(), _request(), reply=_reply(), guard_err="forbidden literal", may_act=False
    )
    assert refused(resp)
    call.assert_called_once()


@pytest.mark.asyncio
async def test_response_guard_may_have_acted_withheld() -> None:
    # A tool that may have acted gets an executed-but-withheld result, not an error.
    resp, _ = await _run_capture(
        _profile(), _request(), reply=_reply(), guard_err="forbidden literal", may_act=True
    )
    assert "result" in resp
    assert resp["result"][REFUSAL_KEY]["executed"] is True


# --- The crossing driver itself ---------------------------------------------


class _RecordingFace(Face):
    name = "test_face"

    def __init__(self, *, parse_result: Any) -> None:
        self._parse_result = parse_result
        self.delivered: Any = None
        self.wrapped: Any = None

    async def parse(self, ctx: Any) -> Any:
        return self._parse_result

    async def deliver(self, ctx: Any, parsed: Any, carried: Any) -> Any:
        self.delivered = (parsed, carried)
        return {"delivered": carried}

    def wrap(self, ctx: Any, result: Any) -> Any:
        self.wrapped = result
        return {"wrapped": result}


class _RecordingCarrier(Carrier):
    name = "test_carrier"

    def __init__(self, *, carry_result: Any) -> None:
        self._carry_result = carry_result
        self.carried: Any = None

    async def carry(self, ctx: Any, parsed: Any) -> Any:
        self.carried = parsed
        return self._carry_result


@pytest.mark.asyncio
async def test_crossing_short_circuits_on_early_parse() -> None:
    face = _RecordingFace(parse_result=Early({"refused": True}))
    carrier = _RecordingCarrier(carry_result="unreached")
    result = await crossing(Transport(face=face, carrier=carrier), ctx=object())
    assert result == {"refused": True}
    assert carrier.carried is None  # carry never ran
    assert face.wrapped is None  # wrap never ran


@pytest.mark.asyncio
async def test_crossing_short_circuits_on_early_carry() -> None:
    face = _RecordingFace(parse_result="parsed")
    carrier = _RecordingCarrier(carry_result=Early({"backend": "error"}))
    result = await crossing(Transport(face=face, carrier=carrier), ctx=object())
    assert result == {"backend": "error"}
    assert face.delivered is None  # deliver never ran
    assert face.wrapped is None


@pytest.mark.asyncio
async def test_crossing_runs_all_edges_in_order() -> None:
    face = _RecordingFace(parse_result="parsed")
    carrier = _RecordingCarrier(carry_result="carried")
    result = await crossing(Transport(face=face, carrier=carrier), ctx=object())
    assert carrier.carried == "parsed"  # parse fed carry
    assert face.delivered == ("parsed", "carried")  # carry fed deliver
    assert result == {"wrapped": {"delivered": "carried"}}  # deliver fed wrap
