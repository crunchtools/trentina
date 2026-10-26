"""Phase 4: the orchestrator's MCP crossing is byte-identical to the router path.

PR #2 routes one profile's ``tools/call`` through ``orchestrator.crossing`` and
the MCP ``Face``/``Carrier`` (``transports.mcp``) instead of
``router._tools_call``. The crossing COMPOSES the same collaborators in the same
order, so its JSON-RPC response must match the hand-rolled path's byte for byte.

These tests drive one request through a profile with ``orchestrated=True`` and an
otherwise-identical profile with ``orchestrated=False`` and assert the two
responses are equal, across every branch of the call path: a clean delivery, a
flag warning, a defense block, a redact extraction, a backend error, an unknown
tool, non-object arguments, a disallowed mode, and an allowlist denial. The
``crossing`` driver itself is unit-tested for its short-circuit on an ``Early``.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from trentina.gateway.backend import BackendCall
from trentina.gateway.errors import BackendCallError
from trentina.gateway.ingress_defense import IngressDecision
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.orchestrator import crossing
from trentina.transports.base import Carrier, Early, Face, Transport

ROUTER = "trentina.gateway.router"


def _profile(
    *,
    orchestrated: bool,
    enforcement: str = "flag",
    modes: list[str] | None = None,
    tools_deny: list[str] | None = None,
) -> Profile:
    """Two of these, differing only in ``orchestrated``, must behave identically."""
    p = Profile(
        name="agent",
        short_names=False,  # calls use <backend>__<tool>
        orchestrated=orchestrated,
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
    """Route one request with the backend call and the scan patched to fixed values."""
    call = AsyncMock(side_effect=exc) if exc is not None else AsyncMock(return_value=reply)
    verdict = decision if decision is not None else IngressDecision(warning=None)
    scan = AsyncMock(return_value=verdict)
    with (
        patch(f"{ROUTER}.call_backend_tool", call),
        patch(f"{ROUTER}.scan_tool_response", scan),
        patch(f"{ROUTER}._audit", MagicMock()),
    ):
        return await route_jsonrpc(profile, request)


# --- Parity across every delivery verdict -------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "decision",
    [
        IngressDecision(warning=None),
        IngressDecision(warning={"flagged_by": "l2", "risk_level": "high"}),
        IngressDecision(warning=None, extraction="the gist of the response"),
    ],
    ids=["clean", "flag-warning", "redact-extraction"],
)
async def test_deliver_parity(decision: IngressDecision) -> None:
    req = _request()
    orch = await _run(_profile(orchestrated=True), req, reply=_reply(), decision=decision)
    plain = await _run(_profile(orchestrated=False), req, reply=_reply(), decision=decision)
    assert orch == plain
    assert "result" in orch  # a delivered call, not an error envelope


@pytest.mark.asyncio
async def test_block_refusal_parity() -> None:
    decision = IngressDecision(
        warning={"flagged_by": "l2", "risk_level": "high"},
        blocked=True,
        refusal={"reason": "flagged by l2", "mode": "block", "alternatives": []},
    )
    req = _request()
    orch = await _run(
        _profile(orchestrated=True, enforcement="block"), req, reply=_reply(), decision=decision
    )
    plain = await _run(
        _profile(orchestrated=False, enforcement="block"), req, reply=_reply(), decision=decision
    )
    assert orch == plain


# --- Parity across every early-return branch ----------------------------------


@pytest.mark.asyncio
async def test_backend_error_parity() -> None:
    req = _request()
    exc = BackendCallError("backend unreachable")
    orch = await _run(_profile(orchestrated=True), req, exc=exc)
    plain = await _run(_profile(orchestrated=False), req, exc=exc)
    assert orch == plain
    assert "error" in orch


@pytest.mark.asyncio
async def test_unknown_tool_parity() -> None:
    # A backend not in the profile: the served name resolves to nothing.
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": f"ghost{NAMESPACE_SEP}tool", "arguments": {}},
    }
    orch = await _run(_profile(orchestrated=True), req, reply=_reply())
    plain = await _run(_profile(orchestrated=False), req, reply=_reply())
    assert orch == plain
    assert "error" in orch


@pytest.mark.asyncio
async def test_non_object_arguments_parity() -> None:
    req = _request()
    req["params"]["arguments"] = ["not", "an", "object"]
    orch = await _run(_profile(orchestrated=True), req, reply=_reply())
    plain = await _run(_profile(orchestrated=False), req, reply=_reply())
    assert orch == plain
    assert "error" in orch


@pytest.mark.asyncio
async def test_disallowed_mode_parity() -> None:
    # flag-only profile; a call asking for block must be refused the same way.
    req = _request(arguments={"trentina_mode": "block"})
    orch = await _run(_profile(orchestrated=True), req, reply=_reply())
    plain = await _run(_profile(orchestrated=False), req, reply=_reply())
    assert orch == plain
    assert "error" in orch


@pytest.mark.asyncio
async def test_allowlist_denied_parity() -> None:
    req = _request()
    orch = await _run(_profile(orchestrated=True, tools_deny=["search"]), req, reply=_reply())
    plain = await _run(_profile(orchestrated=False, tools_deny=["search"]), req, reply=_reply())
    assert orch == plain
    assert "error" in orch


# --- The crossing driver itself -----------------------------------------------


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
