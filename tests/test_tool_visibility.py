"""E2a: the tool-visibility diagnostic names the stage that drops a tool (#592).

Each test seeds exactly one drop and asserts the diagnostic names that stage,
so a federation operator (or any operator) stops guessing between reconnect,
flush and reload for a tool that simply never cleared a pin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from trentina import perimeter_db
from trentina.gateway import aggregate, diagnose
from trentina.gateway.diagnose import diagnose_tool_visibility
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.tool_pins import backend_id

if TYPE_CHECKING:
    import pytest

URL = "http://backend.example:8000/mcp"


def _tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"do {name}",
        "inputSchema": {"type": "object", "properties": {}},
    }


def _profile(backend: Backend, name: str = "agent") -> Profile:
    profile = Profile(name=name, auth=AuthConfig(bearer_token_env="A"), backends={"b": backend})
    profile.auth.bearer_token = SecretStr("t")
    return profile


def _offer(monkeypatch: pytest.MonkeyPatch, tools: list[dict[str, Any]]) -> None:
    """Make both the diagnostic and the aggregate see ``tools`` as offered."""

    async def fake(_name: str, _backend: Backend, _profile: Profile) -> list[dict[str, Any]]:
        return [dict(t) for t in tools]

    # Both the diagnostic's offered call and ensure_profile_build go through
    # aggregate._offered_tools -> aggregate.list_backend_tools.
    monkeypatch.setattr(aggregate, "list_backend_tools", fake)


async def test_unknown_backend() -> None:
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "missing", "foo")
    assert result["reason"] == diagnose.UNKNOWN_BACKEND
    assert result["visible"] is False


async def test_not_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("foo")])
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "b", "bar")
    assert result["reason"] == diagnose.NOT_OFFERED


async def test_excluded_by_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("foo")])
    profile = _profile(Backend(url=URL, tools_allow=["something_else"]))
    result = await diagnose_tool_visibility(profile, "b", "foo")
    assert result["reason"] == diagnose.EXCLUDED_BY_ALLOWLIST


async def test_excluded_by_denylist(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("foo")])
    profile = _profile(Backend(url=URL, tools_deny=["foo"]))
    result = await diagnose_tool_visibility(profile, "b", "foo")
    assert result["reason"] == diagnose.EXCLUDED_BY_DENYLIST


async def test_held_pending_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("foo")])
    # A pin hold is read-only state the diagnostic must notice without writing.
    perimeter_db.put_pin(backend_id(URL), "foo", approved=None, pending=("h", "{}"), rejected=False)
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "b", "foo")
    assert result["reason"] == diagnose.HELD_PENDING_PIN


async def test_served(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("foo")])
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "b", "foo")
    assert result["visible"] is True, result
    assert result["reason"] == diagnose.SERVED
    assert result["served_as"]
