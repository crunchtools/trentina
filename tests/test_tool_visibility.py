"""E2a: the tool-visibility diagnostic names the stage that drops a tool (#592).

Each test seeds exactly one drop and asserts the diagnostic names that stage,
so a federation operator (or any operator) stops guessing between reconnect,
flush and reload for a tool that simply never cleared a pin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from trentina import perimeter_db
from trentina.gateway import aggregate, diagnose
from trentina.gateway.context import profile_context
from trentina.gateway.diagnose import diagnose_tool_visibility, diagnose_visibility
from trentina.gateway.errors import BackendCallError
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.tool_pins import backend_id

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


async def test_backend_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(_name: str, _backend: Backend, _profile: Profile) -> list[dict[str, Any]]:
        raise BackendCallError("backend down")

    monkeypatch.setattr(aggregate, "list_backend_tools", boom)
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "b", "foo")
    assert result["reason"] == diagnose.BACKEND_UNREACHABLE


async def test_description_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    # Offered, not held, passes the allowlist — but absent from the served
    # aggregate: the perimeter withheld its description.
    _offer(monkeypatch, [_tool("foo")])

    async def empty(_profile: Profile) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(aggregate, "ensure_profile_build", empty)
    result = await diagnose_tool_visibility(_profile(Backend(url=URL)), "b", "foo")
    assert result["reason"] == diagnose.DESCRIPTION_WITHHELD
    assert result["visible"] is False


# --- scope / authorization (the scope-resolving entry) ---

_YAML = """\
profiles:
  alpha:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      jira:
        url: http://jira:1/mcp
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      wiki:
        url: http://wiki:1/mcp
"""


class TestScope:
    @pytest.fixture
    def live(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A registered ActiveConfig — a running, multi-tenant gateway."""
        from trentina.gateway.compress import set_profiles

        monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
        monkeypatch.setenv("TEST_BETA_TOKEN", "b")
        path = tmp_path / "profiles.yaml"
        path.write_text(_YAML, encoding="utf-8")
        cfg = load_profiles(path)
        register_active_config(path, cfg, {})  # makes current_scope live
        set_profiles(cfg.profiles)  # what get_profiles() reads for operator lookup

    @pytest.fixture(autouse=True)
    def _unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Make the backend step deterministic so a test asserts the AUTH outcome,
        # not a live connection: a resolved target reaches list_backend_tools.
        async def boom(_n: str, _b: Backend, _p: Profile) -> list[dict[str, Any]]:
            raise BackendCallError("unreachable")

        monkeypatch.setattr(aggregate, "list_backend_tools", boom)

    def _profiles(self) -> dict[str, Profile]:
        from trentina.gateway.compress import get_profiles

        return get_profiles() or {}

    async def test_agent_diagnoses_its_own_profile(self, live: None) -> None:
        with profile_context(self._profiles()["beta"]):
            result = await diagnose_visibility("wiki", "x")
        # Proceeded past authorization (its own backend is just unreachable here).
        assert "error" not in result
        assert result["reason"] == diagnose.BACKEND_UNREACHABLE

    async def test_agent_cannot_diagnose_another_profile(self, live: None) -> None:
        with profile_context(self._profiles()["beta"]):
            result = await diagnose_visibility("jira", "x", profile="alpha")
        assert "error" in result
        assert "operator" in result["error"].lower()

    async def test_operator_diagnoses_another_profile(self, live: None) -> None:
        with profile_context(self._profiles()["alpha"]):
            result = await diagnose_visibility("wiki", "x", profile="beta")
        assert "error" not in result
        assert result["reason"] == diagnose.BACKEND_UNREACHABLE

    async def test_operator_unknown_profile_names_no_other(self, live: None) -> None:
        with profile_context(self._profiles()["alpha"]):
            result = await diagnose_visibility("x", "y", profile="zeta")
        assert "error" in result
        assert "no such profile" in result["error"].lower()

    async def test_unbound_caller_is_refused(self, live: None) -> None:
        result = await diagnose_visibility("x", "y")
        assert "error" in result
        assert "no calling profile" in result["error"].lower()
