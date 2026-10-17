"""Tests for tool discovery (#473): gateway/discovery.py through the router."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

import trentina.database as db_mod
from trentina.database import get_gateway_call_stats
from trentina.gateway import discovery
from trentina.gateway.backend import BackendCall
from trentina.gateway.context import current_session, session_fingerprint
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    Honeytoken,
    Profile,
    ToolDiscoveryConfig,
)
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.gateway.sessions import SessionRegistry, session_registry

SEP = NAMESPACE_SEP
PLANTED = "AKIAFAKEPLANTED00001"

TOOLS: dict[str, list[dict[str, Any]]] = {
    "mail": [
        {
            "name": "send_gmail_message",
            "description": "Send an email message.",
            "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}}},
        },
        {"name": "search_gmail_messages", "description": "Search the mailbox.", "inputSchema": {}},
        {"name": "delete_everything", "description": "Delete every message.", "inputSchema": {}},
    ],
    "systemd": [
        {"name": "unit_restart", "description": "Restart a systemd unit.", "inputSchema": {}},
        {"name": "unit_status", "description": "Show a unit's status.", "inputSchema": {}},
    ],
}


def _profile(mode: str = "search", **discovery_config: Any) -> Profile:
    p = Profile(
        short_names=False,
        name="disc",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mail": Backend(
                url="http://mail:8000/mcp", tools_allow=["*"], tools_deny=["delete_everything"]
            ),
            "systemd": Backend(url="http://systemd:8000/mcp", tools_allow=["*"]),
        },
        honeytokens={"aws-key": Honeytoken(value_env="K", value=SecretStr(PLANTED))},
        tool_discovery=ToolDiscoveryConfig(
            mode=mode, core=[f"systemd{SEP}unit_status"], **discovery_config
        ),
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


async def _list_tools(backend_name: str, _backend: Backend) -> list[dict[str, Any]]:
    return [dict(t) for t in TOOLS[backend_name]]


@pytest.fixture(autouse=True)
def backends(tmp_path: Any) -> Iterator[list[tuple[str, str, dict[str, Any]]]]:
    """Mocked backends and a private audit database; yields the calls forwarded."""
    forwarded: list[tuple[str, str, dict[str, Any]]] = []

    async def call(bn: str, _b: Backend, tn: str, args: dict[str, Any]) -> BackendCall:
        forwarded.append((bn, tn, args))
        return BackendCall(
            content=[{"type": "text", "text": "done"}], is_error=False, structured_content=None
        )

    db_mod._db = None
    with (
        patch("trentina.gateway.router.list_backend_tools", side_effect=_list_tools),
        patch("trentina.gateway.router.call_backend_tool", side_effect=call),
        patch("trentina.database.get_config") as cfg,
    ):
        cfg.return_value.db_path = str(tmp_path / "audit.db")
        cfg.return_value.ensure_db_dir = lambda: None
        cfg.return_value.blocklist_ttl_days = 30
        cfg.return_value.audit_retention_days = 90
        yield forwarded
    db_mod._db = None


async def _rpc(profile: Profile, method: str, params: dict[str, Any] | None = None) -> Any:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return await route_jsonrpc(profile, body)


async def _call(profile: Profile, name: str, arguments: Any) -> Any:
    return await _rpc(profile, "tools/call", {"name": name, "arguments": arguments})


async def _names(profile: Profile) -> list[str]:
    resp = await _rpc(profile, "tools/list")
    return [t["name"] for t in resp["result"]["tools"]]


def _outcomes() -> dict[tuple[str, str], dict[str, int]]:
    stats = get_gateway_call_stats("disc", days=1)
    return {(e["backend"], e["tool"]): e["outcomes"] for e in stats["by_tool"]}


@pytest.mark.asyncio
class TestListing:
    async def test_off_lists_everything_and_no_discovery_tool(self) -> None:
        names = await _names(_profile("off"))
        assert sorted(names) == sorted(
            [
                f"mail{SEP}send_gmail_message",
                f"mail{SEP}search_gmail_messages",
                f"systemd{SEP}unit_restart",
                f"systemd{SEP}unit_status",
            ]
        )

    async def test_search_lists_the_core_and_find_and_call(self) -> None:
        assert await _names(_profile()) == [f"systemd{SEP}unit_status", "find_tools", "call_tool"]

    async def test_dynamic_lists_the_core_and_load(self) -> None:
        assert await _names(_profile("dynamic")) == [f"systemd{SEP}unit_status", "load_tools"]

    async def test_describe_backend_leads_with_the_category(self) -> None:
        p = _profile("off", describe_backend=True, categories={"infra": ["systemd"]})
        resp = await _rpc(p, "tools/list")
        described = {t["name"]: t["description"] for t in resp["result"]["tools"]}
        assert described[f"systemd{SEP}unit_restart"] == "infra: Restart a systemd unit."
        assert described[f"mail{SEP}send_gmail_message"] == "mail: Send an email message."


@pytest.mark.asyncio
class TestInstructions:
    async def test_search_names_categories_and_how_to_find(self) -> None:
        p = _profile(categories={"infra": ["systemd"]})
        text = (await _rpc(p, "initialize"))["result"]["instructions"]
        assert "Tool categories: mail; infra (systemd)." in text
        assert "find_tools" in text and "call_tool" in text

    async def test_off_without_categories_says_nothing(self) -> None:
        text = (await _rpc(_profile("off"), "initialize"))["result"]["instructions"]
        assert "categories" not in text
        assert "find_tools" not in text

    async def test_off_with_categories_names_them(self) -> None:
        p = _profile("off", categories={"infra": ["systemd"]})
        text = (await _rpc(p, "initialize"))["result"]["instructions"]
        assert "Tool categories: mail; infra (systemd)." in text
        assert "find_tools" not in text


@pytest.mark.asyncio
class TestFindAndCall:
    async def test_find_returns_the_tool_ready_to_call_and_is_audited(self) -> None:
        resp = await _call(_profile(), "find_tools", {"query": "send an email"})
        body = json.loads(resp["result"]["content"][0]["text"])
        assert body["tools"][0]["name"] == f"mail{SEP}send_gmail_message"
        assert body["tools"][0]["inputSchema"]["properties"]["to"] == {"type": "string"}
        assert _outcomes()[("", "find_tools")] == {"ok": 1}

    async def test_find_never_returns_a_denied_tool(self) -> None:
        resp = await _call(_profile(), "find_tools", {"query": "delete every message"})
        body = json.loads(resp["result"]["content"][0]["text"])
        assert f"mail{SEP}delete_everything" not in [t["name"] for t in body["tools"]]

    async def test_find_refuses_bad_arguments(self) -> None:
        p = _profile()
        for arguments in (
            {},
            {"query": ""},
            {"query": "x", "limit": 0},
            {"query": "x", "category": "nope"},
        ):
            resp = await _call(p, "find_tools", arguments)
            assert resp["error"]["code"] == -32602
        assert _outcomes()[("", "find_tools")] == {"denied_guard": 4}

    async def test_call_routes_the_real_tool_with_one_row_under_its_name(
        self, backends: list[tuple[str, str, dict[str, Any]]]
    ) -> None:
        resp = await _call(
            _profile(), "call_tool", {"name": f"systemd{SEP}unit_restart", "arguments": {}}
        )
        assert resp["result"]["content"][0]["text"] == "done"
        assert backends == [("systemd", "unit_restart", {})]
        assert _outcomes() == {("systemd", "unit_restart"): {"ok": 1}}

    async def test_call_meets_the_allowlist_under_the_real_name(
        self, backends: list[tuple[str, str, dict[str, Any]]]
    ) -> None:
        resp = await _call(
            _profile(), "call_tool", {"name": f"mail{SEP}delete_everything", "arguments": {}}
        )
        assert resp["error"]["code"] == -32602
        assert backends == []
        assert _outcomes() == {("mail", "delete_everything"): {"denied_allowlist": 1}}

    async def test_call_cannot_reach_a_discovery_tool(self) -> None:
        for name in ("call_tool", "find_tools"):
            resp = await _call(_profile(), "call_tool", {"name": name, "arguments": {}})
            assert resp["error"]["code"] == -32602

    async def test_guarded_execution_sees_the_real_backend_and_tool(self) -> None:
        seen: list[tuple[str, str]] = []

        async def judge(_p: Any, _b: Any, backend_name: str, tool: str, *_a: Any) -> None:
            seen.append((backend_name, tool))

        with patch("trentina.gateway.router.judge_call", side_effect=judge):
            await _call(
                _profile(),
                "call_tool",
                {"name": f"mail{SEP}send_gmail_message", "arguments": {"to": "a@example.com"}},
            )
        assert seen == [("mail", "send_gmail_message")]

    async def test_a_honeytoken_inside_call_tool_trips_under_the_real_tool(
        self, backends: list[tuple[str, str, dict[str, Any]]]
    ) -> None:
        await _call(
            _profile(),
            "call_tool",
            {"name": f"mail{SEP}send_gmail_message", "arguments": {"to": PLANTED}},
        )
        assert backends == []
        assert _outcomes() == {("mail", "send_gmail_message"): {"decoy_tripped": 1}}

    async def test_an_unlisted_tool_is_still_callable_by_name(
        self, backends: list[tuple[str, str, dict[str, Any]]]
    ) -> None:
        resp = await _call(_profile(), f"systemd{SEP}unit_restart", {})
        assert resp["result"]["content"][0]["text"] == "done"

    async def test_discovery_tools_do_not_exist_when_off(self) -> None:
        resp = await _call(_profile("off"), "find_tools", {"query": "x"})
        assert resp["error"]["code"] == -32602
        assert "Unknown tool" in resp["error"]["message"]


@pytest.mark.asyncio
class TestDynamic:
    async def test_load_needs_a_session(self) -> None:
        resp = await _call(_profile("dynamic"), "load_tools", {"category": "mail"})
        assert resp["error"]["code"] == -32602
        assert "session" in resp["error"]["message"]

    async def test_load_a_category_grows_this_session_only_and_notifies_it(self) -> None:
        p = _profile("dynamic")
        mine, other = session_fingerprint("session-a"), session_fingerprint("session-b")
        with patch.object(session_registry, "notify_session") as notify:
            notify.return_value = asyncio.Future()
            notify.return_value.set_result(True)
            token = current_session.set(mine)
            try:
                resp = await _call(p, "load_tools", {"category": "mail"})
                loaded = json.loads(resp["result"]["content"][0]["text"])["loaded"]
                assert sorted(loaded) == [
                    f"mail{SEP}search_gmail_messages",
                    f"mail{SEP}send_gmail_message",
                ]
                assert f"mail{SEP}send_gmail_message" in await _names(p)
                # Loading again changes nothing, and says nothing.
                await _call(p, "load_tools", {"category": "mail"})
            finally:
                current_session.reset(token)
            notify.assert_called_once_with("disc", mine)
            token = current_session.set(other)
            try:
                assert f"mail{SEP}send_gmail_message" not in await _names(p)
            finally:
                current_session.reset(token)

    async def test_load_by_query(self) -> None:
        p = _profile("dynamic")
        token = current_session.set(session_fingerprint("session-q"))
        try:
            resp = await _call(p, "load_tools", {"query": "restart a unit"})
            loaded = json.loads(resp["result"]["content"][0]["text"])["loaded"]
            assert loaded[0] == f"systemd{SEP}unit_restart"
        finally:
            current_session.reset(token)

    async def test_an_ended_session_forgets_what_it_loaded(self) -> None:
        registry = SessionRegistry()
        registry.on_remove(discovery.forget_session)
        sid = registry.create_session("disc")
        token = current_session.set(session_fingerprint(sid))
        try:
            await _call(_profile("dynamic"), "load_tools", {"category": "mail"})
        finally:
            current_session.reset(token)
        assert session_fingerprint(sid) in discovery._loaded
        registry.delete_session(sid)
        assert session_fingerprint(sid) not in discovery._loaded


@pytest.mark.asyncio
async def test_notify_session_reaches_one_session() -> None:
    registry = SessionRegistry()
    a, b = registry.create_session("disc"), registry.create_session("disc")
    qa, qb = registry.subscribe(a), registry.subscribe(b)
    assert await registry.notify_session("disc", session_fingerprint(a))
    assert qa.get_nowait()["method"] == "notifications/tools/list_changed"
    assert qb.empty()
    assert not await registry.notify_session("other", session_fingerprint(a))
    assert not await registry.notify_session("disc", "")


class TestConfig:
    def test_a_category_must_name_a_backend_of_the_profile(self) -> None:
        with pytest.raises(ValidationError, match="backends not in this profile"):
            _profile(categories={"x": ["nope"]})

    def test_a_backend_sits_in_one_category(self) -> None:
        with pytest.raises(ValidationError, match="two categories"):
            ToolDiscoveryConfig(categories={"a": ["mail"], "b": ["mail"]})

    def test_core_cannot_name_a_discovery_tool(self) -> None:
        with pytest.raises(ValidationError, match="discovery tool"):
            ToolDiscoveryConfig(core=["find_tools"])

    def test_top_k_is_bounded(self) -> None:
        with pytest.raises(ValidationError):
            ToolDiscoveryConfig(top_k=0)
        with pytest.raises(ValidationError):
            ToolDiscoveryConfig(top_k=26)
