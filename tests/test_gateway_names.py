"""Short tool names (0.38.0): simplest name, tags only on collision, never reassigned."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from trentina.database import issued_tool_names
from trentina.gateway.backend import BackendCall
from trentina.gateway.ingress_defense import IngressDecision
from trentina.gateway.names import _issued, assign, base_names
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.router import reset_profile_tools_cache, route_jsonrpc

ROUTER = "trentina.gateway.router"


@pytest.mark.parametrize(
    ("backend", "tools", "expected"),
    [
        (
            "jira",
            ["jira_get_issue", "jira_search", "jira_add_comment"],
            ["get_issue", "jira_search", "add_comment"],
        ),
        ("cloudflare", ["list_zones_tool", "purge_cache_tool"], ["list_zones", "purge_cache"]),
        ("memory", ["memory_store", "memory_search"], ["memory_store", "memory_search"]),
        ("rt", ["rt_get_ticket_tool"], ["get_ticket"]),
        ("lightspeed", ["planning__get_rhel_lifecycle"], ["planning_get_rhel_lifecycle"]),
        ("web", ["fetch_tool", "fetch"], ["fetch_tool", "fetch"]),
    ],
)
def test_base_names(backend: str, tools: list[str], expected: list[str]) -> None:
    assert list(base_names(backend, tools).values()) == expected


def test_only_colliding_names_are_tagged() -> None:
    wanted = [
        ("mail-work", "send_gmail_message"),
        ("mail-home", "send_gmail_message"),
        ("mail-home", "list_task_lists"),
    ]
    served, new = assign(wanted, {"mail-work": "work", "mail-home": "home"}, {})
    assert served == {
        ("mail-work", "send_gmail_message"): "work_send_gmail_message",
        ("mail-home", "send_gmail_message"): "home_send_gmail_message",
        ("mail-home", "list_task_lists"): "list_task_lists",
    }
    assert set(new) == set(served.values())


def test_an_issued_name_is_never_reassigned() -> None:
    """A newcomer takes the tag; the name an agent knows stays put."""
    issued = {"search": ("wiki", "search_tool"), "gone": ("old", "gone_tool")}
    wanted = [("wiki", "search_tool"), ("web", "search_tool"), ("new", "gone_tool")]
    served, new = assign(wanted, {"wiki": "wiki", "web": "web", "new": "new"}, issued)
    assert served[("wiki", "search_tool")] == "search"
    assert served[("web", "search_tool")] == "web_search"
    assert served[("new", "gone_tool")] == "new_gone", "a retired name stays reserved"
    assert "search" not in new


def test_a_tag_clash_falls_back_to_the_long_form() -> None:
    issued = {"x_list": ("x", "list_tool"), "list": ("y", "list_tool")}
    served, _ = assign([("z", "list_tool")], {"z": "x"}, issued)
    assert served[("z", "list_tool")] == "z__list_tool"


def _profile(short_names: bool = True) -> Profile:
    p = Profile(
        name="names",
        short_names=short_names,
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "jira": Backend(url="http://jira:8000/mcp"),
            "github": Backend(url="http://github:8000/mcp", name_tag="gh"),
        },
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


LISTS = {
    "jira": [{"name": "jira_get_issue"}, {"name": "jira_search_fields"}],
    "github": [{"name": "get_issue_tool"}, {"name": "list_repo_tree_tool"}],
}


async def _list(profile: Profile) -> list[str]:
    async def fake_list(name: str, _b: Any, *_: Any) -> list[dict[str, Any]]:
        return [{**t, "description": "d", "inputSchema": {}} for t in LISTS[name]]

    async def fake_scan(_p: Any, _b: str, _before: Any, tools: list[Any]) -> list[Any]:
        return tools

    reset_profile_tools_cache()
    with (
        patch(f"{ROUTER}.list_backend_tools", side_effect=fake_list),
        patch(f"{ROUTER}.scan_tool_list", side_effect=fake_scan),
    ):
        resp = await route_jsonrpc(profile, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return [t["name"] for t in resp["result"]["tools"]]


async def _call(profile: Profile, name: str) -> tuple[dict[str, Any], AsyncMock]:
    backend = AsyncMock(
        return_value=BackendCall(
            content=[{"type": "text", "text": "ok"}], is_error=False, structured_content=None
        )
    )
    with (
        patch(f"{ROUTER}.call_backend_tool", backend),
        patch(
            f"{ROUTER}.scan_tool_response", AsyncMock(return_value=IngressDecision(warning=None))
        ),
        patch(f"{ROUTER}._audit", MagicMock()) as audit,
    ):
        backend.audit = audit
        resp = await route_jsonrpc(
            profile,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            },
        )
    return resp, backend


@pytest.mark.asyncio
class TestTheEdge:
    async def test_tools_list_serves_short_names_and_records_them(self) -> None:
        names = await _list(_profile())
        assert names == ["jira_get_issue", "search_fields", "gh_get_issue", "list_repo_tree"]
        assert issued_tool_names("names")["gh_get_issue"] == ("github", "get_issue_tool")

    async def test_a_short_name_routes_to_the_real_tool(self) -> None:
        await _list(_profile())
        _, backend = await _call(_profile(), "gh_get_issue")
        assert backend.call_args.args[0] == "github"
        assert backend.call_args.args[2] == "get_issue_tool"

    async def test_a_name_issued_before_a_restart_routes_without_a_list(self) -> None:
        await _list(_profile())
        _issued.clear()
        _, backend = await _call(_profile(), "search_fields")
        assert backend.call_args.args[2] == "jira_search_fields"

    async def test_the_long_form_no_longer_routes_under_short_names(self) -> None:
        """0.43.0: only a name tools/list serves resolves."""
        resp, backend = await _call(_profile(), "jira__jira_get_issue")
        assert "Unknown tool" in resp["error"]["message"]
        backend.assert_not_awaited()

    async def test_an_unknown_name_is_refused(self) -> None:
        resp, backend = await _call(_profile(), "no_such_tool")
        assert "Unknown tool" in resp["error"]["message"]
        backend.assert_not_awaited()

    async def test_an_unknown_name_is_audited_by_fingerprint(self) -> None:
        """A probe for names never served leaves a row (#269), not the caller's text."""
        _, backend = await _call(_profile(), "no_such_tool")
        backend.audit.assert_called_once()
        profile, backend_name, tool, outcome, *_ = backend.audit.call_args.args
        assert (profile, backend_name, outcome.value) == ("names", "", "denied_allowlist")
        assert tool.startswith("sha256:")
        assert "no_such_tool" not in str(backend.audit.call_args)

    async def test_names_are_on_by_default(self) -> None:
        p = Profile(
            name="names",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"jira": Backend(url="http://jira:8000/mcp")},
        )
        assert p.short_names

    async def test_off_serves_the_long_form(self) -> None:
        assert (await _list(_profile(short_names=False)))[0] == "jira__jira_get_issue"
        resp, _ = await _call(_profile(short_names=False), "search_fields")
        assert "Unknown tool" in resp["error"]["message"]
