"""Tests for gateway/router.py — JSON-RPC dispatch with mocked backends."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from tests.refusal_shape import refused, refused_text
from trentina.database import get_gateway_call_stats
from trentina.gateway.backend import BackendCall
from trentina.gateway.circuit import breaker
from trentina.gateway.context import (
    get_current_profile,
    profile_context,
)
from trentina.gateway.errors import BackendCallError
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    ParameterConstraint,
    Profile,
)
from trentina.gateway.router import (
    NAMESPACE_SEP,
    PROTOCOL_VERSION,
    _profile_tools_cache,
    route_jsonrpc,
)


def _profile() -> Profile:
    """Build a Profile with two backends and one deny pattern for testing."""
    p = Profile(
        short_names=False,
        name="testp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mcp-slack": Backend(
                url="http://mcp-slack:8000/mcp",
                tools_allow=["*"],
                tools_deny=["slack_dangerous"],
            ),
            "mcp-atlassian": Backend(
                url="http://mcp-atlassian:8000/mcp",
                tools_allow=["*"],
            ),
        },
    )
    p.auth.bearer_token = SecretStr("x")
    return p


def _mixed_profile() -> Profile:
    """Profile mixing an http backend with an internal:// (trentina-tools) backend."""
    p = Profile(
        short_names=False,
        name="mixed",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mcp-slack": Backend(url="http://mcp-slack:8000/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["*"]),
        },
    )
    p.auth.bearer_token = SecretStr("x")
    return p


@pytest.mark.asyncio
class TestRouter:
    """JSON-RPC dispatch covers initialize, ping, tools/list, tools/call."""

    async def test_initialize_returns_server_info(self) -> None:
        resp = await route_jsonrpc(_profile(), {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert resp["result"]["serverInfo"]["name"] == "trentina-gateway:testp"
        assert "tools" in resp["result"]["capabilities"]

    async def test_ping_returns_empty_result(self) -> None:
        resp = await route_jsonrpc(_profile(), {"jsonrpc": "2.0", "id": 7, "method": "ping"})
        assert resp == {"jsonrpc": "2.0", "id": 7, "result": {}}

    async def test_unknown_method_returns_method_not_found(self) -> None:
        resp = await route_jsonrpc(
            _profile(),
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
        )
        assert resp["error"]["code"] == -32601

    async def test_tools_list_aggregates_and_namespaces(self) -> None:
        async def fake_list(backend_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack":
                return [
                    {"name": "slack_list_channels", "description": "", "inputSchema": {}},
                    {"name": "slack_dangerous", "description": "", "inputSchema": {}},
                ]
            return [{"name": "jira_search", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
            )

        names = sorted(str(t["name"]) for t in resp["result"]["tools"])
        assert names == [
            f"mcp-atlassian{NAMESPACE_SEP}jira_search",
            f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
        ]

    async def test_tools_list_skips_unreachable_backend(self) -> None:
        async def fake_list(backend_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack":
                raise BackendCallError("simulated outage")
            return [{"name": "jira_search", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}
            )
        names = [str(t["name"]) for t in resp["result"]["tools"]]
        assert names == [f"mcp-atlassian{NAMESPACE_SEP}jira_search"]

    async def test_tools_call_routes_to_correct_backend(self) -> None:
        called: dict[str, Any] = {}

        async def fake_call(
            backend_name: str,
            _backend: Backend,
            tool_name: str,
            arguments: dict[str, Any],
        ) -> BackendCall:
            called["backend"] = backend_name
            called["tool"] = tool_name
            called["args"] = arguments
            return BackendCall(
                content=[{"type": "text", "text": "ok"}],
                is_error=False,
                structured_content=None,
            )

        with patch(
            "trentina.gateway.router.call_backend_tool",
            side_effect=fake_call,
        ):
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {"limit": 5},
                    },
                },
            )

        assert called == {
            "backend": "mcp-slack",
            "tool": "slack_list_channels",
            "args": {"limit": 5},
        }
        assert resp["result"]["content"] == [{"type": "text", "text": "ok"}]
        assert resp["result"]["isError"] is False

    async def test_tools_call_rejects_non_namespaced_name(self) -> None:
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "no_namespace", "arguments": {}},
            },
        )
        assert resp["error"]["code"] == -32602

    async def test_tools_call_rejects_unknown_backend(self) -> None:
        # Refused like any unknown name (#293), not raised past the audit.
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": f"mcp-unknown{NAMESPACE_SEP}some_tool",
                    "arguments": {},
                },
            },
        )
        assert resp["error"]["code"] == -32602
        assert resp["error"]["message"].startswith("Unknown tool")

    async def test_tools_list_aggregates_http_and_internal(self) -> None:
        """Mixed-backend tools/list: http + internal both filtered and namespaced."""

        async def fake_list(_backend_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            return [{"name": "slack_list_channels", "description": "", "inputSchema": {}}]

        async def fake_internal_list() -> list[dict[str, Any]]:
            return [
                {"name": "block_fetch_tool", "description": "", "inputSchema": {}},
                {"name": "quarantine_stats_tool", "description": "", "inputSchema": {}},
            ]

        with (
            patch(
                "trentina.gateway.router.list_backend_tools",
                side_effect=fake_list,
            ),
            patch(
                "trentina.gateway.router.list_internal_tools",
                side_effect=fake_internal_list,
            ),
        ):
            resp = await route_jsonrpc(
                _mixed_profile(), {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}
            )

        names = sorted(str(t["name"]) for t in resp["result"]["tools"])
        assert names == [
            f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
            f"web{NAMESPACE_SEP}block_fetch_tool",
            f"web{NAMESPACE_SEP}quarantine_stats_tool",
        ]

    async def test_tools_call_routes_to_internal_backend(self) -> None:
        """A call on the internal backend dispatches to call_internal_tool, not http."""
        called: dict[str, Any] = {}

        async def fake_internal_call(
            tool_name: str, arguments: dict[str, Any], **_: Any
        ) -> BackendCall:
            called["tool"] = tool_name
            called["args"] = arguments
            return BackendCall(
                content=[{"type": "text", "text": "fetched"}],
                is_error=False,
                structured_content=None,
            )

        async def fail_http(*_args: Any, **_kwargs: Any) -> BackendCall:
            raise AssertionError("http backend must not be called for internal://")

        with (
            patch(
                "trentina.gateway.router.call_internal_tool",
                side_effect=fake_internal_call,
            ),
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=fail_http,
            ),
        ):
            resp = await route_jsonrpc(
                _mixed_profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": f"web{NAMESPACE_SEP}block_fetch_tool",
                        "arguments": {"url": "http://example.com"},
                    },
                },
            )

        assert called == {"tool": "block_fetch_tool", "args": {"url": "http://example.com"}}
        assert resp["result"]["content"] == [{"type": "text", "text": "fetched"}]
        assert resp["result"]["isError"] is False

    async def test_tools_call_enforces_denylist_at_call_time(self) -> None:
        """Defense in depth: a deny-listed tool name on a valid backend must
        be rejected at call time even if the consumer somehow learned the name."""
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": f"mcp-slack{NAMESPACE_SEP}slack_dangerous",
                    "arguments": {},
                },
            },
        )
        assert resp["error"]["code"] == -32602
        assert "not permitted" in resp["error"]["message"].lower()

    async def test_tools_call_records_audit_on_success(self, tmp_path: Any) -> None:
        """Successful tools/call writes an audit row to gateway_calls."""
        import trentina.database as db_mod

        db_mod._db = None
        db_path = str(tmp_path / "audit_test.db")

        async def fake_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "ok"}],
                is_error=False,
                structured_content=None,
            )

        tool_name = f"mcp-slack{NAMESPACE_SEP}slack_list_channels"
        with (
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=fake_call,
            ),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = db_path
            mock_cfg.return_value.ensure_db_dir = lambda: None
            await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
            )

        stats = get_gateway_call_stats("testp", days=1)
        assert stats["total_calls"] == 1
        assert stats["by_tool"][0]["tool"] == "slack_list_channels"
        assert stats["by_tool"][0]["ok"] == 1
        assert stats["by_tool"][0]["failed"] == 0
        assert stats["by_tool"][0]["outcomes"] == {"ok": 1}
        db_mod._db = None

    async def test_tools_call_records_audit_on_failure(self, tmp_path: Any) -> None:
        """Failed tools/call writes an audit row with error_message."""
        import trentina.database as db_mod

        db_mod._db = None
        db_path = str(tmp_path / "audit_fail_test.db")

        async def fail_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            raise BackendCallError("backend down")

        tool_name = f"mcp-slack{NAMESPACE_SEP}slack_list_channels"
        with (
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=fail_call,
            ),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = db_path
            mock_cfg.return_value.ensure_db_dir = lambda: None
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 21,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
            )

        assert resp["error"]["code"] == -32603
        stats = get_gateway_call_stats("testp", days=1)
        assert stats["total_calls"] == 1
        assert stats["by_tool"][0]["failed"] == 1
        assert stats["by_tool"][0]["outcomes"] == {"backend_error": 1}
        db_mod._db = None

    async def test_denied_allowlist_is_audited(self, tmp_path: Any) -> None:
        """An allowlist denial must leave an audit row.

        These returned before _audit was reached, so a consumer probing tools
        outside its allowlist was invisible — the exact signal you want for
        spotting a misbehaving or hijacked consumer.
        """
        import trentina.database as db_mod

        db_mod._db = None
        with patch("trentina.database.get_config") as mock_cfg:
            mock_cfg.return_value.db_path = str(tmp_path / "denied_allow.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 40,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_dangerous",
                        "arguments": {},
                    },
                },
            )

            assert resp["error"]["code"] == -32602
            stats = get_gateway_call_stats("testp", days=1)
            assert stats["total_calls"] == 1
            entry = stats["by_tool"][0]
            assert entry["tool"] == "slack_dangerous"
            assert entry["blocked"] == 1
            assert entry["failed"] == 0
            assert entry["outcomes"] == {"denied_allowlist": 1}
        db_mod._db = None

    async def test_denied_guard_is_audited(self, tmp_path: Any) -> None:
        """A parameter-guard rejection must leave an audit row."""
        import trentina.database as db_mod

        db_mod._db = None
        p = Profile(
            short_names=False,
            name="guarded",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "gws": Backend(
                    url="http://gws:8011/mcp",
                    tools_allow=["*"],
                    parameter_guards={
                        "send_gmail_message": {
                            "to": ParameterConstraint(allow=["self@example.com"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")

        with patch("trentina.database.get_config") as mock_cfg:
            mock_cfg.return_value.db_path = str(tmp_path / "denied_guard.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            await route_jsonrpc(
                p,
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "tools/call",
                    "params": {
                        "name": f"gws{NAMESPACE_SEP}send_gmail_message",
                        "arguments": {"to": "evil@example.com"},
                    },
                },
            )

            stats = get_gateway_call_stats("guarded", days=1)
            assert stats["by_tool"][0]["outcomes"] == {"denied_guard": 1}
            assert stats["totals"]["blocked"] == 1
        db_mod._db = None

    @pytest.mark.usefixtures("read_only_tools")
    async def test_denied_response_guard_blocks_and_skips_the_perimeter(
        self, tmp_path: Any
    ) -> None:
        """A response guard withholds the result and short-circuits transform + scan.

        Reduction can paraphrase a literal out of existence, so the guard reads
        the RAW payload and nothing downstream runs once it fires.
        """
        import trentina.database as db_mod

        db_mod._db = None
        secret = "NIGHTJAR ships on a date nobody outside may read"

        async def memory_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": f"NIGHTJAR note: {secret}"}],
                is_error=False,
                structured_content=None,
            )

        p = Profile(
            short_names=False,
            name="isolated",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "memory": Backend(
                    url="http://mcp-memory:8000/mcp",
                    tools_allow=["*"],
                    response_guards={
                        "memory_search": {
                            "content": ParameterConstraint(deny=["*NIGHTJAR*"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")

        with (
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=memory_call,
            ),
            patch("trentina.transports.mcp.transform_response") as mock_transform,
            patch("trentina.gateway.router.scan_tool_response") as mock_scan,
            patch("trentina.transports.mcp.scan_tool_response", mock_scan),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = str(tmp_path / "denied_response.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            resp = await route_jsonrpc(
                p,
                {
                    "jsonrpc": "2.0",
                    "id": 43,
                    "method": "tools/call",
                    "params": {
                        "name": f"memory{NAMESPACE_SEP}memory_search",
                        "arguments": {"query": "my employer's OS roadmap"},
                    },
                },
            )

            assert refused(resp)
            assert secret not in refused_text(resp)
            mock_transform.assert_not_called()
            mock_scan.assert_not_called()

            stats = get_gateway_call_stats("isolated", days=1)
            assert stats["by_tool"][0]["outcomes"] == {"denied_response_guard": 1}
            assert stats["totals"]["blocked"] == 1
        db_mod._db = None

    async def test_response_guard_passes_unmatched_content(self) -> None:
        """A response the guard does not match is delivered as normal."""

        async def memory_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "the Trentino route notes"}],
                is_error=False,
                structured_content=None,
            )

        p = Profile(
            short_names=False,
            name="isolated2",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "memory": Backend(
                    url="http://mcp-memory:8000/mcp",
                    tools_allow=["*"],
                    response_guards={
                        "memory_search": {
                            "content": ParameterConstraint(deny=["*NIGHTJAR*"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")

        with patch(
            "trentina.gateway.router.call_backend_tool",
            side_effect=memory_call,
        ):
            resp = await route_jsonrpc(
                p,
                {
                    "jsonrpc": "2.0",
                    "id": 44,
                    "method": "tools/call",
                    "params": {
                        "name": f"memory{NAMESPACE_SEP}memory_search",
                        "arguments": {"query": "motorcycle"},
                    },
                },
            )

        assert "error" not in resp
        assert "Trentino" in resp["result"]["content"][0]["text"]

    async def test_backend_reported_error_is_not_counted_as_ok(self, tmp_path: Any) -> None:
        """isError=True previously audited as a success, inflating the ok column."""
        import trentina.database as db_mod

        db_mod._db = None

        async def error_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "tool blew up"}],
                is_error=True,
                structured_content=None,
            )

        with (
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=error_call,
            ),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = str(tmp_path / "tool_error.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 42,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {},
                    },
                },
            )

            entry = get_gateway_call_stats("testp", days=1)["by_tool"][0]
            assert entry["ok"] == 0
            assert entry["failed"] == 1
            assert entry["outcomes"] == {"tool_error": 1}
        db_mod._db = None

    async def test_tools_call_rejects_guarded_parameter(self) -> None:
        """Parameter guard blocks a call with a forbidden argument value."""
        p = Profile(
            short_names=False,
            name="guarded",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "gws": Backend(
                    url="http://gws:8011/mcp",
                    tools_allow=["*"],
                    parameter_guards={
                        "send_gmail_message": {
                            "to": ParameterConstraint(allow=["self@example.com"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")
        resp = await route_jsonrpc(
            p,
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": f"gws{NAMESPACE_SEP}send_gmail_message",
                    "arguments": {"to": "evil@example.com"},
                },
            },
        )
        assert refused(resp)
        assert "not in allow list" in refused_text(resp)

    async def test_tools_call_allowed_guarded_parameter_passes(self) -> None:
        """Parameter guard allows a call with a permitted argument value."""
        called: dict[str, Any] = {}

        async def fake_call(
            _bn: str,
            _b: Backend,
            _tn: str,
            _args: dict[str, Any],
        ) -> BackendCall:
            called["tool"] = _tn
            return BackendCall(
                content=[{"type": "text", "text": "sent"}],
                is_error=False,
                structured_content=None,
            )

        p = Profile(
            short_names=False,
            name="guarded",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "gws": Backend(
                    url="http://gws:8011/mcp",
                    tools_allow=["*"],
                    parameter_guards={
                        "send_gmail_message": {
                            "to": ParameterConstraint(allow=["self@example.com"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")
        with patch(
            "trentina.gateway.router.call_backend_tool",
            side_effect=fake_call,
        ):
            resp = await route_jsonrpc(
                p,
                {
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": "tools/call",
                    "params": {
                        "name": f"gws{NAMESPACE_SEP}send_gmail_message",
                        "arguments": {"to": "self@example.com"},
                    },
                },
            )
        assert called["tool"] == "send_gmail_message"
        assert resp["result"]["content"] == [{"type": "text", "text": "sent"}]

    async def test_tools_list_fetches_concurrently(self) -> None:
        """Prove backends are fetched in parallel, not sequentially.

        Measures peak in-flight calls rather than wall-clock time: a shared CI
        runner stretched the old 0.30 s bound to 0.39 s with the code correct.
        Sequential fetching can never see two calls in flight, however fast or
        slow the machine.
        """
        in_flight = 0
        peak = 0

        async def slow_list(backend_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.05)
            in_flight -= 1
            return [{"name": f"{backend_name}_tool", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=slow_list,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 40, "method": "tools/list"}
            )

        names = sorted(str(t["name"]) for t in resp["result"]["tools"])
        assert f"mcp-atlassian{NAMESPACE_SEP}mcp-atlassian_tool" in names
        assert f"mcp-slack{NAMESPACE_SEP}mcp-slack_tool" in names
        assert peak == 2, f"Expected both backends in flight at once, peak was {peak}"

    async def test_tools_list_circuit_open_skips_immediately(self) -> None:
        """Circuit-open backend is skipped via real list_backend_tools code path.

        Patches _do_list_tools (transport layer) so the real list_backend_tools
        runs its circuit breaker check.  The circuit-open backend never reaches
        the transport; the healthy backend does.
        """
        slack_url = "http://mcp-slack:8000/mcp"
        for _ in range(3):
            breaker.record_failure(slack_url)

        transport_calls: list[str] = []

        class _FakeToolsResult:
            def __init__(self) -> None:
                self.tools = [_FakeTool("jira_search")]

        class _FakeTool:
            def __init__(self, name: str) -> None:
                self.name = name
                self.description = ""
                self.inputSchema: dict[str, Any] = {}

        async def fake_transport(url: str, _headers: Any, *_: Any) -> _FakeToolsResult:
            transport_calls.append(url)
            return _FakeToolsResult()

        with patch(
            "trentina.gateway.backend._do_list_tools",
            side_effect=fake_transport,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 41, "method": "tools/list"}
            )

        names = [str(t["name"]) for t in resp["result"]["tools"]]
        assert f"mcp-atlassian{NAMESPACE_SEP}jira_search" in names
        assert slack_url not in transport_calls
        assert len(transport_calls) == 1

    async def test_tools_call_circuit_open_returns_error(self) -> None:
        """A tools/call to a circuit-open backend returns a JSON-RPC error immediately."""
        slack_url = "http://mcp-slack:8000/mcp"
        for _ in range(3):
            breaker.record_failure(slack_url)

        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                    "arguments": {},
                },
            },
        )
        assert resp["error"]["code"] == -32603
        assert "circuit open" in resp["error"]["message"]


@pytest.mark.asyncio
class TestProfileToolsCache:
    """Profile-level tool list cache (Feature B) tests."""

    async def test_profile_cache_hit_skips_backend_calls(self) -> None:
        call_count = 0

        async def counting_list(
            _bn: str,
            _b: Backend,
        ) -> list[dict[str, Any]]:
            nonlocal call_count
            call_count += 1
            return [{"name": "tool_a", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=counting_list,
        ):
            await route_jsonrpc(
                _profile(),
                {"jsonrpc": "2.0", "id": 50, "method": "tools/list"},
            )
            first_count = call_count
            await route_jsonrpc(
                _profile(),
                {"jsonrpc": "2.0", "id": 51, "method": "tools/list"},
            )

        assert call_count == first_count

    async def test_profile_cache_keyed_by_name(self) -> None:
        async def fake_list(
            _bn: str,
            _b: Backend,
            *_: Any,
        ) -> list[dict[str, Any]]:
            return [{"name": "tool_a", "description": "", "inputSchema": {}}]

        p2 = Profile(
            short_names=False,
            name="other",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "mcp-slack": Backend(
                    url="http://mcp-slack:8000/mcp",
                    tools_allow=["*"],
                ),
            },
        )
        p2.auth.bearer_token = SecretStr("x")

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            await route_jsonrpc(
                _profile(),
                {"jsonrpc": "2.0", "id": 54, "method": "tools/list"},
            )
            await route_jsonrpc(
                p2,
                {"jsonrpc": "2.0", "id": 55, "method": "tools/list"},
            )

        assert "testp" in _profile_tools_cache
        assert "other" in _profile_tools_cache

    async def test_partial_aggregate_not_cached_and_self_heals(self) -> None:
        """A hard-failed backend suppresses caching so the profile self-heals.

        While a backend raises, the aggregate is returned partial but NOT
        cached, so the next tools/list re-aggregates. Once the backend recovers,
        the full list is assembled and cached.
        """
        slack_down = True

        async def flaky_list(
            backend_name: str,
            _b: Backend,
            *_: Any,
        ) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack" and slack_down:
                raise BackendCallError("simulated outage")
            return [{"name": f"{backend_name}_tool", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=flaky_list,
        ):
            resp1 = await route_jsonrpc(
                _profile(),
                {"jsonrpc": "2.0", "id": 56, "method": "tools/list"},
            )
            assert "testp" not in _profile_tools_cache
            names1 = [str(t["name"]) for t in resp1["result"]["tools"]]
            assert names1 == [f"mcp-atlassian{NAMESPACE_SEP}mcp-atlassian_tool"]

            slack_down = False
            resp2 = await route_jsonrpc(
                _profile(),
                {"jsonrpc": "2.0", "id": 57, "method": "tools/list"},
            )

        assert "testp" in _profile_tools_cache
        names2 = sorted(str(t["name"]) for t in resp2["result"]["tools"])
        assert names2 == [
            f"mcp-atlassian{NAMESPACE_SEP}mcp-atlassian_tool",
            f"mcp-slack{NAMESPACE_SEP}mcp-slack_tool",
        ]

    async def test_profile_single_flight_coalesces_concurrent_calls(self) -> None:
        """Concurrent tools/list for one profile share a single fan-out.

        Without single-flight, N concurrent calls over 2 backends would issue
        2*N backend fetches. With it, each backend is fetched exactly once.
        """
        per_backend_calls: dict[str, int] = {}
        release = asyncio.Event()

        async def slow_list(
            backend_name: str,
            _b: Backend,
            *_: Any,
        ) -> list[dict[str, Any]]:
            per_backend_calls[backend_name] = per_backend_calls.get(backend_name, 0) + 1
            await release.wait()
            return [{"name": f"{backend_name}_tool", "description": "", "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=slow_list,
        ):
            calls = [
                asyncio.ensure_future(
                    route_jsonrpc(
                        _profile(),
                        {"jsonrpc": "2.0", "id": 60 + i, "method": "tools/list"},
                    )
                )
                for i in range(4)
            ]
            await asyncio.sleep(0)
            release.set()
            responses = await asyncio.gather(*calls)

        assert per_backend_calls == {"mcp-slack": 1, "mcp-atlassian": 1}
        for resp in responses:
            names = sorted(str(t["name"]) for t in resp["result"]["tools"])
            assert names == [
                f"mcp-atlassian{NAMESPACE_SEP}mcp-atlassian_tool",
                f"mcp-slack{NAMESPACE_SEP}mcp-slack_tool",
            ]


class TestProfileContext:
    """Covers the ContextVar reset shipped untested in 4d44916."""

    def test_profile_visible_inside_block(self) -> None:
        profile = _mixed_profile()
        assert get_current_profile() is None
        with profile_context(profile):
            assert get_current_profile() is profile
        assert get_current_profile() is None

    def test_profile_reset_when_body_raises(self) -> None:
        """A failing internal tool call must not leak its profile."""
        profile = _mixed_profile()
        with pytest.raises(RuntimeError), profile_context(profile):
            raise RuntimeError("tool blew up")
        assert get_current_profile() is None

    def test_nested_contexts_restore_outer(self) -> None:
        outer = _mixed_profile()
        inner = _profile()
        with profile_context(outer):
            with profile_context(inner):
                assert get_current_profile() is inner
            assert get_current_profile() is outer
        assert get_current_profile() is None

    async def test_internal_dispatch_resets_profile_after_call(self) -> None:
        """End-to-end: routing an internal:// call leaves no residual context."""
        seen: dict[str, Any] = {}

        async def fake_internal_call(
            _tool_name: str, _arguments: dict[str, Any], **_: Any
        ) -> BackendCall:
            seen["profile_during_call"] = get_current_profile()
            return BackendCall(
                content=[{"type": "text", "text": "ok"}],
                is_error=False,
                structured_content=None,
            )

        with patch(
            "trentina.gateway.router.call_internal_tool",
            side_effect=fake_internal_call,
        ):
            await route_jsonrpc(
                _mixed_profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": f"web{NAMESPACE_SEP}block_fetch_tool",
                        "arguments": {},
                    },
                },
            )

        assert seen["profile_during_call"] is not None
        assert get_current_profile() is None


class TestOneAuditRowPerCall:
    """The row is written after assembly, so it says what the agent received.

    Until 0.40.0 a blocked response wrote ``ok`` before the perimeter ran and
    ``blocked_defense`` after it: every block was counted twice.
    """

    @staticmethod
    async def _call(
        tmp_path: Any, decision: Any, content: list[dict[str, Any]], scan: Any = None
    ) -> tuple[dict[str, Any], Any]:
        import trentina.database as db_mod

        db_mod._db = None

        async def fake_call(_bn: str, _b: Backend, _tn: str, _a: dict[str, Any]) -> BackendCall:
            return BackendCall(content=content, is_error=False, structured_content=None)

        async def fake_scan(**_kwargs: Any) -> Any:
            return decision

        with (
            patch(
                "trentina.gateway.router.call_backend_tool",
                side_effect=fake_call,
            ),
            patch(
                "trentina.gateway.router.scan_tool_response",
                side_effect=scan or fake_scan,
            ) as mock_scan,
            patch("trentina.transports.mcp.scan_tool_response", mock_scan),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = str(tmp_path / "one_row.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            if scan is not None:
                try:
                    await route_jsonrpc(
                        _profile(),
                        {
                            "jsonrpc": "2.0",
                            "id": 92,
                            "method": "tools/call",
                            "params": {
                                "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                                "arguments": {},
                            },
                        },
                    )
                finally:
                    rows = db_mod.get_db().execute("SELECT * FROM gateway_calls").fetchall()
                    db_mod._db = None
                    assert [r["outcome"] for r in rows] == ["gateway_error"]
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 90,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {},
                    },
                },
            )
            rows = db_mod.get_db().execute("SELECT * FROM gateway_calls").fetchall()
        db_mod._db = None
        return resp, rows

    async def test_a_blocked_response_writes_one_blocked_row(self, tmp_path: Any) -> None:
        decision = SimpleNamespace(
            blocked=True, warning={"risk_level": "high"}, refusal=None, extraction=None
        )
        _resp, rows = await self._call(tmp_path, decision, [{"type": "text", "text": "evil"}])

        assert [r["outcome"] for r in rows] == ["blocked_defense"]
        assert "risk=high" in rows[0]["error_message"]

    async def test_a_delivered_response_carries_both_sizes(self, tmp_path: Any) -> None:
        from trentina.gateway.surface import wire_bytes

        decision = SimpleNamespace(blocked=False, warning=None, refusal=None, extraction=None)
        content = [{"type": "text", "text": "x" * 500}]
        resp, rows = await self._call(tmp_path, decision, content)

        assert [r["outcome"] for r in rows] == ["ok"]
        assert rows[0]["bytes_arrived"] == wire_bytes(
            {"content": content, "structuredContent": None}
        )
        assert rows[0]["bytes_delivered"] == wire_bytes(resp["result"])

    async def test_an_internal_tool_has_no_arrived_size(self, tmp_path: Any) -> None:
        """It minified inside itself: what reached the router is already delivered."""
        import trentina.database as db_mod
        from trentina.gateway.surface import wire_bytes

        db_mod._db = None

        async def fake_internal(_tool: str, _args: dict[str, Any], **_: Any) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "fetched"}],
                is_error=False,
                structured_content=None,
            )

        with (
            patch(
                "trentina.gateway.router.call_internal_tool",
                side_effect=fake_internal,
            ),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = str(tmp_path / "internal.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            resp = await route_jsonrpc(
                _mixed_profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 91,
                    "method": "tools/call",
                    "params": {"name": f"web{NAMESPACE_SEP}fetch_tool", "arguments": {}},
                },
            )
            row = db_mod.get_db().execute("SELECT * FROM gateway_calls ORDER BY id DESC").fetchone()
        db_mod._db = None

        assert row["bytes_arrived"] is None
        assert row["bytes_delivered"] == wire_bytes(resp["result"])

    async def test_a_failed_assembly_is_still_audited(self, tmp_path: Any) -> None:
        async def boom(**_kwargs: Any) -> Any:
            raise RuntimeError("scanner exploded")

        with pytest.raises(RuntimeError):
            await self._call(tmp_path, None, [{"type": "text", "text": "x"}], scan=boom)

    async def test_a_minified_response_delivers_fewer_bytes(self, tmp_path: Any) -> None:
        decision = SimpleNamespace(blocked=False, warning=None, refusal=None, extraction=None)
        html = "<html><body>" + "<div><p>hello</p></div>" * 200 + "</body></html>"
        _resp, rows = await self._call(tmp_path, decision, [{"type": "text", "text": html}])

        assert rows[0]["bytes_delivered"] < rows[0]["bytes_arrived"]


class TestSurfaceRecording:
    """The surface is measured on the real tools/list build, not injected."""

    @staticmethod
    async def _list(profile: Profile) -> dict[str, Any]:
        async def fake_list(backend_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack":
                return [
                    {"name": "slack_list_channels", "description": "d" * 50, "inputSchema": {}},
                    {"name": "slack_dangerous", "description": "d" * 50, "inputSchema": {}},
                ]
            return [{"name": "jira_search", "description": "d" * 50, "inputSchema": {}}]

        with patch(
            "trentina.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            return await route_jsonrpc(profile, {"jsonrpc": "2.0", "id": 5, "method": "tools/list"})

    async def test_stages_match_the_list_served(self) -> None:
        from trentina.gateway.surface import surface_report, wire_bytes

        resp = await self._list(_profile())
        report = surface_report("testp")

        assert report is not None
        assert report["offered"]["tools"] == 3
        assert report["allowed"]["tools"] == 2  # slack_dangerous is denied
        assert report["served"]["tools"] == 2
        assert report["served"]["bytes"] == wire_bytes(resp["result"]["tools"])
        assert report["by_backend"]["mcp-slack"]["allowed"]["tools"] == 1

    async def test_invalidation_drops_the_surface(self) -> None:
        from trentina.gateway.router import invalidate_profile_cache
        from trentina.gateway.surface import surface_report

        await self._list(_profile())
        invalidate_profile_cache("testp")

        assert surface_report("testp") is None


_LUNA_SCHEMAS: dict[str, dict[str, Any]] = {
    # mcp-feed-reader under constitution mcp-server 1.5.0: IDs declare ge=1.
    "list_entries_tool": {
        "properties": {
            "feed_id": {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
            "published_after": {"type": "string", "format": "date-time"},
            "limit": {"type": "integer", "default": 50},
            "unread_only": {"type": "boolean", "default": False},
        },
    },
    "search_drive_files": {
        "properties": {"query": {"type": "string"}, "file_type": {"type": "string"}},
        "required": ["query"],
    },
    "save_output": {
        "properties": {
            "content": {"type": "string"},
            "run_id": {"type": "string"},
            "priority": {"type": "integer", "minimum": 1},
        },
        "required": ["content", "priority"],
    },
    "send_message": {
        "properties": {"to": {"type": "string"}, "cc": {"type": "string"}},
        "required": ["to"],
    },
    # mcp-podman's image_prune, the call in #335: both optionals narrow it.
    "image_prune_tool": {
        "properties": {
            "all": {"type": "boolean", "default": False},
            "filters": {"anyOf": [{"type": "object"}, {"type": "null"}]},
        },
    },
    "list_files": {
        "properties": {"kind": {"type": "string", "enum": ["doc", "sheet"]}},
    },
}
# What the backend annotated ``readOnlyHint``. The rest said nothing.
_LUNA_READ_ONLY = {"list_entries_tool", "list_files"}


class TestArgumentHygiene:
    """Schema-driven normalization (#241), replaying Kagetora's Luna calls (RT #1505)."""

    @staticmethod
    async def _call(
        tmp_path: Any,
        tool: str,
        arguments: dict[str, Any],
        backend: Backend | None = None,
        warning: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None, Any]:
        """(response, arguments the backend saw or None, the audit row)."""
        import trentina.database as db_mod
        from trentina.gateway.backend import _tool_list_cache

        db_mod._db = None
        backend = backend or Backend(url="http://luna:8000/mcp", tools_allow=["*"])
        profile = Profile(
            short_names=False,
            name="kagetora",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"luna": backend},
        )
        profile.auth.bearer_token = SecretStr("x")
        seen: list[dict[str, Any]] = []

        async def fake_call(_bn: str, _b: Backend, _tn: str, args: dict[str, Any]) -> BackendCall:
            seen.append(args)
            return BackendCall(
                content=[{"type": "text", "text": "ok"}], is_error=False, structured_content=None
            )

        async def fake_scan(**_kwargs: Any) -> Any:
            return SimpleNamespace(blocked=False, extraction=None, warning=warning)

        _tool_list_cache[backend.url] = [
            {
                "name": name,
                "inputSchema": schema,
                "annotations": {"readOnlyHint": name in _LUNA_READ_ONLY},
            }
            for name, schema in _LUNA_SCHEMAS.items()
        ]
        try:
            with (
                patch(
                    "trentina.gateway.router.call_backend_tool",
                    side_effect=fake_call,
                ),
                patch(
                    "trentina.gateway.router.scan_tool_response",
                    side_effect=fake_scan,
                ) as mock_scan,
                patch("trentina.transports.mcp.scan_tool_response", mock_scan),
                patch("trentina.database.get_config") as mock_cfg,
            ):
                mock_cfg.return_value.db_path = str(tmp_path / "hygiene.db")
                mock_cfg.return_value.ensure_db_dir = lambda: None
                resp = await route_jsonrpc(
                    profile,
                    {
                        "jsonrpc": "2.0",
                        "id": 95,
                        "method": "tools/call",
                        "params": {"name": f"luna{NAMESPACE_SEP}{tool}", "arguments": arguments},
                    },
                )
                row = (
                    db_mod.get_db()
                    .execute("SELECT * FROM gateway_calls ORDER BY id DESC")
                    .fetchone()
                )
        finally:
            _tool_list_cache.pop(backend.url, None)
            db_mod._db = None
        return resp, (seen[0] if seen else None), row

    async def test_list_entries_placeholders_are_dropped(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(
            tmp_path,
            "list_entries_tool",
            {"feed_id": 0, "published_after": "", "limit": 50, "unread_only": True},
        )

        assert seen == {"limit": 50, "unread_only": True}
        dropped = {
            "feed_id": "dropped: below minimum 1",
            "published_after": "dropped: empty",
        }
        assert resp["result"]["_trentina_warning"] == {"normalized": dropped}
        assert row["outcome"] == "ok"
        assert json.loads(row["normalized"]) == dropped

    async def test_search_drive_files_empty_type_is_dropped(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(
            tmp_path, "search_drive_files", {"query": "okrs", "file_type": ""}
        )

        assert seen == {"query": "okrs"}
        assert "result" in resp
        assert json.loads(row["normalized"]) == {"file_type": "dropped: empty"}

    async def test_save_output_empty_run_id_is_dropped(self, tmp_path: Any) -> None:
        _resp, seen, row = await self._call(
            tmp_path, "save_output", {"content": "x", "run_id": "", "priority": 1}
        )

        assert seen == {"content": "x", "priority": 1}
        assert row["outcome"] == "ok"

    async def test_normalized_joins_a_defense_warning(self, tmp_path: Any) -> None:
        resp, _seen, _row = await self._call(
            tmp_path,
            "search_drive_files",
            {"query": "q", "file_type": ""},
            warning={"risk_level": "low", "l3_truncated": True},
        )

        assert resp["result"]["_trentina_warning"] == {
            "risk_level": "low",
            "l3_truncated": True,
            "normalized": {"file_type": "dropped: empty"},
        }

    async def test_a_clean_call_carries_no_warning(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(tmp_path, "search_drive_files", {"query": "q"})

        assert seen == {"query": "q"}
        assert "_trentina_warning" not in resp["result"]
        assert row["normalized"] is None

    async def test_an_invalid_required_argument_never_reaches_the_backend(
        self, tmp_path: Any
    ) -> None:
        url = "http://luna:8000/mcp"
        breaker.reset(url)
        resp, seen, row = await self._call(tmp_path, "save_output", {"content": "x", "priority": 0})

        assert seen is None
        assert refused(resp)
        assert "priority below minimum 1" in refused_text(resp)
        assert row["outcome"] == "tool_error"
        assert breaker._get(url).consecutive_failures == 0

    async def test_a_refused_call_still_records_its_drops(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(
            tmp_path, "save_output", {"content": "x", "run_id": "", "priority": 0}
        )

        assert seen is None
        assert refused(resp)
        assert json.loads(row["normalized"]) == {"run_id": "dropped: empty"}

    @pytest.mark.parametrize(
        "arguments",
        [
            {"all": "true", "filters": '{"until": "720h"}'},
            {"all": True, "filters": '{"until": "720h"}'},
        ],
    )
    async def test_a_narrowing_argument_that_fails_refuses_the_call(
        self, tmp_path: Any, arguments: dict[str, Any]
    ) -> None:
        """Forwarded without its filter, the prune removes everything (#335)."""
        url = "http://luna:8000/mcp"
        breaker.reset(url)
        resp, seen, row = await self._call(tmp_path, "image_prune_tool", arguments)

        assert seen is None
        assert refused(resp)
        assert "filters matches no allowed form" in refused_text(resp)
        assert "720h" not in refused_text(resp)
        assert row["outcome"] == "tool_error"
        assert breaker._get(url).consecutive_failures == 0

    async def test_zero_is_a_value_to_a_tool_that_writes(self, tmp_path: Any) -> None:
        """``feed_id: 0`` is a placeholder, ``limit: 0`` is not; the schema says neither."""
        schema = {"properties": {"limit": {"type": "integer", "minimum": 1}}}
        with patch.dict(_LUNA_SCHEMAS, {"delete_entries": schema}):
            resp, seen, _row = await self._call(tmp_path, "delete_entries", {"limit": 0})

        assert seen is None
        assert "limit below minimum 1" in refused_text(resp)

    async def test_empty_optionals_on_a_writing_tool_are_still_dropped(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(
            tmp_path, "image_prune_tool", {"all": True, "filters": None}
        )

        assert seen == {"all": True}
        assert "result" in resp
        assert json.loads(row["normalized"]) == {"filters": "dropped: empty"}

    async def test_a_read_only_tool_still_drops_what_fails(self, tmp_path: Any) -> None:
        resp, seen, row = await self._call(tmp_path, "list_files", {"kind": "all"})

        assert seen == {}
        dropped = {"kind": "dropped: is not an allowed value"}
        assert resp["result"]["_trentina_warning"] == {"normalized": dropped}
        assert row["outcome"] == "ok"

    async def test_a_guard_refusal_outranks_a_schema_refusal(self, tmp_path: Any) -> None:
        guarded = Backend(
            url="http://luna:8000/mcp",
            tools_allow=["*"],
            parameter_guards={"save_output": {"priority": ParameterConstraint(deny=["0"])}},
        )

        resp, seen, row = await self._call(
            tmp_path, "save_output", {"content": "x", "priority": 0}, guarded
        )

        assert seen is None
        assert refused(resp)
        assert row["outcome"] == "denied_guard"

    async def test_guards_judge_the_forwarded_arguments(self, tmp_path: Any) -> None:
        guarded = Backend(
            url="http://luna:8000/mcp",
            tools_allow=["*"],
            parameter_guards={"send_message": {"cc": ParameterConstraint(allow=["*@ok.com"])}},
        )

        resp, seen, _row = await self._call(
            tmp_path, "send_message", {"to": "a@ok.com", "cc": ""}, guarded
        )
        assert seen == {"to": "a@ok.com"}
        assert "result" in resp

        resp, seen, row = await self._call(
            tmp_path, "send_message", {"to": "a@ok.com", "cc": "b@evil.com"}, guarded
        )
        assert seen is None
        assert row["outcome"] == "denied_guard"
