"""Every refused or failed tools/call writes one audit row, with the right outcome (#293).

The #87 class again: a probe the audit exists to show was refused with no row,
or filed under an outcome that hides it. Each path below drives the real
router and reads the row back.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import SecretStr

from tests.refusal_shape import refused, refused_text
from trentina.client import fetch_url
from trentina.database import get_db, issue_tool_names
from trentina.errors import QuarantineAgentError, SearchCanaryLeakedError
from trentina.gateway import internal
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.router import route_jsonrpc
from trentina.logsafe import redact_source
from trentina.transports import mcp as mcp_mod

from .egress_harness import route
from .mode_harness import layers

pytestmark = pytest.mark.usefixtures("env", "real_server")


@pytest.fixture
def real_server() -> Iterator[None]:
    from trentina.server import mcp

    saved = internal._server
    internal.register_internal_server(mcp)
    try:
        yield
    finally:
        internal._server = saved


def _profile(*, short_names: bool = False) -> Profile:
    profile = Profile(
        short_names=short_names,
        name="alpha",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={"web": Backend(url="internal://web", tools_allow=["*"])},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return profile


async def _call(profile: Profile, params: Any) -> dict[str, Any]:
    return await route_jsonrpc(
        profile, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    )


def _rows() -> list[tuple[str, str, str]]:
    rows = get_db().execute("SELECT backend, tool, outcome FROM gateway_calls").fetchall()
    return [(r["backend"], r["tool"], r["outcome"]) for r in rows]


class TestNamesThatDoNotResolve:
    """One refusal and one row for every way a name fails, and nothing saying which."""

    async def test_never_issued(self) -> None:
        resp = await _call(_profile(short_names=True), {"name": "nope", "arguments": {}})
        assert resp["error"]["message"] == "Unknown tool 'nope'"
        assert _rows() == [("", redact_source("nope"), "denied_allowlist")]

    async def test_long_form_backend_outside_the_profile(self) -> None:
        name = f"jira{NAMESPACE_SEP}delete_issue"
        resp = await _call(_profile(), {"name": name, "arguments": {}})
        assert resp["error"]["message"] == f"Unknown tool {name!r}"
        assert _rows() == [("", redact_source(name), "denied_allowlist")]

    async def test_issued_name_whose_backend_left(self) -> None:
        issue_tool_names("alpha", {"delete_issue": ("jira", "delete_issue")})
        resp = await _call(_profile(short_names=True), {"name": "delete_issue", "arguments": {}})
        assert resp["error"]["message"] == "Unknown tool 'delete_issue'"
        assert _rows() == [("", redact_source("delete_issue"), "denied_allowlist")]

    async def test_name_that_is_not_a_string(self) -> None:
        resp = await _call(_profile(), {"name": ["web", "fetch_tool"], "arguments": {}})
        assert resp["error"]["code"] == -32602
        assert _rows()[0][2] == "denied_allowlist"


class TestMalformedCalls:
    @pytest.mark.parametrize("arguments", [[1], [], "", 0, False])
    async def test_arguments_not_an_object(self, arguments: Any) -> None:
        """Falsy ones too: `or {}` used to turn `[]` into a well-formed call."""
        name = f"web{NAMESPACE_SEP}fetch_tool"
        resp = await _call(_profile(), {"name": name, "arguments": arguments})
        assert resp["error"] == {"code": -32602, "message": "arguments must be an object"}
        assert _rows() == [("web", "fetch_tool", "denied_guard")]

    @pytest.mark.parametrize("params", [["web__fetch_tool"], [], "", 0])
    async def test_params_not_an_object(self, params: Any) -> None:
        resp = await _call(_profile(), params)
        assert resp["error"] == {"code": -32602, "message": "params must be an object"}
        assert _rows() == [("", "", "denied_guard")]

    async def test_params_not_an_object_elsewhere_is_refused_unaudited(self) -> None:
        resp = await route_jsonrpc(
            _profile(), {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [1]}
        )
        assert resp["error"]["code"] == -32602
        assert _rows() == []


class TestCatchAll:
    async def test_an_escaped_exception_is_a_gateway_error_row(self) -> None:
        # ``resolve_call`` runs on the orchestrated request edge
        # (``transports.mcp`` parse); a bug there escapes every audited path and
        # lands in ``_route_tools_call``'s outer except as the one gateway_error row.
        with (
            patch("trentina.transports.mcp.resolve_call", side_effect=RuntimeError("bug")),
            pytest.raises(RuntimeError),
        ):
            await _call(_profile(), {"name": f"web{NAMESPACE_SEP}fetch_tool", "arguments": {}})
        assert _rows() == [("", redact_source(f"web{NAMESPACE_SEP}fetch_tool"), "gateway_error")]

    async def test_a_cancelled_call_is_a_cancelled_row(self) -> None:
        with (
            patch("trentina.transports.mcp.resolve_call", side_effect=asyncio.CancelledError),
            pytest.raises(asyncio.CancelledError),
        ):
            await _call(_profile(), {"name": f"web{NAMESPACE_SEP}fetch_tool", "arguments": {}})
        assert _rows() == [("", redact_source(f"web{NAMESPACE_SEP}fetch_tool"), "cancelled")]

    async def test_a_path_that_audited_before_raising_is_not_counted_twice(self) -> None:
        # Dispatch returns, then assembly raises: the response edge's
        # ``McpServerFace._assemble`` is the orchestrated equivalent of the old
        # ``router._assemble_call_result``. Its failure is audited gateway_error
        # by ``audit._audit_assembly_failure`` (deliver's except), which sets the
        # audited flag so the outer except does not count it a second time.
        with (
            patch.object(
                mcp_mod,
                "_dispatch",
                return_value=SimpleNamespace(content=[], structured_content=None, is_error=False),
            ),
            patch(
                "trentina.transports.mcp.McpServerFace._assemble",
                side_effect=RuntimeError("bug"),
            ),
            pytest.raises(RuntimeError),
        ):
            await _call(
                _profile(),
                {"name": f"web{NAMESPACE_SEP}content_tool", "arguments": {"content": "x"}},
            )
        assert _rows() == [("web", "content_tool", "gateway_error")]


class TestFetchAdvisory:
    async def test_415_audits_blocked_defense(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        route(monkeypatch, lambda _r: httpx.Response(415, text="use curl instead"))
        with (
            layers(tmp_path) as fakes,
            patch("trentina.tools.fetch.emit_request_event") as emitted,
        ):
            fakes.fetch_url.side_effect = fetch_url  # the real fetch, over the mock transport
            resp = await _call(
                _profile(),
                {
                    "name": f"web{NAMESPACE_SEP}fetch_tool",
                    "arguments": {"url": "https://x.example/"},
                },
            )
        data = refused(resp)
        assert data["reason"] == "security advisory (suspicious_http_415)"
        assert data["security_advisory"]["pattern"] == "suspicious_http_415"
        assert data["alternatives"] == []
        assert "curl" in refused_text(resp), "the text says what not to do, too"
        assert _rows() == [("web", "fetch_tool", "blocked_defense")]
        emitted.assert_called_once()
        assert emitted.call_args.kwargs["disposition"] == "refused"
        assert emitted.call_args.kwargs["source"] == "https://x.example/"


class TestSearchFailures:
    async def test_provider_outage_is_a_backend_error(self, tmp_path: Path) -> None:
        with layers(tmp_path) as fakes:
            fakes.search_grounded.side_effect = QuarantineAgentError(
                "connect to http://ollama.internal:11434 failed"
            )
            resp = await _call(
                _profile(),
                {"name": f"web{NAMESPACE_SEP}search_tool", "arguments": {"query": "q"}},
            )
        assert "ollama.internal" not in str(resp)
        assert "data" not in resp["error"], "an outage is not a refusal"
        assert _rows() == [("web", "search_tool", "backend_error")]

    async def test_l0_canary_leak_is_a_refusal(self, tmp_path: Path) -> None:
        with layers(tmp_path) as fakes:
            fakes.search_grounded.side_effect = SearchCanaryLeakedError()
            resp = await _call(
                _profile(),
                {"name": f"web{NAMESPACE_SEP}search_tool", "arguments": {"query": "q"}},
            )
        assert refused(resp)["flagged_by"] == "l0"
        assert _rows() == [("web", "search_tool", "blocked_defense")]
