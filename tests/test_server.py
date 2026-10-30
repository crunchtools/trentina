"""Tests for MCP server registration."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.tools import ToolResult

from trentina.modes import Mode
from trentina.server import mcp

FAMILIES = ("fetch", "read", "dir", "content", "search")


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """13: one tool per family, seven that deliver no content (``tool_pins``,
        #469, is one tool with an action, and ``audit_verify``, #472, is
        operator-only), and ``read_part`` (#340), which
        delivers the parts of a response another tool produced.

        The count is asserted because every tool definition sits in every
        agent's context on every call. Adding one should be a decision
        somebody made, not something that happened. It was 19 until 0.32.0,
        when the mode moved from the tool NAME to an argument (#193).
        ``backend_auth`` (#479) is one tool with an action for the same reason.
        """
        tools = await mcp.list_tools()
        assert len(tools) == 13, f"Expected 13 tools, got {len(tools)}"

    async def test_every_family_takes_a_mode(self) -> None:
        """The mode is an argument the policy checks, not a name the agent picks."""
        tools = {t.name: t for t in await mcp.list_tools()}
        for family in FAMILIES:
            props = tools[f"{family}_tool"].parameters["properties"]
            assert "trentina_mode" in props, family
            assert "trentina_prompt" not in props, family  # removed in 0.43.0
            assert "trentina_mode" not in tools[f"{family}_tool"].parameters.get("required", [])

    async def test_expected_tools_registered(self) -> None:
        """Nothing delivers content except a family tool (#187, #193) and
        ``read_part``, which delivers what the router judged (#340)."""
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        families = {f"{family}_tool" for family in FAMILIES}
        admin = {
            "quarantine_stats_tool",
            "cache_flush_tool",
            "reconnect_backend_tool",
            "reload_profiles_tool",
            "backend_auth_tool",
            "tool_pins_tool",
            "audit_verify_tool",
        }
        assert tool_names == families | admin | {"read_part_tool"}

    async def test_read_part_holds_nothing_without_a_gateway(self) -> None:
        """Behind the gateway the router answers it; standalone nothing is paged."""
        from trentina.server import read_part_tool

        answer = await read_part_tool(handle="0" * 32, part=2)
        assert answer["held"] == []

    def test_server_name(self) -> None:
        assert mcp.name == "trentina"


FAMILY_CALLS = [
    ("fetch_tool", "fetch_page", {"url": "https://example.com"}),
    ("read_tool", "read_file", {"path": "/tmp/x"}),
    ("dir_tool", "list_dir", {"path": "/tmp"}),
    ("content_tool", "judge_content", {"content": "x"}),
    ("search_tool", "web_search", {"query": "x"}),
]


async def test_the_dict_form_is_declared_and_strict() -> None:
    """0.39.0: {"redact": "<question>"} is a model with no other keys."""
    tools = {t.name: t for t in await mcp.list_tools()}
    schema = tools["fetch_tool"].parameters
    shapes = schema["properties"]["trentina_mode"]["anyOf"]
    model = next(s for s in shapes if s.get("type") == "object")
    assert model["required"] == ["redact"]
    assert model["additionalProperties"] is False


@pytest.mark.parametrize(("tool", "family", "args"), FAMILY_CALLS)
async def test_every_family_extracts_what_the_dict_form_asks(
    tool: str, family: str, args: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRENTINA_MODES", "block,redact")
    from trentina import config as config_mod

    config_mod._config = None
    fake = AsyncMock(return_value={"content": "ok"})
    with patch(f"trentina.server.{family}", fake):
        await mcp.call_tool(tool, {**args, "trentina_mode": {"redact": "What ships?"}})
    config_mod._config = None
    call = fake.call_args
    assert Mode.REDACT in (*call.args, *call.kwargs.values())
    assert "What ships?" in (*call.args, *call.kwargs.values())


# (tool name, patched underlying fn, call kwargs) for all five wrapped tools.
_STANDALONE_TOOLS = [
    ("fetch_tool", "fetch_page", {"url": "https://example.com"}),
    ("read_tool", "read_file", {"path": "/tmp/x"}),
    ("dir_tool", "list_dir", {"path": "/tmp"}),
    ("content_tool", "judge_content", {"content": "x"}),
    ("search_tool", "web_search", {"query": "x"}),
]


def _bound_profile() -> Any:
    """A profile to bind so ``_delivered`` sees the gateway dispatch path."""
    from pydantic import SecretStr

    from trentina.gateway.profile import AuthConfig, Profile

    p = Profile(name="p", auth=AuthConfig(bearer_token_env="TEST"), backends={})
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


class TestStandaloneRefusalsAreResults:
    """#550: a standalone tool returns a policy REFUSAL as an ordinary result
    (``isError`` false), not a raised exception, so a stock agent's strike
    breaker does not count the refusal against the server. A genuine failure
    (a timeout, a provider error) still raises, and behind a gateway (a profile
    bound) the exception is re-raised so the gateway shapes and audits it.
    """

    @pytest.mark.parametrize(("tool", "fn", "kwargs"), _STANDALONE_TOOLS)
    async def test_a_blocked_source_is_a_result_for_every_tool(
        self, tool: str, fn: str, kwargs: dict[str, str]
    ) -> None:
        from trentina import server
        from trentina.errors import BlockedSourceError

        refusal = {"reason": "on the blocklist", "alternatives": []}
        with patch(
            f"trentina.server.{fn}",
            AsyncMock(side_effect=BlockedSourceError("src", "on the blocklist", refusal=refusal)),
        ):
            result = await getattr(server, tool)(**kwargs)
        assert isinstance(result, ToolResult)
        assert result.is_error is False
        assert result.structured_content == {"_trentina_refusal": refusal}
        assert "[TRENTINA] Refused" in result.content[0].text

    async def test_a_file_read_refusal_is_a_result(self) -> None:
        from trentina.errors import FileReadError
        from trentina.server import read_tool

        with patch("trentina.server.read_file", AsyncMock(side_effect=FileReadError("binary"))):
            result = await read_tool(path="/tmp/x")
        assert isinstance(result, ToolResult)
        assert result.is_error is False
        assert result.structured_content == {
            "_trentina_refusal": {"reason": "binary", "alternatives": []}
        }

    async def test_an_egress_refusal_is_a_result(self) -> None:
        from trentina.errors import EgressRefusedError
        from trentina.server import fetch_tool

        with patch(
            "trentina.server.fetch_page",
            AsyncMock(side_effect=EgressRefusedError("non_global_address")),
        ):
            result = await fetch_tool(url="https://example.com")
        assert isinstance(result, ToolResult)
        assert result.is_error is False
        assert result.structured_content == {
            "_trentina_refusal": {"reason": "non_global_address", "alternatives": []}
        }

    @pytest.mark.parametrize(("tool", "fn", "kwargs"), _STANDALONE_TOOLS)
    async def test_a_bound_profile_re_raises_the_refusal(
        self, tool: str, fn: str, kwargs: dict[str, str]
    ) -> None:
        """Behind a gateway a profile is bound; the tool must still RAISE so the
        internal backend shapes the refusal and audits it blocked_defense."""
        from trentina import server
        from trentina.errors import BlockedSourceError
        from trentina.gateway.context import profile_context

        refusal = {"reason": "on the blocklist", "alternatives": []}
        with (
            patch(
                f"trentina.server.{fn}",
                AsyncMock(
                    side_effect=BlockedSourceError("src", "on the blocklist", refusal=refusal)
                ),
            ),
            profile_context(_bound_profile()),
            pytest.raises(BlockedSourceError),
        ):
            await getattr(server, tool)(**kwargs)

    async def test_a_genuine_failure_still_raises(self) -> None:
        from trentina.server import fetch_tool

        with (
            patch("trentina.server.fetch_page", AsyncMock(side_effect=TimeoutError("slow"))),
            pytest.raises(TimeoutError),
        ):
            await fetch_tool(url="https://example.com")

    async def test_a_clean_result_passes_through_unchanged(self) -> None:
        from trentina.server import fetch_tool

        with patch("trentina.server.fetch_page", AsyncMock(return_value={"content": "ok"})):
            result = await fetch_tool(url="https://example.com")
        assert result == {"content": "ok"}
