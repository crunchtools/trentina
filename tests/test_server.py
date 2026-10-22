"""Tests for MCP server registration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from trentina.modes import Mode
from trentina.server import mcp

FAMILIES = ("fetch", "read", "dir", "content", "search")


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """12: one tool per family, six that deliver no content (``tool_pins``,
        #469, is one tool with an action), and ``read_part`` (#340), which
        delivers the parts of a response another tool produced.

        The count is asserted because every tool definition sits in every
        agent's context on every call. Adding one should be a decision
        somebody made, not something that happened. It was 19 until 0.32.0,
        when the mode moved from the tool NAME to an argument (#193).
        ``backend_auth`` (#479) is one tool with an action for the same reason.
        """
        tools = await mcp.list_tools()
        assert len(tools) == 12, f"Expected 12 tools, got {len(tools)}"

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
