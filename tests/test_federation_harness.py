"""H1: the two-gateway federation harness works end to end (#592).

These tests are the harness's own acceptance: a primary Trentina mounts an
secondary Trentina, lists its tools, and calls one, getting the real result back
across the boundary. Later federation items (B2/C/D/E) build their tests on
``tests/federation_harness.py``.
"""

from __future__ import annotations

import json

from tests.federation_harness import default_tools, federated_pair


async def test_primary_lists_the_secondarys_tools() -> None:
    async with federated_pair() as fed, fed.primary_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    # The secondary's echo/emit/lines reach the primary through federation.
    assert any(n.endswith("echo") for n in names), names
    assert any(n.endswith("emit") for n in names), names
    assert any(n.endswith("lines") for n in names), names


async def test_primary_calls_a_federated_tool_and_gets_the_real_result() -> None:
    async with federated_pair() as fed, fed.primary_client() as client:
        tools = await client.list_tools()
        echo = next(t["name"] for t in tools if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "hello-across-the-boundary"})
    # The payload made the full round trip: client -> primary -> secondary ->
    # internal tool -> secondary -> primary -> client, through two perimeters.
    assert "echo:hello-across-the-boundary" in json.dumps(result), result


async def test_secondary_serves_the_same_tools_directly() -> None:
    # The harness's secondary is a real gateway on its own, not a stub.
    async with federated_pair() as fed, fed.secondary_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert any(n.endswith("echo") for n in names), names


async def test_a_custom_secondary_tool_set_is_federated() -> None:
    # Later items drive the secondary's offered surface; prove that seam works.
    def only_ping() -> str:
        """A single bespoke tool."""
        return "pong"

    async with federated_pair(tools=[only_ping]) as fed, fed.primary_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert any(n.endswith("only_ping") or n == "only_ping" for n in names), names
    assert not any(n.endswith("echo") for n in names), names
    # default_tools is still importable for the common case.
    assert {t.__name__ for t in default_tools()} == {"echo", "emit", "lines"}


async def test_a_second_pair_is_not_served_the_first_pairs_tool_list() -> None:
    """The harness must stand up more than one pair per test.

    Two pairs reuse the profile NAMES, and a profile aggregate is cached by
    name, so the second pair's ``tools/list`` was answered out of the first
    one's cache. That is not a visible failure — it is the same list twice, so
    every assertion comparing a seat's offering before a change against after
    it compared a list with itself and passed. It read as a harness that could
    only stand up one pair per process; it was a cache. ``federated_pair`` now
    resets the profile aggregates on the way in and out.
    """

    def alpha_only() -> str:
        """The first pair's only tool."""
        return "first"

    def beta_only() -> str:
        """The second pair's only tool."""
        return "second"

    async with federated_pair(tools=[alpha_only]) as fed, fed.primary_client() as client:
        first = {t["name"] for t in await client.list_tools()}
    async with federated_pair(tools=[beta_only]) as fed, fed.primary_client() as client:
        second = {t["name"] for t in await client.list_tools()}

    assert any("alpha_only" in name for name in first), first
    assert any("beta_only" in name for name in second), second
    assert not any("alpha_only" in name for name in second), (
        f"the second pair was served the first pair's list: {second}"
    )
