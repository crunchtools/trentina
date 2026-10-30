"""H1: the two-gateway federation harness works end to end (#592).

These tests are the harness's own acceptance: a downstream Trentina mounts an
upstream Trentina, lists its tools, and calls one, getting the real result back
across the boundary. Later federation items (B2/C/D/E) build their tests on
``tests/federation_harness.py``.
"""

from __future__ import annotations

import json

from tests.federation_harness import default_tools, federated_pair


async def test_downstream_lists_the_upstreams_tools() -> None:
    async with federated_pair() as fed, fed.downstream_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    # The upstream's echo/emit/lines reach the downstream through federation.
    assert any(n.endswith("echo") for n in names), names
    assert any(n.endswith("emit") for n in names), names
    assert any(n.endswith("lines") for n in names), names


async def test_downstream_calls_a_federated_tool_and_gets_the_real_result() -> None:
    async with federated_pair() as fed, fed.downstream_client() as client:
        tools = await client.list_tools()
        echo = next(t["name"] for t in tools if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "hello-across-the-boundary"})
    # The payload made the full round trip: client -> downstream -> upstream ->
    # internal tool -> upstream -> downstream -> client, through two perimeters.
    assert "echo:hello-across-the-boundary" in json.dumps(result), result


async def test_upstream_serves_the_same_tools_directly() -> None:
    # The harness's upstream is a real gateway on its own, not a stub.
    async with federated_pair() as fed, fed.upstream_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert any(n.endswith("echo") for n in names), names


async def test_a_custom_upstream_tool_set_is_federated() -> None:
    # Later items drive the upstream's offered surface; prove that seam works.
    def only_ping() -> str:
        """A single bespoke tool."""
        return "pong"

    async with federated_pair(tools=[only_ping]) as fed, fed.downstream_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert any(n.endswith("only_ping") or n == "only_ping" for n in names), names
    assert not any(n.endswith("echo") for n in names), names
    # default_tools is still importable for the common case.
    assert {t.__name__ for t in default_tools()} == {"echo", "emit", "lines"}
