"""Two real Trentina gateways on loopback, for gateway-to-gateway federation (#592).

The thing under test is a DOWNSTREAM gateway that mounts an UPSTREAM gateway as a
backend and uses its tools. This harness stands both gateways up in the test
process and lets a client drive the downstream, so what is exercised is the real
federation data path — the downstream's MCP client speaking to the upstream's
``/<profile>/mcp`` route, the upstream dispatching to its own backend, and every
response crossing each gateway's perimeter — and not what a test author believes
that path does.

What is real and what is stood in:

- **Both gateways are real** ``gateway_app`` sub-apps served by uvicorn on free
  loopback ports, exactly as ``tests/git_harness.py`` serves the git route.
  ``lifespan="off"`` means warmup never runs; the first ``tools/list`` fetches
  live, as production's first list does.
- **The link is a plain MCP backend with a static bearer**, which is the interim
  federation in use today (issue #592) and needs no code change: the downstream's
  ``Backend.url`` is the upstream's loopback route and the upstream's token rides
  in ``Backend.headers``. The MCP backend path skips the egress guard
  (``gateway/backend.py`` builds its own client), so a loopback URL needs no
  ``TRENTINA_FETCH_ALLOW_PRIVATE``. Later items (B1+) replace this plain backend
  with a first-class ``federated:`` block; the harness carries whatever the
  downstream profile declares.
- **The upstream's tools are an in-process FastMCP** bound as the internal
  backend (``register_internal_server``, which its own docstring blesses for
  tests), so there is no leaf subprocess and a test controls exactly what the
  upstream offers and returns — including a tool that returns caller-chosen text,
  for the scan-once items (D) to push a payload across the boundary.

Profiles default to ``flag`` enforcement (``DefenseConfig.enforcement`` default),
so a benign response is delivered verbatim with no L2/L3 configured; items that
test block/redact set their own mode and stub the judge.

Two gateways in one process share Trentina's module globals (the URL-keyed
circuit breaker and tool-list cache, the profile-name-keyed name and aggregate
caches, the perimeter SQLite store). The harness keeps them legible the only way
that works: **distinct profile names and distinct ports (hence distinct backend
URLs) for the two gateways, and a separate SessionRegistry each.**
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
import uvicorn
from fastmcp import FastMCP
from mcp_types.version import LATEST_HANDSHAKE_VERSION
from pydantic import SecretStr

from trentina.gateway import internal
from trentina.gateway.app import MCP_SESSION_ID_HEADER, gateway_app
from trentina.gateway.internal import register_internal_server
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.sessions import SessionRegistry

if TYPE_CHECKING:
    from starlette.applications import Starlette

UPSTREAM_PROFILE = "upstream"
DOWNSTREAM_PROFILE = "downstream"
UPSTREAM_TOKEN = "upstream-token-the-agent-never-types"
DOWNSTREAM_TOKEN = "downstream-token"
INTERNAL_KEY = "up"
FEDERATED_KEY = "fed"

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def default_tools() -> list[Callable[..., Any]]:
    """The upstream's default offered tools: enough to exercise federation.

    ``echo`` and ``emit`` return caller-chosen text, so a federation test — and
    later a scan-once test — can push a known string (or an injection payload)
    across the boundary and see it arrive. ``lines`` returns a large body, for
    the paging item (B2).
    """

    def echo(text: str) -> str:
        """Echo the supplied text back to the caller."""
        return f"echo:{text}"

    def emit(text: str) -> str:
        """Return the supplied text verbatim."""
        return text

    def lines(count: int) -> str:
        """Return ``count`` numbered lines, for exercising large responses."""
        return "\n".join(f"line {i}" for i in range(count))

    return [echo, emit, lines]


def internal_server(tools: list[Callable[..., Any]] | None = None) -> FastMCP:
    """A FastMCP whose tools the upstream's ``internal://`` backend will serve."""
    server: FastMCP = FastMCP("federation-upstream")
    for tool in default_tools() if tools is None else tools:
        server.tool()(tool)
    return server


def upstream_profile(
    *,
    name: str = UPSTREAM_PROFILE,
    token: str = UPSTREAM_TOKEN,
    backend_key: str = INTERNAL_KEY,
) -> Profile:
    """The upstream: a bearer-authenticated profile serving its internal tools.

    Modelled on an agent seat, which is what a federation profile is (#592):
    later items narrow its ``tools_allow`` and declare its trust posture.
    """
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="UP"),
        backends={backend_key: Backend(url="internal://web")},
    )
    profile.auth.bearer_token = SecretStr(token)
    return profile


def downstream_profile(
    *,
    upstream_port: int,
    name: str = DOWNSTREAM_PROFILE,
    token: str = DOWNSTREAM_TOKEN,
    upstream_name: str = UPSTREAM_PROFILE,
    upstream_token: str = UPSTREAM_TOKEN,
    backend_key: str = FEDERATED_KEY,
) -> Profile:
    """The downstream: a profile that mounts the upstream gateway as a backend.

    The interim federation (#592): a plain MCP backend at the upstream's route
    with the upstream's bearer in ``headers``. B1 replaces this with a
    ``federated:`` block; pass a different profile to the harness to exercise it.
    """
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="DOWN"),
        backends={
            backend_key: Backend(
                url=f"http://127.0.0.1:{upstream_port}/{upstream_name}/mcp",
                headers={"Authorization": f"Bearer {upstream_token}"},
            )
        },
    )
    profile.auth.bearer_token = SecretStr(token)
    return profile


@contextlib.asynccontextmanager
async def serving(app: Starlette, *, lifespan: str = "off") -> AsyncIterator[int]:
    """Serve ``app`` with uvicorn on a free loopback port; yield the port.

    ``lifespan="off"`` keeps a gateway's warmup from running, and
    ``log_config=None`` leaves the process's uvicorn loggers as the log-hygiene
    tests expect them — the same choices ``tests/git_harness.py`` makes. A
    FastMCP backend served here needs ``lifespan="auto"``: its session manager
    starts in the app's lifespan.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    config = uvicorn.Config(app, log_config=None, lifespan=lifespan)
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        yield port
    finally:
        server.should_exit = True
        await task
        listener.close()


@contextlib.asynccontextmanager
async def serving_mcp_backend(
    tools: list[Callable[..., Any]] | None = None,
) -> AsyncIterator[int]:
    """Serve demo tools as a REAL remote MCP backend over loopback (#592, C2).

    A federation ingress offers its own REMOTE backends to a peer, never the
    gateway's internal surface (that is the directed edge: a peer reaches
    nothing of the gateway but a paging continuation). So a federated tool is a
    remote tool behind the upstream's perimeter — this is that backend, which
    an upstream profile mounts at ``http://127.0.0.1:<port>/mcp``.
    """
    app = internal_server(tools).http_app(path="/mcp")
    async with serving(app, lifespan="auto") as port:
        yield port


@contextlib.contextmanager
def bound_internal_server(server: FastMCP) -> Iterator[FastMCP]:
    """Bind ``server`` as the internal backend for the duration, then restore.

    ``register_internal_server`` is a module-level singleton the whole process
    shares; its docstring blesses re-binding in tests. Restoring the previous
    binding keeps one test's upstream from leaking into the next.
    """
    previous = internal._server
    register_internal_server(server)
    try:
        yield server
    finally:
        internal._server = previous


class MCPClient:
    """A minimal async MCP-over-HTTP client for driving a gateway on loopback.

    Speaks Streamable HTTP JSON-RPC directly (there is no in-process client
    helper in the tree), parsing either a JSON or an SSE reply, and carries the
    session id the gateway hands back on ``initialize``.
    """

    def __init__(self, base_url: str, token: str) -> None:
        self._base = base_url
        self._headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token}"}
        self._client = httpx.AsyncClient(timeout=30.0)
        self.session_id: str | None = None
        self._closed = False

    async def __aenter__(self) -> MCPClient:
        await self.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        headers = dict(self._headers)
        if self.session_id is not None:
            headers[MCP_SESSION_ID_HEADER] = self.session_id
        resp = await self._client.post(self._base, json=body, headers=headers)
        if self.session_id is None:
            self.session_id = resp.headers.get(MCP_SESSION_ID_HEADER)
        resp.raise_for_status()
        # Streamable HTTP may answer a POST as JSON or as SSE; when it is an
        # event stream the JSON-RPC body is the first `data:` frame.
        if resp.headers.get("content-type", "").startswith("text/event-stream"):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    return dict(json.loads(line[len("data:") :].strip()))
            raise AssertionError(f"no data frame in SSE response: {resp.text!r}")
        return dict(resp.json())

    async def initialize(self) -> dict[str, Any]:
        reply = await self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LATEST_HANDSHAKE_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "federation-harness", "version": "0"},
                },
            }
        )
        return dict(reply.get("result", {}))

    async def list_tools(self) -> list[dict[str, Any]]:
        reply = await self._post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return list(reply.get("result", {}).get("tools", []))

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        reply = await self._post(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        return dict(reply.get("result", reply))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.session_id is not None:
            with contextlib.suppress(httpx.HTTPError):
                await self._client.request(
                    "DELETE",
                    self._base,
                    headers={**self._headers, MCP_SESSION_ID_HEADER: self.session_id},
                )
        await self._client.aclose()


@dataclass
class Federation:
    """A standing downstream→upstream federation and how to drive it."""

    upstream_port: int
    downstream_port: int
    upstream_name: str = UPSTREAM_PROFILE
    downstream_name: str = DOWNSTREAM_PROFILE
    upstream_token: str = UPSTREAM_TOKEN
    downstream_token: str = DOWNSTREAM_TOKEN
    clients: list[MCPClient] = field(default_factory=list)

    def _url(self, port: int, profile: str) -> str:
        return f"http://127.0.0.1:{port}/{profile}/mcp"

    def downstream_client(self) -> MCPClient:
        """A client for the downstream gateway (the federation consumer)."""
        url = self._url(self.downstream_port, self.downstream_name)
        client = MCPClient(url, self.downstream_token)
        self.clients.append(client)
        return client

    def upstream_client(self) -> MCPClient:
        """A client for the upstream gateway directly, for comparison."""
        url = self._url(self.upstream_port, self.upstream_name)
        client = MCPClient(url, self.upstream_token)
        self.clients.append(client)
        return client


@contextlib.asynccontextmanager
async def federated_pair(
    *,
    tools: list[Callable[..., Any]] | None = None,
    upstream: Profile | None = None,
    downstream: Callable[[int], Profile] | None = None,
) -> AsyncIterator[Federation]:
    """Stand an upstream gateway and a downstream gateway that federates it.

    Args:
        tools: the upstream's offered tools (default: ``default_tools()``).
        upstream: override the upstream profile (default: ``upstream_profile()``).
        downstream: a factory taking the upstream's port and returning the
            downstream profile (default: ``downstream_profile``). B1+ pass a
            factory that builds a profile with a ``federated:`` block here.

    Yields a :class:`Federation` whose ``downstream_client()`` drives the
    consumer gateway.
    """
    up_profile = upstream or upstream_profile()
    with bound_internal_server(internal_server(tools)):
        up_sessions = SessionRegistry()
        up_app = gateway_app({up_profile.name: up_profile}, sessions=up_sessions)
        async with serving(up_app) as up_port:
            if downstream is not None:
                down_profile = downstream(up_port)
            else:
                down_profile = downstream_profile(upstream_port=up_port)
            down_sessions = SessionRegistry()
            down_app = gateway_app({down_profile.name: down_profile}, sessions=down_sessions)
            async with serving(down_app) as down_port:
                fed = Federation(
                    upstream_port=up_port,
                    downstream_port=down_port,
                    upstream_name=up_profile.name,
                    downstream_name=down_profile.name,
                    upstream_token=up_profile.auth.bearer_token.get_secret_value()
                    if up_profile.auth and up_profile.auth.bearer_token
                    else UPSTREAM_TOKEN,
                    downstream_token=down_profile.auth.bearer_token.get_secret_value()
                    if down_profile.auth and down_profile.auth.bearer_token
                    else DOWNSTREAM_TOKEN,
                )
                try:
                    yield fed
                finally:
                    for client in fed.clients:
                        await client.close()
