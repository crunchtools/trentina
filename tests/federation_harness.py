"""Two real Trentina gateways on loopback, for gateway-to-gateway federation (#592).

The thing under test is a PRIMARY gateway that mounts an SECONDARY gateway as a
backend and uses its tools. This harness stands both gateways up in the test
process and lets a client drive the primary, so what is exercised is the real
federation data path — the primary's MCP client speaking to the secondary's
``/<profile>/mcp`` route, the secondary dispatching to its own backend, and every
response crossing each gateway's perimeter — and not what a test author believes
that path does.

What is real and what is stood in:

- **Both gateways are real** ``gateway_app`` sub-apps served by uvicorn on free
  loopback ports, exactly as ``tests/git_harness.py`` serves the git route.
  ``lifespan="off"`` means warmup never runs; the first ``tools/list`` fetches
  live, as production's first list does.
- **The link is a plain MCP backend with a static bearer**, which is the interim
  federation in use today (issue #592) and needs no code change: the primary's
  ``Backend.url`` is the secondary's loopback route and the secondary's token rides
  in ``Backend.headers``. The MCP backend path skips the egress guard
  (``gateway/backend.py`` builds its own client), so a loopback URL needs no
  ``TRENTINA_FETCH_ALLOW_PRIVATE``. Later items (B1+) replace this plain backend
  with a first-class ``federated:`` block; the harness carries whatever the
  primary profile declares.
- **The secondary's tools are an in-process FastMCP** bound as the internal
  backend (``register_internal_server``, which its own docstring blesses for
  tests), so there is no leaf subprocess and a test controls exactly what the
  secondary offers and returns — including a tool that returns caller-chosen text,
  for the scan-once items (D) to push a payload across the boundary.

Profiles default to ``flag`` enforcement (``DefenseConfig.enforcement`` default),
so a benign response is delivered verbatim with no L2/L3 configured; items that
test block/redact set their own mode and stub the judge.

Two gateways in one process share Trentina's module globals (the URL-keyed
circuit breaker and tool-list cache, the profile-name-keyed name and aggregate
caches, the perimeter SQLite store). The harness keeps them legible the only way
that works: **distinct profile names and distinct ports (hence distinct backend
URLs) for the two gateways, and a separate SessionRegistry each.**

That holds the two gateways of ONE pair apart. It does not hold two pairs
apart, and `federated_pair` is a context manager a test may enter twice —
which is the only way to assert that a change to a seat changes what a peer is
served. The second pair reuses the profile NAMES, so without
`reset_profile_tools_cache` on the way in it is answered out of the first
pair's aggregate: `tools/list` returns the first pair's tool list, and a test
comparing before against after compares a list with itself. That read as a
harness that could only stand up one pair per process. It was a cache.
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
from trentina.gateway.aggregate import reset_profile_tools_cache
from trentina.gateway.app import MCP_SESSION_ID_HEADER, gateway_app
from trentina.gateway.federation_link import derive_all
from trentina.gateway.internal import register_internal_server
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile
from trentina.gateway.sessions import SessionRegistry

if TYPE_CHECKING:
    from starlette.applications import Starlette

SECONDARY_PROFILE = "secondary"
PRIMARY_PROFILE = "primary"
SECONDARY_TOKEN = "secondary-token-the-agent-never-types"
PRIMARY_TOKEN = "primary-token"
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
    """The secondary's default offered tools: enough to exercise federation.

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
    """A FastMCP whose tools the secondary's ``internal://`` backend will serve."""
    server: FastMCP = FastMCP("federation-secondary")
    for tool in default_tools() if tools is None else tools:
        server.tool()(tool)
    return server


def secondary_profile(
    *,
    name: str = SECONDARY_PROFILE,
    token: str = SECONDARY_TOKEN,
    backend_key: str = INTERNAL_KEY,
) -> Profile:
    """The secondary: a bearer-authenticated profile serving its internal tools.

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


def primary_profile(
    *,
    secondary_port: int,
    name: str = PRIMARY_PROFILE,
    token: str = PRIMARY_TOKEN,
    secondary_name: str = SECONDARY_PROFILE,
    secondary_token: str = SECONDARY_TOKEN,
    backend_key: str = FEDERATED_KEY,
) -> Profile:
    """The primary: a profile that mounts the secondary gateway as a backend.

    A first-class `federated:` block, which is what production runs. It carries
    no `primary_key`, so the link authenticates with the secondary's bearer in
    `headers` — a federated backend without a key falls back to it
    (`backend._auth_headers`) — which keeps the harness key-free while still
    being the shape the loader accepts.

    It used to be the interim arrangement: a plain MCP backend at the
    secondary's route with that bearer and no `federated:` block. Production
    refuses that shape as of 5.0.0, and a harness whose default certifies a
    refused link is a harness that tests the wrong thing. The loader never
    caught it here because these profiles are built directly and the route is
    `/<profile>/mcp` rather than `/gateway/<profile>/mcp`.
    """
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="DOWN"),
        backends={
            backend_key: Backend(
                url=f"http://127.0.0.1:{secondary_port}/{secondary_name}/mcp",
                headers={"Authorization": f"Bearer {secondary_token}"},
                federated=FederatedConfig(),
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
    remote tool behind the secondary's perimeter — this is that backend, which
    an secondary profile mounts at ``http://127.0.0.1:<port>/mcp``.
    """
    app = internal_server(tools).http_app(path="/mcp")
    async with serving(app, lifespan="auto") as port:
        yield port


@contextlib.contextmanager
def bound_internal_server(server: FastMCP) -> Iterator[FastMCP]:
    """Bind ``server`` as the internal backend for the duration, then restore.

    ``register_internal_server`` is a module-level singleton the whole process
    shares; its docstring blesses re-binding in tests. Restoring the previous
    binding keeps one test's secondary from leaking into the next.
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
    """A standing primary→secondary federation and how to drive it."""

    secondary_port: int
    primary_port: int
    secondary_name: str = SECONDARY_PROFILE
    primary_name: str = PRIMARY_PROFILE
    secondary_token: str = SECONDARY_TOKEN
    primary_token: str = PRIMARY_TOKEN
    clients: list[MCPClient] = field(default_factory=list)

    def _url(self, port: int, profile: str) -> str:
        return f"http://127.0.0.1:{port}/{profile}/mcp"

    def primary_client(self) -> MCPClient:
        """A client for the primary gateway (the federation consumer)."""
        url = self._url(self.primary_port, self.primary_name)
        client = MCPClient(url, self.primary_token)
        self.clients.append(client)
        return client

    def secondary_client(self) -> MCPClient:
        """A client for the secondary gateway directly, for comparison."""
        url = self._url(self.secondary_port, self.secondary_name)
        client = MCPClient(url, self.secondary_token)
        self.clients.append(client)
        return client


@contextlib.asynccontextmanager
async def federated_pair(
    *,
    tools: list[Callable[..., Any]] | None = None,
    secondary: Profile | None = None,
    primary: Callable[[int], Profile] | None = None,
) -> AsyncIterator[Federation]:
    """Stand an secondary gateway and a primary gateway that federates it.

    Args:
        tools: the secondary's offered tools (default: ``default_tools()``).
        secondary: override the secondary profile (default: ``secondary_profile()``).
        primary: a factory taking the secondary's port and returning the
            primary profile (default: ``primary_profile``). B1+ pass a
            factory that builds a profile with a ``federated:`` block here.

    Yields a :class:`Federation` whose ``primary_client()`` drives the
    consumer gateway.
    """
    # Profile aggregates are keyed by profile NAME and two pairs in one test
    # reuse the names, so the second pair would be answered out of the first
    # one's cache. Both ends, because a pair left standing while the next one
    # is built is the same collision from the other side. The URL-keyed backend
    # cache is deliberately left alone: a backend at the same URL in both pairs
    # is one backend, and reusing its list is what production does.
    # Profile aggregates are keyed by profile NAME and two pairs in one test
    # reuse the names, so the second pair would be answered out of the first
    # one's cache. Both ends, because a pair left standing while the next one
    # is built is the same collision from the other side. The URL-keyed backend
    # cache is deliberately left alone: a backend at the same URL in both pairs
    # is one backend, and reusing its list is what production does.
    reset_profile_tools_cache()
    up_profile = secondary or secondary_profile()
    # The secondary's registry the way `load_profiles` builds it: a SEAT
    # carrying `federation` also serves the ingress derived from it. Passing a
    # seat here is how a test exercises the shape production runs; passing an
    # already-derived ingress (one with `federation_of`) derives nothing.
    up_registry = {up_profile.name: up_profile}
    up_registry.update(derive_all(up_registry))
    with bound_internal_server(internal_server(tools)):
        up_sessions = SessionRegistry()
        up_app = gateway_app(up_registry, sessions=up_sessions)
        async with serving(up_app) as up_port:
            if primary is not None:
                down_profile = primary(up_port)
            else:
                down_profile = primary_profile(secondary_port=up_port)
            down_sessions = SessionRegistry()
            down_app = gateway_app({down_profile.name: down_profile}, sessions=down_sessions)
            async with serving(down_app) as down_port:
                fed = Federation(
                    secondary_port=up_port,
                    primary_port=down_port,
                    secondary_name=up_profile.name,
                    primary_name=down_profile.name,
                    secondary_token=up_profile.auth.bearer_token.get_secret_value()
                    if up_profile.auth and up_profile.auth.bearer_token
                    else SECONDARY_TOKEN,
                    primary_token=down_profile.auth.bearer_token.get_secret_value()
                    if down_profile.auth and down_profile.auth.bearer_token
                    else PRIMARY_TOKEN,
                )
                try:
                    yield fed
                finally:
                    for client in fed.clients:
                        await client.close()
                    reset_profile_tools_cache()
