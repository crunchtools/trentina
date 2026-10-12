"""A real forge and a real gateway on loopback, for the git transport (#453).

The forge is ``git http-backend``, the program a git server runs, behind a
few lines of CGI. The gateway is the route under test in a Starlette app.
Both are served by uvicorn on real sockets, and the client is the ``git``
binary, so what is tested is what git sends and expects, protocol v0 and v2,
gzip and chunked bodies included, and not what a test author believes it
sends.

The one seam is ``egress.PinnedTransport``: the route asks for
``https://git.example.com`` and the transport here carries that request to
the forge's loopback port. Everything before it (the address check, the
pin) and everything after it (real HTTP on a real socket) is the code that
runs in production.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import uvicorn
from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route

from trentina.gateway import git_transport
from trentina.gateway.profile import AuthConfig, GitGrant, GitRemote, Profile

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Sequence

    from starlette.requests import Request

FORGE_HOST = "git.example.com"
REMOTE = "forge"
GATEWAY_TOKEN = "gateway-token-for-agent1"
FORGE_TOKEN = "forge-token-the-agent-never-sees"

_BACKENDS = ("/usr/lib/git-core/git-http-backend", "/usr/libexec/git-core/git-http-backend")


def http_backend() -> str | None:
    """Where ``git http-backend`` is installed, or None."""
    git_binary = shutil.which("git")
    if git_binary is None:
        return None
    exec_path = subprocess.run(
        [git_binary, "--exec-path"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    for candidate in (f"{exec_path}/git-http-backend", *_BACKENDS):
        if Path(candidate).is_file():
            return candidate
    return None


def git_env(home: Path) -> dict[str, str]:
    """An environment in which git reads no configuration but its own flags."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }


def git_sync(home: Path, *args: str, cwd: Path | None = None) -> str:
    """Run git to completion, for building fixtures. Raises on failure."""
    done = subprocess.run(
        [shutil.which("git") or "git", *args],
        cwd=cwd,
        env=git_env(home),
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def profile(
    fetch: Sequence[str] = ("acme/*",),
    push: Sequence[str] = ("acme/widgets",),
    push_refs: Sequence[str] = ("refs/heads/agent/*",),
    deny: Sequence[str] = ("*-private",),
) -> Profile:
    """A profile whose bearer is ``GATEWAY_TOKEN`` and whose grant is on ``REMOTE``."""
    grant = GitGrant(
        token_env="FORGE_TOKEN",
        fetch=list(fetch),
        push=list(push),
        push_refs=list(push_refs),
        deny=list(deny),
    )
    grant.token = SecretStr(FORGE_TOKEN)
    auth = AuthConfig(bearer_token_env="TOK")
    auth.bearer_token = SecretStr(GATEWAY_TOKEN)
    return Profile(name="agent1", auth=auth, git={REMOTE: grant})


def remotes() -> dict[str, GitRemote]:
    return {REMOTE: GitRemote(upstream=f"https://{FORGE_HOST}")}


@dataclass
class Forge:
    """``git http-backend`` over HTTP, and a record of what reached it."""

    root: Path
    backend: str
    port: int = 0
    requests: list[dict[str, str]] = field(default_factory=list)
    bodies: list[int] = field(default_factory=list)

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/{path:path}", self.handle, methods=["GET", "POST"])])

    async def handle(self, request: Request) -> Response:
        self.requests.append({k.lower(): v for k, v in request.headers.items()})
        body = await request.body()
        self.bodies.append(len(body))
        env = {
            "GIT_PROJECT_ROOT": str(self.root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": request.method,
            "PATH_INFO": request.url.path,
            "QUERY_STRING": request.url.query,
            "CONTENT_TYPE": request.headers.get("content-type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_USER": "forge",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        if "git-protocol" in request.headers:
            env["GIT_PROTOCOL"] = request.headers["git-protocol"]
        process = await asyncio.create_subprocess_exec(
            self.backend,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        output, _ = await process.communicate(body)
        head, _, payload = output.partition(b"\r\n\r\n")
        headers = dict(line.split(": ", 1) for line in head.decode("latin-1").split("\r\n") if line)
        status = int(headers.pop("Status", "200").split(" ")[0])
        return Response(payload, status_code=status, headers=headers)


def pkt(payload: bytes) -> bytes:
    """One data pkt-line carrying ``payload``."""
    return f"{len(payload) + 4:04x}".encode() + payload


FLUSH = b"0000"
DELIMITER = b"0001"
ZERO = b"0" * 40
ONE = b"1" * 40
TWO = b"2" * 40


def push_body(*commands: tuple[bytes, bytes, str], capabilities: str = "report-status") -> bytes:
    """A receive-pack command list, as git writes one: capabilities on the first line."""
    lines = [b" ".join((old, new, ref.encode())) for old, new, ref in commands]
    if lines:
        lines[0] += b"\0" + capabilities.encode()
    return b"".join(pkt(line + b"\n") for line in lines) + FLUSH


@dataclass
class Scripted:
    """A forge that answers what a test tells it to, and records what reached it.

    By default it reads the whole request and answers ``200`` with ``body``
    under the content type the request asked for. A test that needs to watch
    a stream replaces ``answer``.
    """

    body: bytes = FLUSH
    status: int = 200
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    requests: list[dict[str, str]] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    bodies: list[bytes] = field(default_factory=list)
    answer: Callable[[Request], Awaitable[Response]] | None = None

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/{path:path}", self.handle, methods=["GET", "POST"])])

    async def handle(self, request: Request) -> Response:
        self.requests.append({k.lower(): v for k, v in request.headers.items()})
        query = f"?{request.url.query}" if request.url.query else ""
        self.targets.append(f"{request.method} {request.url.path}{query}")
        if self.answer is not None:
            return await self.answer(request)
        self.bodies.append(await request.body())
        content_type = self.content_type or request.headers.get("accept", "text/plain")
        return Response(
            self.body,
            status_code=self.status,
            headers={"Content-Type": content_type, **self.headers},
        )


class ToForge(httpx.AsyncBaseTransport):
    """Carries a request for ``https://FORGE_HOST`` to a loopback port over
    plain HTTP. Stands in for ``egress.PinnedTransport`` and for nothing else."""

    def __init__(self, port: int) -> None:
        self._port = port
        self._inner = httpx.AsyncHTTPTransport()
        self.hosts: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.hosts.append(f"{request.url.scheme}://{request.url.host}")
        request.url = request.url.copy_with(scheme="http", host="127.0.0.1", port=self._port)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


@contextlib.asynccontextmanager
async def serving(app: Starlette) -> AsyncIterator[int]:
    """Serve ``app`` with uvicorn on a free loopback port; yields the port."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    # log_config=None and nothing else about logging: uvicorn's defaults
    # (and access_log=False) rewrite the process's uvicorn loggers, and the
    # log-hygiene tests read those.
    config = uvicorn.Config(app, log_config=None, lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[listener]))
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        yield port
    finally:
        server.should_exit = True
        await task
        listener.close()


def gateway_app(profiles: dict[str, Profile]) -> Starlette:
    """The route under test, as ``register_git_routes`` wires it."""

    async def endpoint(request: Request) -> Response:
        return await git_transport.serve(request, profiles)

    return Starlette(routes=[Route(git_transport.ROUTE, endpoint, methods=git_transport.METHODS)])


async def raw_request(port: int, head: str, body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    """Send one request exactly as written, with no client to tidy its path.

    Args:
        port: the gateway's port.
        head: the request line and headers, without the final blank line.
            ``Connection: close`` and the bearer token are added.
        body: sent after the head, with its ``Content-Length``.

    Returns:
        The status, the response headers lower-cased, and the body.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [
        head,
        "Host: gateway",
        f"Authorization: Bearer {GATEWAY_TOKEN}",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    writer.write("\r\n".join(lines).encode() + b"\r\n\r\n" + body)
    await writer.drain()
    answer = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    top, _, payload = answer.partition(b"\r\n\r\n")
    status_line, *header_lines = top.decode("latin-1").split("\r\n")
    headers = dict(line.lower().split(": ", 1) for line in header_lines)
    return int(status_line.split(" ")[1]), headers, payload


async def git(home: Path, port: int, *args: str, cwd: Path | None = None) -> tuple[int, str]:
    """Run git against the gateway on ``port``, as ``agent1``.

    The bearer token reaches git the way ``docs/git-transport.md`` says to
    give it one: through ``GIT_CONFIG_*`` in the environment, scoped to the
    route's URL, and never written to a configuration file.

    Returns:
        Its exit status and everything it printed.
    """
    base = f"http://127.0.0.1:{port}/git/"
    env = {
        **git_env(home),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.{base}.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {GATEWAY_TOKEN}",
    }
    process = await asyncio.create_subprocess_exec(
        "git",
        *(arg.replace("GATEWAY", f"{base}{REMOTE}") for arg in args),
        cwd=cwd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await asyncio.wait_for(process.communicate(), 60)
    return process.returncode or 0, output.decode("utf-8", "replace")
