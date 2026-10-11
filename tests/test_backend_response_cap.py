"""A backend's response is read under a byte cap while it streams (#267).

The MCP SDK reads a JSON reply with ``response.aread()`` and an SSE reply
through ``EventSource``, both unbounded, so a backend relaying attacker-sized
mail or syslog used to land in the gateway's memory whole before admission
could refuse it. These tests run the real SDK client against a real local
HTTP server, so what they prove is what the transport actually does.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import httpx2
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from trentina.gateway import backend as backend_mod
from trentina.gateway.backend import (
    BYTES_PER_TOKEN,
    MIN_RESPONSE_BYTES,
    ResponseCap,
    call_backend_tool,
    response_byte_cap,
)
from trentina.gateway.circuit import State, breaker
from trentina.gateway.errors import (
    BackendCallError,
    BackendResponseTooLargeError,
)
from trentina.gateway.profile import Backend
from trentina.outcomes import Outcome, classify_exception

if TYPE_CHECKING:
    from starlette.requests import Request

CAP = 64 * 1024
BIG = 64 * 1024 * 1024
"""An endless reply, for practical purposes: an uncapped read would pull all of it,
while a capped one stops at CAP plus whatever loopback socket buffers already
held (a few MiB) before the client hung up."""
DECLARED = 4 * 1024 * 1024
CHUNK = 16 * 1024


class _Server:
    """A minimal streamable-HTTP MCP server whose ``tools/call`` reply is chosen per test."""

    def __init__(self) -> None:
        self.mode = "ok"
        self.streams: list[list[int]] = []
        self.calls = 0
        self.accept_encodings: list[str] = []
        self.port = _free_port()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def app(self) -> Starlette:
        async def mcp(request: Request) -> Response:
            self.accept_encodings.append(request.headers.get("accept-encoding", ""))
            if request.method != "POST":
                return Response(status_code=405)
            body = json.loads(await request.body())
            if "id" not in body:
                return Response(status_code=202)
            if body["method"] == "initialize":
                return JSONResponse(
                    _result(
                        body,
                        {
                            "protocolVersion": body["params"]["protocolVersion"],
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "big", "version": "1"},
                        },
                    )
                )
            if body["method"] == "tools/list":
                # The SDK lists tools before a call, for their output schemas.
                tool = {"name": "t", "inputSchema": {"type": "object"}}
                return JSONResponse(_result(body, {"tools": [tool]}))
            self.calls += 1
            return self._call(body)

        return Starlette(routes=[Route("/mcp", mcp, methods=["POST", "GET", "DELETE"])])

    def _call(self, body: dict[str, Any]) -> Response:
        ok = _result(body, {"content": [{"type": "text", "text": "fine"}], "isError": False})
        if self.mode == "ok":
            return JSONResponse(ok)
        if self.mode == "gzip":
            packed = gzip.compress(json.dumps(ok).encode())
            return Response(
                packed,
                media_type="application/json",
                headers={"content-encoding": "gzip"},
            )
        if self.mode == "declared":
            return Response(
                b" " * DECLARED + json.dumps(ok).encode(), media_type="application/json"
            )
        media = "text/event-stream" if self.mode == "sse" else "application/json"
        return StreamingResponse(self._stream(body), media_type=media)

    async def _stream(self, body: dict[str, Any]) -> AsyncIterator[bytes]:
        """``BIG`` bytes with no Content-Length, one chunk at a time, counted."""
        head = b"event: message\ndata: " if self.mode == "sse" else b""
        prefix = json.dumps(_result(body, {"content": [{"type": "text", "text": ""}]}))
        opening = prefix[: prefix.index('"text": "') + len('"text": "')].encode()
        yield head + opening
        # One counter per stream: an earlier test's stream may still be unwinding.
        produced = [0]
        self.streams.append(produced)
        while produced[0] < BIG:
            produced[0] += CHUNK
            yield b"x" * CHUNK
            # Once the client hangs up, uvicorn's send() returns at once
            # without awaiting, so without a checkpoint here Starlette's
            # disconnect listener never runs and this loop counts all of BIG
            # whether or not the client was still reading.
            await asyncio.sleep(0)
        yield b'"}]}}' + (b"\n\n" if self.mode == "sse" else b"")

    def start(self) -> None:
        # log_config=None: uvicorn's own dictConfig would rewire the process's
        # uvicorn.* loggers, which test_log_hygiene asserts on.
        config = uvicorn.Config(self.app(), host="127.0.0.1", port=self.port, log_config=None)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("test server did not start")
            time.sleep(0.02)

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


def _result(body: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": body["id"], "result": result}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def server() -> Iterator[_Server]:
    srv = _Server()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture(autouse=True)
def _small_cap(server: _Server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backend_mod, "response_byte_cap", lambda: CAP)
    server.streams.clear()
    server.calls = 0
    server.accept_encodings.clear()


def _backend(server: _Server) -> Backend:
    return Backend(url=server.url, timeout_seconds=20.0, list_timeout_seconds=20.0)


class TestAgainstARealServer:
    async def test_a_normal_reply_passes(self, server: _Server) -> None:
        server.mode = "ok"
        result = await call_backend_tool("big", _backend(server), "t", {})
        assert result.content == [{"type": "text", "text": "fine"}]

    @pytest.mark.parametrize("mode", ["json", "sse"])
    async def test_an_endless_reply_is_cut_at_the_cap(self, server: _Server, mode: str) -> None:
        """No Content-Length: the stream is counted and the read stops."""
        server.mode = mode
        started = time.monotonic()
        with pytest.raises(BackendResponseTooLargeError) as caught:
            await call_backend_tool("big", _backend(server), "t", {})

        assert caught.value.cap_bytes == CAP
        assert server.calls == 1  # cut on the tools/call reply, not before it
        # Resolved promptly, not by waiting out timeout_seconds.
        assert time.monotonic() - started < 10
        # The read stopped: the server got nowhere near sending all of it.
        assert len(server.streams) == 1
        assert server.streams[0][0] < BIG // 4
        # The backend answered: that is not a reason to open its circuit.
        assert breaker.get_state(server.url) is State.CLOSED

    async def test_a_declared_oversize_is_refused_from_the_header(self, server: _Server) -> None:
        server.mode = "declared"
        with pytest.raises(BackendResponseTooLargeError):
            await call_backend_tool("big", _backend(server), "t", {})

    async def test_identity_is_requested_and_an_encoded_reply_refused(
        self, server: _Server
    ) -> None:
        server.mode = "gzip"
        with pytest.raises(BackendCallError) as caught:
            await call_backend_tool("big", _backend(server), "t", {})

        assert not isinstance(caught.value, BackendResponseTooLargeError)
        assert server.accept_encodings
        assert set(server.accept_encodings) == {"identity"}

    def test_it_audits_as_a_defense_block(self) -> None:
        exc = BackendResponseTooLargeError("x", cap_bytes=1)
        assert classify_exception(exc) is Outcome.BLOCKED_DEFENSE


class TestResponseCap:
    """The hook itself, over httpx2's MockTransport."""

    async def _get(self, cap: ResponseCap, response: httpx2.Response) -> httpx2.Response:
        transport = httpx2.MockTransport(lambda _r: response)
        async with httpx2.AsyncClient(
            transport=transport, event_hooks={"response": [cap.hook]}
        ) as client:
            return await client.get("http://backend/mcp")

    async def test_an_encoded_reply_is_never_decoded(self) -> None:
        cap = ResponseCap(limit=CAP)
        bomb = gzip.compress(b"\0" * (BIG * 2))
        with pytest.raises(httpx2.StreamError):
            await self._get(
                cap, httpx2.Response(200, content=bomb, headers={"content-encoding": "gzip"})
            )
        assert cap.encoded and not cap.overflowed

    async def test_identity_is_not_an_encoding(self) -> None:
        cap = ResponseCap(limit=CAP)
        resp = await self._get(
            cap, httpx2.Response(200, content=b"ok", headers={"content-encoding": "identity"})
        )
        assert resp.content == b"ok"


class TestTheFactor:
    def test_cap_follows_admission(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina import config as config_mod

        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "100000")
        monkeypatch.setenv("QUARANTINE_CONTEXT_TOKENS", "1000000")
        config_mod._config = None
        assert response_byte_cap() == 100_000 * BYTES_PER_TOKEN

    def test_floor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina import config as config_mod

        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "10")
        config_mod._config = None
        assert response_byte_cap() == MIN_RESPONSE_BYTES


class TestDeliveredAsTheOversizeRefusal:
    """The agent gets admission's oversize refusal; the audit calls it a block."""

    @pytest.mark.usefixtures("read_only_tools")
    async def test_router_refuses_with_the_oversize_gap(self, tmp_path: Any) -> None:
        from pydantic import SecretStr

        import trentina.database as db_mod
        from trentina.database import get_gateway_call_stats
        from trentina.gateway.profile import AuthConfig, Profile
        from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc

        profile = Profile(
            short_names=False,
            name="capped",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"mail": Backend(url="http://mail:8000/mcp", tools_allow=["*"])},
        )
        profile.auth.bearer_token = SecretStr("x")

        async def too_big(*_args: Any) -> Any:
            raise BackendResponseTooLargeError("cut", cap_bytes=CAP)

        db_mod._db = None
        with (
            patch("trentina.gateway.router.call_backend_tool", side_effect=too_big),
            patch("trentina.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = str(tmp_path / "audit.db")
            mock_cfg.return_value.ensure_db_dir = lambda: None
            # The first audit write of a process runs the expiry sweep, which
            # reads this; a mock attribute there loses the row (TypeError).
            mock_cfg.return_value.blocklist_ttl_days = 30
            resp = await route_jsonrpc(
                profile,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": f"mail{NAMESPACE_SEP}read_mail", "arguments": {}},
                },
            )
            stats = get_gateway_call_stats("capped", days=1)
        db_mod._db = None

        data = resp["error"]["data"]
        assert data["gaps"] == ["oversize"]
        assert "admission cap" in data["reason"]
        # Admission would offer flag; here nothing was read, so nothing would help.
        assert data["alternatives"] == []
        assert resp["error"]["message"].startswith("[TRENTINA] Refused")
        assert stats["by_tool"][0]["outcomes"] == {"blocked_defense": 1}
