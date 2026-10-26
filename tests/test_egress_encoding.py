"""fetch asks for identity and refuses an encoded body before decoding it (#276).

``MAX_RESPONSE_SIZE`` and ``MAX_ERROR_BODY`` were checked on bytes httpx had
already decompressed, and httpx decompresses each 64 KiB read whole before
yielding it. A few KiB of gzip therefore became megabytes in memory before
either cap was consulted. These tests serve a real gzip bomb from a real
socket and assert it is refused and never decoded.
"""

from __future__ import annotations

import asyncio
import gzip
from typing import Any

import httpcore
import httpx
import pytest

from tests.egress_harness import PUBLIC_ADDRESS
from trentina.client import MAX_RESPONSE_SIZE, fetch_url
from trentina.errors import BlockedSourceError, EgressRefusedError
from trentina.gateway.errors import BackendCallError
from trentina.modes import Mode
from trentina.outcomes import Outcome, classify_exception
from trentina.reach import egress

BOMB = gzip.compress(b"\0" * (MAX_RESPONSE_SIZE * 4))
"""20 MB of zeros in about 20 KB: four times the cap once inflated."""


class _BombServer:
    """A real HTTP/1.1 server on loopback that answers every request the same way."""

    def __init__(self, status: str, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.requests: list[bytes] = []
        self.port = 0
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _BombServer:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            self.requests.append(await reader.readuntil(b"\r\n\r\n"))
            head = [f"HTTP/1.1 {self.status}", f"Content-Length: {len(self.body)}"]
            head += [f"{k}: {v}" for k, v in self.headers.items()]
            writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + self.body)
            await writer.drain()
        finally:
            writer.close()


class _Loopback(httpcore.AsyncNetworkBackend):
    """Dials the test server whatever pinned address the guard hands it."""

    def __init__(self, port: int) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._port = port

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        assert host == PUBLIC_ADDRESS  # the guard pinned the checked address
        return await self._inner.connect_tcp("127.0.0.1", self._port, timeout=timeout)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


@pytest.fixture
def never_decode(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Fail the test if any decompressor is ever handed a byte."""
    calls: list[int] = []

    def refuse(_self: Any, data: bytes) -> bytes:
        calls.append(len(data))
        raise AssertionError("an encoded body was decoded")

    for decoder in ("GZipDecoder", "DeflateDecoder", "BrotliDecoder", "ZStandardDecoder"):
        cls = getattr(httpx._decoders, decoder, None)
        if cls is not None:
            monkeypatch.setattr(cls, "decode", refuse)
    return calls


def _route_to(monkeypatch: pytest.MonkeyPatch, server: _BombServer) -> None:
    monkeypatch.setattr(egress, "_lookup", lambda _h, _p: [PUBLIC_ADDRESS])
    monkeypatch.setattr(egress, "_socket_backend", lambda: _Loopback(server.port))


class TestTheBomb:
    @pytest.mark.parametrize("status", ["200 OK", "404 Not Found"])
    async def test_a_gzip_bomb_is_refused_and_never_decoded(
        self, monkeypatch: pytest.MonkeyPatch, never_decode: list[int], status: str
    ) -> None:
        """The 2xx body path and the 4xx ``_error_body`` path alike."""
        headers = {"Content-Type": "text/plain", "Content-Encoding": "gzip"}
        async with _BombServer(status, headers, BOMB) as server:
            _route_to(monkeypatch, server)
            with pytest.raises(EgressRefusedError) as caught:
                await fetch_url("http://bomb.example/")

        assert caught.value.reason == "encoded"
        assert never_decode == []
        assert len(BOMB) < MAX_RESPONSE_SIZE < len(gzip.decompress(BOMB))

    async def test_control_without_the_check_the_bomb_is_decoded(
        self, monkeypatch: pytest.MonkeyPatch, never_decode: list[int]
    ) -> None:
        """Proves the fixture bites: with the refusal off, httpx inflates the body."""
        monkeypatch.setattr(egress, "is_encoded", lambda _resp: False)
        headers = {"Content-Type": "text/plain", "Content-Encoding": "gzip"}
        async with _BombServer("200 OK", headers, BOMB) as server:
            _route_to(monkeypatch, server)
            with pytest.raises(AssertionError, match="decoded"):
                await fetch_url("http://bomb.example/")
        assert never_decode

    @pytest.mark.parametrize("encoding", ["br", "deflate", "zstd", "gzip, identity", "x-custom"])
    async def test_any_encoding_but_identity_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, never_decode: list[int], encoding: str
    ) -> None:
        headers = {"Content-Type": "text/plain", "Content-Encoding": encoding}
        async with _BombServer("200 OK", headers, b"opaque") as server:
            _route_to(monkeypatch, server)
            with pytest.raises(EgressRefusedError) as caught:
                await fetch_url("http://bomb.example/")
        assert caught.value.reason == "encoded"

    async def test_identity_is_asked_for_and_a_plain_body_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        headers = {"Content-Type": "text/plain", "Content-Encoding": "identity"}
        async with _BombServer("200 OK", headers, b"plain text") as server:
            _route_to(monkeypatch, server)
            content, _, _ = await fetch_url("http://bomb.example/")

        assert content == "plain text"
        request = server.requests[0].lower()
        assert b"accept-encoding: identity\r\n" in request
        assert b"gzip" not in request

    async def test_head_is_not_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No body to inflate; grounding redirects are resolved with HEAD."""
        headers = {"Content-Encoding": "gzip"}
        async with _BombServer("200 OK", headers, b"") as server:
            _route_to(monkeypatch, server)
            async with egress.open_guarded(
                "HEAD", "http://bomb.example/", timeout=5, deadline=5
            ) as resp:
                assert resp.status_code == 200


class TestDeliveredAsARefusal:
    """Why ``EgressRefusedError``: it audits as a defense block with no way round it.

    A ``FetchError`` would audit as a backend error, and on a 4xx it would be
    routed into the advisory path that reads the error body.
    """

    async def test_fetch_tool_refuses_with_no_alternatives(
        self, monkeypatch: pytest.MonkeyPatch, never_decode: list[int]
    ) -> None:
        from trentina.tools.fetch import fetch_page

        monkeypatch.setattr("trentina.tools.fetch.check_blocklist", lambda _u, _m: False)
        headers = {"Content-Type": "text/html", "Content-Encoding": "gzip"}
        async with _BombServer("200 OK", headers, BOMB) as server:
            _route_to(monkeypatch, server)
            with pytest.raises(BlockedSourceError) as caught:
                await fetch_page("http://bomb.example/", Mode.BLOCK)

        assert caught.value.refusal == {
            "reason": "egress refused (encoded)",
            "mode": "block",
            "flagged_by": "egress",
            "alternatives": [],
        }
        wrapped = BackendCallError("internal tool 'fetch_tool' call failed")
        wrapped.__cause__ = caught.value
        assert classify_exception(wrapped) is Outcome.BLOCKED_DEFENSE
        assert never_decode == []
