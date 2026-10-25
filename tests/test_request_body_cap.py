"""The MCP routes refuse an oversized request body with 413, unread (#267).

``_handle_post`` called ``request.body()`` with no cap, so one request could
push the container toward OOM. The cap is ASGI middleware, so it holds for a
chunked body with no ``Content-Length`` as well as for one that declares its
size, and it stops reading at the cap rather than after the whole body.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from trentina import httpbody
from trentina.gateway.app import gateway_app
from trentina.gateway.profile import AuthConfig, Profile
from trentina.httpbody import (
    DEFAULT_MAX_REQUEST_BYTES,
    MIN_REQUEST_BYTES,
    RequestBodyCap,
    TooLargeError,
    drain_capped,
    max_request_bytes,
    mcp_path_matcher,
    read_capped,
)

CAP = 2048


class _Receive:
    """An ASGI ``receive`` that hands out chunks and counts how many it gave."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.pulled = 0

    async def __call__(self) -> dict[str, Any]:
        if self.pulled >= len(self._chunks):
            return {"type": "http.disconnect"}
        chunk = self._chunks[self.pulled]
        self.pulled += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": self.pulled < len(self._chunks),
        }


class _Send:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int:
        return int(self.messages[0]["status"])


def _scope(
    path: str, method: str = "POST", headers: list[tuple[bytes, bytes]] | None = None
) -> Any:
    return {"type": "http", "method": method, "path": path, "headers": headers or []}


class _Echo:
    """The inner app: reads its whole body and reports the length."""

    def __init__(self) -> None:
        self.called = False
        self.body = b""

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        request = Request(scope, receive)
        self.body = await request.body()
        await Response(str(len(self.body)))(scope, receive, send)


class TestMiddleware:
    async def test_chunked_body_over_the_cap_is_refused_without_reading_the_rest(self) -> None:
        """No Content-Length: the cap is counted on the chunks as they arrive."""
        inner = _Echo()
        chunks = [b"x" * 1024] * 50
        receive = _Receive(chunks)
        send = _Send()

        await RequestBodyCap(inner, cap=CAP)(_scope("/gateway/alice/mcp"), receive, send)

        assert send.status == 413
        assert inner.body == b""  # the handler's read was stopped, not fed
        # Three 1 KiB chunks pass 2 KiB; the other 47 are never pulled.
        assert receive.pulled == 3

    async def test_declared_length_over_the_cap_is_refused_before_any_read(self) -> None:
        inner = _Echo()
        receive = _Receive([b"x" * 10])
        send = _Send()
        headers = [(b"content-length", str(CAP + 1).encode())]

        await RequestBodyCap(inner, cap=CAP)(
            _scope("/gateway/a/mcp", headers=headers), receive, send
        )

        assert send.status == 413
        assert receive.pulled == 0

    async def test_a_lying_small_content_length_is_still_counted(self) -> None:
        inner = _Echo()
        receive = _Receive([b"x" * 1024] * 4)
        send = _Send()
        headers = [(b"content-length", b"10")]

        await RequestBodyCap(inner, cap=CAP)(
            _scope("/gateway/a/mcp", headers=headers), receive, send
        )

        assert send.status == 413
        assert inner.body == b""

    async def test_body_under_the_cap_reaches_the_handler_whole(self) -> None:
        inner = _Echo()
        receive = _Receive([b"a" * 1000, b"b" * 1000])
        send = _Send()

        await RequestBodyCap(inner, cap=CAP)(_scope("/gateway/a/mcp"), receive, send)

        assert inner.body == b"a" * 1000 + b"b" * 1000
        assert send.status == 200

    @pytest.mark.parametrize(
        ("path", "method"),
        [("/proxy/llm/v1/messages", "POST"), ("/gateway/a/mcp", "GET"), ("/matrix/x", "PUT")],
    )
    async def test_other_routes_and_bodyless_methods_pass_untouched(
        self, path: str, method: str
    ) -> None:
        """The LLM and Matrix proxies stream bodies they never hold."""
        inner = _Echo()
        receive = _Receive([b"x" * 1024] * 5)
        send = _Send()

        await RequestBodyCap(inner, cap=CAP)(_scope(path, method), receive, send)

        assert inner.called
        assert len(inner.body) == 5 * 1024

    async def test_nothing_is_read_ahead_of_the_handler(self) -> None:
        """A handler that refuses before reading (the gateway authenticates
        first) costs no body memory: the middleware buffers nothing itself."""

        async def refuses_unread(scope: Any, receive: Any, send: Any) -> None:
            await Response("no", status_code=401)(scope, receive, send)

        receive = _Receive([b"x" * 1024] * 50)
        send = _Send()

        await RequestBodyCap(refuses_unread, cap=CAP)(_scope("/gateway/a/mcp"), receive, send)

        assert send.status == 401
        assert receive.pulled == 0

    async def test_overflow_after_the_response_started_propagates(self) -> None:
        """Too late for a 413: a second response start would be a protocol error."""

        async def starts_then_reads(scope: Any, receive: Any, send: Any) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await Request(scope, receive).body()

        receive = _Receive([b"x" * 1024] * 5)
        send = _Send()

        with pytest.raises(TooLargeError):
            await RequestBodyCap(starts_then_reads, cap=CAP)(
                _scope("/gateway/a/mcp"), receive, send
            )
        starts = [m for m in send.messages if m["type"] == "http.response.start"]
        assert [m["status"] for m in starts] == [200]

    async def test_a_disconnect_mid_body_is_not_a_request(self) -> None:
        """The partial body never reaches the handler as if it were complete."""
        inner = _Echo()

        class _Leaves(_Receive):
            async def __call__(self) -> dict[str, Any]:
                if self.pulled == 1:
                    return {"type": "http.disconnect"}
                return await super().__call__()

        receive = _Leaves([b'{"jsonrpc": "2.0"', b"}"])

        with pytest.raises(ClientDisconnect):
            await RequestBodyCap(inner, cap=CAP)(_scope("/gateway/a/mcp"), receive, _Send())
        assert inner.body == b""

    async def test_drain_capped_reports_a_disconnect(self) -> None:
        class _Leaves(_Receive):
            async def __call__(self) -> dict[str, Any]:
                if self.pulled == 1:
                    return {"type": "http.disconnect"}
                return await super().__call__()

        body, overflowed = await drain_capped(_scope("/register"), _Leaves([b"{", b"}"]), CAP)
        assert body is None
        assert not overflowed

    def test_the_matcher(self) -> None:
        applies = mcp_path_matcher("/mcp-internal-abc", "/mcp")
        assert applies("/gateway/alice/mcp")
        assert applies("/gateway/alice/mcp/")
        assert applies("/mcp-internal-abc")
        assert applies("/mcp")
        assert not applies("/gateway//mcp")
        assert not applies("/gateway/alice/other")
        assert not applies("/proxy/llm/v1/messages")
        assert not applies("/register")


class TestGatewayApp:
    def test_oversized_post_to_a_profile_is_413(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", str(CAP))
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))

        resp = client.post(
            "/alice/mcp",
            content=b"{" + b" " * (CAP * 4) + b"}",
            headers={"Authorization": "Bearer alice-token", "Content-Type": "application/json"},
        )

        assert resp.status_code == 413

    def test_unauthenticated_oversize_is_refused_by_auth_unread(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", str(CAP))
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))

        def chunked() -> Any:
            for _ in range(10):
                yield b"x" * 1024

        resp = client.post("/alice/mcp", content=chunked(), headers={"Authorization": "Bearer no"})

        assert resp.status_code == 401

    def test_authenticated_chunked_oversize_is_413(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", str(CAP))
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))

        def chunked() -> Any:
            for _ in range(10):
                yield b"x" * 1024

        resp = client.post(
            "/alice/mcp", content=chunked(), headers={"Authorization": "Bearer alice-token"}
        )

        assert resp.status_code == 413

    def test_a_normal_request_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", str(CAP))
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))

        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer alice-token"},
        )

        assert resp.status_code != 413


class TestReadCapped:
    """``read_capped``, now also used by the alert ingress."""

    def _app(self, limit: int) -> Starlette:
        async def endpoint(request: Request) -> Response:
            try:
                body = await read_capped(request, limit)
            except TooLargeError:
                return Response("too large", status_code=413)
            return Response(str(len(body)))

        return Starlette(routes=[Route("/", endpoint, methods=["POST"])])

    def test_chunked_over_the_limit(self) -> None:
        client = TestClient(self._app(CAP))

        def body() -> Any:
            for _ in range(10):
                yield b"x" * 1024

        assert client.post("/", content=body()).status_code == 413

    def test_under_the_limit(self) -> None:
        client = TestClient(self._app(CAP))
        assert client.post("/", content=b"x" * 100).text == "100"


class TestSetting:
    def test_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_MAX_REQUEST_BYTES", raising=False)
        assert max_request_bytes() == DEFAULT_MAX_REQUEST_BYTES == 1_048_576

    def test_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", "4096")
        assert max_request_bytes() == 4096

    def test_floored_rather_than_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REQUEST_BYTES", "0")
        assert max_request_bytes() == MIN_REQUEST_BYTES

    def test_the_refusal_log_names_no_path(self, caplog: pytest.LogCaptureFixture) -> None:
        asyncio.run(
            RequestBodyCap(_Echo(), cap=CAP)(
                _scope("/gateway/CANARY-PROFILE/mcp"), _Receive([b"x" * 4096]), _Send()
            )
        )
        assert "CANARY" not in caplog.text
        assert httpbody.STATUS_TOO_LARGE == 413
