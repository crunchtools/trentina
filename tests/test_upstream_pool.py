"""The per-(profile, host, port) pinned connection pool (gateway/upstream.py, #511).

The pool gives /egress, /git, (and later /llm, Matrix) a reused, PINNED client
per operator origin. These tests pin down the invariants the routes rely on: a
client is cached per origin, every send is preceded by a ``checked_target``
lookup (the pin-before-send choke-point), no upstream cookie is replayed, and
``close_pool`` disposes everything.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from trentina.egress import ResolvedTarget
from trentina.gateway import upstream

if TYPE_CHECKING:
    from collections.abc import Iterator

ADDR = "203.0.113.7"


def _profile(name: str = "agent1") -> Any:
    return SimpleNamespace(name=name)


@pytest.fixture(autouse=True)
def clean_pool() -> Iterator[None]:
    upstream._pool.clear()
    yield
    upstream._pool.clear()


def _mock_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Point the pool's PinnedTransport at an httpx.MockTransport running ``handler``."""
    monkeypatch.setattr(
        upstream, "PinnedTransport", lambda _backend, **_kw: httpx.MockTransport(handler)
    )


def _stub_check(monkeypatch: pytest.MonkeyPatch, pinned: list[str]) -> None:
    """Stub checked_target to record the host it was asked for (pin-before-send)."""

    async def fake(_profile: Any, host: str) -> ResolvedTarget:
        pinned.append(host)
        return ResolvedTarget(host, 443, (ADDR,))

    monkeypatch.setattr(upstream, "checked_target", fake)


def test_a_client_is_cached_per_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_transport(monkeypatch, lambda _r: httpx.Response(200))
    p = _profile()
    c1, _ = upstream._client_for(p, "api.example.com", 443, 10.0, 16)
    c2, _ = upstream._client_for(p, "api.example.com", 443, 10.0, 16)
    assert c1 is c2, "the same origin reuses one pooled client"
    c3, _ = upstream._client_for(p, "other.example.com", 443, 10.0, 16)
    assert c3 is not c1, "a different host gets its own client"
    c4, _ = upstream._client_for(_profile("agent2"), "api.example.com", 443, 10.0, 16)
    assert c4 is not c1, "a different profile gets its own client"


async def test_every_send_is_preceded_by_a_checked_target(monkeypatch: pytest.MonkeyPatch) -> None:
    pinned: list[str] = []
    _stub_check(monkeypatch, pinned)

    def handler(_request: httpx.Request) -> httpx.Response:
        # The pin must already have been refreshed by the time the send reaches
        # the wire — the choke-point Fable required.
        assert pinned, "checked_target ran before the request was sent"
        return httpx.Response(200, content=b"ok")

    _mock_transport(monkeypatch, handler)
    async with upstream.pinned_send(
        _profile(), "GET", "https://api.example.com:443/x", idle=10.0, headers={}
    ) as resp:
        body = await resp.aread()
    assert body == b"ok"
    assert pinned == ["api.example.com"]


async def test_accept_encoding_identity_is_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_check(monkeypatch, [])
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200)

    _mock_transport(monkeypatch, handler)
    async with upstream.pinned_send(
        _profile(),
        "GET",
        "https://api.example.com/x",
        idle=10.0,
        headers={"accept-encoding": "gzip"},
    ):
        pass
    assert seen["accept-encoding"] == "identity"


async def test_a_redirect_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_check(monkeypatch, [])
    _mock_transport(monkeypatch, lambda _r: httpx.Response(302, headers={"location": "https://x/"}))
    from trentina.errors import EgressRefusedError

    with pytest.raises(EgressRefusedError, match="redirect"):
        async with upstream.pinned_send(
            _profile(), "GET", "https://api.example.com/x", idle=10.0, headers={}
        ):
            pass


async def test_an_upstream_cookie_is_not_replayed(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_check(monkeypatch, [])
    sent_cookies: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_cookies.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"set-cookie": "sess=secret"})

    _mock_transport(monkeypatch, handler)
    p = _profile()
    # Two requests on the same pooled client: the first stores a Set-Cookie, the
    # second must NOT carry it (the cross-request replay the jar prevents — a
    # clear-after-response would leave a window for a concurrent send).
    for _ in range(2):
        async with upstream.pinned_send(
            p, "GET", "https://api.example.com/x", idle=10.0, headers={}
        ):
            pass
    assert sent_cookies == [None, None], "a provider's Set-Cookie must not ride a later request"
    client, _ = upstream._pool[(p.name, "api.example.com", 443)]
    assert len(client.cookies) == 0, "the pooled client's jar never stores"


async def test_close_pool_disposes_every_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_transport(monkeypatch, lambda _r: httpx.Response(200))
    upstream._client_for(_profile(), "a.example.com", 443, 10.0, 16)
    upstream._client_for(_profile(), "b.example.com", 443, 10.0, 16)
    assert len(upstream._pool) == 2
    await upstream.close_pool()
    assert upstream._pool == {}


async def test_close_profile_closes_only_that_profiles_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reload diff: a changed/removed profile's warm clients are closed; an
    unchanged profile keeps its own (and any /llm stream in flight)."""
    _mock_transport(monkeypatch, lambda _r: httpx.Response(200))
    upstream._client_for(_profile("agent1"), "a.example.com", 443, 10.0, 16)
    upstream._client_for(_profile("agent1"), "b.example.com", 443, 10.0, 16)
    upstream._client_for(_profile("agent2"), "a.example.com", 443, 10.0, 16)
    assert len(upstream._pool) == 3
    await upstream.close_profile("agent1")
    assert set(upstream._pool) == {("agent2", "a.example.com", 443)}
