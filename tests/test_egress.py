"""The egress guard (#260): fetch must not reach the network it sits on.

Production answered ``fetch_tool http://127.0.0.1:8019/health`` with the
gateway's own health JSON. Every case here is refused with a closed-set
reason, and no refusal names the address it refused.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
from typing import Any

import httpcore
import httpx
import pytest

from tests.egress_harness import PUBLIC_ADDRESS, route
from trentina import config as config_mod
from trentina import egress
from trentina.client import fetch_url
from trentina.errors import BlockedSourceError, EgressRefusedError
from trentina.gateway.errors import BackendCallError
from trentina.modes import Mode
from trentina.outcomes import Outcome, classify_exception

OK_RESPONSE = [
    b"HTTP/1.1 200 OK\r\n",
    b"Content-Type: text/plain\r\n",
    b"Content-Length: 2\r\n",
    b"\r\n",
    b"ok",
]


def _unreachable(_request: httpx.Request) -> httpx.Response:
    raise AssertionError("a refused URL must never be requested")


async def _refusal(url: str) -> EgressRefusedError:
    with pytest.raises(EgressRefusedError) as exc:
        await fetch_url(url)
    return exc.value


class TestRefusedAddresses:
    """Decided on the resolved address, whatever the URL spelled."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fe80::1]/",
            "http://100.64.0.1/",
            "http://[fc00::1]/",
            "http://224.0.0.1/",
            "http://0.0.0.0/",
            "http://[::127.0.0.1]/",
            "http://[2002:7f00:1::]/",
            "http://[64:ff9b::a00:1]/",
            "http://[64:ff9b:1::a00:1]/",
            "http://2130706433/",
            "http://0x7f.1/",
            "http://017700000001/",
        ],
    )
    async def test_non_global_literal(self, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
        """Real getaddrinfo: numeric hosts are parsed locally, no DNS query."""
        monkeypatch.setattr(egress, "PinnedTransport", lambda _b: httpx.MockTransport(_unreachable))
        err = await _refusal(url)
        assert err.reason == "non_global_address"

    async def test_single_label_container_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        route(monkeypatch, _unreachable, {"mcp-backend": ["10.89.0.5"]})
        err = await _refusal("http://mcp-backend/")
        assert err.reason == "non_global_address"

    async def test_one_private_answer_among_public_ones(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ANY answer refuses: the connection may land on whichever one."""
        route(monkeypatch, _unreachable, {"mixed.example": [PUBLIC_ADDRESS, "192.168.1.1"]})
        err = await _refusal("https://mixed.example/")
        assert err.reason == "non_global_address"

    async def test_resolver_error_is_unresolvable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fails(_host: str, _port: int) -> list[str]:
            raise OSError("Name or service not known")

        route(monkeypatch, _unreachable)
        monkeypatch.setattr(egress, "_lookup", fails)
        err = await _refusal("https://nowhere.example/")
        assert err.reason == "unresolvable"

    async def test_resolver_timeout_is_unresolvable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        release = threading.Event()

        def stalls(_host: str, _port: int) -> list[str]:
            release.wait(5)
            return [PUBLIC_ADDRESS]

        route(monkeypatch, _unreachable)
        monkeypatch.setattr(egress, "_lookup", stalls)
        monkeypatch.setattr(egress, "RESOLVE_TIMEOUT", 0.05)
        try:
            err = await _refusal("https://slow.example/")
        finally:
            release.set()
        assert err.reason == "unresolvable"

    async def test_a_saturated_resolver_refuses_instead_of_queueing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        busy = threading.BoundedSemaphore(1)
        busy.acquire()
        route(monkeypatch, _unreachable)
        monkeypatch.setattr(egress, "_lookup_slots", busy)
        err = await _refusal("https://example.com/")
        # Not ``unresolvable`` (#449): the name was never asked about.
        assert err.reason == "resolver_busy"

    async def test_a_timed_out_lookup_gives_its_slot_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = threading.Event()
        slots = threading.BoundedSemaphore(1)

        def stalls(_host: str, _port: int) -> list[str]:
            release.wait(5)
            return [PUBLIC_ADDRESS]

        route(monkeypatch, lambda _r: httpx.Response(200, text="ok"))
        monkeypatch.setattr(egress, "_lookup_slots", slots)
        monkeypatch.setattr(egress, "_lookup", stalls)
        monkeypatch.setattr(egress, "RESOLVE_TIMEOUT", 0.05)
        assert (await _refusal("https://slow.example/")).reason == "unresolvable"
        release.set()

        await asyncio.to_thread(lambda: slots.acquire(timeout=5) and slots.release())
        content, _, _ = await fetch_url("https://slow.example/")
        assert content == "ok"

    async def test_unresolvable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        route(monkeypatch, _unreachable, {"nowhere.example": []})
        err = await _refusal("https://nowhere.example/")
        assert err.reason == "unresolvable"


class TestRefusedShapes:
    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("http://example.com:8019/health", "port"),
            ("http://example.com:0/", "port"),
            ("https://example.com:9090/", "port"),
            ("file:///etc/passwd", "scheme"),
            ("gopher://example.com/", "scheme"),
            ("ftp://example.com/", "scheme"),
        ],
    )
    async def test_scheme_and_port(
        self, monkeypatch: pytest.MonkeyPatch, url: str, reason: str
    ) -> None:
        route(monkeypatch, _unreachable)
        err = await _refusal(url)
        assert err.reason == reason

    @pytest.mark.parametrize("url", ["http://example.com:80/", "https://example.com:443/"])
    async def test_explicit_default_ports_pass(
        self, monkeypatch: pytest.MonkeyPatch, url: str
    ) -> None:
        route(monkeypatch, lambda _r: httpx.Response(200, text="ok"))
        content, _, _ = await fetch_url(url)
        assert content == "ok"

    def test_an_unknown_reason_is_a_bug(self) -> None:
        with pytest.raises(ValueError, match="unknown egress reason"):
            EgressRefusedError("because 10.0.0.1 said so")


class TestTLS:
    def test_the_pinned_pool_verifies_the_hostname(self) -> None:
        """Pinning swaps the address, never the verification.

        httpcore hands ``start_tls`` the URL's host (TestPinning asserts it);
        this is the other half: the context it is handed refuses a
        certificate that does not name that host.
        """
        transport = egress.PinnedTransport(egress.PinnedBackend())
        context = transport._pool._ssl_context
        assert context is not None
        assert context.check_hostname is True
        assert context.verify_mode is ssl.CERT_REQUIRED


class TestRedirects:
    """Every hop is checked; httpx no longer follows anything on its own."""

    async def test_public_page_redirecting_inward(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.host)
            return httpx.Response(302, headers={"location": "https://internal.example/admin"})

        route(monkeypatch, handler, {"internal.example": ["10.89.0.1"]})
        err = await _refusal("https://public.example/")
        assert err.reason == "non_global_address"
        assert seen == ["public.example"]

    async def test_https_to_http_downgrade(self, monkeypatch: pytest.MonkeyPatch) -> None:
        route(
            monkeypatch, lambda _r: httpx.Response(301, headers={"location": "http://x.example/"})
        )
        err = await _refusal("https://public.example/")
        assert err.reason == "downgrade"

    async def test_http_to_https_is_fine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        by_scheme = {
            "http": httpx.Response(301, headers={"location": "https://public.example/"}),
            "https": httpx.Response(200, text="secure"),
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return by_scheme[request.url.scheme]

        route(monkeypatch, handler)
        content, _, _ = await fetch_url("http://public.example/")
        assert content == "secure"

    async def test_five_hops_pass_six_refuse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def chain(limit: int) -> Any:
            def handler(request: httpx.Request) -> httpx.Response:
                hop = int(request.url.path.strip("/") or 0)
                if hop < limit:
                    return httpx.Response(302, headers={"location": f"/{hop + 1}"})
                return httpx.Response(200, text="end")

            return handler

        route(monkeypatch, chain(5))
        content, _, _ = await fetch_url("https://public.example/")
        assert content == "end"

        route(monkeypatch, chain(6))
        err = await _refusal("https://public.example/")
        assert err.reason == "too_many_redirects"


class _RecordingStream(httpcore.AsyncMockStream):
    def __init__(self, server_hostnames: list[str | None]) -> None:
        super().__init__(list(OK_RESPONSE))
        self._server_hostnames = server_hostnames

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self._server_hostnames.append(server_hostname)
        return self


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """Records the address dialled and the name TLS was started for."""

    def __init__(self, unreachable: frozenset[str] = frozenset()) -> None:
        self.dialled: list[str] = []
        self.server_hostnames: list[str | None] = []
        self._unreachable = unreachable

    async def connect_tcp(
        self, host: str, port: int, **_kwargs: Any
    ) -> httpcore.AsyncNetworkStream:
        self.dialled.append(host)
        if host in self._unreachable:
            raise httpcore.ConnectError("Network is unreachable")
        return _RecordingStream(self.server_hostnames)

    async def sleep(self, seconds: float) -> None:
        return None


class TestPinning:
    """The connection goes to the address that was checked, not a fresh lookup."""

    async def test_rebinding_after_the_check_does_not_move_the_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers = iter([[PUBLIC_ADDRESS], ["10.89.0.1"]])
        lookups: list[str] = []

        def rebinding(host: str, _port: int) -> list[str]:
            lookups.append(host)
            return next(answers)

        recorder = _RecordingBackend()
        monkeypatch.setattr(egress, "_lookup", rebinding)
        monkeypatch.setattr(egress, "_socket_backend", lambda: recorder)

        content, _, _ = await fetch_url("https://rebind.example/")

        assert content == "ok"
        assert lookups == ["rebind.example"]
        assert recorder.dialled == [PUBLIC_ADDRESS]
        # SNI and certificate verification stay on the name, not the IP.
        assert recorder.server_hostnames == ["rebind.example"]

    async def test_the_next_checked_answer_is_tried_when_one_will_not_connect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An IPv6 answer on a host with no IPv6 route must not fail the fetch."""
        v6, v4 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c", PUBLIC_ADDRESS
        recorder = _RecordingBackend(unreachable=frozenset({v6}))
        monkeypatch.setattr(egress, "_lookup", lambda _h, _p: [v6, v4])
        monkeypatch.setattr(egress, "_socket_backend", lambda: recorder)

        content, _, _ = await fetch_url("https://dual.example/")

        assert content == "ok"
        assert recorder.dialled == [v6, v4]

    async def test_an_unchecked_host_is_never_dialled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _RecordingBackend()
        monkeypatch.setattr(egress, "_socket_backend", lambda: recorder)
        backend = egress.PinnedBackend()
        with pytest.raises(EgressRefusedError):
            await backend.connect_tcp("unchecked.example", 443)
        assert recorder.dialled == []


class TestNothingLeaks:
    async def test_refusal_names_no_address_or_host(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        route(monkeypatch, _unreachable, {"secret-host": ["10.89.0.77"]})
        err = await _refusal("http://secret-host/")
        logged = " ".join(r.getMessage() for r in caplog.records)
        for text in (str(err), logged):
            assert "10.89.0.77" not in text
            assert "secret-host" not in text


class TestEscapeHatch:
    async def test_allow_private_lifts_the_address_rule_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_FETCH_ALLOW_PRIVATE", "true")
        config_mod._config = None
        route(monkeypatch, lambda _r: httpx.Response(200, text="inside"), {"lab": ["10.0.0.9"]})

        content, _, _ = await fetch_url("http://lab/")
        assert content == "inside"

        err = await _refusal("http://lab:8019/")
        assert err.reason == "port"

    def test_warns_when_on(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("TRENTINA_FETCH_ALLOW_PRIVATE", "1")
        config = config_mod.Config()
        assert config.fetch_allow_private
        assert "TRENTINA_FETCH_ALLOW_PRIVATE" in caplog.text

    def test_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_FETCH_ALLOW_PRIVATE", raising=False)
        assert config_mod.Config().fetch_allow_private is False


class TestDeliveredAsARefusal:
    """The agent gets a refusal with no way round it; the audit calls it a block."""

    async def test_fetch_tool_refuses_with_no_alternatives(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.tools.fetch import fetch_page

        monkeypatch.setattr("trentina.tools.fetch.check_blocklist", lambda _u, _m: False)
        route(monkeypatch, _unreachable, {"mcp-backend": ["10.89.0.5"]})

        with pytest.raises(BlockedSourceError) as exc:
            await fetch_page("http://mcp-backend/", Mode.BLOCK)

        refusal = exc.value.refusal
        assert refusal == {
            "reason": "egress refused (non_global_address)",
            "mode": "block",
            "flagged_by": "egress",
            "alternatives": [],
        }
        assert "10.89.0.5" not in str(exc.value)

        wrapped = BackendCallError("internal tool 'fetch_tool' call failed")
        wrapped.__cause__ = exc.value
        assert classify_exception(wrapped) is Outcome.BLOCKED_DEFENSE

    def test_a_bare_egress_refusal_audits_as_a_block(self) -> None:
        assert classify_exception(EgressRefusedError("port")) is Outcome.BLOCKED_DEFENSE
