"""Client egress (#442): a CONNECT tunnel to the hosts a profile names.

The listener and the upstream are real sockets on loopback. The ClientHello
is a real one, made by the ``ssl`` module, so the SNI check reads what a
client sends rather than what a test author believes one sends.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import sqlite3
import ssl
import threading
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from trentina import config as config_mod
from trentina import database as database_mod
from trentina import egress
from trentina.gateway import client_egress
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import ActiveConfig, GatewayConfig, _check_egress_networks
from trentina.gateway.profile import (
    AuthConfig,
    ClientEgressConfig,
    MatrixIngressConfig,
    Profile,
    is_dns_name,
    profile_for_address,
)
from trentina.tools.reload import _hold_perimeter_fields, _unapplied

from .egress_harness import PUBLIC_ADDRESS

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator
    from pathlib import Path

ALLOWED = "api.example.com"
OTHER = "other.example.org"


def _profile(
    name: str = "agent1",
    networks: tuple[str, ...] = ("127.0.0.0/8",),
    hosts: tuple[str, ...] = (ALLOWED,),
) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TOK"),
        client_egress=ClientEgressConfig(source_networks=list(networks), hosts=list(hosts)),
    )


def client_hello(server_name: str | None) -> bytes:
    """The bytes a TLS client sends first, for ``server_name`` (None: no SNI)."""
    context = ssl.create_default_context()
    context.check_hostname = server_name is not None
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=server_name)
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


@pytest.fixture(autouse=True)
def audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Every tunnel writes an audit row; keep it out of the real database."""
    path = tmp_path / "trentina.db"
    monkeypatch.setenv("QUARANTINE_DB", str(path))
    config_mod._config = None
    database_mod._db = None
    yield path
    database_mod._db = None
    config_mod._config = None


def _rows(path: Path) -> list[sqlite3.Row]:
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT profile, backend, tool, outcome, error_message, destination, "
            "destination_kind, bytes_arrived, bytes_delivered FROM gateway_calls ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


class _Upstream:
    """The destination: records what reaches it and answers each chunk in upper case."""

    def __init__(self) -> None:
        self.received = bytearray()
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> _Upstream:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while data := await reader.read(65536):
                self.received += data
                writer.write(data.upper())
                await writer.drain()
        finally:
            writer.close()


@pytest.fixture
async def upstream(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Upstream]:
    """A destination on loopback that every allowed name resolves and connects to."""
    async with _Upstream() as server:

        async def dial(
            address: str, port: int
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            assert (address, port) == (PUBLIC_ADDRESS, 443)  # the address the guard checked
            return await asyncio.open_connection("127.0.0.1", server.port)

        monkeypatch.setattr(egress, "_lookup", lambda _host, _port: [PUBLIC_ADDRESS])
        monkeypatch.setattr(client_egress, "open_upstream", dial)
        yield server


@pytest.fixture
async def listener(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[dict[str, Profile]]:
    """The egress listener on a free loopback port. Yields the live profile registry."""
    profiles = {"agent1": _profile()}
    active = SimpleNamespace(
        config=SimpleNamespace(profiles=profiles), egress_listener_configured=True
    )
    monkeypatch.setattr(client_egress, "get_active_config", lambda: active)
    monkeypatch.setattr(client_egress, "_listen", ("127.0.0.1", 0))
    await client_egress.start()
    try:
        yield profiles
    finally:
        await client_egress.stop()


def _port() -> int:
    assert client_egress._server is not None
    return int(client_egress._server.sockets[0].getsockname()[1])


async def _request(head: str) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    """Send a request head; return the response head and the open streams."""
    reader, writer = await asyncio.open_connection("127.0.0.1", _port())
    writer.write(head.encode())
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    return response, reader, writer


async def _connect(
    host: str = ALLOWED, port: int = 443
) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    return await _request(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")


async def _closed(reader: asyncio.StreamReader) -> bool:
    return await asyncio.wait_for(reader.read(), 5) == b""


async def _settled(path: Path, count: int = 1) -> list[sqlite3.Row]:
    """The audit rows, once the listener has written ``count`` of them."""
    for _ in range(200):
        rows = _rows(path)
        if len(rows) >= count:
            return rows
        await asyncio.sleep(0.01)
    return _rows(path)


class TestTheListenerIsBoundOnlyWhenAsked:
    @pytest.mark.parametrize(
        ("listen", "active"),
        [
            (None, SimpleNamespace(egress_listener_configured=True)),
            (("127.0.0.1", 0), None),
            (("127.0.0.1", 0), SimpleNamespace(egress_listener_configured=False)),
        ],
        ids=["no-address", "no-gateway", "no-profile-has-the-block"],
    )
    async def test_start_opens_no_socket(
        self,
        monkeypatch: pytest.MonkeyPatch,
        listen: tuple[str, int] | None,
        active: SimpleNamespace | None,
    ) -> None:
        monkeypatch.setattr(client_egress, "_listen", listen)
        monkeypatch.setattr(client_egress, "get_active_config", lambda: active)
        await client_egress.start()
        assert client_egress._server is None
        await client_egress.stop()


class TestTunnel:
    async def test_an_allowed_host_carries_bytes_both_ways(
        self, listener: dict[str, Profile], upstream: _Upstream, audit_db: Path
    ) -> None:
        response, reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 200 ")

        hello = client_hello(ALLOWED)
        writer.write(hello)
        assert await asyncio.wait_for(reader.readexactly(len(hello)), 5) == hello.upper()
        writer.write(b"ping")
        assert await asyncio.wait_for(reader.readexactly(4), 5) == b"PING"
        writer.close()
        await writer.wait_closed()

        (row,) = await _settled(audit_db)
        assert bytes(upstream.received) == hello + b"ping"
        assert (row["profile"], row["backend"], row["tool"]) == ("agent1", "egress", "connect")
        assert row["outcome"] == "ok"
        assert (row["destination"], row["destination_kind"]) == (f"{ALLOWED}:443", "tunnel")
        assert row["bytes_delivered"] == len(hello) + 4
        assert row["bytes_arrived"] == len(hello) + 4

    async def test_the_host_is_matched_case_insensitively_and_without_a_trailing_dot(
        self, listener: dict[str, Profile], upstream: _Upstream
    ) -> None:
        response, _reader, writer = await _connect("API.Example.com.")
        assert response.startswith(b"HTTP/1.1 200 ")
        writer.close()

    async def test_an_idle_tunnel_is_closed(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        audit_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(client_egress, "IDLE_TIMEOUT", 0.2)
        _response, reader, writer = await _connect()
        hello = client_hello(ALLOWED)
        writer.write(hello)
        await asyncio.wait_for(reader.readexactly(len(hello)), 5)
        assert await _closed(reader)
        (row,) = await _settled(audit_db)
        assert row["outcome"] == "ok"
        writer.close()


class TestRefusedBeforeConnecting:
    @pytest.mark.parametrize(
        ("head", "status", "reason"),
        [
            (f"CONNECT {OTHER}:443 HTTP/1.1\r\n\r\n", b"403", b"host_not_listed"),
            (f"CONNECT {ALLOWED}:80 HTTP/1.1\r\n\r\n", b"403", b"port"),
            (f"GET http://{ALLOWED}/ HTTP/1.1\r\n\r\n", b"405", b"method"),
            (f"CONNECT {ALLOWED} HTTP/1.1\r\n\r\n", b"400", b"malformed"),
            ("CONNECT 203.0.113.9:443 HTTP/1.1\r\n\r\n", b"400", b"malformed"),
            (f"CONNECT {ALLOWED}:443 SPDY/3\r\n\r\n", b"400", b"malformed"),
            ("nonsense\r\n\r\n", b"400", b"malformed"),
        ],
    )
    async def test_refusals_answer_with_a_status_and_a_closed_reason(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        head: str,
        status: bytes,
        reason: bytes,
    ) -> None:
        response, reader, writer = await _request(head)
        assert response.startswith(b"HTTP/1.1 " + status)
        assert b"X-Trentina-Reason: " + reason + b"\r\n" in response
        assert await _closed(reader)
        assert upstream.connections == 0
        writer.close()

    async def test_an_unlisted_host_is_audited_as_a_denial(
        self, listener: dict[str, Profile], upstream: _Upstream, audit_db: Path
    ) -> None:
        _response, _reader, writer = await _connect(OTHER)
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("denied_allowlist", "host_not_listed")
        assert row["destination"] == f"{OTHER}:443"
        writer.close()

    async def test_a_listed_name_that_resolves_inward_is_refused(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        audit_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(egress, "_lookup", lambda _host, _port: ["10.0.0.5"])
        response, _reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 403")
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("blocked_defense", "non_global_address")
        assert upstream.connections == 0
        writer.close()

    async def test_a_destination_that_refuses_is_a_bad_gateway(
        self, listener: dict[str, Profile], audit_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def refuse(_address: str, _port: int) -> None:
            raise ConnectionRefusedError

        monkeypatch.setattr(egress, "_lookup", lambda _host, _port: [PUBLIC_ADDRESS])
        monkeypatch.setattr(client_egress, "open_upstream", refuse)
        response, _reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 502")
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("backend_error", "connect_failed")
        writer.close()

    async def test_a_head_over_the_limit_is_refused(
        self, listener: dict[str, Profile], upstream: _Upstream
    ) -> None:
        padding = "X-Pad: " + "a" * client_egress.HEAD_LIMIT
        response, _reader, writer = await _request(
            f"CONNECT {ALLOWED}:443 HTTP/1.1\r\n{padding}\r\n\r\n"
        )
        assert response.startswith(b"HTTP/1.1 400")
        writer.close()

    async def test_a_profile_cannot_hold_more_than_its_tunnels(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(client_egress, "MAX_TUNNELS_PER_PROFILE", 1)
        first, _reader, held = await _connect()
        assert first.startswith(b"HTTP/1.1 200")
        second, _reader2, writer = await _connect()
        assert second.startswith(b"HTTP/1.1 503")
        assert b"X-Trentina-Reason: busy" in second
        held.close()
        writer.close()

    async def test_a_fan_out_of_parallel_streams_fits(
        self, listener: dict[str, Profile], upstream: _Upstream
    ) -> None:
        tunnels = [await _connect() for _ in range(client_egress.MAX_TUNNELS_PER_PROFILE)]
        assert all(response.startswith(b"HTTP/1.1 200") for response, _r, _w in tunnels)
        over, _reader, refused = await _connect()
        assert b"X-Trentina-Reason: busy" in over
        refused.close()
        tunnels.pop()[2].close()
        await asyncio.sleep(0.05)
        again, _reader2, writer = await _connect()
        assert again.startswith(b"HTTP/1.1 200")
        for _response, _r, held in [*tunnels, (None, None, writer)]:
            held.close()

    async def test_a_caller_in_no_profiles_network_gets_nothing(
        self, listener: dict[str, Profile], upstream: _Upstream, audit_db: Path
    ) -> None:
        listener["agent1"] = _profile(networks=("192.0.2.0/29",))
        response, reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 403")
        assert await _closed(reader)
        assert upstream.connections == 0
        assert _rows(audit_db) == []
        writer.close()


class TestTheFirstRecordIsCheckedBeforeAnythingIsForwarded:
    @pytest.mark.parametrize(
        ("first_bytes", "reason"),
        [
            (client_hello(OTHER), "sni_mismatch"),
            (client_hello(None), "sni_mismatch"),
            (b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "not_tls"),
            (b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00", "not_tls"),
        ],
        ids=["another-name", "no-sni", "plain-http", "not-a-client-hello"],
    )
    async def test_the_tunnel_closes_and_the_destination_sees_no_byte(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        audit_db: Path,
        first_bytes: bytes,
        reason: str,
    ) -> None:
        response, reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 200")
        writer.write(first_bytes)
        assert await _closed(reader)
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("denied_guard", reason)
        assert bytes(upstream.received) == b""
        writer.close()

    async def test_a_client_that_sends_nothing_is_dropped(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        audit_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(client_egress, "HELLO_TIMEOUT", 0.2)
        _response, reader, writer = await _connect()
        assert await _closed(reader)
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("denied_guard", "no_hello")
        writer.close()


class TestClientHelloParsing:
    def test_a_real_hello_yields_its_name(self) -> None:
        hello = client_hello(ALLOWED)
        assert client_egress.client_hello_sni(hello[5:]) == ALLOWED

    def test_a_hello_without_the_extension_yields_none(self) -> None:
        assert client_egress.client_hello_sni(client_hello(None)[5:]) is None

    @pytest.mark.parametrize("cut", [1, 4, 40, 80, -1])
    def test_a_truncated_hello_is_an_error_not_a_guess(self, cut: int) -> None:
        with pytest.raises(ValueError, match=r"truncated|ClientHello"):
            client_egress.client_hello_sni(client_hello(ALLOWED)[5:][:cut])

    async def test_a_hello_split_across_records_is_reassembled(self) -> None:
        record = client_hello(ALLOWED)
        message = record[5:]
        half = len(message) // 2
        wire = b"".join(
            record[:3] + len(part).to_bytes(2, "big") + part
            for part in (message[:half], message[half:])
        )
        reader = asyncio.StreamReader()
        reader.feed_data(wire + b"application data")
        read, hello = await client_egress.read_client_hello(reader)
        assert read == wire
        assert client_egress.client_hello_sni(hello) == ALLOWED

    async def test_an_oversized_hello_is_refused(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x16\x03\x01\x00\x04\x01\xff\xff\xff")
        with pytest.raises(client_egress.TunnelRefusedError, match="not_tls"):
            await client_egress.read_client_hello(reader)


class TestParseConnect:
    def test_a_connect_line_yields_host_and_port(self) -> None:
        assert client_egress.parse_connect(b"CONNECT Api.Example.com:443 HTTP/1.1\r\n\r\n") == (
            ALLOWED,
            443,
        )

    @pytest.mark.parametrize(
        "line",
        [b"CONNECT [2001:db8::1]:443 HTTP/1.1", b"CONNECT localhost:443 HTTP/1.1", b"\xff\xfe"],
    )
    def test_what_is_not_a_dns_name_is_malformed(self, line: bytes) -> None:
        with pytest.raises(client_egress.TunnelRefusedError, match="malformed"):
            client_egress.parse_connect(line + b"\r\n\r\n")


class TestConfig:
    @pytest.mark.parametrize(
        "host",
        [
            "*.example.com",
            "Example.com",
            "example.com:443",
            "https://example.com",
            "192.0.2.7",
            "localhost",
            "",
        ],
    )
    def test_hosts_are_exact_lower_case_names(self, host: str) -> None:
        assert not is_dns_name(host)
        with pytest.raises(ValidationError):
            ClientEgressConfig(source_networks=["192.0.2.0/29"], hosts=[host])

    @pytest.mark.parametrize(
        "address", ["192.0.2.7", "10.1", "0x7f.1", "2130706433.0", "example.123", "host.0"]
    )
    def test_a_numeric_last_label_marks_an_address_however_it_is_spelled(
        self, address: str
    ) -> None:
        assert not is_dns_name(address)

    @pytest.mark.parametrize(
        "name",
        [
            "api.example.com",
            "a1.example.com",
            "1.example.com",
            "123.example.co1",
            "xn--bcher-kva.example",
        ],
    )
    def test_digits_elsewhere_in_a_name_are_fine(self, name: str) -> None:
        assert is_dns_name(name)

    def test_a_name_listed_twice_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            ClientEgressConfig(source_networks=["192.0.2.0/29"], hosts=[ALLOWED, ALLOWED])

    def test_networks_and_hosts_are_both_required(self) -> None:
        with pytest.raises(ValidationError):
            ClientEgressConfig(source_networks=[], hosts=[ALLOWED])
        with pytest.raises(ValidationError):
            ClientEgressConfig(source_networks=["192.0.2.0/29"], hosts=[])

    def test_there_is_no_field_for_a_credential(self) -> None:
        assert set(ClientEgressConfig.model_fields) == {"source_networks", "hosts"}

    def test_a_honeypot_cannot_have_one(self) -> None:
        with pytest.raises(ValidationError, match="client_egress does not apply"):
            Profile(
                name="agent3",
                auth=AuthConfig(bearer_token_env="TOK"),
                honeypot=True,
                client_egress=ClientEgressConfig(source_networks=["192.0.2.0/29"], hosts=[ALLOWED]),
            )


class TestOneAgentPerNetwork:
    def test_two_profiles_cannot_share_an_egress_network(self) -> None:
        registry = {
            "agent1": _profile("agent1", networks=("192.0.2.0/28",)),
            "agent2": _profile("agent2", networks=("192.0.2.8/29",)),
        }
        with pytest.raises(ProfileConfigError, match="one agent per network"):
            _check_egress_networks(registry)

    def test_an_egress_network_cannot_be_another_profiles_matrix_network(self) -> None:
        other = Profile(
            name="agent2",
            auth=AuthConfig(bearer_token_env="TOK"),
            matrix_ingress=MatrixIngressConfig(source_networks=["192.0.2.0/29"]),
        )
        registry = {"agent1": _profile("agent1", networks=("192.0.2.0/29",)), "agent2": other}
        with pytest.raises(ProfileConfigError, match="one agent per network"):
            _check_egress_networks(registry)

    def test_a_profile_may_use_one_network_for_both_of_its_own(self) -> None:
        profile = _profile("agent1", networks=("192.0.2.0/29",))
        profile.matrix_ingress = MatrixIngressConfig(source_networks=["192.0.2.0/29"])
        _check_egress_networks(
            {"agent1": profile, "agent2": _profile("agent2", ("198.51.100.0/29",))}
        )

    def test_resolution_picks_the_profile_holding_the_address(self) -> None:
        registry = {
            "agent1": _profile("agent1", networks=("192.0.2.0/29",)),
            "agent2": _profile("agent2", networks=("198.51.100.0/29",)),
        }
        assert profile_for_address("198.51.100.3", registry, "client_egress") is registry["agent2"]
        assert profile_for_address("203.0.113.1", registry, "client_egress") is None
        assert profile_for_address(None, registry, "client_egress") is None
        assert (
            ipaddress.ip_address("192.0.2.1") in registry["agent1"].client_egress.source_networks[0]
        )


class TestAnAgentCannotReloadItsOwnEgress:
    def test_added_hosts_are_held(self) -> None:
        before = _profile()
        after = _profile(hosts=(ALLOWED, OTHER))
        assert "client_egress" in _hold_perimeter_fields(before, after)
        assert after.client_egress == before.client_egress

    def test_a_new_block_is_held_off(self) -> None:
        before = Profile(name="agent1", auth=AuthConfig(bearer_token_env="TOK"))
        after = _profile()
        assert "client_egress" in _hold_perimeter_fields(before, after)
        assert after.client_egress is None

    def test_an_unchanged_block_is_not_reported(self) -> None:
        assert "client_egress" not in _hold_perimeter_fields(_profile(), _profile())


class TestAFirstBlockNeedsARestart:
    """The listener is a socket bound at startup; a reload cannot open one."""

    @staticmethod
    def _active(tmp_path: Path, *, listening: bool) -> ActiveConfig:
        plain = Profile(name="agent1", auth=AuthConfig(bearer_token_env="TOK"))
        return ActiveConfig(
            path=tmp_path / "profiles.yaml",
            config=GatewayConfig(profiles={"agent1": plain}),
            llm_providers={},
            alert_route_registered=False,
            matrix_route_registered=False,
            oauth_route_registered=False,
            egress_listener_configured=listening,
        )

    def test_a_block_added_to_a_gateway_with_no_listener_is_reported(self, tmp_path: Path) -> None:
        notes = _unapplied(
            self._active(tmp_path, listening=False), GatewayConfig(profiles={"agent1": _profile()})
        )
        assert any("client_egress" in note and "restart" in note for note in notes)

    def test_a_block_edited_under_a_running_listener_is_not(self, tmp_path: Path) -> None:
        notes = _unapplied(
            self._active(tmp_path, listening=True), GatewayConfig(profiles={"agent1": _profile()})
        )
        assert not any("client_egress" in note for note in notes)


class TestABurstIsOneLookup:
    """#449: a client opens its connections together, and a lookup never queues."""

    @staticmethod
    def _counting(monkeypatch: pytest.MonkeyPatch, answer: list[str]) -> list[str]:
        asked: list[str] = []

        def lookup(host: str, _port: int) -> list[str]:
            asked.append(host)
            return answer

        monkeypatch.setattr(egress, "_lookup", lookup)
        return asked

    async def test_tunnels_that_start_together_share_one_lookup(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        release = threading.Event()
        asked: list[str] = []

        def slow(host: str, _port: int) -> list[str]:
            asked.append(host)
            release.wait(5)
            return [PUBLIC_ADDRESS]

        monkeypatch.setattr(egress, "_lookup", slow)
        burst = [asyncio.create_task(_connect()) for _ in range(12)]
        try:
            # More tunnels than the profile has resolver slots, all waiting.
            for _ in range(200):
                if client_egress._open.get("agent1", 0) == len(burst):
                    break
                await asyncio.sleep(0.01)
        finally:
            release.set()
        answers = await asyncio.gather(*burst)
        assert all(response.startswith(b"HTTP/1.1 200") for response, _r, _w in answers)
        assert asked == [ALLOWED]
        for _response, _reader, writer in answers:
            writer.close()

    async def test_a_checked_name_answers_the_next_tunnel_until_it_expires(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        asked = self._counting(monkeypatch, [PUBLIC_ADDRESS])
        for _ in range(3):
            response, _reader, writer = await _connect()
            assert response.startswith(b"HTTP/1.1 200")
            writer.close()
        assert asked == [ALLOWED]

        key = ("agent1", ALLOWED)
        _until, target = client_egress._checked[key]
        client_egress._checked[key] = (time.monotonic() - 1, target)
        response, _reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 200")
        assert asked == [ALLOWED, ALLOWED]
        writer.close()

    async def test_a_refusal_is_not_kept(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._counting(monkeypatch, ["10.0.0.5"])
        refused, _reader, writer = await _connect()
        assert refused.startswith(b"HTTP/1.1 403")
        writer.close()
        assert client_egress._checked == {}

        self._counting(monkeypatch, [PUBLIC_ADDRESS])
        response, _reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 200")
        writer.close()

    async def test_another_profile_does_not_read_this_ones_answer(
        self, listener: dict[str, Profile], upstream: _Upstream
    ) -> None:
        _response, _reader, writer = await _connect()
        writer.close()
        assert list(client_egress._checked) == [("agent1", ALLOWED)]

    async def test_no_free_resolver_slot_is_busy_and_not_a_defense_block(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        audit_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        taken = threading.BoundedSemaphore(1)
        taken.acquire()
        monkeypatch.setattr(egress, "_lookup_slots", taken)
        response, reader, writer = await _connect()
        assert response.startswith(b"HTTP/1.1 503")
        assert b"X-Trentina-Reason: resolver_busy\r\n" in response
        assert await _closed(reader)
        (row,) = await _settled(audit_db)
        assert (row["outcome"], row["error_message"]) == ("denied_guard", "resolver_busy")
        assert upstream.connections == 0
        writer.close()

    async def test_a_refusal_after_an_expired_answer_leaves_nothing_behind(
        self,
        listener: dict[str, Profile],
        upstream: _Upstream,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The stale answer is not what a later tunnel connects to."""
        self._counting(monkeypatch, [PUBLIC_ADDRESS])
        _response, _reader, writer = await _connect()
        writer.close()
        key = ("agent1", ALLOWED)
        other = ("agent2", ALLOWED)
        _until, target = client_egress._checked[key]
        client_egress._checked[key] = (time.monotonic() - 1, target)
        client_egress._checked[other] = (time.monotonic() - 1, target)

        self._counting(monkeypatch, ["10.0.0.5"])
        refused, _reader, writer = await _connect()
        assert refused.startswith(b"HTTP/1.1 403")
        writer.close()
        assert key not in client_egress._checked
        # Another profile's entry is its own: neither read nor removed here.
        assert other in client_egress._checked

    async def test_a_cancelled_check_keeps_nothing_and_is_asked_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()
        calls = 0

        async def check(_url: str) -> egress.ResolvedTarget:
            nonlocal calls
            calls += 1
            await release.wait()
            return egress.ResolvedTarget(ALLOWED, 443, (PUBLIC_ADDRESS,))

        monkeypatch.setattr(client_egress, "check_url", check)
        profile = _profile()
        key = (profile.name, ALLOWED)
        waiting = asyncio.create_task(client_egress.checked_target(profile, ALLOWED))
        while not calls:  # until the shared check itself is running
            await asyncio.sleep(0)
        client_egress._checking[key].cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert key not in client_egress._checked
        assert key not in client_egress._checking

        release.set()
        target = await client_egress.checked_target(profile, ALLOWED)
        assert target.addresses == (PUBLIC_ADDRESS,)
        assert calls == 2
        assert client_egress._checked.pop(key)[1] is target

    async def test_a_client_that_hangs_up_does_not_cancel_the_check_for_the_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()

        async def check(_url: str) -> egress.ResolvedTarget:
            await release.wait()
            return egress.ResolvedTarget(ALLOWED, 443, (PUBLIC_ADDRESS,))

        monkeypatch.setattr(client_egress, "check_url", check)
        profile = _profile()
        gone = asyncio.create_task(client_egress.checked_target(profile, ALLOWED))
        stays = asyncio.create_task(client_egress.checked_target(profile, ALLOWED))
        await asyncio.sleep(0)
        gone.cancel()
        release.set()
        assert (await stays).addresses == (PUBLIC_ADDRESS,)
        client_egress._checked.clear()
