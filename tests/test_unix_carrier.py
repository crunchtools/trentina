"""The ``unix`` carrier against a real stdio server, started the way systemd would (#724).

``_SocketActivation`` stands in for a ``.socket`` with ``Accept=yes`` and a
``.service`` with ``StandardInput=socket``: for each connection it starts
``tests/probe_stdio_server.py`` with the connection as its stdin and stdout.
Everything above the socket is the gateway's own path, unpatched below
``call_backend_tool``/``list_backend_tools``.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from tests.probe_stdio_server import CANARY
from tests.refusal_shape import refused
from trentina import config as config_mod
from trentina.core.stages import IngressDecision
from trentina.gateway.backend import _tool_list_cache, call_backend_tool, list_backend_tools
from trentina.gateway.circuit import DEFAULT_FAILURE_THRESHOLD, State, breaker
from trentina.gateway.errors import (
    BackendCallError,
    BackendResponseTooLargeError,
    ProfileConfigError,
)
from trentina.gateway.loader import _check_transports_and_carriers
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.transports import registry
from trentina.transports.mcp import route_jsonrpc
from trentina.transports.socket_roots import SocketRefusedError, admitted, socket_path
from trentina.transports.unix_carrier import UnixCarrier

ROOT = Path(__file__).resolve().parent.parent


class _SocketActivation:
    """What systemd does for ``Accept=yes``: a stdio server per connection."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(8)
        self.servers: list[subprocess.Popen[bytes]] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                self.servers.append(
                    subprocess.Popen(
                        [sys.executable, "-m", "tests.probe_stdio_server"],
                        stdin=conn.fileno(),
                        stdout=conn.fileno(),
                        stderr=subprocess.DEVNULL,
                        cwd=ROOT,
                    )
                )

    def close(self) -> None:
        self.listener.close()
        for server in self.servers:
            server.kill()
            server.wait()


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "sockets"
    root.mkdir()
    monkeypatch.setenv("TRENTINA_SOCKET_ROOTS", str(root))
    config_mod._config = None
    breaker.reset()
    _tool_list_cache.clear()
    yield root
    config_mod._config = None
    breaker.reset()
    _tool_list_cache.clear()


@pytest.fixture
def activated(roots: Path) -> Iterator[Path]:
    path = roots / "probe.sock"
    unit = _SocketActivation(path)
    yield path
    unit.close()


def _backend(path: Path) -> Backend:
    return Backend(url=f"unix://{path}", timeout_seconds=30, list_timeout_seconds=30)


def _profile(path: Path) -> Profile:
    profile = Profile(
        name="agent1",
        short_names=False,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="block", modes=["block"]),
        backends={"probe": _backend(path)},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return profile


class TestTheSocketCarriesTheSession:
    def test_a_unix_backend_rides_the_unix_carrier(self, roots: Path) -> None:
        assert isinstance(registry.carrier_for(_backend(roots / "x.sock")), UnixCarrier)

    async def test_the_list_and_the_call_ride_it(self, activated: Path) -> None:
        backend = _backend(activated)
        tools = await list_backend_tools("probe", backend)
        assert {t["name"] for t in tools} == {"echo", "poisoned"}
        result = await call_backend_tool("probe", backend, "echo", {"text": "hello"})
        assert result.content == [{"type": "text", "text": "hello"}]

    async def test_what_it_carries_is_judged(self, activated: Path) -> None:
        _tool_list_cache[(f"unix://{activated}", "")] = [{"name": "poisoned"}]
        blocked = IngressDecision(
            warning={"flagged_by": "L1", "risk_level": "high", "blocked": True},
            blocked=True,
            refusal={"reason": "flagged by L1", "mode": "block", "flagged_by": "L1"},
        )
        scan = AsyncMock(return_value=blocked)
        with (
            patch("trentina.orchestrator.scan_tool_response", scan),
            patch("trentina.gateway.parts.scan_tool_response", scan),
        ):
            response = await route_jsonrpc(
                _profile(activated),
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": f"probe{NAMESPACE_SEP}poisoned", "arguments": {}},
                },
            )
        judged = scan.await_args.kwargs["content_blocks"]
        assert any(CANARY in block.get("text", "") for block in judged)
        assert refused(response)["flagged_by"] == "L1"
        assert CANARY not in str(response)

    async def test_a_read_past_the_cap_is_refused(
        self, activated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("trentina.gateway.backend.response_byte_cap", lambda: 4096)
        with pytest.raises(BackendResponseTooLargeError):
            await call_backend_tool("probe", _backend(activated), "echo", {"text": "x" * 16384})


class TestAWireThatWillNotOpen:
    async def test_a_socket_nobody_listens_on_opens_the_circuit(self, roots: Path) -> None:
        stale = roots / "stale.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as gone:
            gone.bind(str(stale))
        backend = _backend(stale)
        for _ in range(DEFAULT_FAILURE_THRESHOLD):
            with pytest.raises(BackendCallError):
                await call_backend_tool("probe", backend, "echo", {"text": "x"})
        assert breaker.get_state(backend.url) is State.OPEN

    async def test_a_refusal_never_logs_the_path(
        self, roots: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        with pytest.raises(BackendCallError):
            await call_backend_tool("probe", _backend(roots / "missing.sock"), "echo", {})
        assert str(roots) not in caplog.text
        assert "missing.sock" not in caplog.text


class TestConfinementAtConnect:
    def _reason(self, path: Path) -> str:
        with pytest.raises(SocketRefusedError) as caught, admitted(str(path)):
            pass
        return caught.value.reason

    def test_a_missing_socket(self, roots: Path) -> None:
        assert self._reason(roots / "nothing.sock") == "not_found"

    def test_a_regular_file(self, roots: Path) -> None:
        (roots / "file.sock").write_text("")
        assert self._reason(roots / "file.sock") == "not_a_socket"

    def test_a_link_to_a_socket_outside(self, roots: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(str(outside))
            (roots / "link.sock").symlink_to(outside)
            assert self._reason(roots / "link.sock") == "not_a_socket"

    def test_a_directory_link_out_of_the_roots(self, roots: Path, tmp_path: Path) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(str(elsewhere / "x.sock"))
            (roots / "dir").symlink_to(elsewhere)
            assert self._reason(roots / "dir" / "x.sock") == "outside_socket_roots"

    def test_a_path_outside_the_roots(self, roots: Path, tmp_path: Path) -> None:
        assert self._reason(tmp_path / "x.sock") == "outside_socket_roots"

    def test_an_admitted_socket_is_reached_through_its_checked_directory(
        self, activated: Path
    ) -> None:
        with admitted(str(activated)) as path:
            assert path.startswith("/proc/self/fd/")
            assert path.endswith("/probe.sock")
            assert os.path.samefile(path, activated)


class TestConfinementAtLoad:
    def _profile(self, url: str) -> Profile:
        return Profile(
            name="agent1",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"probe": Backend(url=url)},
        )

    def test_a_socket_under_a_root_loads(self, roots: Path) -> None:
        _check_transports_and_carriers("agent1", self._profile(f"unix://{roots}/a.sock"))

    def test_outside_every_root_is_refused(self, roots: Path, tmp_path: Path) -> None:
        with pytest.raises(ProfileConfigError, match="outside_socket_roots"):
            _check_transports_and_carriers("agent1", self._profile(f"unix://{tmp_path}/a.sock"))

    def test_no_roots_refuses_every_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_SOCKET_ROOTS", raising=False)
        config_mod._config = None
        try:
            with pytest.raises(ProfileConfigError, match="no_socket_roots"):
                _check_transports_and_carriers("agent1", self._profile("unix:///run/mcp/a.sock"))
        finally:
            config_mod._config = None

    def test_a_relative_root_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.errors import ConfigError

        monkeypatch.setenv("TRENTINA_SOCKET_ROOTS", "run/mcp")
        config_mod._config = None
        try:
            with pytest.raises(ConfigError, match="TRENTINA_SOCKET_ROOTS"):
                config_mod.get_config()
        finally:
            config_mod._config = None


class TestTheUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "unix://host/run/a.sock",
            "unix:///run/a.sock?x=1",
            "unix:///run/a.sock#f",
            "unix:///run/%2e%2e/a.sock",
            "unix:///run/../a.sock",
            "unix:///run/mcp/",
            "unix:///run/" + "a" * 81,
        ],
    )
    def test_a_malformed_url_is_refused(self, url: str) -> None:
        with pytest.raises(ValueError, match=r"unix://|socket file name"):
            Backend(url=url)

    def test_the_path_is_the_url_path(self) -> None:
        assert socket_path("unix:///run/mcp/hub.sock") == "/run/mcp/hub.sock"

    @pytest.mark.parametrize(
        "field",
        [
            {"headers": {"Authorization": "Bearer x"}},
            {"auth": {"type": "oauth"}},
            {"federated": {"primary_key_env": "K"}},
        ],
    )
    def test_what_only_http_carries_is_refused(self, field: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match=r"does not apply to a unix:// backend"):
            Backend(url="unix:///run/mcp/hub.sock", **field)

    def test_no_plugin_takes_a_socket(self) -> None:
        with pytest.raises(ValueError, match="rides the 'unix' carrier"):
            Backend(url="unix:///run/mcp/hub.sock", carrier="acme:wire")
