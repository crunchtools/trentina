"""End-to-end tests against a real MCP backend over real HTTP.

Issue #107, item 4. Every other backend test patches ``_do_list_tools`` /
``_do_call_tool`` and asserts against hand-built stand-ins, so the gateway's
actual job -- speaking MCP to another process -- was never exercised. A
production outage on 2026-09-05 happened with CI fully green, and these are the
tests that would have caught it: nothing here is faked, so an SDK field rename
or a framework API removal fails right here.

The filename contains "integration" deliberately: ``conftest.py`` uses that to
skip stripping ``GEMINI_API_KEY``.

Protocol coverage note: the gateway is exercised across every protocol revision
the SDK knows, using a single fastmcp 4 stack. That works because a fastmcp 4
server honours whatever revision the client asks for (measured across seven
production backends in #107), so one stack covers the whole matrix -- no second
interpreter with an older SDK required.
"""

from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

from trentina.gateway.app import MCP_SESSION_ID_HEADER
from trentina.gateway.backend import (
    _disable_output_validation,
    call_backend_tool,
    list_backend_tools,
)
from trentina.gateway.errors import BackendCallError
from trentina.gateway.profile import Backend

REPO_ROOT = Path(__file__).resolve().parent.parent

# Startup is a uvicorn boot, not a network round trip; generous because CI
# runners are slower and a flaky fixture here would get this suite deleted,
# which is the opposite of the point.
_BOOT_TIMEOUT_S = 30.0
_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _initialize_body(protocol_version: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "trentina-probe", "version": "0"},
        },
    }


def _parse_mcp_response(resp: httpx.Response) -> dict[str, Any]:
    """Read a JSON-RPC reply from either a JSON or an SSE response.

    Streamable HTTP may answer a POST with ``text/event-stream``, in which case
    the JSON-RPC body arrives as the first ``data:`` frame.
    """
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return dict(json.loads(line[len("data:") :].strip()))
        raise AssertionError(f"no data frame in SSE response: {resp.text!r}")
    return dict(resp.json())


def _probe_initialize(url: str, revision: str) -> dict[str, Any]:
    """Hand-roll an ``initialize`` at a chosen revision, then hang up cleanly.

    ``ClientSession.initialize`` hardcodes the SDK's newest handshake revision
    with no override, so exercising the other revisions means speaking JSON-RPC
    directly.

    Every ``initialize`` opens a server-side session, so the DELETE hangs up
    rather than leaving one dangling for the rest of the module. Measured at
    ~0.02s, so it costs nothing worth saving.
    """
    resp = httpx.post(url, json=_initialize_body(revision), headers=_MCP_HEADERS, timeout=10.0)
    session_id = resp.headers.get(MCP_SESSION_ID_HEADER)
    try:
        return _parse_mcp_response(resp)
    finally:
        if session_id:
            with contextlib.suppress(httpx.HTTPError):
                httpx.request(
                    "DELETE",
                    url,
                    headers={**_MCP_HEADERS, MCP_SESSION_ID_HEADER: session_id},
                    timeout=10.0,
                )


@pytest.fixture(scope="module")
def backend_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Run tests/probe_backend_server.py as a real subprocess, yield its URL.

    The server's output goes to a FILE, never to ``subprocess.PIPE``. uvicorn
    logs a line per request, and an undrained pipe buffer fills at around 64KB,
    at which point the server blocks forever on write and every subsequent tool
    call times out. That failure looks like a transport bug in whichever test
    happens to run once the buffer is full -- it moves when you reorder tests
    and vanishes when you run them in small groups, which is a thoroughly
    misleading way to spend an afternoon. A file never blocks, and it is still
    there to report when the server dies.
    """
    port = _free_port()
    log_path = tmp_path_factory.mktemp("probe-backend") / "server.log"

    def _log() -> str:
        return log_path.read_text(errors="replace") if log_path.exists() else ""

    with log_path.open("w") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "tests.probe_backend_server", str(port)],
            cwd=REPO_ROOT,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        url = f"http://127.0.0.1:{port}/mcp"

        deadline = time.monotonic() + _BOOT_TIMEOUT_S
        try:
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(
                        f"probe backend exited early rc={proc.returncode}:\n{_log()}"
                    )
                with contextlib.suppress(httpx.HTTPError):
                    resp = httpx.post(
                        url,
                        json=_initialize_body(HANDSHAKE_PROTOCOL_VERSIONS[-1]),
                        headers=_MCP_HEADERS,
                        timeout=2.0,
                    )
                    if resp.status_code < 500:
                        break
                if time.monotonic() > deadline:
                    raise RuntimeError(f"probe backend did not come up in time:\n{_log()}")
                time.sleep(0.1)

            yield url
        finally:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=10)
            if proc.poll() is None:
                proc.kill()


@pytest.fixture
def backend(backend_url: str) -> Backend:
    return Backend(url=backend_url, timeout_seconds=30.0, list_timeout_seconds=30.0)


class TestRealTransportToolList:
    """list_backend_tools against a process that is genuinely speaking MCP."""

    async def test_lists_real_tools(self, backend: Backend) -> None:
        tools = await list_backend_tools("probe", backend)

        assert {t["name"] for t in tools} >= {"echo", "structured_echo", "explode"}

    async def test_serializes_wire_format_keys_not_python_field_names(
        self, backend: Backend
    ) -> None:
        """The wire format stayed camelCase even though the SDK fields did not.

        This is the assertion that a fake cannot make honestly: the tool object
        being serialized came off a real socket, so it carries only the SDK's
        real field names.
        """
        tools = await list_backend_tools("probe", backend)
        echo = next(t for t in tools if t["name"] == "echo")

        assert "inputSchema" in echo, "wire key must stay camelCase"
        assert "input_schema" not in echo, "python field name must not leak to the wire"
        assert echo["inputSchema"]["properties"]["text"]["type"] == "string"
        assert echo["description"]

    async def test_schema_survives_round_trip_as_json(self, backend: Backend) -> None:
        """Whatever we emit has to survive json.dumps -- the router will do it."""
        tools = await list_backend_tools("probe", backend)

        assert json.loads(json.dumps(tools)) == tools


class TestRealTransportToolCall:
    """call_backend_tool against a real backend process."""

    async def test_round_trips_text_content(self, backend: Backend) -> None:
        result = await call_backend_tool("probe", backend, "echo", {"text": "hi"})

        assert result.is_error is False
        assert any(b.get("text") == "echo:hi" for b in result.content)
        assert all(b["type"] == "text" for b in result.content)

    async def test_round_trips_structured_content(self, backend: Backend) -> None:
        result = await call_backend_tool("probe", backend, "structured_echo", {"text": "hi"})

        assert result.is_error is False
        assert result.structured_content is not None
        assert result.structured_content["echoed"] == "hi"

    async def test_backend_tool_error_reports_as_is_error(self, backend: Backend) -> None:
        """A raising tool must surface as is_error, not as a transport failure.

        ``is_error`` is read off a real CallToolResult here. Reading the wrong
        field name would silently yield False and audit a failure as a success.
        """
        result = await call_backend_tool("probe", backend, "explode", {})

        assert result.is_error is True

    async def test_unknown_tool_reports_in_band_error(self, backend: Backend) -> None:
        """An unknown tool is a tool-level error, not a transport failure.

        MCP reports it in-band as ``is_error`` on a normal result rather than
        as a protocol error, so the gateway must not treat it as a backend
        outage and trip the circuit breaker.
        """
        result = await call_backend_tool("probe", backend, "no_such_tool", {})

        assert result.is_error is True


class TestProtocolRevisionMatrix:
    """The gateway must not be pinned to one protocol revision (issue #107).

    Parametrized over the SDK's registry rather than a literal list, so a new
    revision shipped by a future SDK is covered automatically.
    """

    @pytest.mark.parametrize("revision", HANDSHAKE_PROTOCOL_VERSIONS)
    def test_backend_honours_every_handshake_revision(
        self, backend_url: str, revision: str
    ) -> None:
        body = _probe_initialize(backend_url, revision)

        assert "error" not in body, body
        negotiated = body["result"]["protocolVersion"]
        assert negotiated in HANDSHAKE_PROTOCOL_VERSIONS
        # The server may cap below what was asked, but must never answer with
        # something newer than the client offered.
        asked = HANDSHAKE_PROTOCOL_VERSIONS.index(revision)
        assert HANDSHAKE_PROTOCOL_VERSIONS.index(negotiated) <= asked

    async def test_tool_calls_work_at_the_oldest_supported_revision(
        self, backend: Backend, backend_url: str
    ) -> None:
        """Negotiating an old revision is not enough -- tools must still work."""
        assert "error" not in _probe_initialize(backend_url, HANDSHAKE_PROTOCOL_VERSIONS[0])

        result = await call_backend_tool("probe", backend, "echo", {"text": "old"})
        assert any(b.get("text") == "echo:old" for b in result.content)


class TestOutputValidationOverride:
    """``validate_output_schema=False`` must actually disable validation.

    SDK 2.x renamed ``_validate_tool_result`` to ``validate_tool_result``.
    Assigning the old name still "succeeds" -- it just creates an unused
    attribute -- so this override could silently stop working and leave
    validation on for the buggy backends the flag exists to tolerate.
    """

    async def test_patches_a_validator_that_actually_exists(self, backend: Backend) -> None:
        from mcp import ClientSession

        from trentina.gateway.backend import _noop_validate
        from trentina.transports.base import CarrierTarget, Reading
        from trentina.transports.http_carrier import HttpCarrier

        async with (
            HttpCarrier().connect(CarrierTarget(backend.url, {}), Reading(1 << 20)) as (
                read,
                write,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            _disable_output_validation(session)

            patched = [
                name
                for name in ("validate_tool_result", "_validate_tool_result")
                if getattr(session, name, None) is _noop_validate
            ]
            assert patched, (
                "output-schema validation override patched nothing on a real "
                "ClientSession -- the SDK renamed the validator hook again"
            )

    async def test_call_succeeds_with_validation_disabled(self, backend_url: str) -> None:
        backend = Backend(
            url=backend_url,
            timeout_seconds=30.0,
            list_timeout_seconds=30.0,
            validate_output_schema=False,
        )

        result = await call_backend_tool("probe", backend, "structured_echo", {"text": "hi"})

        assert result.is_error is False
        assert result.structured_content == {"echoed": "hi"}

    async def test_missing_validator_hook_fails_loudly(self) -> None:
        """A silent no-op here would invert the profile's stated intent."""

        class _NoValidator:
            _tool_output_schemas: ClassVar[dict[str, Any]] = {}

        with pytest.raises(BackendCallError, match="no known validator hook"):
            _disable_output_validation(_NoValidator())
