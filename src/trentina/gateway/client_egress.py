"""Client egress: a CONNECT tunnel to the hosts a profile names (#442).

An agent on an internal network reaches its tools through the gateway. Its
own client often cannot: a coding agent's model API, its session service and
its git forge are HTTPS the client opens itself. Rather than give the agent a
route out, the gateway carries those connections, on a listener of its own
that speaks ``CONNECT`` and nothing else.

What the tunnel decides, in order, each one deterministic:

- **who is calling**: the peer address picks the profile, as it does for the
  Matrix proxy (#330). No credential rides in the proxy URL, because clients
  print proxy URLs in errors and status output.
- **where it may go**: an exact name in that profile's ``client_egress.hosts``,
  port 443, and through ``egress.check_url`` so every address it resolves to
  is global. The tunnel connects to an address that was checked. A client
  opens its connections in a burst, so one check answers every tunnel to the
  same name that starts while it runs or within ``CHECKED_TTL`` of it (#449).
- **what it may speak**: TLS that names the host it asked for. The first
  record must be a ClientHello whose SNI is the CONNECT host, so the tunnel
  cannot carry another protocol or open with another site's name. This is a
  check on the handshake, not on what follows: inside the TLS the client can
  still ask the server for a different virtual host, and whether a shared
  front end honours that is the server's decision, not the gateway's.

What it does not decide: anything about the bytes inside. They are TLS, the
gateway holds no key, and no layer reads them. That is known gap 26 in
``docs/defense-pipeline.md``. The tunnel bounds where an agent's client can
talk and records how much; it does not judge what.

Since #535 this module is the listener's own half, on the perimeter spine
(``transports/perimeter.py``): ``admit`` parses the CONNECT request, ``relay``
opens the tunnel, checks the ClientHello and copies both ways, ``respond``
words a refusal. The caller's address, the hosts and port, the slot, the
checked dial, the listener's lifecycle and the row are the spine's.

One ``gateway_calls`` row per tunnel, written when it closes or is refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from ..outcomes import Outcome
from ..transports.base import (
    SPINE_REFUSALS,
    Admitted,
    AgentUrl,
    Listener,
    PeerAddress,
    Refusal,
    RefusedError,
)
from .destination import MAX_DESTINATION_CHARS
from .profile import CLIENT_EGRESS_PORT, is_dns_name

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .relay import Operation

logger = logging.getLogger(__name__)

BACKEND = "egress"
TOOL = "connect"

HEAD_LIMIT = 8192
"""Longest request head read. A CONNECT line and a few headers fit many times over."""

HEAD_TIMEOUT = 10.0
HELLO_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0

IDLE_TIMEOUT = 900.0
"""Seconds with no byte in either direction before a tunnel is closed. A
client holding a streaming response sees keep-alives well inside this."""

MAX_TUNNELS_PER_PROFILE = 64
"""Tunnels one profile may hold open. A client pools a handful per host, but
one profile serves every session of its agent: a fan-out of parallel
subagents holds one streaming tunnel each for minutes. At 16, fifteen such
streams to one API refused the rest."""

_CHUNK = 65536
_RECORD_HEADER = 5
_HANDSHAKE_HEADER = 4
_TLS_HANDSHAKE = 22
_TLS_MAJOR = 3
_CLIENT_HELLO = 1
_MAX_RECORD = 16384
_MAX_HELLO = 4 * _MAX_RECORD
_SNI_EXTENSION = 0
_SNI_HOST_NAME = 0

REASONS = frozenset(
    {
        "malformed",
        "method",
        "port",
        "host_not_listed",
        "busy",
        "connect_failed",
        "no_hello",
        "not_tls",
        "sni_mismatch",
        "unknown_caller",
    }
)
"""Every ``error_message`` this module writes besides the egress guard's own
reason codes. Closed, so the audit never carries the caller's text there."""


class TunnelRefusedError(RefusedError):
    """A tunnel the gateway will not open, or will not keep open. A
    ``RefusedError``, so the perimeter spine answers it like any other."""

    def __init__(self, status: HTTPStatus, reason: str, outcome: Outcome) -> None:
        super().__init__(reason, status=status, outcome=outcome)


@dataclass
class _Tunnel:
    """One tunnel's live relay state. ``sent`` is from the agent, ``received`` to
    it; both are mapped onto the ``Operation`` when the tunnel finishes.
    ``established`` and ``last_activity`` are relay-only (whether the 200 has gone
    out, and the shared idle clock the two copy directions update)."""

    sent: int = 0
    received: int = 0
    established: bool = False
    last_activity: float = field(default_factory=time.monotonic)


def parse_connect(head: bytes) -> tuple[str, int]:
    """The host and port a request head asks to be connected to.

    Raises:
        TunnelRefusedError: not a CONNECT request, or one whose target is not ``name:port``.
    """
    try:
        method, target, version = head.split(b"\r\n", 1)[0].decode("ascii").split(" ")
    except ValueError:
        raise TunnelRefusedError(
            HTTPStatus.BAD_REQUEST, "malformed", Outcome.DENIED_GUARD
        ) from None
    if method != "CONNECT":
        # No plain-HTTP proxying: a request the gateway could read is one it
        # would owe a verdict on, and that path is fetch_tool.
        raise TunnelRefusedError(HTTPStatus.METHOD_NOT_ALLOWED, "method", Outcome.DENIED_GUARD)
    host, colon, port = target.rpartition(":")
    host = host.lower().removesuffix(".")
    if (
        not version.startswith("HTTP/1.")
        or not colon
        or not port.isdigit()
        or not is_dns_name(host)
    ):
        raise TunnelRefusedError(HTTPStatus.BAD_REQUEST, "malformed", Outcome.DENIED_GUARD)
    return host, int(port)


class _Cursor:
    """Bounds-checked reads over a ClientHello. Running off the end is ``ValueError``."""

    def __init__(self, message: bytes) -> None:
        self._data = message
        self._at = 0

    def take(self, count: int) -> bytes:
        end = self._at + count
        if count < 0 or end > len(self._data):
            raise ValueError("truncated")
        chunk = self._data[self._at : end]
        self._at = end
        return chunk

    def number(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, width: int) -> _Cursor:
        return _Cursor(self.take(self.number(width)))

    def rest(self) -> bytes:
        return self.take(len(self._data) - self._at)

    def more(self) -> bool:
        return self._at < len(self._data)


def client_hello_sni(hello: bytes) -> str | None:
    """The server name in a ClientHello handshake message, or None if it has none.

    Args:
        hello: the whole message, starting at its four-byte handshake header.

    Raises:
        ValueError: the bytes are not a well-formed ClientHello.
    """
    message = _Cursor(hello)
    if message.number(1) != _CLIENT_HELLO:
        raise ValueError("not a ClientHello")
    body = message.vector(3)
    body.take(2 + 32)  # legacy_version, random
    body.vector(1)  # legacy_session_id
    body.vector(2)  # cipher_suites
    body.vector(1)  # legacy_compression_methods
    if not body.more():
        return None
    extensions = body.vector(2)
    while extensions.more():
        kind = extensions.number(2)
        extension = extensions.vector(2)
        if kind != _SNI_EXTENSION:
            continue
        names = extension.vector(2)
        while names.more():
            name_type = names.number(1)
            name = names.vector(2)
            if name_type == _SNI_HOST_NAME:
                return name.rest().decode("ascii").lower().removesuffix(".")
        return None
    return None


async def read_client_hello(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    """Read TLS records until one whole ClientHello has arrived.

    Returns:
        The bytes read off the wire, to forward unchanged, and the ClientHello
        message inside them.

    Raises:
        TunnelRefusedError: the client sent something other than a TLS ClientHello, or
            nothing in time.
    """
    wire = bytearray()
    message = bytearray()
    try:
        while True:
            header = await reader.readexactly(_RECORD_HEADER)
            length = int.from_bytes(header[3:5], "big")
            if (
                header[0] != _TLS_HANDSHAKE
                or header[1] != _TLS_MAJOR
                or not 0 < length <= _MAX_RECORD
            ):
                raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "not_tls", Outcome.DENIED_GUARD)
            fragment = await reader.readexactly(length)
            wire += header + fragment
            message += fragment
            if len(message) < _HANDSHAKE_HEADER:
                continue
            needed = _HANDSHAKE_HEADER + int.from_bytes(message[1:4], "big")
            if message[0] != _CLIENT_HELLO or needed > _MAX_HELLO:
                raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "not_tls", Outcome.DENIED_GUARD)
            if len(message) >= needed:
                return bytes(wire), bytes(message[:needed])
    except asyncio.IncompleteReadError:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "no_hello", Outcome.DENIED_GUARD) from None


async def _copy(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tunnel: _Tunnel, counter: str
) -> None:
    """Copy one direction until it ends or the whole tunnel has gone idle."""
    while True:
        try:
            payload = await asyncio.wait_for(reader.read(_CHUNK), IDLE_TIMEOUT)
        except TimeoutError:
            # This direction was quiet. The tunnel is idle only if the other was too.
            if time.monotonic() - tunnel.last_activity >= IDLE_TIMEOUT:
                return
            continue
        if not payload:
            break
        tunnel.last_activity = time.monotonic()
        setattr(tunnel, counter, getattr(tunnel, counter) + len(payload))
        writer.write(payload)
        await writer.drain()
    with contextlib.suppress(OSError):
        if writer.can_write_eof():
            writer.write_eof()


async def _relay(
    client: tuple[asyncio.StreamReader, asyncio.StreamWriter],
    upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tunnel: _Tunnel,
) -> None:
    """Copy both directions until both have ended. A reset on either ends both."""
    directions = [
        asyncio.create_task(_copy(client[0], upstream[1], tunnel, "sent")),
        asyncio.create_task(_copy(upstream[0], client[1], tunnel, "received")),
    ]
    try:
        # A reset is how many clients end a connection; it is not a failure.
        with contextlib.suppress(OSError):
            await asyncio.gather(*directions)
    finally:
        for task in directions:
            task.cancel()
        await asyncio.gather(*directions, return_exceptions=True)


async def _checked_hello(reader: asyncio.StreamReader, host: str) -> bytes:
    """The client's first TLS records, once they name ``host``; to forward unchanged.

    Raises:
        TunnelRefusedError: no ClientHello in time, not TLS, or another name.
    """
    try:
        wire, hello = await asyncio.wait_for(read_client_hello(reader), HELLO_TIMEOUT)
        named = client_hello_sni(hello)
    except TimeoutError:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "no_hello", Outcome.DENIED_GUARD) from None
    except ValueError:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "not_tls", Outcome.DENIED_GUARD) from None
    if named != host:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "sni_mismatch", Outcome.DENIED_GUARD)
    return wire


#: The tunnel's refusals: the spine's, each reason this module raises (each
#: raise carries its own status and outcome), and the tunnel's own spelling of
#: four of the spine's.
REFUSALS: Mapping[str, Refusal] = {
    **{reason: Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_GUARD) for reason in REASONS},
    **SPINE_REFUSALS,
    "unauthorized": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_GUARD, wire="unknown_caller"),
    "malformed_head": Refusal(HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD, wire="malformed"),
    "upstream_unreachable": Refusal(
        HTTPStatus.BAD_GATEWAY, Outcome.BACKEND_ERROR, wire="connect_failed"
    ),
}


def _status_line(status: HTTPStatus, reason: str | None = None) -> bytes:
    """An answer to the CONNECT request. ``reason`` is one of the closed codes."""
    lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
    if reason is not None:
        lines += [f"X-Trentina-Reason: {reason}", "Content-Length: 0", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


class ConnectListener(Listener):
    """``CONNECT host:443`` on ``--egress-port``: a TLS tunnel to a listed host."""

    name = BACKEND
    operation = TOOL
    auth = PeerAddress("client_egress")
    refusals = REFUSALS
    ports = frozenset({CLIENT_EGRESS_PORT})
    head_limit = HEAD_LIMIT
    head_timeout = HEAD_TIMEOUT
    slots = MAX_TUNNELS_PER_PROFILE

    def admit(self, head: bytes) -> Admitted:
        """The host and port the CONNECT names; ``host`` is the caller's text,
        so it is the row's destination and goes nowhere else (#266)."""
        host, port = parse_connect(head)
        return Admitted(
            origin=AgentUrl(f"https://{host}:{port}"),
            destination=f"{host}:{CLIENT_EGRESS_PORT}"[:MAX_DESTINATION_CHARS],
        )

    async def relay(self, client: Any, upstream: Any, op: Operation) -> None:
        """Answer 200, hold the first TLS record to the CONNECT host, then copy.

        Raises:
            TunnelRefusedError: no ClientHello in time, not TLS, or another name;
                the stream has been answered, so closing is the refusal.
        """
        tunnel = _Tunnel()
        try:
            client[1].write(_status_line(HTTPStatus.OK))
            with contextlib.suppress(OSError):
                await client[1].drain()
            host = (op.destination or "").rpartition(":")[0]
            wire = await _checked_hello(client[0], host)
            tunnel.sent = len(wire)
            upstream[1].write(wire)
            await upstream[1].drain()
            await _relay(client, upstream, tunnel)
        finally:
            op.sent, op.received = tunnel.sent, tunnel.received

    def respond(self, refused: RefusedError) -> bytes:
        """The refusal line; a guard refusal names the guard's own reason."""
        shown = refused.detail if refused.reason == "denied_guard" else refused.reason
        status = HTTPStatus(refused.status or HTTPStatus.FORBIDDEN)
        return _status_line(status, shown or refused.reason)
