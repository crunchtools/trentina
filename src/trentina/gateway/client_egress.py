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

One ``gateway_calls`` row per tunnel, written when it closes or is refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from functools import partial
from http import HTTPStatus
from typing import TYPE_CHECKING

from ..database import record_gateway_call
from ..egress import check_url
from ..errors import EgressRefusedError
from ..logsafe import exc_kind
from ..outcomes import Outcome
from .context import profile_context
from .destination import MAX_DESTINATION_CHARS, DestinationKind
from .loader import get_active_config
from .profile import CLIENT_EGRESS_PORT, is_dns_name, profile_for_address

if TYPE_CHECKING:
    from ..egress import ResolvedTarget
    from .profile import Profile

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

MAX_TUNNELS_PER_PROFILE = 16
"""Tunnels one profile may hold open. A client pools a handful per host."""

CHECKED_TTL = 5.0
"""Seconds a name's checked addresses answer the same profile's next tunnel
(#449). A client opens a pool of connections to two or three names at once,
and each lookup takes one of the profile's four resolver slots, which never
queue: without this the fifth tunnel of a burst was refused. Safe for a
tunnel and not for ``fetch``: the name is one the operator listed, checked
against the list before this is asked, and the tunnel dials the addresses
that were checked. A refusal is never kept."""

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

RESOLVER_BUSY = "resolver_busy"
"""The egress guard's reason when no resolver slot was free. It is the
gateway's load and not a verdict on the name, so a tunnel answers it as it
answers its own ``busy``: 503, ``denied_guard``."""


class TunnelRefusedError(Exception):
    """A tunnel the gateway will not open, or will not keep open."""

    def __init__(self, status: HTTPStatus, reason: str, outcome: Outcome) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.outcome = outcome


@dataclass
class _Tunnel:
    """One tunnel's counters. ``sent`` is from the agent, ``received`` to it."""

    sent: int = 0
    received: int = 0
    established: bool = False
    last_activity: float = field(default_factory=time.monotonic)


_listen: tuple[str, int] | None = None
_server: asyncio.Server | None = None
_open: dict[str, int] = {}
_tasks: set[asyncio.Task[None]] = set()
_checking: dict[tuple[str, str], asyncio.Task[ResolvedTarget]] = {}
_checked: dict[tuple[str, str], tuple[float, ResolvedTarget]] = {}


def configure(host: str, port: int) -> None:
    """Record where the listener would bind. Called at startup, before serving."""
    global _listen
    _listen = (host, port)


async def start() -> None:
    """Start listening, if a profile has ``client_egress``. Idempotent.

    With no such block anywhere there is no second socket. A block added by
    a later reload does not start one: ``reload_profiles`` says a restart is
    needed.
    """
    global _server
    active = get_active_config()
    if _listen is None or _server is not None or active is None:
        return
    if not active.egress_listener_configured:
        return
    host, port = _listen
    _server = await asyncio.start_server(_accept, host, port, limit=_CHUNK)
    bound = _server.sockets[0].getsockname()[1]
    logger.warning("client egress: listening on port %d", bound)


async def stop() -> None:
    """Stop listening and close every tunnel."""
    global _server
    if _server is None:
        return
    _server.close()
    for task in list(_tasks):
        task.cancel()
    await asyncio.gather(*_tasks, return_exceptions=True)
    await _server.wait_closed()
    _server = None
    _open.clear()
    _checked.clear()


# TRUST: the peer address picks the profile (#442, after #330)
#   untrusted: every byte the caller sends
#   judged-by: nothing; an address is resolved, not judged
#   on-failure: fail-closed; an address in no profile's networks gets 403
#   owner: client_egress._accept
#   evidence: T2 the address is the accepted socket's peer, and this listener
#     reads no forwarding header; T3 loader._check_egress_networks (one
#     profile per address)


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


async def open_upstream(
    address: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to one checked address. A seam: tests point it at a local server."""
    return await asyncio.open_connection(address, port)


def _settle(key: tuple[str, str], task: asyncio.Task[ResolvedTarget]) -> None:
    """Keep a finished check's answer for ``CHECKED_TTL``; drop a refusal."""
    _checking.pop(key, None)
    now = time.monotonic()
    for stale in [name for name, (until, _) in _checked.items() if until <= now]:
        del _checked[stale]
    # Read here so a check nobody waited out is not reported as unretrieved.
    if not task.cancelled() and task.exception() is None:
        _checked[key] = (now + CHECKED_TTL, task.result())


async def _check(profile: Profile, host: str) -> ResolvedTarget:
    """``host``'s checked addresses, from one lookup per burst (#449).

    Tunnels to one name that start together share the check in flight, and
    ones that start within ``CHECKED_TTL`` of it share its answer. The check
    is shielded: a client that hangs up does not cancel it for the others.

    Raises:
        EgressRefusedError: the egress guard refused the name.
    """
    key = (profile.name, host)
    held = _checked.get(key)
    if held is not None and time.monotonic() < held[0]:
        return held[1]
    task = _checking.get(key)
    if task is None:
        with profile_context(profile):
            task = asyncio.create_task(check_url(f"https://{host}:{CLIENT_EGRESS_PORT}"))
        _checking[key] = task
        task.add_done_callback(partial(_settle, key))
    return await asyncio.shield(task)


async def _connect(
    profile: Profile, host: str
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Resolve ``host`` through the egress guard and connect to what was checked."""
    try:
        target = await _check(profile, host)
    except EgressRefusedError as exc:
        if exc.reason == RESOLVER_BUSY:
            raise TunnelRefusedError(
                HTTPStatus.SERVICE_UNAVAILABLE, exc.reason, Outcome.DENIED_GUARD
            ) from None
        raise TunnelRefusedError(
            HTTPStatus.FORBIDDEN, exc.reason, Outcome.BLOCKED_DEFENSE
        ) from None
    # Each checked address in turn; one that refuses or times out is passed over.
    for address in target.addresses:
        with contextlib.suppress(OSError, TimeoutError):
            return await asyncio.wait_for(open_upstream(address, target.port), CONNECT_TIMEOUT)
    raise TunnelRefusedError(HTTPStatus.BAD_GATEWAY, "connect_failed", Outcome.BACKEND_ERROR)


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


def _audit(
    profile: Profile,
    host: str | None,
    outcome: Outcome,
    started: float,
    reason: str | None = None,
    tunnel: _Tunnel | None = None,
) -> None:
    """One ``gateway_calls`` row per tunnel, opened or refused.

    ``host`` is the caller's text, so it is stored as a destination and goes
    nowhere else (#266). For a tunnel ``bytes_arrived`` is what came back
    from the destination and ``bytes_delivered`` is what the agent sent to
    it. Like ``router._audit``, a lost row never fails what it records.
    """
    destination = f"{host}:{CLIENT_EGRESS_PORT}"[:MAX_DESTINATION_CHARS] if host else None
    try:
        record_gateway_call(
            profile.name,
            BACKEND,
            TOOL,
            outcome.value,
            int((time.monotonic() - started) * 1000),
            reason,
            bytes_arrived=tunnel.received if tunnel else None,
            bytes_delivered=tunnel.sent if tunnel else None,
            destination=destination,
            destination_kind=DestinationKind.TUNNEL.value if destination else None,
        )
    except Exception as exc:
        logger.warning(
            "client egress: audit row lost profile=%s err=%s", profile.name, exc_kind(exc)
        )


async def _respond(
    writer: asyncio.StreamWriter, status: HTTPStatus, reason: str | None = None
) -> None:
    """Answer the CONNECT request. ``reason`` is one of this module's closed codes."""
    lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
    if reason is not None:
        lines += [f"X-Trentina-Reason: {reason}", "Content-Length: 0", "Connection: close"]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    with contextlib.suppress(OSError):
        await writer.drain()


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        raise TunnelRefusedError(
            HTTPStatus.BAD_REQUEST, "malformed", Outcome.DENIED_GUARD
        ) from None
    if len(head) > HEAD_LIMIT:
        raise TunnelRefusedError(HTTPStatus.BAD_REQUEST, "malformed", Outcome.DENIED_GUARD)
    return head


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


async def _carry(
    profile: Profile,
    target: tuple[str, int],
    client: tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tunnel: _Tunnel,
) -> None:
    """Admit one target, then hold a tunnel to it: connect, answer, check, relay.

    Raises:
        TunnelRefusedError: the target is not this profile's to reach, the
            profile holds its tunnels already, or a later check refused it.
    """
    host, port = target
    block = profile.client_egress
    if port != CLIENT_EGRESS_PORT:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "port", Outcome.DENIED_GUARD)
    if block is None or host not in block.hosts:
        raise TunnelRefusedError(HTTPStatus.FORBIDDEN, "host_not_listed", Outcome.DENIED_ALLOWLIST)
    if _open.get(profile.name, 0) >= MAX_TUNNELS_PER_PROFILE:
        raise TunnelRefusedError(HTTPStatus.SERVICE_UNAVAILABLE, "busy", Outcome.DENIED_GUARD)

    _open[profile.name] = _open.get(profile.name, 0) + 1
    upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    try:
        upstream = await _connect(profile, host)
        await _respond(client[1], HTTPStatus.OK)
        tunnel.established = True
        wire = await _checked_hello(client[0], host)
        tunnel.sent = len(wire)
        upstream[1].write(wire)
        await upstream[1].drain()
        await _relay(client, upstream, tunnel)
    finally:
        _open[profile.name] -= 1
        if upstream is not None:
            upstream[1].close()


async def _serve(
    profile: Profile, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """One connection from a known profile, from its request line to its audit row."""
    started = time.monotonic()
    host: str | None = None
    tunnel = _Tunnel()
    outcome, reason = Outcome.OK, None
    try:
        target = parse_connect(await _read_head(reader))
        host = target[0]
        await _carry(profile, target, (reader, writer), tunnel)
    except TunnelRefusedError as refusal:
        # Once 200 has gone out the client is speaking TLS; closing is the answer.
        if not tunnel.established:
            await _respond(writer, refusal.status, refusal.reason)
        outcome, reason = refusal.outcome, refusal.reason
    except OSError as exc:
        logger.warning("client egress: tunnel failed err=%s", exc_kind(exc))
        outcome, reason = Outcome.BACKEND_ERROR, "connect_failed"
    except asyncio.CancelledError:
        _audit(profile, host, Outcome.CANCELLED, started, tunnel=tunnel)
        raise
    _audit(profile, host, outcome, started, reason, tunnel)


async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """A new connection: find its profile, or refuse it without acting on a byte."""
    task = asyncio.current_task()
    if task is not None:
        _tasks.add(task)
    try:
        active = get_active_config()
        peer = writer.get_extra_info("peername")
        profile = None
        if active is not None and peer:
            profile = profile_for_address(peer[0], active.config.profiles, "client_egress")
        if profile is None:
            logger.warning("client egress: refused a caller in no profile's source_networks")
            # Read the request before answering, without acting on it: closing
            # on unread bytes resets the connection and the caller never sees
            # the status.
            with contextlib.suppress(TunnelRefusedError):
                await _read_head(reader)
            await _respond(writer, HTTPStatus.FORBIDDEN, "unknown_caller")
            return
        await _serve(profile, reader, writer)
    finally:
        if task is not None:
            _tasks.discard(task)
        writer.close()
        with contextlib.suppress(OSError, asyncio.CancelledError):
            await writer.wait_closed()
