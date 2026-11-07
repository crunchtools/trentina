"""The ``unix`` carrier: an MCP server that speaks stdio, behind a socket (#724).

Many MCP servers ship stdio-only. The gateway does not start one: it is hardened
against exactly that, and process supervision is the init system's job. The host
runs the server under systemd socket activation (a ``.socket`` with
``Accept=yes`` and a ``.service`` with ``StandardInput=socket``), which wires
each connection to a fresh server process's stdin and stdout. This carrier
connects to that socket and speaks what the server speaks on stdio: one
JSON-RPC message per line, as the MCP SDK's own stdio client does. Closing the
session closes the socket; the server reads EOF and exits.

There is no credential on this wire and no HTTP, so a ``unix://`` backend takes
no ``headers``, ``auth`` or ``federated`` (``Backend.carrier_matches_url``), and
``reading.unauthorized`` is never set. Where the socket may be is
``socket_roots``. See docs/stdio-backends.md.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import anyio
from mcp import types
from mcp.shared.message import SessionMessage

from .base import Carrier, CarrierTarget, Reading, ReadStream, WriteStream
from .socket_roots import admitted, socket_path

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from anyio.abc import ByteStream

#: The bytes asked of the socket at once. The cap is counted on what arrives,
#: before any of it is decoded, whatever the size of a read.
READ_SIZE = 65536


def _parsed(line: bytes) -> SessionMessage | Exception:
    """One line of the server's output, as the session reads it. A line that is
    not JSON-RPC reaches the session as the error it is, as on the SDK's stdio."""
    try:
        return SessionMessage(types.jsonrpc_message_adapter.validate_json(line, by_name=False))
    except ValueError as exc:
        return exc


class UnixCarrier(Carrier):
    """MCP stdio framing over a unix socket, for a ``unix://`` backend."""

    name = "unix"

    @asynccontextmanager
    async def connect(
        self, target: CarrierTarget, reading: Reading
    ) -> AsyncIterator[tuple[ReadStream, WriteStream]]:
        """Connect to the admitted socket and carry one session over it."""
        with admitted(socket_path(target.url)) as path:
            stream = await anyio.connect_unix(path)
        to_session, from_server = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        to_server, from_session = anyio.create_memory_object_stream[SessionMessage](0)

        async def read_server(sock: ByteStream) -> None:
            buffer = b""
            async with to_session:
                while True:
                    try:
                        chunk = await sock.receive(READ_SIZE)
                    except (anyio.EndOfStream, anyio.ClosedResourceError):
                        return
                    # Counted before a byte is parsed: past the cap this
                    # raises and the session ends with it (#267).
                    reading.count(len(chunk))
                    *lines, buffer = (buffer + chunk).split(b"\n")
                    for line in lines:
                        if line.strip():
                            await to_session.send(_parsed(line))

        async def write_server(sock: ByteStream) -> None:
            async with from_session:
                async for sent in from_session:
                    message = sent.message
                    wire = message.model_dump_json(by_alias=True, exclude_unset=True)
                    await sock.send(wire.encode() + b"\n")
                    if isinstance(message, types.JSONRPCRequest) and message.method == "tools/call":
                        # It has left: from here the server may have run it.
                        reading.call_accepted = True

        async with stream, anyio.create_task_group() as tasks:
            tasks.start_soon(read_server, stream)
            tasks.start_soon(write_server, stream)
            try:
                yield from_server, to_server
            finally:
                tasks.cancel_scope.cancel()
