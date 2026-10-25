# Fixture for trentina-dial-outside-egress.
import asyncio
import socket


async def tunnel(address, port):
    # ruleid: trentina-dial-outside-egress
    reader, writer = await asyncio.open_connection(address, port)
    return reader, writer


def pooled_connection(address, port):
    # ruleid: trentina-dial-outside-egress
    return socket.create_connection((address, port))


def raw_socket():
    # ruleid: trentina-dial-outside-egress
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


async def loop_dial(loop, protocol, address, port):
    # ruleid: trentina-dial-outside-egress
    return await loop.create_connection(protocol, address, port)


async def checked_dial(address, port):
    # A dial to an already-checked address is sanctioned inline, the way the
    # CONNECT tunnel's own module is sanctioned by the rule's paths.exclude.
    # ok: trentina-dial-outside-egress
    return await asyncio.open_connection(address, port)  # nosemgrep: trentina-dial-outside-egress -- checked address
