"""The built-in carrier: MCP's streamable HTTP (#740).

Every ``http(s)://`` backend rides it, and every one did before carriers had a
name: this is ``gateway/backend.py``'s old ``_connect_streamable_http`` and the
byte cap's httpx hooks, moved behind the ``Carrier`` contract unchanged.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import httpx2
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from .base import Carrier, CarrierTarget, Reading, ReadStream, ResponseOverflowError, WriteStream

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

#: The POSTs whose 401 means "ran nothing, authorize and try again".
_AUTH_METHODS = frozenset({"initialize", "tools/list", "tools/call"})


class _ResponseRefused(httpx2.StreamError):
    """Raised inside the SDK's read. A ``StreamError`` because that is what
    the SDK catches there, so the pending request resolves at once as an error
    instead of waiting out ``timeout_seconds``."""


class _CappedStream(httpx2.AsyncByteStream):
    """One response's raw byte stream, counted as it arrives and cut at the cap.

    Per RESPONSE, not per session, as it always was: each is its own
    ``Reading`` over the one ``limit``, and an overflow is reported on the
    session's."""

    def __init__(self, inner: Any, reading: Reading) -> None:
        self._inner = inner
        self._reading = reading

    async def __aiter__(self) -> AsyncIterator[bytes]:
        counted = Reading(self._reading.limit)
        async for chunk in self._inner:
            try:
                counted.count(len(chunk))
            except ResponseOverflowError as exc:
                self._reading.overflowed = True
                raise _ResponseRefused(str(exc)) from exc
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


def identity_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """The backend's headers, with ``Accept-Encoding: identity`` in place of any other."""
    kept = {k: v for k, v in (headers or {}).items() if k.lower() != "accept-encoding"}
    kept["Accept-Encoding"] = "identity"
    return kept


async def tag_request(request: httpx2.Request) -> None:
    """Request hook: note which JSON-RPC method a POST carries."""
    if request.method == "POST":
        try:
            method = json.loads(request.content).get("method")
        except (ValueError, AttributeError, httpx2.RequestNotRead):
            method = None
        request.extensions["trentina_method"] = method


def response_hook(reading: Reading) -> Any:
    """The response hook that reports one session's replies into ``reading``.

    The MCP SDK reads a JSON reply with ``response.aread()`` and an SSE reply
    through ``EventSource``, both unbounded, and gives no hook between the
    socket and either. So the cap sits under them, on the transport's RAW
    stream: this swaps ``response.stream`` for a counting wrapper before the
    SDK reads a byte. Raw, because httpx decompresses after that stream, and a
    count taken after decompression is the #276 bug. For the same reason the
    client asks for ``identity`` and an encoded reply is refused outright
    rather than inflated. A 401 on the SSE GET stream is not counted as
    ``unauthorized``; the SDK carries on past it (#479).
    """

    async def hook(response: httpx2.Response) -> None:
        method = response.request.extensions.get("trentina_method")
        if response.status_code == HTTPStatus.UNAUTHORIZED and method in _AUTH_METHODS:
            reading.unauthorized = True
        elif method == "tools/call" and response.is_success:
            reading.call_accepted = True
        encoding = response.headers.get("content-encoding", "")
        if any(part.strip().lower() not in ("", "identity") for part in encoding.split(",")):
            reading.encoded = True
            await _refuse(response, "backend response is content-encoded")
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > reading.limit:
            reading.overflowed = True
            await _refuse(response, f"backend response over {reading.limit} bytes")
        response.stream = _CappedStream(response.stream, reading)

    return hook


async def _refuse(response: httpx2.Response, reason: str) -> None:
    """Close the unread response and raise. httpx2 closes a response whose
    hook raised as well; closing here does not depend on that."""
    await response.aclose()
    raise _ResponseRefused(reason)


class HttpCarrier(Carrier):
    """MCP streamable HTTP, for an ``http(s)://`` backend."""

    name = "http"

    @asynccontextmanager
    async def connect(
        self, target: CarrierTarget, reading: Reading
    ) -> AsyncIterator[tuple[ReadStream, WriteStream]]:
        """One session's client, read under ``reading``'s cap (#267).

        The client is ``httpx2``, not ``httpx``: that is the fork the MCP SDK
        builds on and annotates for. The two are separate distributions with
        separate import names and coexist happily, so trentina's own ``httpx``
        use elsewhere (quarantine's Gemini REST calls) is untouched.

        The client comes from the SDK's ``create_mcp_http_client`` so a backend
        with headers gets the same timeouts (30s connect, 300s read) as one
        without. A bare ``httpx2.AsyncClient`` inherits httpx's 5-second
        default, which cut every authenticated call off at ~5s regardless of
        ``timeout_seconds`` -- that deadline is the caller's
        ``asyncio.wait_for`` and cannot lengthen an HTTP timeout underneath it.

        The SDK has shipped the stream bundle as both a 2-tuple and a 3-tuple
        (trailing session-id callback); that trailing element is unused here,
        so take the first two either way rather than unpacking a fixed width.
        """
        http_client = create_mcp_http_client(headers=identity_headers(target.headers))
        http_client.event_hooks = {"request": [tag_request], "response": [response_hook(reading)]}
        async with (
            http_client,
            streamable_http_client(target.url, http_client=http_client) as streams,
        ):
            yield streams[0], streams[1]
