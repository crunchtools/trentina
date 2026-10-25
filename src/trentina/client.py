"""HTTP client for fetching web content."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import NamedTuple

import httpx

from .config import int_env
from .egress import open_guarded
from .errors import FetchError, UnsupportedContentTypeError

log = logging.getLogger(__name__)

FETCH_TIMEOUT = 30.0
# Wall clock for the whole fetch, every hop and the body (#295). FETCH_TIMEOUT
# is per read and resets on every byte. 5 MB in 60 s is ~85 KB/s.
FETCH_DEADLINE = 60.0
DEFAULT_FETCH_CONCURRENCY = 8
MAX_RESPONSE_SIZE = 5_000_000  # 5 MB
MAX_ERROR_BODY = 2048
USER_AGENT = "trentina/0.1.0 (security-scanner)"

TEXT_CONTENT_TYPES = frozenset(
    {
        "application/atom+xml",
        "application/ecmascript",
        "application/javascript",
        "application/json",
        "application/ld+json",
        "application/rss+xml",
        "application/x-ndjson",
        "application/xhtml+xml",
        "application/xml",
        "application/yaml",
    }
)
"""Media types the defense pipeline can read as text.

Anything outside this set — images, archives, office documents —
decodes into replacement characters that tokenize into hundreds of
thousands of meaningless tokens."""

PDF_CONTENT_TYPE = "application/pdf"
"""The one binary type fetched (#369): it is handed on as base64 and read by
``transforms/pdf.py`` or, undelivered as text, by the unpack stage."""

TEXT_CONTENT_SUFFIXES = ("+json", "+xml")
"""Structured-syntax suffixes (RFC 6839) that imply a text body."""


def _is_text_content_type(content_type: str) -> bool:
    """True if the media type is text the defense pipeline can handle.

    An absent content-type is common on plain files, so it counts as text;
    the size cap and L1 handle whatever actually turns up.
    """
    media_type = content_type.split(";", 1)[0].strip().lower()

    if not media_type:
        return True
    if media_type.startswith("text/"):
        return True
    if media_type in TEXT_CONTENT_TYPES:
        return True
    return media_type.endswith(TEXT_CONTENT_SUFFIXES)


def _build_redirect_chain(resp: httpx.Response) -> list[dict[str, object]] | None:
    """Extract the redirect chain from an httpx response, if any."""
    if not resp.history:
        return None
    chain = []
    for hop in resp.history:
        chain.append(
            {
                "url": str(hop.url),
                "status": hop.status_code,
                "content_type": hop.headers.get("content-type", ""),
            }
        )
    chain.append(
        {
            "url": str(resp.url),
            "status": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
        }
    )
    return chain


async def _error_body(resp: httpx.Response) -> str | None:
    """The first ``MAX_ERROR_BODY`` bytes of a 4xx body, read while the stream is open.

    Reading it after the ``stream`` block closed, as this used to, always
    failed, so no 4xx body ever reached the advisory scan. A body that breaks
    off mid-read still leaves the status to report.
    """
    buf = bytearray()
    try:
        # open_guarded refused an encoded body before this, so these are the
        # bytes that crossed the wire, not a decompressor's output (#276).
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) >= MAX_ERROR_BODY:
                break
    except httpx.HTTPError as exc:
        log.debug("could not read a %d error body: %s", resp.status_code, type(exc).__name__)
        return None
    return bytes(buf[:MAX_ERROR_BODY]).decode("utf-8", errors="replace")


_slots: tuple[asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]] | None = None


def _fetch_slot() -> asyncio.Semaphore:
    """This profile's fetch slots: ``TRENTINA_FETCH_CONCURRENCY`` at once (#295).

    Per profile, so one agent holding its slots open against a slow server
    queues only itself; standalone is one tenant and one key. One table per
    event loop, because a semaphore binds to the loop it first waits on.
    """
    from .gateway.context import get_current_profile

    global _slots
    loop = asyncio.get_running_loop()
    if _slots is None or _slots[0] is not loop:
        _slots = (loop, {})
    profile = get_current_profile()
    key = profile.name if profile is not None else ""
    slot = _slots[1].get(key)
    if slot is None:
        limit = int_env("TRENTINA_FETCH_CONCURRENCY", DEFAULT_FETCH_CONCURRENCY, minimum=1)
        slot = _slots[1][key] = asyncio.Semaphore(limit)
    return slot


class Fetched(NamedTuple):
    """A fetched page, and every URL that served a hop of it.

    ``hops`` is each redirect's URL in order, ending with the URL the body
    came from. A trust decision about the page is a decision about every one
    of them, never only the URL the agent asked for (#298).
    """

    content: str
    content_type: str
    hops: tuple[str, ...]


async def fetch_url(url: str) -> Fetched:
    """Fetch a URL and return it as a :class:`Fetched` (content, content type, hops).

    Every hop passes the egress guard (``egress.open_guarded``). The response
    is streamed so the content-type and size can be rejected from headers
    alone, before a large or binary body is pulled over the wire and decoded.
    Servers lie about or omit content-length, so the cap is re-checked
    against bytes actually received. Those are wire bytes: the guard asks for
    ``identity`` and refuses an encoded body (#276), so nothing is inflated.

    The whole fetch, waiting for one of the profile's slots included, is
    bounded by ``FETCH_DEADLINE``.

    Raises FetchError on failure, UnsupportedContentTypeError on non-text,
    EgressRefusedError when the guard refuses a hop.
    """
    try:
        async with asyncio.timeout(FETCH_DEADLINE), _fetch_slot():
            return await _fetch(url)
    except TimeoutError as exc:
        raise FetchError(url, "Request timed out") from exc


async def _fetch(url: str) -> Fetched:
    try:
        async with open_guarded(
            "GET",
            url,
            timeout=FETCH_TIMEOUT,
            deadline=FETCH_DEADLINE,
            headers={"User-Agent": USER_AGENT},
        ) as resp:
            status = resp.status_code
            # Not only >= 400: a 3xx the guard did not follow (304, a 300
            # with no Location) is no page either, as raise_for_status held.
            if not resp.is_success:
                error_body = await _error_body(resp) if 400 <= status < 500 else None
                raise FetchError(url, f"HTTP {status}", status_code=status, error_body=error_body)

            content_type = resp.headers.get("content-type", "text/html")
            is_pdf = content_type.split(";", 1)[0].strip().lower() == PDF_CONTENT_TYPE
            if not is_pdf and not _is_text_content_type(content_type):
                raise UnsupportedContentTypeError(
                    url, content_type, redirect_chain=_build_redirect_chain(resp)
                )

            declared = resp.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > MAX_RESPONSE_SIZE:
                raise FetchError(url, f"Response too large: {declared} bytes")

            buf = bytearray()
            # Identity only (open_guarded refuses anything else), so the cap
            # counts what crossed the wire, never a decompressor's output (#276).
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_RESPONSE_SIZE:
                    raise FetchError(url, f"Response too large: exceeds {MAX_RESPONSE_SIZE} bytes")

            # A PDF travels as canonical base64 (#369): stage 1 converts it to
            # the text its pages show, and with `trentina_preprocess: false`
            # the unpack stage reads inside the file itself.
            body = (
                base64.b64encode(bytes(buf)).decode("ascii")
                if is_pdf
                else bytes(buf).decode(resp.encoding or "utf-8", errors="replace")
            )
            return Fetched(
                body,
                content_type,
                (*(str(hop.url) for hop in resp.history), str(resp.url)),
            )

    except httpx.TimeoutException as exc:
        raise FetchError(url, "Request timed out") from exc
    except httpx.RequestError as exc:
        raise FetchError(url, str(exc)) from exc
