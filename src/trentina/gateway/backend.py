"""Backend MCP connection management with persistent tool list caching.

Opens a fresh MCP session per call (streamable_http_client creates anyio
task groups that cannot cross task boundaries, so pooling is not viable).
Caches tool lists per URL indefinitely — invalidated only on explicit flush
or reconnect, persisted in SQLite across restarts. Crucially, a fetch failure
never evicts: a cached backend keeps being served from cache through a transient
outage, so a backend blip can never wipe the cache (which previously triggered a
fan-out stampede). Concurrent misses for the same URL coalesce into a single
in-flight fetch.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, TypeVar

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND

from ..database import delete_all_tool_lists, delete_tool_list, save_tool_list
from ..logsafe import exc_kind, redact_source, safe_url
from . import edge_key
from .circuit import breaker
from .context import get_current_profile
from .errors import (
    BackendCallError,
    BackendNeedsAuthError,
    BackendRejectedCallError,
    BackendResponseTooLargeError,
    GatewayError,
)
from .profile import federation_audience

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from .backend_tokens import BackendGrant
    from .profile import Backend, Profile

_T = TypeVar("_T")
#: The POSTs whose 401 means "ran nothing, authorize and try again".
_AUTH_METHODS = frozenset({"initialize", "tools/list", "tools/call"})


BYTES_PER_TOKEN = 32
"""Wire bytes allowed per admitted token when capping a backend response (#267).

``Config.admission_tokens`` counts L2 tokens in the text ``defend()`` reads;
this cap counts bytes on the wire before any of that text exists. English
runs about 4 bytes a token. The factor has to cover the worst case, not the
usual one, because a cap tighter than admission would refuse content
admission would have judged: a token that is one CJK character JSON-escaped
as ``\\uXXXX`` is 6 bytes, the same text can arrive twice (``content`` and
``structuredContent``, deduplicated only after the read), and SSE and
JSON-RPC framing add more. 32 is that worst case with headroom; the cap's job
is bounding memory, and admission still decides what is judged. With paging
on (#340) the tokens counted are ``Config.paged_tokens``, every part of the
largest response that can be delivered."""

MIN_RESPONSE_BYTES = 1_048_576
"""The cap never drops below 1 MiB, so a tiny ``CLASSIFIER_MAX_TOKENS`` cannot
make a backend's ``tools/list`` unreadable."""


def response_byte_cap() -> int:
    """The most bytes one backend response may stream before the read stops."""
    from ..config import get_config

    # ``paged_tokens``, not the admission cap: a response delivered in parts
    # (#340) is read whole before it is cut, and is the admission cap itself
    # when paging is off.
    return max(MIN_RESPONSE_BYTES, get_config().paged_tokens * BYTES_PER_TOKEN)


class _ResponseRefused(httpx2.StreamError):
    """Raised inside the SDK's read. A ``StreamError`` because that is what
    the SDK catches there, so the pending request resolves at once as an error
    instead of waiting out ``timeout_seconds``."""


class _CappedStream(httpx2.AsyncByteStream):
    """The transport's raw byte stream, counted as it arrives and cut at the cap."""

    def __init__(self, inner: Any, cap: ResponseCap) -> None:
        self._inner = inner
        self._cap = cap

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._inner:
            total += len(chunk)
            if total > self._cap.limit:
                self._cap.overflowed = True
                raise _ResponseRefused(f"backend response over {self._cap.limit} bytes")
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


@dataclass
class ResponseCap:
    """A byte cap on every response one backend session receives (#267).

    The MCP SDK reads a JSON reply with ``response.aread()`` and an SSE reply
    through ``EventSource``, both unbounded, and gives no hook between the
    socket and either. So the cap sits under them, on the transport's RAW
    stream: an httpx response hook swaps ``response.stream`` for a counting
    wrapper before the SDK reads a byte. Raw, because httpx decompresses
    after that stream, and a count taken after decompression is the #276 bug.
    For the same reason the client asks for ``identity`` and an encoded reply
    is refused outright rather than inflated.

    One per call. ``overflowed`` is how ``call_backend_tool`` tells a cut
    read from any other failure, whatever shape the SDK gave the error.
    """

    limit: int
    overflowed: bool = False
    encoded: bool = False
    #: A request that ran nothing came back 401: the session's ``initialize``
    #: or the ``tools/list`` / ``tools/call`` itself. A 401 on the SSE GET
    #: stream is not counted; the SDK carries on past it (#479).
    unauthorized: bool = False
    #: The ``tools/call`` POST was answered 2xx: the backend may have run it,
    #: so nothing about this call is retried, whatever fails after.
    call_accepted: bool = False

    async def tag(self, request: httpx2.Request) -> None:
        """Request hook: note which JSON-RPC method a POST carries."""
        if request.method == "POST":
            try:
                method = json.loads(request.content).get("method")
            except (ValueError, AttributeError, httpx2.RequestNotRead):
                method = None
            request.extensions["trentina_method"] = method

    async def hook(self, response: httpx2.Response) -> None:
        method = response.request.extensions.get("trentina_method")
        if response.status_code == HTTPStatus.UNAUTHORIZED and method in _AUTH_METHODS:
            self.unauthorized = True
        elif method == "tools/call" and response.is_success:
            self.call_accepted = True
        encoding = response.headers.get("content-encoding", "")
        if any(part.strip().lower() not in ("", "identity") for part in encoding.split(",")):
            self.encoded = True
            await self._refuse(response, "backend response is content-encoded")
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.limit:
            self.overflowed = True
            await self._refuse(response, f"backend response over {self.limit} bytes")
        response.stream = _CappedStream(response.stream, self)

    def reset(self) -> None:
        """Clear what one attempt saw, before the next."""
        self.overflowed = self.encoded = self.unauthorized = self.call_accepted = False

    @staticmethod
    async def _refuse(response: httpx2.Response, reason: str) -> None:
        """Close the unread response and raise. httpx2 closes a response whose
        hook raised as well; closing here does not depend on that."""
        await response.aclose()
        raise _ResponseRefused(reason)


def _identity_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """The backend's headers, with ``Accept-Encoding: identity`` in place of any other."""
    kept = {k: v for k, v in (headers or {}).items() if k.lower() != "accept-encoding"}
    kept["Accept-Encoding"] = "identity"
    return kept


@asynccontextmanager
async def _connect_streamable_http(
    url: str,
    headers: dict[str, str] | None,
    cap: ResponseCap | None = None,
) -> AsyncIterator[Any]:
    """Adapt this module's ``headers`` dict onto mcp's ``http_client=`` API.

    ``streamable_http_client`` only manages an ``httpx2.AsyncClient``'s
    lifecycle when it creates one itself -- passing a pre-configured client
    makes the caller responsible for closing it.

    The client is ``httpx2``, not ``httpx``: that is the fork the MCP SDK
    builds on and annotates for. The two are separate distributions with
    separate import names and coexist happily, so trentina's own ``httpx``
    use elsewhere (quarantine's Gemini REST calls) is untouched. Passing an
    ``httpx`` client here does work at runtime -- httpx2 is a fork with the
    same API -- but it is a type error, and relying on two HTTP stacks
    staying API-identical is not a bet worth carrying.

    The client comes from the SDK's ``create_mcp_http_client`` so a backend
    with headers gets the same timeouts (30s connect, 300s read) as one
    without. A bare ``httpx2.AsyncClient`` inherits httpx's 5-second default,
    which cut every authenticated call off at ~5s regardless of
    ``timeout_seconds`` -- that deadline is the caller's ``asyncio.wait_for``
    and cannot lengthen an HTTP timeout underneath it.

    Yields ``(read, write)``. The SDK has shipped the stream bundle as both a
    2-tuple and a 3-tuple (trailing session-id callback); that trailing element
    is unused here, so take the first two either way rather than unpacking a
    fixed width at the call sites.

    Every session gets its own client now, headers or not, because every
    response is read under ``cap`` (#267); one is made if the caller has none.
    """
    cap = cap or ResponseCap(response_byte_cap())
    http_client = create_mcp_http_client(headers=_identity_headers(headers))
    http_client.event_hooks = {"request": [cap.tag], "response": [cap.hook]}
    async with (
        http_client,
        streamable_http_client(url, http_client=http_client) as streams,
    ):
        yield streams[0], streams[1]


logger = logging.getLogger(__name__)

_MISSING = object()


def _field(obj: Any, snake: str, camel: str, default: Any = None) -> Any:
    """Read an MCP model field without depending on fastmcp's alias shim.

    SDK 2.x renamed every model field to snake_case (``input_schema``,
    ``is_error``, ``structured_content``); camelCase survives only as a
    pydantic *serialization* alias, so it is absent from objects deserialized
    off the wire.

    fastmcp re-attaches the camelCase spellings as deprecated properties when
    it is imported, which means reading ``tool.inputSchema`` appears to keep
    working -- but only as a side effect of importing fastmcp, and only until
    the shim is dropped (it already emits FastMCPDeprecationWarning). That is
    a trap, not compatibility: this module must be correct on a raw SDK object
    with fastmcp absent, which ``tests/test_backend_no_fastmcp.py`` enforces.

    Reads the real field name first and keeps camelCase only as a fallback for
    SDK 1.x objects, so the gateway stays correct against either SDK vintage.
    """
    value = getattr(obj, snake, _MISSING)
    if value is _MISSING:
        value = getattr(obj, camel, _MISSING)
    return default if value is _MISSING else value


@dataclass(frozen=True)
class BackendCall:
    """Outcome of a backend tool invocation.

    ``meta`` is the response's ``_meta`` object, carried ONLY for a federated
    backend (#592, B2): a federated upstream Trentina puts its paging marker at
    ``_meta._trentina_part`` because the SDK drops a root-level ``_trentina_part``
    before we see it. For every other backend it is None, and the consumer reads
    only the one key it expects, shape-checked.
    """

    content: list[dict[str, Any]]
    is_error: bool
    structured_content: dict[str, Any] | None
    meta: dict[str, Any] | None = None


_tool_list_cache: dict[str, list[dict[str, Any]]] = {}

# JSON-RPC errors that mean "your request was wrong", said by a backend that
# is up. Each is named in the refusal by our own words, never the backend's:
# its message text has not crossed the perimeter.
_REJECTIONS = {
    INVALID_PARAMS: "invalid arguments",
    METHOD_NOT_FOUND: "method not found",
    INVALID_REQUEST: "invalid request",
}
_MAX_REJECTION_WALK = 32


def _rejection(exc: BaseException) -> str | None:
    """What the backend rejected, if *exc* is a backend refusing the request.

    The SDK raises the backend's JSON-RPC error inside its task group, so it
    arrives wrapped in an ExceptionGroup; walk the group's leaves and each
    ``__cause__``, bounded.
    """
    stack: list[BaseException] = [exc]
    seen = 0
    while stack and seen < _MAX_REJECTION_WALK:
        err = stack.pop()
        seen += 1
        if isinstance(err, MCPError):
            reason = _REJECTIONS.get(err.code)
            if reason is not None:
                return reason
        if isinstance(err, BaseExceptionGroup):
            stack.extend(err.exceptions)
        if err.__cause__ is not None:
            stack.append(err.__cause__)
    return None


def cached_tool_schema(url: str, tool_name: str) -> dict[str, Any] | None:
    """The inputSchema a backend listed for *tool_name*, if its list is cached."""
    for tool in _tool_list_cache.get(url, ()):
        if tool.get("name") == tool_name:
            schema = tool.get("inputSchema")
            return schema if isinstance(schema, dict) else None
    return None


def cached_tool_read_only(url: str, tool_name: str) -> bool:
    """Whether the backend annotated *tool_name* ``readOnlyHint`` in its cached list.

    Unlisted, unannotated or anything but ``true`` is False: a tool that did
    not say it only reads may write.
    """
    for tool in _tool_list_cache.get(url, ()):
        if tool.get("name") == tool_name:
            annotations = tool.get("annotations")
            return isinstance(annotations, dict) and annotations.get("readOnlyHint") is True
    return False


#: MCP's tool-name charset. A listed name outside it could forge a log line.
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,128}")


def loggable_tool(url: str, tool_name: str) -> str:
    """The name when the backend listed it and it is shaped like a tool name;
    otherwise a fingerprint. A long-form call can forward a name the caller
    typed, unlisted (#262), and a listed name is one the backend already
    publishes to every agent through tools/list."""
    listed = any(tool.get("name") == tool_name for tool in _tool_list_cache.get(url, ()))
    if listed and _TOOL_NAME.fullmatch(tool_name):
        return tool_name
    return redact_source(tool_name)


_inflight: dict[str, asyncio.Task[list[dict[str, Any]]]] = {}

_on_evict_callbacks: list[Any] = []


def on_backend_cache_evict(callback: Any) -> None:
    """Register a callback(url) to fire when a backend cache entry is evicted."""
    _on_evict_callbacks.append(callback)


def _evict_backend_cache(url: str) -> None:
    """Remove a backend's cached tool list and notify listeners."""
    if _tool_list_cache.pop(url, None) is not None:
        delete_tool_list(url)
        for cb in _on_evict_callbacks:
            cb(url)
        logger.info("cache: evicted backend %s", safe_url(url))


def evict_backend_cache_url(url: str) -> int:
    """Evict one backend's cached tool list, by exact URL. Returns 1 or 0.

    Named for what it takes. It was ``..._by_name``, which invited its caller
    to hand it a backend NAME and match loosely — and one did, substring-wise,
    so flushing ``gw`` reached ``gw-work`` and ``gw-personal`` both. The cache
    is keyed by URL; resolving a name to a URL belongs to whoever knows which
    profile is asking.
    """
    if url in _tool_list_cache:
        _evict_backend_cache(url)
        return 1
    return 0


def flush_all_caches() -> int:
    """Flush all backend caches + SQLite. Returns count evicted."""
    count = len(_tool_list_cache)
    urls = list(_tool_list_cache.keys())
    for url in urls:
        _tool_list_cache.pop(url, None)
        for cb in _on_evict_callbacks:
            cb(url)
    delete_all_tool_lists()
    logger.info("cache: flushed all %d backend caches", count)
    return count


def load_tool_list_cache() -> int:
    """Populate in-memory cache from SQLite at startup. Returns count loaded."""
    from ..database import get_all_tool_lists

    loaded = get_all_tool_lists()
    _tool_list_cache.update(loaded)
    logger.info("cache: loaded %d tool lists from database", len(loaded))
    return len(loaded)


def reset_tool_list_cache() -> None:
    """Clear the in-memory cache without touching SQLite (for testing)."""
    _tool_list_cache.clear()
    _inflight.clear()
    _on_evict_callbacks.clear()


async def list_backend_tools(
    backend_name: str,
    backend: Backend,
    profile: Profile | None = None,
) -> list[dict[str, Any]]:
    """Fetch the tool list from one backend MCP server.

    A cached backend is always served from cache — the fast path never touches
    the transport or circuit breaker. Because the cache is never evicted on
    failure (only on explicit flush/reconnect), a transient backend outage can
    neither wipe nor bypass the last-known-good list: it keeps being served
    here. On a genuine miss, concurrent callers coalesce onto one in-flight
    fetch per URL — per URL and profile for a backend with ``auth``, which is
    fetched with that profile's own grant (#479).

    The cache stays keyed by URL alone. For an ``auth`` backend that means the
    list one profile fetched, with its own entitlements, is what every
    profile on the URL is offered, each through its own allowlist; a profile
    with no grant sees those tools and is told to authorize when it calls one.

    ``profile`` is the profile the list is for. An ``auth`` backend is never
    fetched without one: the startup warm-ups pass none, and skip it.

    Raises:
        BackendCallError: connection failure, protocol error, timeout, or
            circuit open — only on a cold miss with nothing cached to serve.
        BackendNeedsAuthError: an ``auth`` backend, cold, with no grant.
    """
    cached = _tool_list_cache.get(backend.url)
    if cached is not None:
        return cached
    return await _joined_fetch(backend_name, backend, profile)


async def refresh_backend_tools(
    backend_name: str,
    backend: Backend,
    profile: Profile | None = None,
) -> list[dict[str, Any]]:
    """Fetch one backend's tool list afresh, replacing the cached one in place.

    Unlike ``evict_backend_cache_url``, no eviction callback fires, so no
    profile's aggregate is dropped. That is what an agent's
    ``reconnect_backend`` needs (#291): evicting reached every profile on the
    URL and moved their ``surface.built_at``, a bit another agent could read.
    A fetch already in flight for the URL is joined, not doubled.

    Raises:
        BackendCallError: as ``list_backend_tools`` on a cold miss.
    """
    return await _joined_fetch(backend_name, backend, profile)


def _inflight_key(backend: Backend, profile: Profile | None) -> str:
    """One fetch per URL; per URL and profile when the fetch carries a grant."""
    if backend.auth is None:
        return backend.url
    return f"{backend.url}#{profile.name if profile else ''}"


async def _joined_fetch(
    backend_name: str, backend: Backend, profile: Profile | None
) -> list[dict[str, Any]]:
    key = _inflight_key(backend, profile)
    inflight = _inflight.get(key)
    if inflight is None:
        inflight = asyncio.ensure_future(_single_flight_fetch(backend_name, backend, profile, key))
        _inflight[key] = inflight
    return await inflight


async def revalidate_backend_tools(backend_name: str, backend: Backend) -> bool:
    """Refetch a list loaded from SQLite at startup; True when it changed (#335).

    The persisted list survives a restart so a backend that is down still has
    its last-known-good one. It also outlived every backend upgrade until
    someone ran ``reconnect_backend``, and arguments were judged against the
    schema of a tool that had since changed. A backend with nothing cached is
    left to the first build, and one that cannot be reached keeps its list.
    An ``auth`` backend is left alone: there is no profile to fetch it as.
    """
    before = _tool_list_cache.get(backend.url)
    if before is None or backend.auth is not None:
        return False
    try:
        return await refresh_backend_tools(backend_name, backend) != before
    except BackendCallError:
        return False


async def _single_flight_fetch(
    backend_name: str,
    backend: Backend,
    profile: Profile | None,
    key: str,
) -> list[dict[str, Any]]:
    """Run one fetch and drop its in-flight slot when done."""
    try:
        return await _fetch_and_cache(backend_name, backend, profile)
    finally:
        _inflight.pop(key, None)


async def _fetch_and_cache(
    backend_name: str,
    backend: Backend,
    profile: Profile | None = None,
) -> list[dict[str, Any]]:
    """Fetch one backend's tool list, cache it, and persist to SQLite.

    Only invoked on a cache miss (``list_backend_tools`` serves any cached list
    directly and never evicts on failure), so there is never a stale entry to
    fall back on here — a failure simply raises.
    """
    headers, grant = await _credentials(backend_name, backend, profile)
    if not breaker.allow(backend.url):
        raise BackendCallError(f"backend {backend_name!r} circuit open — skipped")

    cap = ResponseCap(response_byte_cap())
    try:
        tools_result = await _with_reauth(
            backend_name,
            backend,
            profile,
            grant,
            headers,
            cap,
            lambda sent: asyncio.wait_for(
                _do_list_tools(backend.url, sent, cap), timeout=backend.list_timeout_seconds
            ),
        )
    except BackendNeedsAuthError:
        raise
    except Exception as exc:
        breaker.record_failure(backend.url)
        logger.warning(
            "gateway: list_tools failed for backend=%s err=%s",
            backend_name,
            exc_kind(exc),
        )
        raise BackendCallError(
            f"backend {backend_name!r} list_tools failed: {type(exc).__name__}"
        ) from exc

    breaker.record_success(backend.url)
    tools = [_serialize_tool(tool) for tool in tools_result.tools]
    _tool_list_cache[backend.url] = tools
    save_tool_list(backend.url, tools)
    return tools


#: Slots whose backend refused a just-refreshed grant, and until when no
#: further refresh is tried for them: a backend that always answers 401
#: must not cost a token-endpoint round trip on every call.
_auth_cooldown: dict[str, float] = {}
AUTH_COOLDOWN_SECONDS = 60.0


def _cooldown_key(profile: Profile | None, backend_name: str) -> str:
    return f"{profile.name if profile else ''}:{backend_name}"


def _edge_jwt(url: str, private_key_pem: str, caller: str) -> str:
    """Sign the downstream's 60s JWT to a federated upstream (#592, C1).

    The audience is the upstream profile named in the backend URL (the Backend
    validator guarantees it is derivable whenever an edge key is set); the
    subject is the calling profile.
    """
    key = edge_key.load_private_key(private_key_pem)
    return edge_key.sign_edge_jwt(key, sub=caller, aud=federation_audience(url) or "")


async def _credentials(
    backend_name: str, backend: Backend, profile: Profile | None
) -> tuple[dict[str, str] | None, BackendGrant | None]:
    """The headers a request to this backend carries, and the grant behind them.

    Resolved before the breaker is asked: a profile with no grant has not
    reached the backend, and must neither count against the circuit nor
    hold its half-open probe.
    """
    if (
        backend.federated is not None
        and backend.federated.edge_key is not None
        and profile is not None
    ):
        # Federated edge (#592): sign a short-lived JWT to the upstream instead
        # of a static bearer. Takes precedence over any header credential.
        jwt = _edge_jwt(backend.url, backend.federated.edge_key.get_secret_value(), profile.name)
        return {**backend.headers, "Authorization": f"Bearer {jwt}"}, None
    if backend.auth is None:
        return backend.headers or None, None
    from .backend_oauth import fresh_grant

    grant = None
    if (
        profile is not None
        and _auth_cooldown.get(_cooldown_key(profile, backend_name), 0.0) <= time.monotonic()
    ):
        grant = await fresh_grant(profile, backend_name)
    if grant is None:
        raise BackendNeedsAuthError(backend_name)
    return _with_bearer(backend, grant), grant


def _with_bearer(backend: Backend, grant: BackendGrant) -> dict[str, str]:
    """The backend's headers plus the grant. No credential header is configured
    beside ``auth`` (the profile refuses one), so nothing is overwritten."""
    return {
        **backend.headers,
        "Authorization": f"Bearer {grant.access_token.get_secret_value()}",
    }


async def _with_reauth(
    backend_name: str,
    backend: Backend,
    profile: Profile | None,
    grant: BackendGrant | None,
    headers: dict[str, str] | None,
    cap: ResponseCap,
    run: Callable[[dict[str, str] | None], Awaitable[_T]],
) -> _T:
    """``run(headers)``; on a 401 that ran nothing, refresh the grant and run it once more.

    Only a 401 to the session's ``initialize``, ``tools/list`` or a
    ``tools/call`` the backend never accepted is retried: that request did
    nothing. A call the backend accepted is never sent twice.
    """
    try:
        return await run(headers)
    except Exception:
        if grant is None or profile is None or not cap.unauthorized or cap.call_accepted:
            raise
    from .backend_oauth import fresh_grant

    # It answered, so it is up; this is about the grant, not the circuit.
    breaker.record_success(backend.url)
    fresh = await fresh_grant(profile, backend_name, stale_generation=grant.generation)
    if fresh is None:
        raise BackendNeedsAuthError(backend_name)
    cap.reset()
    try:
        return await run(_with_bearer(backend, fresh))
    except Exception as exc:
        if cap.unauthorized and not cap.call_accepted:
            breaker.record_success(backend.url)
            _auth_cooldown[_cooldown_key(profile, backend_name)] = (
                time.monotonic() + AUTH_COOLDOWN_SECONDS
            )
            raise BackendNeedsAuthError(backend_name) from exc
        raise


async def call_backend_tool(
    backend_name: str,
    backend: Backend,
    tool_name: str,
    arguments: dict[str, Any],
) -> BackendCall:
    """Invoke a tool on a backend MCP server, returning the raw result.

    A failed call records a circuit failure but deliberately does NOT evict the
    tool-list cache — a transient call error must not wipe the list and trigger a
    refetch storm on the next tools/list. The list refreshes only on flush.

    A backend with ``auth`` is called with the calling profile's own grant,
    which the router bound to this task (#479).

    Raises:
        BackendCallError: connection failure, protocol error, timeout, or
            circuit open.
        BackendNeedsAuthError: the calling profile holds no usable grant.
    """
    profile = get_current_profile()
    if backend.auth is not None and profile is None:
        raise GatewayError(f"backend {backend_name!r} needs a calling profile")
    headers, grant = await _credentials(backend_name, backend, profile)
    if not breaker.allow(backend.url):
        raise BackendCallError(f"backend {backend_name!r} circuit open — skipped")

    cap = ResponseCap(response_byte_cap())
    try:
        result = await _with_reauth(
            backend_name,
            backend,
            profile,
            grant,
            headers,
            cap,
            lambda sent: asyncio.wait_for(
                _do_call_tool(
                    backend.url,
                    sent,
                    tool_name,
                    arguments,
                    validate_output=backend.validate_output_schema,
                    cap=cap,
                ),
                timeout=backend.timeout_seconds,
            ),
        )
    except BackendNeedsAuthError:
        raise
    except Exception as exc:
        if cap.overflowed:
            # The backend answered, at length: reachable, so not a breaker
            # failure. The read stopped at the cap, so nothing was judged and
            # nothing is delivered (#267).
            breaker.record_success(backend.url)
            logger.warning(
                "gateway: call_tool response over %d bytes backend=%s tool=%s — refused",
                cap.limit,
                backend_name,
                loggable_tool(backend.url, tool_name),
            )
            raise BackendResponseTooLargeError(
                f"backend {backend_name!r} response to {tool_name!r} exceeded "
                f"{cap.limit} bytes; the read was stopped there",
                cap_bytes=cap.limit,
            ) from exc
        rejected = _rejection(exc)
        if rejected is not None:
            # The backend answered: it is reachable, whatever it thought of
            # the request. Counting this opened the breaker on a healthy
            # backend after three bad calls from one client (RT #1505).
            breaker.record_success(backend.url)
            logger.warning(
                "gateway: call_tool rejected backend=%s tool=%s reason=%s",
                backend_name,
                loggable_tool(backend.url, tool_name),
                rejected,
            )
            raise BackendRejectedCallError(
                f"backend {backend_name!r} rejected the call to {tool_name!r}: {rejected}"
            ) from exc
        breaker.record_failure(backend.url)
        logger.warning(
            "gateway: call_tool failed backend=%s tool=%s err=%s",
            backend_name,
            loggable_tool(backend.url, tool_name),
            exc_kind(exc),
        )
        raise BackendCallError(
            f"backend {backend_name!r} call_tool failed: {type(exc).__name__}"
        ) from exc

    breaker.record_success(backend.url)
    # SDK 2.x widened call_tool's return to CallToolResult | InputRequiredResult
    # | Result. Only the first carries content/is_error; the others arrive when
    # a tool wants elicitation or hands back a bare result. The gateway does not
    # negotiate those capabilities, so anything without content is a protocol
    # surprise rather than a tool answer -- surface it instead of reporting an
    # empty success.
    raw_content = _field(result, "content", "content", _MISSING)
    if raw_content is _MISSING:
        raise BackendCallError(
            f"backend {backend_name!r} returned {type(result).__name__} "
            f"for tool {tool_name!r}, which carries no content"
        )
    content: list[dict[str, Any]] = [_serialize_content_block(b) for b in raw_content]
    structured = _field(result, "structured_content", "structuredContent")
    # _meta is carried only for a federated peer (B2): it is where an upstream
    # Trentina leaves its paging marker, since the SDK drops a root-level one.
    meta = _field(result, "meta", "_meta") if backend.federated is not None else None
    return BackendCall(
        content=content,
        is_error=bool(_field(result, "is_error", "isError", False)),
        structured_content=structured if isinstance(structured, dict) else None,
        meta=meta if isinstance(meta, dict) else None,
    )


async def _do_list_tools(
    url: str, headers: dict[str, str] | None, cap: ResponseCap | None = None
) -> Any:
    """Open a fresh session and call list_tools."""
    async with (
        _connect_streamable_http(url, headers, cap) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        return await session.list_tools()


async def _do_call_tool(
    url: str,
    headers: dict[str, str] | None,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    validate_output: bool = True,
    cap: ResponseCap | None = None,
) -> Any:
    """Open a fresh session and call_tool.

    When ``validate_output`` is False, client-side output-schema validation is
    disabled for buggy backends: the cached schemas are cleared and the
    validator is replaced with a no-op. The SDK internals are reached through
    an ``Any`` alias so the method override type-checks without a suppression.

    SDK 2.x renamed the validator ``_validate_tool_result`` -> public
    ``validate_tool_result``. Assigning the old name would silently create a
    dead attribute, leaving validation switched ON for exactly the backends
    this flag exists to accommodate -- a misconfiguration that reports as a
    backend failure. So the override asserts it actually patched something.
    """
    async with (
        _connect_streamable_http(url, headers, cap) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        if not validate_output:
            _disable_output_validation(session)
        return await session.call_tool(tool_name, arguments=arguments)


def _disable_output_validation(session: Any) -> None:
    """Neuter client-side output-schema validation on an open session.

    Raises:
        BackendCallError: the SDK exposes neither known validator name, so the
            override would be a no-op. Fail loudly rather than quietly honour
            the opposite of what the profile asked for.
    """
    schemas = getattr(session, "_tool_output_schemas", None)
    if schemas is not None:
        schemas.clear()

    for attr in ("validate_tool_result", "_validate_tool_result"):
        if hasattr(session, attr):
            setattr(session, attr, _noop_validate)
            return

    raise BackendCallError(
        "cannot disable output-schema validation: this MCP SDK exposes no "
        "known validator hook (tried validate_tool_result, "
        "_validate_tool_result)"
    )


async def _noop_validate(name: str, result: Any) -> None:
    """Skip client-side output schema validation."""


def _serialize_tool(tool: Any) -> dict[str, Any]:
    """Convert an MCP Tool dataclass to a JSON-serializable dict.

    Reads snake_case field names (see ``_field``) but **emits camelCase keys**:
    those are the MCP wire format, unchanged across every protocol revision,
    and the whole defense pipeline downstream keys off them. The rename was
    Python-side only.
    """
    out: dict[str, Any] = {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": _field(tool, "input_schema", "inputSchema"),
    }
    for wire_key, snake, camel in (
        ("title", "title", "title"),
        ("annotations", "annotations", "annotations"),
        ("outputSchema", "output_schema", "outputSchema"),
    ):
        value = _field(tool, snake, camel)
        if value is None:
            continue
        if hasattr(value, "model_dump"):
            value = value.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        out[wire_key] = value
    return out


def _serialize_content_block(block: Any) -> dict[str, Any]:
    """Convert an MCP content block to a dict."""
    kind = getattr(block, "type", None)
    if kind == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if kind == "image":
        return {
            "type": "image",
            "data": getattr(block, "data", ""),
            "mimeType": _field(block, "mime_type", "mimeType", ""),
        }
    if kind == "resource":
        resource = getattr(block, "resource", None)
        if resource is not None and hasattr(resource, "model_dump"):
            # The SDK hands back a pydantic TextResourceContents, not a
            # dict. Passing the model through raw meant the perimeter's
            # isinstance(resource, dict) walk never saw its text (a scan
            # skip) and json.dumps crashed the response (a 500). Dump it.
            resource = resource.model_dump(mode="json", exclude_none=True)
        return {
            "type": "resource",
            "resource": resource if resource is not None else {},
        }
    return {"type": kind or "unknown"}
