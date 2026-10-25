"""The one egress guard for every gateway-side fetch (#260).

Trentina sits on the container network beside backends with no auth of their
own, so a URL an agent (or a page it fetched) chooses must never reach them.
Three rules, each closing a way round the one before:

- ``check_url`` resolves the host and refuses unless EVERY answer is a global
  address. Deciding on the resolved address, not the spelling, is what
  catches ``2130706433``, ``0x7f.1`` and a single-label container name.
- ``PinnedBackend`` connects to the address that was checked. Resolving again
  at connect time would let a DNS answer that changes in between (rebinding)
  swap the target after the check passed. TLS still verifies the hostname:
  httpcore passes the URL's host as ``server_hostname``, not the pinned IP.
- ``open_guarded`` follows redirects itself and checks every hop, because a
  public page that redirects inward is the same attack by other means.
- It asks for ``identity`` and refuses a body that arrives encoded anyway
  (#276). httpx decompresses before any caller can count, so a size cap on
  a gzip or brotli body is checked after the bomb has gone off.
- ``open_pinned`` is the same pin for a caller that streams a body out and a
  body back and holds the check itself (the git transport, #453). It follows
  no redirect at all: a 3xx is refused as ``redirect``.

``TRENTINA_FETCH_ALLOW_PRIVATE`` lifts the address rule only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpcore
import httpx

from .config import get_config
from .errors import EgressRefusedError

if TYPE_CHECKING:
    import ssl
    from collections.abc import AsyncIterator, Iterable

log = logging.getLogger(__name__)

DEFAULT_PORTS = {"http": 80, "https": 443}
ALLOWED_SCHEMES = frozenset(DEFAULT_PORTS)
ALLOWED_PORTS = frozenset({80, 443})
MAX_REDIRECTS = 5
IDENTITY = "identity"
RESOLVE_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
_REDIRECTS = range(300, 400)
MAX_LOOKUPS = 64
"""Lookups in flight at once, gateway-wide, counting ones whose caller timed out.

``getaddrinfo`` cannot be cancelled, so a stalled resolver keeps its thread
after ``RESOLVE_TIMEOUT``. The executor has exactly this many workers and a
lookup takes a slot before it is submitted, so nothing ever queues behind a
stalled one; past the limit a fetch is refused as ``resolver_busy``."""

MAX_LOOKUPS_PER_PROFILE = 4
"""Of those, what one profile may hold (#291). The global pool was the only
limit, so one agent pointing 16 lookups at a black-holed name server refused
every other profile's fetch: a gateway-wide DoS, and a bit another agent could
read. Now it takes ``MAX_LOOKUPS / MAX_LOOKUPS_PER_PROFILE`` profiles stalling
together to reach the backstop, which docs/profiles.md records as a residual."""

_RESOLVER = ThreadPoolExecutor(max_workers=MAX_LOOKUPS, thread_name_prefix="egress-dns")
_lookup_slots = threading.BoundedSemaphore(MAX_LOOKUPS)
_profile_slots: dict[str | None, threading.BoundedSemaphore] = {}
_profile_slots_lock = threading.Lock()


def _slots_for_caller() -> threading.BoundedSemaphore:
    """The calling profile's own lookup slots; standalone shares one set."""
    # Imported here: the gateway package imports this module on its way in.
    from .gateway.context import get_current_profile

    profile = get_current_profile()
    name = profile.name if profile is not None else None
    with _profile_slots_lock:
        slots = _profile_slots.get(name)
        if slots is None:
            slots = _profile_slots[name] = threading.BoundedSemaphore(MAX_LOOKUPS_PER_PROFILE)
        return slots


_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# The well-known NAT64 prefix is global in ipaddress's table, so the IPv4
# address it carries is checked instead.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
# Refused outright: v4-compatible is missing from ipaddress's table, and the
# local-use NAT64 prefix (RFC 8215) is local by definition, whatever layout
# its translator embeds the IPv4 address in.
_REFUSED_V6 = (ipaddress.IPv6Network("::/96"), ipaddress.IPv6Network("64:ff9b:1::/48"))


@dataclass(frozen=True)
class ResolvedTarget:
    """A host that passed the check, and the addresses its connection is pinned to.

    Every answer, in the resolver's order: each one was checked, and trying
    the next when one will not connect is what a client dialling the name
    would do (an IPv6 answer on a host with no IPv6 route, say).
    """

    host: str
    port: int
    addresses: tuple[str, ...]


def _embedded_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 answer carries: mapped, 6to4 and NAT64."""
    embedded = [v4 for v4 in (ip.ipv4_mapped, ip.sixtofour) if v4 is not None]
    if ip in _NAT64:
        embedded.append(ipaddress.IPv4Address(ip.packed[-4:]))
    return embedded


def is_global_address(ip: _IPAddress) -> bool:
    """True only for an address on the public internet.

    ``is_global`` alone already excludes loopback, RFC 1918, link-local
    (169.254.169.254, fe80::/10), CGNAT and ULA. The explicit terms are there
    so a change to Python's table cannot quietly readmit one.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if any(ip in net for net in _REFUSED_V6):
            return False
        if any(not is_global_address(v4) for v4 in _embedded_v4(ip)):
            return False
    return ip.is_global and not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _lookup(host: str, port: int) -> list[str]:
    """Every address the resolver returns for ``host``. Blocking; run in a thread."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(sockaddr[0]) for *_, sockaddr in answers]


async def _resolve(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to, or ``unresolvable``.

    A lookup takes one of the caller's ``MAX_LOOKUPS_PER_PROFILE`` slots and
    one of ``MAX_LOOKUPS`` gateway-wide, and never queues: with either
    exhausted the fetch is refused as ``resolver_busy`` (#449: the name was
    never asked about, so the refusal does not say it failed to resolve).
    After ``RESOLVE_TIMEOUT``, or on a resolver error, it is ``unresolvable``.
    Both slots come back when the thread ends.
    """
    mine, slots = _slots_for_caller(), _lookup_slots
    if not mine.acquire(blocking=False):
        log.warning("egress: this profile's resolver slots are busy; refusing")
        raise EgressRefusedError("resolver_busy")
    if not slots.acquire(blocking=False):
        mine.release()
        log.warning("egress: every resolver slot is busy; refusing")
        raise EgressRefusedError("resolver_busy")
    job = _RESOLVER.submit(_lookup, host, port)
    # On the executor's future, not asyncio's: it fires when the thread
    # finishes, however long after the caller timed out.
    job.add_done_callback(lambda _job: slots.release())
    job.add_done_callback(lambda _job: mine.release())
    try:
        return await asyncio.wait_for(asyncio.wrap_future(job), RESOLVE_TIMEOUT)
    except (OSError, UnicodeError, TimeoutError) as exc:
        raise EgressRefusedError("unresolvable") from exc


async def check_url(url: str | httpx.URL) -> ResolvedTarget:
    """Refuse a URL the gateway must not fetch; otherwise the addresses to pin.

    Args:
        url: an absolute URL, as the agent sent it or as a redirect built it.

    Returns:
        The host as httpx will connect to it (IDNA-encoded, IPv6 without
        brackets), the effective port, and every address it resolved to,
        all of them checked, for ``PinnedBackend.pin``.

    Raises:
        EgressRefusedError: with the reason only, never the host or address.
    """
    # Parsed by httpx, so the check and the connection read the same host.
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError) as exc:
        raise EgressRefusedError("unresolvable") from exc
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise EgressRefusedError("scheme")
    port = DEFAULT_PORTS[parsed.scheme] if parsed.port is None else parsed.port
    if port not in ALLOWED_PORTS:
        raise EgressRefusedError("port")
    host = parsed.raw_host.decode("ascii")
    if not host:
        raise EgressRefusedError("unresolvable")

    addresses = await _resolve(host, port)
    if not addresses:
        raise EgressRefusedError("unresolvable")
    if not get_config().fetch_allow_private:
        for answer in addresses:
            try:
                ip = ipaddress.ip_address(answer)
            except ValueError:
                raise EgressRefusedError("non_global_address") from None
            if not is_global_address(ip):
                log.warning("egress: refused a non-global address")
                raise EgressRefusedError("non_global_address")
    return ResolvedTarget(host=host, port=port, addresses=tuple(dict.fromkeys(addresses)))


def is_encoded(response: httpx.Response) -> bool:
    """True when the body carries any ``Content-Encoding`` but identity."""
    encoding = response.headers.get("content-encoding", "")
    return any(part.strip().lower() not in ("", IDENTITY) for part in encoding.split(","))


def _socket_backend() -> httpcore.AsyncNetworkBackend:
    """The real network backend. Tests replace it to watch what is dialled."""
    return httpcore.AnyIOBackend()


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Dials only checked addresses for each (host, port), and nothing unchecked.

    ``connect_unix_socket`` is left as the base class's NotImplementedError:
    the pool is never given a socket path.
    """

    def __init__(self) -> None:
        self._inner = _socket_backend()
        self._pins: dict[tuple[str, int], tuple[str, ...]] = {}

    def pin(self, target: ResolvedTarget) -> None:
        self._pins[(target.host, target.port)] = target.addresses

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        addresses = self._pins.get((host, port))
        if not addresses:
            # TRUST: dialling a (host, port) for an outbound fetch
            #   untrusted: host and port, from the agent's URL or a redirect Location
            #   judged-by: egress.check_url, which pins every address it admitted
            #   on-failure: fail-closed; a request the loop never checked is refused
            #   owner: egress.open_guarded
            #   evidence: T3 module docstring; T4 open_guarded pins before every send;
            #     T2 httpcore sends the URL host as server_hostname, so TLS checks the name
            raise EgressRefusedError("unresolvable")
        options = list(socket_options or ())
        *fallbacks, last = addresses
        for address in fallbacks:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout):
                continue
        return await self._inner.connect_tcp(
            last, port, timeout=timeout, local_address=local_address, socket_options=options
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


_ssl_context: ssl.SSLContext | None = None


def shared_ssl_context() -> ssl.SSLContext:
    """One CA-verified TLS context for every pinned connection.

    ``httpx.create_ssl_context()`` loads the system CA bundle, which is slow and
    blocks the event loop. It was built once per ``PinnedTransport`` — i.e. per
    ``/egress`` and ``/git`` request — and is now built once and reused.
    ``warmup.trentina_lifespan`` calls this on a worker thread at startup, so the
    CA load lands there and not on the event loop during the first request.
    Sharing one context is how httpx's own
    ``AsyncClient`` runs its pool, so httpcore is built for it: the one write it
    makes to the context is ``set_alpn_protocols`` on every connect, and with
    every ``PinnedTransport`` at ``http2=False`` that write is always
    ``["http/1.1"]`` — idempotent, and synchronous on the one loop thread, so no
    race. SNI and hostname verification stay per-connection (``server_hostname``),
    and no session is ever set, so nothing leaks between pinned connections to
    different hosts. (A future ``http2=True`` pinned transport would flip ALPN
    for every pinned connection built afterwards — revisit then.) The CA bundle
    is now frozen at first use for the process lifetime, as a certifi bump
    already needs a container restart.
    """
    global _ssl_context
    if _ssl_context is None:
        _ssl_context = httpx.create_ssl_context()
    return _ssl_context


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx's transport over a connection pool that dials through ``PinnedBackend``.

    ``AsyncHTTPTransport`` takes no network backend, so the pool it builds is
    replaced with one that does. Everything else — request and response
    mapping, exception mapping — is httpx's own. Tests replace the class
    with an ``httpx.MockTransport``.
    """

    def __init__(
        self,
        backend: PinnedBackend,
        *,
        max_connections: int | None = None,
        keepalive_expiry: float | None = None,
    ) -> None:
        ssl_context = shared_ssl_context()
        super().__init__(verify=ssl_context, trust_env=False)
        # A per-call transport (open_pinned/open_guarded) leaves these unset and
        # keeps httpcore's defaults; the pooled sender in gateway/upstream.py
        # passes explicit limits so a long-lived client's keepalive and
        # connection budget are its own, per origin (#511). Passed only when
        # given: httpcore reads max_connections=None as UNLIMITED, not its
        # default of 10, so forwarding None would quietly uncap the per-call pool.
        limits: dict[str, Any] = {}
        if max_connections is not None:
            limits["max_connections"] = max_connections
        if keepalive_expiry is not None:
            limits["keepalive_expiry"] = keepalive_expiry
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context, network_backend=backend, **limits
        )


@asynccontextmanager
async def open_guarded(
    method: str,
    url: str,
    *,
    timeout: float,
    deadline: float,
    headers: dict[str, str] | None = None,
) -> AsyncIterator[httpx.Response]:
    """Send ``method`` to ``url`` and follow up to five redirects, checking every hop.

    Args:
        method: HTTP method, sent unchanged except where a 303 makes it GET.
        url: the URL to fetch; checked like every hop after it.
        timeout: seconds for each connect, read and write, per hop.
        deadline: wall-clock seconds for everything, from the first lookup
            to the context's exit, the caller's body read included. The
            per-operation ``timeout`` resets on every byte, so a server
            dripping one byte inside it held a call open for as long as it
            liked (#295). Required: no caller gets an unbounded fetch by
            forgetting it.
        headers: sent on every hop, as httpx sends a client's headers.

    Yields the final ``httpx.Response``, still streaming, with ``history``
    holding the redirects that led to it, as httpx's own redirect handling
    would. It is closed, with its client, when the context exits.
    ``trust_env`` is off: an environment proxy is mounted beside the
    transport, not through it, and would route round the pin.

    ``Accept-Encoding: identity`` goes on every hop, and a final response
    with a body that is encoded anyway is refused before a byte of it is
    read (#276), whatever its status. A HEAD response has no body to inflate,
    so it passes.

    Raises:
        EgressRefusedError: a hop failed the check, dropped to http, there
            were more than five, or the body arrived encoded.
        TimeoutError: ``deadline`` passed.
    """
    async with asyncio.timeout(deadline):
        async with _open_guarded(method, url, timeout=timeout, headers=headers) as resp:
            yield resp


@asynccontextmanager
async def _open_guarded(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None,
) -> AsyncIterator[httpx.Response]:
    backend = PinnedBackend()
    transport = PinnedTransport(backend)
    sent = {k: v for k, v in (headers or {}).items() if k.lower() != "accept-encoding"}
    sent["Accept-Encoding"] = IDENTITY
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        headers=sent,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        request = client.build_request(method, url)
        history: list[httpx.Response] = []
        while True:
            backend.pin(await check_url(request.url))
            resp = await client.send(request, stream=True)
            # httpx builds next_request only for a 3xx with a usable Location;
            # a 304, or a 300 without one, is the final response.
            hop = resp.next_request
            if hop is None:
                break
            await resp.aclose()
            history.append(resp)
            if len(history) > MAX_REDIRECTS:
                raise EgressRefusedError("too_many_redirects")
            if request.url.scheme == "https" and hop.url.scheme == "http":
                raise EgressRefusedError("downgrade")
            request = hop
        resp.history = history
        try:
            if request.method != "HEAD" and is_encoded(resp):
                log.warning("egress: refused a content-encoded response")
                raise EgressRefusedError("encoded")
            yield resp
        finally:
            await resp.aclose()


@asynccontextmanager
async def open_pinned(
    method: str,
    url: str,
    target: ResolvedTarget,
    *,
    idle: float,
    headers: dict[str, str],
    content: bytes | AsyncIterator[bytes] | None = None,
) -> AsyncIterator[httpx.Response]:
    """Send one request to addresses that were already checked, and follow nothing.

    For a caller whose bodies are too large to hold and whose exchange has no
    natural wall-clock bound (a git clone or push, #453). ``open_guarded``
    stays the call for everything else.

    Args:
        method: HTTP method.
        url: the URL to send to. Its host and port must be ``target``'s: the
            pinned backend dials nothing else, so a URL for another host is
            refused as ``unresolvable`` before a byte leaves.
        target: what ``check_url`` returned for that host. The caller holds
            it, so one check can serve a burst of requests.
        idle: seconds any one read or write may take. There is no deadline
            on the whole exchange; a peer that keeps bytes moving is served.
        headers: the caller's headers, sent with ``Accept-Encoding:
            identity``. Nothing else is added but what httpx sets on every
            request (``Host``, ``Connection``, and ``Accept`` and
            ``User-Agent`` where the caller gave none).
        content: the request body, whole or as a stream sent as it is read.

    Yields the ``httpx.Response``, still streaming; read it with
    ``aiter_raw``. It is closed, with its client, when the context exits.

    Raises:
        EgressRefusedError: ``redirect`` for any 3xx, whatever its
            ``Location``: a redirect followed here would carry the caller's
            injected credential to a host nobody checked. ``encoded`` for a
            body that arrives content-encoded. ``unresolvable`` when ``url``
            is not for the checked host.
        httpx.TimeoutException: a connect, read or write passed its limit.
        httpx.HTTPError: the connection failed. Either can also be raised
            later, while the caller reads the response it was handed.
    """
    backend = PinnedBackend()
    backend.pin(target)
    sent = {k: v for k, v in headers.items() if k.lower() != "accept-encoding"}
    sent["Accept-Encoding"] = IDENTITY
    async with httpx.AsyncClient(
        transport=PinnedTransport(backend),
        timeout=httpx.Timeout(idle, connect=CONNECT_TIMEOUT),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        request = client.build_request(method, url, headers=sent, content=content)
        resp = await client.send(request, stream=True)
        try:
            raise_on_bad_pinned_response(resp)
            yield resp
        finally:
            await resp.aclose()


def raise_on_bad_pinned_response(resp: httpx.Response) -> None:
    """Refuse a pinned response that redirects or arrived content-encoded.

    A redirect followed on a pinned request would carry the caller's injected
    credential to a host nobody checked; an encoded body defeats the size cap
    (httpx decompresses before any caller can count). The ONE check shared by
    ``open_pinned`` and the pooled sender in ``gateway/upstream.py`` (#511), so
    neither path can forget it.
    """
    if resp.status_code in _REDIRECTS:
        log.warning("egress: refused a redirect on a pinned request")
        raise EgressRefusedError("redirect")
    if is_encoded(resp):
        log.warning("egress: refused a content-encoded response")
        raise EgressRefusedError("encoded")
