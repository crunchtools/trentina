"""The operator-named-origin spine (#511 convergence).

Shared today by ``/egress``, ``/git`` and the CONNECT tunnel (``/llm`` and the
Matrix proxy join when they move onto the pinned client, a later phase). These
paths differ from ``fetch`` in *who chose the destination*: ``fetch`` hands
``egress.open_guarded`` an agent-chosen URL,
checked per hop, redirects followed, a per-call client, never pooled. Here the
agent supplies only a *path*; the *host* is one the operator named. So the
address is checked ONCE per burst, the connection is pinned to it, no redirect
is followed, and — because the key set is operator config, not agent input —
the check may be cached.

Nothing here judges content. It is the network leg only; the address rule lives
in ``egress.py`` (the ONE egress guard, #260), which this calls.

``checked_target`` lived in ``client_egress.py`` until the convergence moved it
here: the terminating HTTP routes imported it *up* from the tunnel module, an
inverted dependency. The tunnel now imports it from here like everyone else.
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import time
from contextlib import asynccontextmanager
from functools import partial
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from ..egress import (
    CONNECT_TIMEOUT,
    IDENTITY,
    PinnedBackend,
    PinnedTransport,
    check_url,
    raise_on_bad_pinned_response,
)
from .context import profile_context
from .profile import CLIENT_EGRESS_PORT

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ..egress import ResolvedTarget
    from .profile import Profile

RESOLVER_BUSY = "resolver_busy"
"""The egress guard's reason when no resolver slot was free. It is the
gateway's load, not a verdict on the name, so a route answers it as it answers
its own ``busy``: 503, ``denied_guard`` — never a defense block."""

CHECKED_TTL = 5.0
"""Seconds a name's checked addresses answer the same profile's next call
(#449). A client opens a pool of connections to two or three names at once, and
each lookup takes one of the profile's four resolver slots, which never queue:
without this the fifth call of a burst was refused. Safe for an operator-named
origin and not for ``fetch``: the name is one the operator listed, checked
against the list before this is asked, and the caller dials the addresses that
were checked. A refusal is never kept."""

#: In-flight checks, shared by every caller of a name that starts while one runs.
_checking: dict[tuple[str, str], asyncio.Task[ResolvedTarget]] = {}
#: Finished checks, kept for ``CHECKED_TTL``. Nothing sweeps it: a key is a name
#: some profile lists, so there are at most a bounded set per profile, and a
#: stale answer is replaced when its name is next asked for.
_checked: dict[tuple[str, str], tuple[float, ResolvedTarget]] = {}


def forget_checked() -> None:
    """Drop every cached check. Called when the tunnel listener stops; this now
    also clears ``/egress`` and ``/git``'s cache for the same profiles, which
    costs at most one re-lookup on the next call."""
    _checked.clear()


def _settle(key: tuple[str, str], task: asyncio.Task[ResolvedTarget]) -> None:
    """Keep a finished check's answer for ``CHECKED_TTL``; drop a refusal."""
    _checking.pop(key, None)
    # Read here so a check nobody waited out is not reported as unretrieved.
    if task.cancelled() or task.exception() is not None:
        _checked.pop(key, None)
        return
    _checked[key] = (time.monotonic() + CHECKED_TTL, task.result())


async def checked_target(profile: Profile, host: str) -> ResolvedTarget:
    """``host``'s checked addresses, from one lookup per burst (#449).

    Calls to one name that start together share the check in flight, and ones
    that start within ``CHECKED_TTL`` of it share its answer. The check is
    shielded: a caller that hangs up does not cancel it for the others. The
    tunnel (#442), the git transport (#453) and the egress route (#511) all ask
    here, for a host the operator named; one profile's burst is one burst,
    whichever way it leaves.

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


# The per-(profile, host, port) pinned connection pool (#511, Phase 2): one
# long-lived PINNED client per operator origin, so /egress and /git reuse
# connections instead of handshaking per call. Keyed per origin (not per
# profile) so one's budget cannot starve another's; the pin is refreshed from
# ``checked_target`` before every send (the ONE choke-point below) over the
# unchanged fail-closed ``PinnedBackend``, so a stale entry dials a once-checked
# address, never an unchecked one.

#: Connections one pooled origin may hold, and how long an idle one is kept. Per
#: origin, not gateway-wide: a subagent fan-out to one provider gets its own
#: budget. A handful of warm connections covers a client's parallelism; a minute
#: of keepalive spans the gaps between a session's calls.
MAX_POOL_CONNECTIONS = 16
KEEPALIVE_EXPIRY = 60.0

#: One pinned client per operator origin. The backend is held beside the client
#: so the pin can be refreshed before each send.
_pool: dict[tuple[str, str, int], tuple[httpx.AsyncClient, PinnedBackend]] = {}


def _no_cookie_jar() -> http.cookiejar.CookieJar:
    """A cookie jar that rejects every ``Set-Cookie``.

    A long-lived pooled client would otherwise keep a provider's cookie and
    replay it on later requests — a state carry the per-call clients never had.
    Clearing the jar after each request does NOT close the window: between one
    request's ``send`` returning (cookie stored) and its cleanup, a CONCURRENT
    request on the same client builds its own request reading the jar and
    carries the cookie upstream. A reject-all policy keeps the jar permanently
    empty instead, so no request — concurrent or later — can observe another
    response's cookie, with no reliance on timing. (A ``Cookies`` subclass would
    not do: httpx re-wraps a ``Cookies`` into a plain one and drops the
    override; it uses a raw ``CookieJar`` as given, so the policy sticks.)
    """
    return http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))


def _client_for(
    profile: Profile, host: str, port: int, idle: float
) -> tuple[httpx.AsyncClient, PinnedBackend]:
    """The pooled pinned client for one operator origin, built once.

    The client carries NO auth or cookie defaults: the caller's injected
    credential rides on the per-request headers, never on the client, so a
    long-lived client cannot leak one request's credential onto the next.
    ``idle`` sets the read/write timeout; callers to one origin are one route,
    so it is consistent, and the first caller's value stands for the client.
    """
    key = (profile.name, host, port)
    entry = _pool.get(key)
    if entry is None:
        backend = PinnedBackend()
        client = httpx.AsyncClient(
            transport=PinnedTransport(
                backend,
                max_connections=MAX_POOL_CONNECTIONS,
                keepalive_expiry=KEEPALIVE_EXPIRY,
            ),
            timeout=httpx.Timeout(idle, connect=CONNECT_TIMEOUT),
            follow_redirects=False,
            trust_env=False,
            cookies=_no_cookie_jar(),
        )
        entry = _pool[key] = (client, backend)
    return entry


@asynccontextmanager
async def pinned_send(
    profile: Profile,
    method: str,
    url: str,
    *,
    idle: float,
    headers: dict[str, str],
    content: bytes | AsyncIterator[bytes] | None = None,
) -> AsyncIterator[httpx.Response]:
    """Send one request to an operator origin over a reused, pinned connection.

    The ONE pin-before-send choke-point (#511): the origin is re-checked through
    ``checked_target`` (one lookup per burst, cached ``CHECKED_TTL``) and the
    backend pinned to it immediately before the send, so a reused keepalive
    connection is to an address that was checked and a new connection dials a
    currently-checked one. Nothing else may call the pooled client's ``send``.

    Same contract as ``egress.open_pinned`` otherwise: ``Accept-Encoding:
    identity`` is forced, no redirect is followed (a 3xx is ``redirect``), an
    encoded body is refused, the response streams, and it is closed — but the
    CLIENT is not — when the context exits.

    Raises:
        EgressRefusedError: the guard refused the origin (``resolver_busy`` or a
            closed address-rail reason), a 3xx was returned, or the body arrived
            content-encoded.
    """
    host = urlsplit(url).hostname or ""
    port = urlsplit(url).port or CLIENT_EGRESS_PORT
    client, backend = _client_for(profile, host, port, idle)
    backend.pin(await checked_target(profile, host))
    sent = {k: v for k, v in headers.items() if k.lower() != "accept-encoding"}
    sent["Accept-Encoding"] = IDENTITY
    resp = await client.send(
        client.build_request(method, url, headers=sent, content=content), stream=True
    )
    try:
        raise_on_bad_pinned_response(resp)
        yield resp
    finally:
        # The client is pooled, so only the response is closed. Its cookie jar
        # never stores (``_no_cookie_jar``), so there is nothing to clear.
        await resp.aclose()


async def close_pool() -> None:
    """Close every pooled client. Called ONLY at shutdown, where tearing down an
    in-flight request's connection is expected. A reload does NOT call this: it
    would cut a request mid-read on a route still serving, and a repointed
    origin's old client simply goes idle (keepalive expires it; it is never
    keyed again). The per-origin reload diff lands with the /llm slice, where a
    pooled interactive stream makes the cleanup worth the care."""
    clients = [client for client, _backend in _pool.values()]
    _pool.clear()
    for client in clients:
        await client.aclose()
