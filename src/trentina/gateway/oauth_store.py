"""Lifetimes and disk hygiene for the OAuth proxy's on-disk store.

FastMCP's ``OAuthProxy`` keeps its clients, transactions, CSRF tokens, codes
and token metadata in one ``FileTreeStore`` — a file per key. Two properties of
that store are fine on their own and bad together:

- a record written with **no TTL lives forever**, and a DCR registration was
  written that way;
- an **expired record is only unlinked when something reads its key**, and an
  abandoned OAuth flow is by definition never read again.

So a gateway accumulated one permanent file per registration and one immortal
file per abandoned flow, at zero cost to whoever caused it. See #156.

This module supplies the two halves of the answer.

**Lifetimes.** A new registration is provisional and short-lived — an hour is
generous, since a real client registers and logs in within seconds. Completing
a token exchange promotes it to long-lived, and every later exchange re-stamps
it. Nothing tracks "last used" separately: re-putting the record with a fresh
TTL *is* the stamp, which is why there is no second bookkeeping store to get
out of step with the first.

**Sweeping.** ``cull()`` walks the store and unlinks what has expired. It is
driven from the first request the OAuth routes serve and then on an interval,
rather than from a lifespan hook, because records only accumulate as a
consequence of traffic: a gateway serving none has nothing to sweep, and one
serving traffic sweeps from the moment it does.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from ..config import int_env
from ..logsafe import exc_kind, exc_where, redact_source

logger = logging.getLogger(__name__)

#: Seconds in a day. Named because `days * 24 * 3600` reads as a magic pair
#: everywhere it appears, and one of the two numbers is the one that changes.
SECONDS_PER_DAY = 86_400

#: A registration that has not completed a token exchange. Short on purpose:
#: the ordinary connect/reconnect cycle of a DCR client leaves one of these
#: behind every time, and two legitimate clients had already littered three
#: records into production with no attacker involved.
PROVISIONAL_TTL_SECONDS = 3600

#: A registration promoted by a successful token exchange, re-stamped on each
#: later exchange. Long enough that a client used a few times a year survives;
#: short enough that one abandoned for good eventually goes away.
DEFAULT_PROMOTED_TTL_DAYS = 90

#: Gap between sweeps. Nothing here is urgent — the cost of a late sweep is an
#: inode, not a wrong answer — so this is sized to be invisible rather than
#: prompt.
DEFAULT_CULL_INTERVAL_SECONDS = 3600

_cull_task: asyncio.Task[None] | None = None


def promoted_ttl_seconds() -> int:
    """Lifetime of a used registration, from ``TRENTINA_REGISTRATION_TTL_DAYS``.

    Documented in README.md's environment table.
    """
    days = int_env(
        "TRENTINA_REGISTRATION_TTL_DAYS",
        DEFAULT_PROMOTED_TTL_DAYS,
        minimum=1,
    )
    return days * SECONDS_PER_DAY


def cull_interval_seconds() -> int:
    """Gap between sweeps, from ``TRENTINA_OAUTH_CULL_INTERVAL``.

    Floored at a minute. A one-second sweep would walk the whole store in a
    hot loop and cost more than the inodes it reclaims. Documented in
    README.md's environment table.
    """
    return int_env(
        "TRENTINA_OAUTH_CULL_INTERVAL",
        DEFAULT_CULL_INTERVAL_SECONDS,
        minimum=60,
    )


def resolve_cullable(storage: Any) -> Any | None:
    """Find the store underneath the wrappers that can actually ``cull()``.

    The proxy hands its collections a ``FernetEncryptionWrapper`` around a
    ``FileTreeStore``; each wrapper exposes the thing it wraps as
    ``key_value``. Walking that chain rather than reaching for a known
    attribute means an operator who supplies their own ``client_storage``,
    wrapped however they like, still gets swept — and one whose store has no
    ``cull()`` at all gets None rather than an exception.
    """
    seen = 0
    current = storage
    while current is not None and seen < 10:
        if callable(getattr(current, "cull", None)):
            return current
        current = getattr(current, "key_value", None)
        seen += 1
    return None


async def promote_registration(client_store: Any, client_id: str) -> None:
    """Re-stamp a stored registration with the long lifetime.

    Called after a successful token exchange — the moment that separates a
    client someone actually uses from the record an abandoned connect attempt
    left behind. Re-putting the record with a fresh TTL IS the "last used"
    stamp; there is no second store holding a timestamp that could disagree
    with this one.

    Silent about a client it cannot find, which is the normal case for a CIMD
    client (resolved through the document cache, never persisted) and for the
    synthesized upstream client. Neither is a DCR registration, so neither is
    this function's business.

    Never raises. Housekeeping must not fail a login: the worst case is a
    registration that keeps its provisional hour and has to be re-registered,
    which every DCR client does automatically.
    """
    try:
        stored = await client_store.get(key=client_id)
        if stored is None:
            return
        await client_store.put(
            key=client_id,
            value=stored,
            ttl=promoted_ttl_seconds(),
        )
    except Exception as exc:
        # The id's fingerprint and the error's kind (#292): under CIMD the
        # client_id is a URL the client chose, and a store error can quote
        # the key it failed on.
        logger.warning(
            "oauth-store: could not promote registration %s — it keeps its "
            "provisional lifetime and the client will re-register: %s at %s",
            redact_source(client_id),
            exc_kind(exc),
            exc_where(exc),
        )
        return


async def mark_provisional(client_store: Any, client_id: str) -> None:
    """Give a freshly registered client the short, provisional lifetime.

    The SDK stores a DCR registration with no TTL, which is what made every
    registration permanent. Rather than reimplement that construction, the
    record it just wrote is read back and re-put with an expiry: the record is
    already correct, only its lifetime is not.

    Shares ``promote_registration``'s contract — silent on a client it cannot
    find, and never raises. A registration that failed to get its expiry is
    one stale file, and the sweeper does not remove it; refusing the
    registration over that would be the worse trade.
    """
    try:
        stored = await client_store.get(key=client_id)
        if stored is None:
            return
        await client_store.put(
            key=client_id,
            value=stored,
            ttl=PROVISIONAL_TTL_SECONDS,
        )
    except Exception as exc:
        # As in promote_registration: fingerprint and kind, never the text.
        logger.warning(
            "oauth-store: could not set a provisional lifetime on "
            "registration %s — it will not expire on its own: %s at %s",
            redact_source(client_id),
            exc_kind(exc),
            exc_where(exc),
        )
        return


if TYPE_CHECKING:

    class _ExchangeHost:
        """The slice of ``OAuthProxy`` that :class:`PromoteOnExchange` uses.

        Type-check-only, so the mixin's ``super()`` calls and its one attribute
        access are checked rather than silenced. At runtime the base is
        ``object`` and the real methods come from the provider it is mixed
        into — importing fastmcp here would break the package's rule that it
        imports without fastmcp installed (`tests/test_backend_no_fastmcp.py`).
        """

        _client_store: Any

        async def exchange_authorization_code(
            self, client: Any, authorization_code: Any
        ) -> Any: ...

        async def exchange_refresh_token(
            self, client: Any, refresh_token: Any, scopes: list[str]
        ) -> Any: ...
else:
    _ExchangeHost = object


class PromoteOnExchange(_ExchangeHost):
    """Mixin: a successful token exchange re-stamps the client's registration.

    Mixed into the gateway's ``GoogleProvider`` subclass, which is defined
    inside a function to keep the fastmcp import lazy. Registration lifetimes
    are this module's subject, so they live here rather than as two more
    methods over there.

    Must precede the provider in the MRO, or these ``super()`` calls never run.
    """

    async def exchange_authorization_code(self, client: Any, authorization_code: Any) -> Any:
        """Exchange the code, then promote the registration that used it.

        A successful exchange is the line between a client someone actually
        uses and the record an abandoned connect attempt left behind.
        Everything a registration keeps past its provisional hour, it keeps
        because of this call.
        """
        token = await super().exchange_authorization_code(client, authorization_code)
        await promote_registration(self._client_store, client.client_id)
        return token

    async def exchange_refresh_token(
        self, client: Any, refresh_token: Any, scopes: list[str]
    ) -> Any:
        """Refresh, then re-stamp — a client refreshing IS a client in use.

        Without this a long-lived client that never re-runs the browser flow
        would age out of the store on the promoted TTL while it was still
        actively refreshing, and its next refresh would fail at ``get_client``
        with nothing in the log to say why.
        """
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        await promote_registration(self._client_store, client.client_id)
        return token


async def cull_once(storage: Any) -> bool:
    """Sweep expired entries from disk once. True when a sweep actually ran.

    Failure is logged and swallowed. A sweep is housekeeping: a gateway that
    cannot reclaim an inode must keep serving logins, not fall over.
    """
    store = resolve_cullable(storage)
    if store is None:
        logger.debug(
            "oauth-store: no cullable store under %s — skipping sweep",
            type(storage).__name__,
        )
        return False
    try:
        await store.cull()
    except Exception as exc:
        # A store error can name the record it failed on, whose key may be
        # a client-chosen CIMD URL.
        logger.warning("oauth-store: sweep failed: %s at %s", exc_kind(exc), exc_where(exc))
        return False
    return True


async def _cull_forever(storage: Any, interval: int) -> None:
    while True:
        await cull_once(storage)
        await asyncio.sleep(interval)


def _sweeper_is_running() -> bool:
    """Whether a live sweeper task exists — the question both callers ask."""
    return _cull_task is not None and not _cull_task.done()


def start_cull_task(storage: Any) -> None:
    """Start the sweeper if it is not already running.

    Idempotent, and restarts after a failure the same way compression does: a
    task that died must not leave the store unswept for the life of the
    process just because something transient happened once.
    """
    global _cull_task

    if _sweeper_is_running():
        return
    _log_previous_sweeper_death()

    interval = cull_interval_seconds()
    try:
        _cull_task = asyncio.get_running_loop().create_task(_cull_forever(storage, interval))
    except RuntimeError:
        # No running loop yet — synchronous startup, or a test. The first
        # request the OAuth routes serve starts it instead, which is the
        # normal path in production anyway.
        return
    # WARNING, not INFO, for the reason describe_limits() is: production runs
    # at TRENTINA_LOG_LEVEL=WARNING, so an INFO line answering "is anything
    # actually removing these records?" is discarded on the one box where the
    # question gets asked. Verified in production at 0.27.2 — this line was missing
    # from the journal and there was no other way to tell.
    logger.warning(
        "oauth-store: expired-record sweeper started (every %ds)",
        interval,
    )


def _log_previous_sweeper_death() -> None:
    """Say why the last sweeper stopped, before a new one hides the evidence."""
    if _cull_task is None or _cull_task.cancelled():
        return
    exc = _cull_task.exception()
    if exc is not None:
        logger.warning(
            "oauth-store: sweeper died (%s at %s) — restarting", exc_kind(exc), exc_where(exc)
        )


def reset_cull_task() -> None:
    """Cancel and forget the sweeper. Used by tests, and by nothing else."""
    global _cull_task

    if _sweeper_is_running() and _cull_task is not None:
        _cull_task.cancel()
    _cull_task = None


class SweeperTrigger:
    """ASGI wrapper that makes the first OAuth request start the sweeper.

    The sweeper needs a running event loop, and the gateway's own startup does
    not have one — ``mcp_server.run()`` creates it. Rather than reach into
    FastMCP's lifespan, the routes that CAUSE records to be written are the
    ones that start the task that removes them, which keeps the two facts next
    to each other.

    ``start_cull_task`` returns on an attribute check once the task exists, so
    the per-request cost after the first is nil.
    """

    __slots__ = ("_inner", "_storage")

    def __init__(self, inner: Any, storage: Any) -> None:
        self._inner = inner
        self._storage = storage

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        start_cull_task(self._storage)
        await self._inner(scope, receive, send)
