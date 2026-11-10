"""Per-profile session registry for Streamable HTTP gateway.

Tracks active MCP sessions per consumer profile, enforces TTL and
max-sessions limits, and broadcasts notifications to all sessions
belonging to a specific profile.

Sessions are lightweight tracking objects — transport-level session
management is handled by the MCP framework.  This registry maps
profile names to their active session IDs so the gateway can broadcast
``notifications/tools/list_changed`` when a circuit breaker state change
affects a profile's tool list.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..logsafe import exc_kind
from .context import session_fingerprint

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

DEFAULT_SESSION_TTL = 300.0
DEFAULT_MAX_SESSIONS_PER_PROFILE = 10

SUBSCRIBER_QUEUE_MAXSIZE = 32
"""Bound per subscriber queue so a stalled SSE reader can't grow memory
without limit. list_changed is idempotent, so dropping a frame on a full
queue is harmless — the client re-requests tools/list on the next one."""

REASON_TTL_EXPIRED = "ttl_expired"
REASON_EVICTED = "evicted_max_sessions"
REASON_CLIENT_DELETE = "client_delete"
REASON_REGISTRY_RESET = "registry_reset"

TOMBSTONE_MAXSIZE = 512
"""How many ended sessions to remember so a later 404 can name its cause.
Without this a stale-session 404 is indistinguishable from a bad token or a
gateway restart, which is exactly the ambiguity that makes disconnects hard
to diagnose."""

SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
"""Exactly what ``uuid4().hex`` issues, and the only shape :meth:`adopt` takes.
An adopted id comes from the caller, so without this a caller could plant
arbitrary text in the registry, the journal and the audit ``session`` column."""


def _tools_changed() -> dict[str, Any]:
    """One ``notifications/tools/list_changed`` frame, fresh per delivery."""
    return {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}


@dataclass
class Session:
    """One active MCP session."""

    session_id: str
    profile_name: str
    created_at: float
    last_access: float


@dataclass
class Tombstone:
    """Why a session stopped existing, kept for post-mortem on the next 404."""

    session_id: str
    profile_name: str
    reason: str
    ended_at: float
    lifetime_seconds: float
    idle_seconds: float


@dataclass
class SessionRegistry:
    """Track active sessions per profile, enforce limits, broadcast notifications."""

    session_ttl: float = DEFAULT_SESSION_TTL
    max_sessions_per_profile: int = DEFAULT_MAX_SESSIONS_PER_PROFILE
    _sessions: dict[str, Session] = field(default_factory=dict)
    _profile_index: dict[str, set[str]] = field(default_factory=dict)
    _notification_callback: Any = field(default=None)
    _subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = field(default_factory=dict)
    _tombstones: dict[str, Tombstone] = field(default_factory=dict)
    _remove_hooks: list[Callable[[str], None]] = field(default_factory=list)
    _pending_tools_changed: set[str] = field(default_factory=set)

    def set_notification_callback(self, callback: Any) -> None:
        """Register a callback for pushing notifications to transport sessions.

        Optional escape hatch for transports other than the built-in SSE GET
        stream (which delivers via :meth:`subscribe` queues).  When set, the
        callback is invoked in addition to any subscriber queues.  Signature:
            async def callback(session_id: str, notification: dict) -> None
        """
        self._notification_callback = callback

    def subscribe(self, session_id: str) -> asyncio.Queue[dict[str, Any]]:
        """Register an SSE stream's notification queue for a session.

        Returns a fresh bounded queue that :meth:`broadcast_tools_changed`
        pushes onto.  The GET SSE handler drains it and must call
        :meth:`unsubscribe` when the stream closes.

        Drains the pending ``list_changed`` :meth:`adopt` left for this session,
        so an adopted client re-requests its tool list as soon as its stream is
        up.  At most once, on the first stream to subscribe: the adopting
        request has no subscriber of its own to deliver to.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_MAXSIZE)
        self._subscribers.setdefault(session_id, set()).add(queue)
        if session_id in self._pending_tools_changed:
            self._pending_tools_changed.discard(session_id)
            try:
                queue.put_nowait(_tools_changed())
            except asyncio.QueueFull:  # pragma: no cover - a fresh queue is empty
                logger.warning(
                    "sessions: subscriber queue full, dropped adoption list_changed for session=%s",
                    session_id[:8],
                )
        return queue

    def unsubscribe(self, session_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Deregister an SSE stream's queue (call on stream close/disconnect)."""
        subs = self._subscribers.get(session_id)
        if subs is None:
            return
        subs.discard(queue)
        if not subs:
            del self._subscribers[session_id]

    def subscriber_count(self, session_id: str) -> int:
        """Number of live SSE streams subscribed to a session (diagnostics/tests)."""
        return len(self._subscribers.get(session_id, ()))

    def create_session(self, profile_name: str) -> str:
        """Create a new session for a profile.  Returns the session ID.

        Enforces max sessions per profile — evicts the oldest session
        if the limit would be exceeded.
        """
        self._expire_stale()
        self._enforce_cap(profile_name)
        session_id = uuid.uuid4().hex
        self._insert(session_id, profile_name)
        logger.info(
            "sessions: created session=%s profile=%s (active=%d/%d, ttl=%.0fs)",
            session_id[:8],
            profile_name,
            self.active(profile_name),
            self.max_sessions_per_profile,
            self.session_ttl,
        )
        return session_id

    def adopt(self, session_id: str, profile_name: str) -> Session | None:
        """Mint a session id this process never issued, against ``profile_name``.

        Sessions live in memory, so a gateway restart ends all of them, and
        recovery was left to the client.  Claude Code re-initializes on a 404 to
        a POST and deliberately does not on a 404 to the standalone SSE GET
        (``app.JSONRPC_SESSION_NOT_FOUND``), so since 2.0.0 gave every
        long-lived seat a GET stream, a restart left those seats retrying a 404
        forever: a dead stream, a CRITICAL monitoring check and a failed call
        (#775).  Adopting the id they already hold ends that.

        Returns the adopted :class:`Session`, or ``None`` when the id is
        refused.  Call it only where :meth:`get_session` returned ``None``, and
        only after the route has authorized the request: the caller's bearer
        token gates every GET, POST and DELETE independently, so a session id is
        a correlation handle, not a credential, and adoption widens no access.
        An ``initialize`` is served by :meth:`create_session` as before — a
        client that recovers on its own must not have its dead id revived.

        Refused when:

        * the id is not the ``uuid4().hex`` shape (:data:`SESSION_ID_RE`);
        * it has a tombstone, whoever owns it.  TTL expiry, eviction and a
          client ``DELETE`` ended on purpose in this process and must stay
          ended, or the TTL and the per-profile cap stop meaning anything.
          Deliberately not scoped the way :meth:`explain_missing` is: resurrect
          another profile's ended id and the cap becomes a suggestion.  The one
          bit that leaks ("someone once held this id") costs a 128-bit guess
          from a caller who is already authenticated;
        * the id is live already.  Unreachable from the handlers, which check
          :meth:`get_session` first, and refusing means no later miscall can
          rebind a live session to another profile.

        Otherwise the same admission as :meth:`create_session`, so the two
        cannot drift: expire, then :meth:`_enforce_cap`.

        What adoption changes: the audit ``session`` column holds the
        fingerprint of a caller-chosen id rather than a server-minted one.
        :data:`SESSION_ID_RE` bounds its shape, and aiming it at another
        session's fingerprint is 2^64 work by someone already authenticated to
        their own profile.  Accepted.

        What it does not carry over: the tools the previous process had loaded
        for this session (``discovery._loaded`` is in-memory), which is why a
        ``list_changed`` is queued for :meth:`subscribe` to drain; and the
        session's flag marks (``session_marks`` is in-memory too, and after a
        restart an unmarked session reads clean whether it re-initializes or is
        adopted, so adoption launders nothing).
        """
        if SESSION_ID_RE.match(session_id) is None:
            return None
        if session_id in self._tombstones:
            return None
        self._expire_stale()
        if session_id in self._sessions:
            return None
        self._enforce_cap(profile_name)
        session = self._insert(session_id, profile_name)
        self._pending_tools_changed.add(session_id)
        logger.info(
            "sessions: adopted session=%s profile=%s — predates this gateway "
            "process; client kept its id instead of losing its tools "
            "(active=%d/%d, ttl=%.0fs)",
            session_id[:8],
            profile_name,
            self.active(profile_name),
            self.max_sessions_per_profile,
            self.session_ttl,
        )
        return session

    def _insert(self, session_id: str, profile_name: str) -> Session:
        """Register one session id under a profile, with no admission checks."""
        now = time.monotonic()
        session = Session(
            session_id=session_id,
            profile_name=profile_name,
            created_at=now,
            last_access=now,
        )
        self._sessions[session_id] = session
        self._profile_index.setdefault(profile_name, set()).add(session_id)
        return session

    def _enforce_cap(self, profile_name: str) -> None:
        """Evict this profile's least recently used sessions down to the cap,
        leaving room for one more.  Shared by :meth:`create_session` and
        :meth:`adopt` so an adopted session is admitted on the same terms."""
        profile_sessions = self._profile_index.get(profile_name, set())
        while len(profile_sessions) >= self.max_sessions_per_profile:
            oldest_id: str | None = None
            oldest_time = float("inf")
            for sid in profile_sessions:
                s = self._sessions.get(sid)
                if s is not None and s.last_access < oldest_time:
                    oldest_time = s.last_access
                    oldest_id = sid
            if oldest_id is None:
                break
            evicted_idle = time.monotonic() - oldest_time
            self._remove(oldest_id, REASON_EVICTED)
            profile_sessions = self._profile_index.get(profile_name, set())
            logger.warning(
                "sessions: EVICTED session=%s profile=%s — at max_sessions_per_profile"
                "=%d; victim was idle %.1fs. Raise gateway.max_sessions_per_profile "
                "in profiles.yaml if this is disconnecting live clients.",
                oldest_id[:8],
                profile_name,
                self.max_sessions_per_profile,
                evicted_idle,
            )

    def census(self) -> dict[str, int]:
        """Live session count per profile, for tracking accumulation over time.

        Never logged (#291): the journal is agent-readable, and every
        profile's count on every session event was a few bits per round
        between agents, plus the whole roster. Log ``active(name)`` instead.
        """
        return {pname: len(ids) for pname, ids in self._profile_index.items() if ids}

    def active(self, profile_name: str) -> int:
        """Live sessions held by one profile: what its own log lines carry."""
        return len(self._profile_index.get(profile_name, ()))

    def explain_missing(self, session_id: str, for_profile: str | None) -> str:
        """Describe why ``session_id`` is not in the registry.

        Turns an otherwise opaque 404 into a cause: TTL expiry, eviction under
        the per-profile cap, an explicit client teardown, or a session this
        process never issued at all (typically a client that outlived a
        gateway restart).

        ``for_profile`` scopes the answer to a caller (#137). The full text
        names the session's owner and its lifetime, which is not fine in a
        response nor in the journal, which agents read (#262, #291):
        presenting another profile's session id would learn that profile's
        name. So a tombstone that belongs to someone else reads exactly like
        one that never existed. Required, so no caller gets the unscoped text
        by omission; the gateway's own call sites all pass the route's profile.
        """
        tomb = self._tombstones.get(session_id)
        if tomb is None or (for_profile is not None and tomb.profile_name != for_profile):
            return (
                "never issued by this gateway process — client predates a "
                "gateway restart, or is using a session from another process"
            )
        return (
            f"{tomb.reason} {time.monotonic() - tomb.ended_at:.1f}s ago "
            f"(profile={tomb.profile_name}, lived {tomb.lifetime_seconds:.1f}s, "
            f"idle {tomb.idle_seconds:.1f}s when it ended)"
        )

    def get_session(self, session_id: str) -> Session | None:
        """Look up a session by ID, returning None if expired or unknown."""
        self._expire_stale()
        session = self._sessions.get(session_id)
        if session is not None:
            session.last_access = time.monotonic()
        return session

    def is_active(self, session_id: str) -> bool:
        """Whether a session is still registered, WITHOUT refreshing it.

        Deliberately bypasses :meth:`get_session`: a periodic liveness poll
        from an idle SSE stream must not keep the session alive forever,
        which is exactly what bumping ``last_access`` would do.
        """
        self._expire_stale()
        return session_id in self._sessions

    def delete_session(self, session_id: str) -> bool:
        """Explicitly tear down a session.  Returns True if it existed."""
        return self._remove(session_id, REASON_CLIENT_DELETE)

    def get_sessions_for_profile(self, profile_name: str) -> list[Session]:
        """Return all active sessions for a profile."""
        self._expire_stale()
        ids = self._profile_index.get(profile_name, set())
        return [self._sessions[sid] for sid in ids if sid in self._sessions]

    def profiles_for_backend_url(self, url: str, all_profiles: dict[str, Any]) -> list[str]:
        """Return profile names whose backends include the given URL."""
        affected: list[str] = []
        for pname, profile in all_profiles.items():
            for backend in profile.backends.values():
                if backend.is_remote and backend.url == url:
                    affected.append(pname)
                    break
        return affected

    async def broadcast_tools_changed(self, profile_name: str) -> int:
        """Push ``notifications/tools/list_changed`` to all sessions for a profile.

        Delivers to each session's live SSE subscriber queues (the built-in
        transport) and, when set, to :attr:`_notification_callback`.  Returns
        the number of sessions that received at least one delivery.
        """
        sessions = self.get_sessions_for_profile(profile_name)
        if not sessions:
            return 0

        notified = 0
        for session in sessions:
            if await self._push_tools_changed(session.session_id):
                notified += 1
        if notified:
            logger.info(
                "sessions: broadcast tools/list_changed to %d session(s) for profile=%s",
                notified,
                profile_name,
            )
        return notified

    async def notify_session(self, profile_name: str, fingerprint: str) -> bool:
        """Push ``notifications/tools/list_changed`` to the one session whose
        fingerprint (``context.session_fingerprint``) is ``fingerprint``.

        For a tool list that changed for one session alone (#473). The router
        knows a session only by its fingerprint, never its id.
        """
        if not fingerprint:
            return False
        for session in self.get_sessions_for_profile(profile_name):
            if session_fingerprint(session.session_id) == fingerprint:
                return await self._push_tools_changed(session.session_id)
        return False

    def holds(self, profile_name: str, fingerprint: str) -> bool:
        """Whether a live session of ``profile_name`` has this fingerprint."""
        return any(
            session_fingerprint(s.session_id) == fingerprint
            for s in self.get_sessions_for_profile(profile_name)
        )

    def on_remove(self, callback: Callable[[str], None]) -> None:
        """Call ``callback(fingerprint)`` whenever a session ends, for state
        held per session elsewhere (``discovery.py``'s loaded tools)."""
        self._remove_hooks.append(callback)

    async def _push_tools_changed(self, session_id: str) -> bool:
        """Deliver one list_changed to a session's streams; whether any took it."""
        notification = _tools_changed()
        delivered = False
        if self._notification_callback is not None:
            try:
                await self._notification_callback(session_id, notification)
                delivered = True
            except Exception as exc:
                logger.warning(
                    "sessions: failed to notify session=%s: %s",
                    session_id[:8],
                    exc_kind(exc),
                )

        for queue in list(self._subscribers.get(session_id, ())):
            try:
                queue.put_nowait(dict(notification))
                delivered = True
            except asyncio.QueueFull:
                logger.warning(
                    "sessions: subscriber queue full, dropped list_changed for session=%s",
                    session_id[:8],
                )
        return delivered

    @property
    def active_count(self) -> int:
        """Total number of active sessions across all profiles."""
        self._expire_stale()
        return len(self._sessions)

    def reset(self) -> None:
        """Clear all sessions (for testing)."""
        for sid in list(self._sessions):
            self._remove(sid, REASON_REGISTRY_RESET)
        self._sessions.clear()
        self._profile_index.clear()
        self._subscribers.clear()
        self._tombstones.clear()
        self._pending_tools_changed.clear()

    def _remove(self, session_id: str, reason: str) -> bool:
        session = self._sessions.pop(session_id, None)
        self._subscribers.pop(session_id, None)
        self._pending_tools_changed.discard(session_id)
        if session is None:
            return False
        for hook in self._remove_hooks:
            hook(session_fingerprint(session_id))
        profile_set = self._profile_index.get(session.profile_name)
        if profile_set is not None:
            profile_set.discard(session_id)
            if not profile_set:
                del self._profile_index[session.profile_name]

        now = time.monotonic()
        self._tombstones[session_id] = Tombstone(
            session_id=session_id,
            profile_name=session.profile_name,
            reason=reason,
            ended_at=now,
            lifetime_seconds=now - session.created_at,
            idle_seconds=now - session.last_access,
        )
        while len(self._tombstones) > TOMBSTONE_MAXSIZE:
            self._tombstones.pop(next(iter(self._tombstones)))
        return True

    def _expire_stale(self) -> None:
        now = time.monotonic()
        expired = [
            (sid, now - s.last_access)
            for sid, s in self._sessions.items()
            if (now - s.last_access) > self.session_ttl
        ]
        for sid, idle in expired:
            profile_name = self._sessions[sid].profile_name
            self._remove(sid, REASON_TTL_EXPIRED)
            logger.info(
                "sessions: EXPIRED session=%s profile=%s — idle %.1fs > ttl %.0fs. "
                "Raise gateway.session_ttl_seconds in profiles.yaml if this is "
                "disconnecting idle clients. active=%d",
                sid[:8],
                profile_name,
                idle,
                self.session_ttl,
                self.active(profile_name),
            )


session_registry = SessionRegistry()
