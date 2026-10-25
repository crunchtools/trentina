"""Room keys from the homeserver's encrypted backup.

Trentina holds a recovery key and reads the backup. It does NOT hold a Matrix
device identity, does not upload keys, and makes no request that changes state
on the homeserver. Every call here is a GET.

Three properties are load-bearing rather than incidental:

**The backup's public key is verified at startup.** The recovery key implies a
public key; the homeserver publishes the one the backup was made with. If they
disagree the key is wrong, and that is a refused start rather than a silent
inability to decrypt anything.

**Fetches are per-room, single-flight, and rate-limited.** This is a SECURITY
control, not an optimisation. Session IDs arrive in events, and events come
from room members. Without a cooldown, anyone in a room could send events
carrying fabricated session IDs and turn every ``/sync`` into N homeserver
round-trips inside Trentina's own request path.

**Nothing is persisted.** A Megolm session key is a permanent decryption
capability for its slice of history. ``/data`` already holds the quarantine
database -- attacker-supplied content, and the artifact most likely to be
examined after an incident. Putting room keys beside it would change the blast
radius of a ``/data`` disclosure from "what the attacker already sent" to
"every historical message in every room, for ever". A cold cache is fully
re-derivable from the recovery key, so persistence buys restart latency and
nothing else.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

from ..logsafe import exc_kind, redact_source
from .megolm import (
    backup_decryptor,
    backup_public_key,
    import_session,
    megolm_available,
    unwrap_session_data,
)
from .recovery_key import decode_recovery_key

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import httpx

    #: A single GET to the homeserver: ``(method, url, headers) -> open response``.
    #: The caller (``_get``) owns the response's close. The transport is injected
    #: so this module stays gateway-agnostic while the gateway hands it a
    #: pin-before-send sender (#532): the homeserver origin is re-checked and the
    #: connection pinned before each dial, so the access token in ``headers`` can
    #: never be shipped to an address a DNS answer moved under the name.
    Send = Callable[[str, str, dict[str, str]], Awaitable[httpx.Response]]

logger = logging.getLogger(__name__)

BACKUP_ALGORITHM = "m.megolm_backup.v1.curve25519-aes-sha2"


class KeyBackupError(RuntimeError):
    """The backup cannot be used. Raised at startup, never per request."""


class _Entry:
    __slots__ = ("fetched_at", "session")

    def __init__(self, session: Any, fetched_at: float) -> None:
        self.session = session
        self.fetched_at = fetched_at


class KeyBackupProvider:
    """Resolves ``(room_id, session_id)`` to something that can decrypt."""

    def __init__(
        self,
        *,
        homeserver: str,
        access_token: str,
        recovery_key: str,
        send: Send,
        max_sessions: int = 4096,
        ttl_seconds: float = 3600.0,
        concurrency: int = 4,
        refetch_cooldown_seconds: float = 60.0,
    ) -> None:
        self._base = homeserver.rstrip("/")
        self._headers = {"Authorization": f"Bearer {access_token}"}
        self._send = send
        self._max_sessions = max_sessions
        self._ttl = ttl_seconds
        self._cooldown = refetch_cooldown_seconds
        self._semaphore = asyncio.Semaphore(concurrency)

        self._private = decode_recovery_key(recovery_key)
        self._decryptor: Any = None
        self._version: str | None = None

        self._sessions: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._room_fetched_at: dict[str, float] = {}
        self._inflight: dict[str, asyncio.Future[None]] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "fetches": 0,
            "fetch_errors": 0,
            "unwrap_errors": 0,
            "cooldown_skips": 0,
        }

    async def start(self) -> None:
        """Verify the backup exists, matches, and our key opens it."""
        if not megolm_available():
            raise KeyBackupError(
                "vodozemac is not installed — install the 'matrix' extra or "
                "set decrypt.enabled: false"
            )
        version_info = await self._get("/_matrix/client/v3/room_keys/version")
        algorithm = version_info.get("algorithm")
        if algorithm != BACKUP_ALGORITHM:
            raise KeyBackupError(
                f"backup algorithm is {algorithm!r}, expected {BACKUP_ALGORITHM!r}"
            )
        self._version = str(version_info["version"])
        self._decryptor = backup_decryptor(self._private)

        published = (version_info.get("auth_data") or {}).get("public_key")
        ours = backup_public_key(self._decryptor)
        if published != ours:
            raise KeyBackupError(
                "the recovery key does not match this backup — its public key "
                "is not the one the homeserver published. Refusing to start "
                "rather than decrypting nothing and reporting it as coverage."
            )
        logger.warning(
            "matrix keybackup: version %s verified, algorithm %s",
            self._version,
            algorithm,
        )

    def cached_session(self, session_id: str) -> Any | None:
        """A session we already hold, without knowing which room it is in.

        Some response shapes carry an event with no room_id. We cannot fetch
        for an unknown room — the backup is indexed by room — but if the key
        is already in hand there is no reason to refuse to use it.
        """
        for (_room, sid), entry in self._sessions.items():
            if sid == session_id:
                return entry.session
        return None

    async def session_for(self, room_id: str, session_id: str) -> Any | None:
        """The session for this event, fetching the room's keys if needed."""
        if not room_id:
            return self.cached_session(session_id)
        key = (room_id, session_id)
        entry = self._sessions.get(key)
        now = time.monotonic()
        if entry is not None and (now - entry.fetched_at) < self._ttl:
            self._sessions.move_to_end(key)
            self._stats["hits"] += 1
            return entry.session

        self._stats["misses"] += 1
        await self._ensure_room(room_id)
        entry = self._sessions.get(key)
        return entry.session if entry is not None else None

    async def _ensure_room(self, room_id: str) -> None:
        """Fetch a room's keys at most once per cooldown, once concurrently."""
        last = self._room_fetched_at.get(room_id)
        if last is not None and (time.monotonic() - last) < self._cooldown:
            self._stats["cooldown_skips"] += 1
            return

        inflight = self._inflight.get(room_id)
        if inflight is not None:
            await asyncio.shield(inflight)
            return

        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()
        self._inflight[room_id] = future
        try:
            await self._fetch_room(room_id)
            if not future.done():
                future.set_result(None)
        except Exception as exc:  # never raises into the request path
            if not future.done():
                future.set_result(None)
            self._stats["fetch_errors"] += 1
            logger.warning(
                "matrix keybackup: fetch failed for room %s: %s",
                redact_source(room_id),
                exc_kind(exc),
            )
        finally:
            self._inflight.pop(room_id, None)
            self._room_fetched_at[room_id] = time.monotonic()

    async def _fetch_room(self, room_id: str) -> None:
        self._stats["fetches"] += 1
        path = f"/_matrix/client/v3/room_keys/keys/{quote(room_id, safe='')}"
        room_keys = await self._get(path, params={"version": self._version or ""})
        sessions = room_keys.get("sessions") or {}
        now = time.monotonic()
        imported = 0
        for session_id, payload in sessions.items():
            try:
                unwrapped = unwrap_session_data(self._decryptor, payload["session_data"])
                session = import_session(unwrapped["session_key"])
            except Exception as exc:
                # Identity only, never key material or ciphertext.
                self._stats["unwrap_errors"] += 1
                logger.warning(
                    "matrix keybackup: cannot import session %s in room %s: %s",
                    redact_source(session_id),
                    redact_source(room_id),
                    exc_kind(exc),
                )
                continue
            self._sessions[(room_id, session_id)] = _Entry(session, now)
            self._sessions.move_to_end((room_id, session_id))
            imported += 1
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)
        logger.warning(
            "matrix keybackup: room %s — imported %d of %d session(s)",
            redact_source(room_id),
            imported,
            len(sessions),
        )

    async def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        async with self._semaphore:
            url = f"{self._base}{path}"
            if params:
                url = f"{url}?{urlencode(params)}"
            response = await self._send("GET", url, self._headers)
            try:
                # The pinned sender streams (stream=True), so read before json().
                await response.aread()
                response.raise_for_status()
                return response.json()
            finally:
                await response.aclose()

    def stats(self) -> dict[str, int]:
        return dict(self._stats)
