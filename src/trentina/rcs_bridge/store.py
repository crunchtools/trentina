"""What the RCS bridge has to remember across a restart.

* ``inbox``: messages the webhook took and the gateway has not yet acked.
  Twilio does not retry an inbound webhook (it tries the fallback URL once,
  then gives up), so a message is written here before Twilio hears 200, and
  leaves only when the gateway has it. ``MessageSid`` is the key, which is
  also the dedupe for a webhook Twilio does deliver twice.
* ``sent``: every chunk of every outbound event, by the gateway's ``txn_id``.
  The gateway retries ``/send`` until it gets an answer, so a retry must
  resend only the chunks that never went.
* ``seen``: message IDs already handed over, so a duplicate webhook after
  delivery is still a duplicate. Pruned with ``sent`` after ``RETENTION_DAYS``.
* ``media``: judged attachments the agent sent, held under an unguessable ID
  for Twilio to fetch from the public listener (#493). Served for
  ``MEDIA_TTL`` seconds, then pruned.

One SQLite file, created 0600: it holds the owner's words until delivery.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from typing import TYPE_CHECKING

from .backend import Inbound

if TYPE_CHECKING:
    from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS inbox (
    message_id  TEXT PRIMARY KEY,
    sender      TEXT NOT NULL,
    body        TEXT NOT NULL,
    attachments INTEGER NOT NULL,
    received    REAL NOT NULL,
    media       TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS seen (
    message_id TEXT PRIMARY KEY,
    created    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sent (
    txn_id     TEXT NOT NULL,
    idx        INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    created    REAL NOT NULL,
    PRIMARY KEY (txn_id, idx)
);
CREATE TABLE IF NOT EXISTS media (
    media_id     TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    body         BLOB NOT NULL,
    created      REAL NOT NULL
);
"""

RETENTION_DAYS = 30
# Messages held for delivery at once. The webhook answers 503 past it, which
# Twilio reports as a failed delivery, rather than grow without bound while
# the gateway is down.
MAX_INBOX = 1000
# How long an outbound attachment is served for Twilio to fetch: Twilio takes
# it when the message is created, so an hour covers its retries, and a public
# URL stays short-lived.
MEDIA_TTL = 3600.0
# Attachments held at once, at most ``MAX_MEDIA_BYTES`` each.
MAX_HELD_MEDIA = 64


class InboxFullError(RuntimeError):
    """The inbox holds ``MAX_INBOX`` undelivered messages."""


class MediaFullError(RuntimeError):
    """``MAX_HELD_MEDIA`` attachments are already held."""


class RcsStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
        # Also when the file already existed with a looser mode. SQLite gives
        # the -wal and -shm files the database file's mode.
        os.chmod(path, 0o600)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(inbox)")}
        if "media" not in columns:
            # A store from before #493.
            self._db.execute("ALTER TABLE inbox ADD COLUMN media TEXT NOT NULL DEFAULT '[]'")
        self._lock = threading.Lock()
        self._prune_now(time.time())

    def close(self) -> None:
        self._db.close()

    # inbox

    def _put_now(self, message: Inbound) -> bool:
        with self._lock:
            known = self._db.execute(
                "SELECT 1 FROM inbox WHERE message_id = ? UNION "
                "SELECT 1 FROM seen WHERE message_id = ?",
                (message.message_id, message.message_id),
            ).fetchone()
            if known:
                return False
            (held,) = self._db.execute("SELECT COUNT(*) FROM inbox").fetchone()
            if held >= MAX_INBOX:
                raise InboxFullError(f"{held} messages undelivered")
            self._db.execute(
                "INSERT INTO inbox (message_id, sender, body, attachments, received, media) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    message.message_id,
                    message.sender,
                    message.body,
                    len(message.media),
                    time.time(),
                    json.dumps([list(item) for item in message.media]),
                ),
            )
        return True

    async def put(self, message: Inbound) -> bool:
        """Hold a message for delivery; False if it was already taken."""
        return await asyncio.to_thread(self._put_now, message)

    def _pending_now(self) -> list[Inbound]:
        with self._lock:
            rows = self._db.execute(
                "SELECT message_id, sender, body, media FROM inbox ORDER BY received, rowid"
            ).fetchall()
        return [Inbound(str(m), str(s), str(b), _media(held)) for m, s, b, held in rows]

    async def pending(self) -> list[Inbound]:
        """Every undelivered message, oldest first."""
        return await asyncio.to_thread(self._pending_now)

    def _delivered_now(self, message_id: str) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM inbox WHERE message_id = ?", (message_id,))
                self._db.execute(
                    "INSERT OR IGNORE INTO seen (message_id, created) VALUES (?, ?)",
                    (message_id, time.time()),
                )
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    async def delivered(self, message_id: str) -> None:
        """The gateway has this message: drop it, and remember it was seen."""
        await asyncio.to_thread(self._delivered_now, message_id)

    # sent

    def _sent_now(self, txn_id: str) -> dict[int, str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT idx, message_id FROM sent WHERE txn_id = ?", (txn_id,)
            ).fetchall()
        return {int(i): str(m) for i, m in rows}

    async def sent(self, txn_id: str) -> dict[int, str]:
        """``{chunk index: provider message ID}`` already sent for ``txn_id``."""
        return await asyncio.to_thread(self._sent_now, txn_id)

    def _record_now(self, txn_id: str, idx: int, message_id: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO sent (txn_id, idx, message_id, created) VALUES (?, ?, ?, ?)",
                (txn_id, idx, message_id, time.time()),
            )

    async def record(self, txn_id: str, idx: int, message_id: str) -> None:
        await asyncio.to_thread(self._record_now, txn_id, idx, message_id)

    # media

    def _hold_media_now(self, media_id: str, content_type: str, body: bytes) -> None:
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM media WHERE created < ?", (now - MEDIA_TTL,))
            (held,) = self._db.execute("SELECT COUNT(*) FROM media").fetchone()
            if held >= MAX_HELD_MEDIA:
                raise MediaFullError(f"{held} attachments held")
            self._db.execute(
                "INSERT INTO media (media_id, content_type, body, created) VALUES (?, ?, ?, ?)",
                (media_id, content_type, body, now),
            )

    async def hold_media(self, media_id: str, content_type: str, body: bytes) -> None:
        """Hold one judged attachment to serve under ``media_id``."""
        await asyncio.to_thread(self._hold_media_now, media_id, content_type, body)

    def _held_media_now(self, media_id: str) -> tuple[str, bytes] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT content_type, body FROM media WHERE media_id = ? AND created >= ?",
                (media_id, time.time() - MEDIA_TTL),
            ).fetchone()
        return (str(row[0]), bytes(row[1])) if row else None

    async def held_media(self, media_id: str) -> tuple[str, bytes] | None:
        """``(content type, bytes)`` of an attachment still served, or None."""
        return await asyncio.to_thread(self._held_media_now, media_id)

    # retention

    def _prune_now(self, now: float) -> None:
        cutoff = now - RETENTION_DAYS * 86400
        with self._lock:
            self._db.execute("DELETE FROM seen WHERE created < ?", (cutoff,))
            self._db.execute("DELETE FROM sent WHERE created < ?", (cutoff,))
            self._db.execute("DELETE FROM media WHERE created < ?", (now - MEDIA_TTL,))

    async def prune(self) -> None:
        await asyncio.to_thread(self._prune_now, time.time())


def _media(held: str) -> tuple[tuple[str, str], ...]:
    """The inbox's ``media`` column, as the ``Inbound`` field."""
    try:
        items = json.loads(held)
    except ValueError:
        return ()
    held_items: list[tuple[str, str]] = []
    for item in items if isinstance(items, list) else ():
        match item:
            case [str(url), str(content_type)]:
                held_items.append((url, content_type))
    return tuple(held_items)
