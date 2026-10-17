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

One SQLite file, created 0600: it holds the owner's words until delivery.
"""

from __future__ import annotations

import asyncio
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
    received    REAL NOT NULL
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
"""

RETENTION_DAYS = 30
# Messages held for delivery at once. The webhook answers 503 past it, which
# Twilio reports as a failed delivery, rather than grow without bound while
# the gateway is down.
MAX_INBOX = 1000


class InboxFullError(RuntimeError):
    """The inbox holds ``MAX_INBOX`` undelivered messages."""


class RcsStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
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
                "INSERT INTO inbox (message_id, sender, body, attachments, received) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    message.message_id,
                    message.sender,
                    message.body,
                    message.attachments,
                    time.time(),
                ),
            )
        return True

    async def put(self, message: Inbound) -> bool:
        """Hold a message for delivery; False if it was already taken."""
        return await asyncio.to_thread(self._put_now, message)

    def _pending_now(self) -> list[Inbound]:
        with self._lock:
            rows = self._db.execute(
                "SELECT message_id, sender, body, attachments FROM inbox ORDER BY received, rowid"
            ).fetchall()
        return [Inbound(str(m), str(s), str(b), int(a)) for m, s, b, a in rows]

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

    # retention

    def _prune_now(self, now: float) -> None:
        cutoff = now - RETENTION_DAYS * 86400
        with self._lock:
            self._db.execute("DELETE FROM seen WHERE created < ?", (cutoff,))
            self._db.execute("DELETE FROM sent WHERE created < ?", (cutoff,))

    async def prune(self) -> None:
        await asyncio.to_thread(self._prune_now, time.time())
