"""The perimeter store read from a worker thread (5.0.1).

``database.py`` has had ``snapshot_reader`` since #295, because
``quarantine_stats`` runs its aggregates under ``asyncio.to_thread``: they cost
seconds on a large audit table and would stall every profile on the event loop.
This store had no equivalent, and 5.0.0 put a reader on that worker —
``_gateway_stats`` -> ``_federation`` -> ``link_report`` ->
``tool_pins.pending`` -> ``list_pending_pins`` — so an operator's
``quarantine_stats`` raised ``sqlite3.ProgrammingError`` on any gateway with a
federation link.

These tests state the rule from both sides. The first asserts the thread
affinity is still real, so nobody "fixes" a future instance of this by putting
``check_same_thread=False`` on the singleton: that would share one connection
between the loop's writes and a multi-second read and serialize them, which is
the cost ``snapshot_reader`` exists to avoid. The second asserts the reader
removes it.
"""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from trentina import perimeter_db
from trentina.gateway.tool_pins import backend_id

URL = "https://backend.example/mcp"


def _one_pending_pin() -> str:
    """Open the store on this thread and leave one tool held for approval."""
    bid = backend_id(URL)
    perimeter_db.put_pin(
        bid,
        "wiki_read",
        approved=None,
        pending=("hash-of-the-new-definition", '{"name": "wiki_read"}'),
        rejected=False,
    )
    return bid


@pytest.mark.asyncio
async def test_the_singleton_is_still_bound_to_the_thread_that_opened_it() -> None:
    """The constraint this is all for. If this test ever fails, someone has
    passed ``check_same_thread=False`` and the reader below is dead weight."""
    bid = _one_pending_pin()

    def read_without_a_reader() -> list[sqlite3.Row]:
        return perimeter_db.list_pending_pins(bid)

    with pytest.raises(sqlite3.ProgrammingError):
        await asyncio.to_thread(read_without_a_reader)


@pytest.mark.asyncio
async def test_a_worker_reads_the_real_store_under_the_snapshot_reader() -> None:
    bid = _one_pending_pin()
    # Opened on the loop, which is where the singleton and the schema live; the
    # path is what the worker is handed.
    path = perimeter_db.opened_path()

    def read_under_a_reader() -> list[str]:
        with perimeter_db.snapshot_reader(path):
            return [row["tool"] for row in perimeter_db.list_pending_pins(bid)]

    assert await asyncio.to_thread(read_under_a_reader) == ["wiki_read"]


@pytest.mark.asyncio
async def test_the_reader_is_read_only_and_per_thread() -> None:
    """A worker cannot write through it, and it does not leak to the next read.

    The second half matters more than it looks: ``_local.reader`` is cleared on
    the way out, so a worker that reads under the reader and then writes is
    writing to the singleton — which raises, loudly, rather than silently
    writing to a connection the loop is also using.
    """
    _one_pending_pin()
    path = perimeter_db.opened_path()

    def write_through_the_reader() -> None:
        with perimeter_db.snapshot_reader(path):
            perimeter_db._read_db().execute("DELETE FROM tool_pins")

    with pytest.raises(sqlite3.OperationalError):
        await asyncio.to_thread(write_through_the_reader)

    def reader_is_gone_after_the_block() -> bool:
        with perimeter_db.snapshot_reader(path):
            pass
        return getattr(perimeter_db._local, "reader", None) is None

    assert await asyncio.to_thread(reader_is_gone_after_the_block)
