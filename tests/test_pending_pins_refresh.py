"""The refresher behind /health's pending_pins (#662)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from trentina import perimeter_db
from trentina.gateway import warmup


@pytest.fixture(autouse=True)
def _reset() -> Any:
    perimeter_db.pending_pins_cached = None
    yield
    perimeter_db.pending_pins_cached = None


async def test_success_fills_the_cache_through_the_snapshot_reader() -> None:
    seen: list[str] = []

    def count(path: str, _ids: set[str]) -> int:
        seen.append(path)
        return 4

    with (
        patch.object(perimeter_db, "opened_path", return_value="/x/perimeter.db"),
        patch.object(warmup, "_count_pins", count),
    ):
        await warmup.refresh_pending_pins()

    assert perimeter_db.pending_pins_cached == 4
    assert seen == ["/x/perimeter.db"]


async def test_failure_clears_the_cache() -> None:
    perimeter_db.pending_pins_cached = 2

    def boom(_path: str, _ids: set[str]) -> int:
        raise RuntimeError("locking protocol")

    with (
        patch.object(perimeter_db, "opened_path", return_value="/x"),
        patch.object(warmup, "_count_pins", boom),
    ):
        await warmup.refresh_pending_pins()

    assert perimeter_db.pending_pins_cached is None


async def test_open_failure_clears_the_cache() -> None:
    perimeter_db.pending_pins_cached = 2
    with patch.object(perimeter_db, "opened_path", side_effect=RuntimeError("x")):
        assert await warmup.refresh_pending_pins() is None
    assert perimeter_db.pending_pins_cached is None


async def test_a_wedged_read_times_out_and_is_not_resubmitted() -> None:
    pending: asyncio.Future[int] = asyncio.get_running_loop().create_future()
    perimeter_db.pending_pins_cached = 2
    with (
        patch.object(warmup, "PINS_TIMEOUT_SECONDS", 0.01),
        patch.object(warmup, "_count_pins", side_effect=AssertionError("resubmitted")),
    ):
        again = await warmup.refresh_pending_pins(pending)

    assert again is pending
    assert perimeter_db.pending_pins_cached is None
