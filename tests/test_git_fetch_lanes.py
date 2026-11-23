"""A profile's judged fetches, one at a time in two lanes (spec 027 phase 1)."""

from __future__ import annotations

import asyncio
from http import HTTPStatus

import pytest

from trentina.gateway import git_fetch
from trentina.gateway.git_fetch import LANE_QUEUE, LaneBusyError, enter_lane


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


async def test_one_lane_serialises() -> None:
    first = await enter_lane("p", False)
    second = asyncio.ensure_future(enter_lane("p", False))
    await _settle()
    assert not second.done(), "the second waits for the first"
    first.release()
    gate = await asyncio.wait_for(second, 1)
    gate.release()


async def test_fetch_and_promisor_lanes_are_independent() -> None:
    fetch = await enter_lane("p", False)
    promisor = await asyncio.wait_for(enter_lane("p", True), 1)
    assert fetch is not promisor
    fetch.release()
    promisor.release()


async def test_profiles_are_independent() -> None:
    mine = await enter_lane("one", False)
    theirs = await asyncio.wait_for(enter_lane("two", False), 1)
    mine.release()
    theirs.release()


async def test_a_full_queue_is_refused_busy() -> None:
    holder = await enter_lane("p", False)
    waiters = [asyncio.ensure_future(enter_lane("p", False)) for _ in range(LANE_QUEUE)]
    await _settle()
    with pytest.raises(LaneBusyError) as busy:
        await enter_lane("p", False)
    assert busy.value.status == HTTPStatus.TOO_MANY_REQUESTS
    assert busy.value.reason == "busy"
    holder.release()
    for waiter in waiters:  # each in turn takes the lane and lets it go
        (await asyncio.wait_for(waiter, 1)).release()


async def test_a_cancelled_waiter_leaks_nothing() -> None:
    holder = await enter_lane("p", False)
    waiters = [asyncio.ensure_future(enter_lane("p", False)) for _ in range(LANE_QUEUE)]
    await _settle()
    lane = git_fetch._lanes[asyncio.get_running_loop()][("p", "fetch")]
    assert lane.waiting == LANE_QUEUE
    waiters[-1].cancel()
    await _settle()
    assert lane.waiting == LANE_QUEUE - 1
    late = asyncio.ensure_future(enter_lane("p", False))  # the freed place is usable
    await _settle()
    assert lane.waiting == LANE_QUEUE
    holder.release()
    for waiter in [*waiters[:-1], late]:
        (await asyncio.wait_for(waiter, 1)).release()
    assert lane.waiting == 0
    assert not lane.gate.locked(), "no permit was leaked"
    again = await asyncio.wait_for(enter_lane("p", False), 1)
    again.release()
