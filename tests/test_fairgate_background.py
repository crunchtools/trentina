"""FairGate's background class (spec 027): bulk scans yield to tool calls."""

from __future__ import annotations

import asyncio

import pytest

from trentina.quarantine import classifier
from trentina.quarantine.classifier import BACKGROUND, FairGate, background_scans


async def _settle() -> None:
    for _ in range(3):
        await asyncio.sleep(0)


def _spawn(gate: FairGate, key: str, order: list[str], *, background: bool) -> asyncio.Task[None]:
    async def run() -> None:
        await gate.acquire(key, background=background)
        order.append(key)

    return asyncio.ensure_future(run())


async def test_a_foreground_waiter_beats_an_earlier_background_one() -> None:
    gate = FairGate(1)
    await gate.acquire("held")
    order: list[str] = []
    bg = _spawn(gate, "bg", order, background=True)
    await _settle()
    fg = _spawn(gate, "fg", order, background=False)
    await _settle()
    gate.release()
    await _settle()
    assert order == ["fg"]
    gate.release()
    await _settle()
    assert order == ["fg", "bg"]
    await asyncio.gather(bg, fg)


async def test_background_runs_when_the_gate_is_idle() -> None:
    gate = FairGate(1)
    await asyncio.wait_for(gate.acquire("bg", background=True), timeout=1)
    assert gate.locked()
    waiting = asyncio.ensure_future(gate.acquire("bg2", background=True))
    await _settle()
    gate.release()
    await asyncio.wait_for(waiting, timeout=1)


async def test_a_new_foreground_caller_does_not_jump_a_background_backlog_at_a_free_gate() -> None:
    """A free permit with a queue behind it is handed on, never taken by a newcomer."""
    gate = FairGate(1)
    await gate.acquire("held")
    bg = asyncio.ensure_future(gate.acquire("bg", background=True))
    await _settle()
    gate.release()
    await asyncio.wait_for(bg, timeout=1)
    assert gate.locked()


async def test_a_cancelled_background_waiter_passes_its_turn_on() -> None:
    gate = FairGate(1)
    await gate.acquire("held")
    first = asyncio.ensure_future(gate.acquire("a", background=True))
    await _settle()
    first.cancel()
    gate.release()
    await asyncio.wait_for(gate.acquire("b", background=True), timeout=1)
    assert gate.locked()


async def test_a_granted_then_cancelled_background_waiter_releases() -> None:
    gate = FairGate(1)
    await gate.acquire("held")
    waiting = asyncio.ensure_future(gate.acquire("a", background=True))
    await _settle()
    gate.release()  # granted, but not yet resumed
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert not gate.locked()


async def test_background_keys_rotate_among_themselves() -> None:
    gate = FairGate(1)
    await gate.acquire("held")
    order: list[str] = []
    tasks = [_spawn(gate, key, order, background=True) for key in ("a", "a", "a", "b", "b", "c")]
    await _settle()
    for _ in tasks:
        gate.release()
        await _settle()
    assert order == ["a", "b", "c", "a", "b", "a"]
    await asyncio.gather(*tasks)


async def test_the_context_var_selects_the_class() -> None:
    assert BACKGROUND.get() is False
    with background_scans():
        assert BACKGROUND.get() is True
    assert BACKGROUND.get() is False


async def test_classify_async_takes_a_background_permit_inside_background_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []

    class Spy(FairGate):
        async def acquire(self, key: str | None, *, background: bool = False) -> None:
            seen.append(background)
            await super().acquire(key, background=background)

    monkeypatch.setattr(classifier, "_gate", (asyncio.get_running_loop(), Spy(2)))
    monkeypatch.setattr(classifier, "classify", lambda *a, **k: None)
    await classifier.classify_async("x")
    with background_scans():
        await classifier.classify_async("x")
    assert seen == [False, True]
