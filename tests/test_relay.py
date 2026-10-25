"""The shared perimeter-call lifecycle (gateway/relay.py).

``Operation.finish`` and ``Slots`` are used by every terminating route, so the
behaviour the routes rely on — the row is written once, the slot comes back even
when closing the upstream fails, a lost audit row never fails the request — is
tested here, once, not only through each route.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest

from trentina.gateway import relay
from trentina.gateway.relay import Operation, Relayed, Slots


def _op(**kw: Any) -> Operation:
    """An Operation for a fake profile; only ``profile.name`` is read."""
    return Operation(SimpleNamespace(name="agent1"), backend="egress:gh", **kw)


async def test_finish_writes_one_row_however_many_times_it_is_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows: list[Any] = []
    monkeypatch.setattr(relay, "record_gateway_call", lambda *a, **k: rows.append(a))
    op = _op()
    await op.finish()
    await op.finish()
    await op.finish()
    assert len(rows) == 1  # finished guard makes the extra calls no-ops


async def test_finish_returns_the_slot_and_writes_the_row_even_if_close_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows: list[Any] = []
    monkeypatch.setattr(relay, "record_gateway_call", lambda *a, **k: rows.append(a))
    slots = Slots(1)
    op = _op()
    assert op.take_slot(slots)
    assert not slots.take("agent1")  # the one slot is held

    async def boom() -> None:
        raise RuntimeError("upstream close failed")

    op.upstream.push_async_callback(boom)
    with pytest.raises(RuntimeError):
        await op.finish()  # the close error propagates, as it did per-route
    assert slots.take("agent1"), "the slot came back despite the close failure"
    assert len(rows) == 1  # and the row was still written


async def test_finish_swallows_an_audit_write_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("audit db down")

    monkeypatch.setattr(relay, "record_gateway_call", boom)
    # Must not raise: a lost audit row never fails the request it records.
    await _op().finish()


def test_slots_cap_is_per_instance_and_returns() -> None:
    slots = Slots(2)
    assert slots.take("a") and slots.take("a")
    assert not slots.take("a")  # full at the cap
    assert slots.take("b")  # a different profile is independent
    slots.give("a")
    assert slots.take("a")  # room again after a give


def test_slots_give_past_zero_is_a_no_op() -> None:
    """A give with no entry must not raise (the old dict ``-= 1`` KeyError'd)."""
    slots = Slots(1)
    slots.give("never-taken")  # no raise
    slots.take("a")
    slots.give("a")
    slots.give("a")  # already at zero; no raise, entry stays absent
    assert slots.take("a")


def test_take_slot_false_holds_nothing() -> None:
    slots = Slots(1)
    first = _op()
    assert first.take_slot(slots)
    second = _op()
    assert not second.take_slot(slots)  # full
    assert not second.holds_slot  # a refused take leaves the op holding nothing


async def test_relayed_finishes_in_call_when_the_client_disconnects_mid_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client that disconnects MID-STREAM must still finish the Operation —
    promptly, in __call__, not whenever the body generator is garbage-collected.
    The body here never completes on its own (it blocks after the first chunk),
    so the only thing that can finish the op is __call__'s finally. On the old
    body-generator-finally design op would be unfinished here (closed at GC), so
    this asserting op.finished right after __call__ returns is the real guard."""
    rows: list[Any] = []
    monkeypatch.setattr(relay, "record_gateway_call", lambda *a, **k: rows.append(a))
    slots = Slots(1)
    op = _op()
    assert op.take_slot(slots)
    op.settle(relay.Outcome.OK)

    first_chunk_sent = asyncio.Event()

    async def body() -> AsyncIterator[bytes]:
        yield b"a"
        first_chunk_sent.set()
        await asyncio.Event().wait()  # never set: the body cannot finish itself
        yield b"unreached"

    async def send(_message: dict[str, Any]) -> None:
        return None

    async def receive() -> dict[str, Any]:
        await first_chunk_sent.wait()  # one chunk relayed, then the client is gone
        return {"type": "http.disconnect"}

    relayed = Relayed(body(), op, media_type="text/plain")
    await relayed({"type": "http", "asgi": {"spec_version": "2.3"}}, receive, send)

    assert op.finished  # finished in __call__, though the body never drained
    assert len(rows) == 1  # exactly one audit row
    assert slots.take("agent1"), "the slot came back after the disconnect"
