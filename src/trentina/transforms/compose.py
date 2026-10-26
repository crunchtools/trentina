"""Composition — run transforms independently or remixed, outside the wall.

The owner's framing: transforms are LEGO. Run a log through petit, then
summarize the result; or run both and keep whichever came out smaller; or
run FREE ones always and spend LLM money only when the payload is still over
budget. New processors join the registry and every strategy can use them.

Every strategy here selects on SIZE, which is narrower than the contract in
``base.py``: transformation, not reduction. ``best_of`` picks the smallest
applied result, so a processor that reshapes without shrinking loses to any
that shrank; ``auto`` escalates to METERED only while over ``target_bytes``.
``chain`` is the strategy that carries a non-shrinking transformation through
unconditionally. This gap is known and deliberate — widening selection wants a
second non-reducing processor to design against.

Whatever the strategy, the caller receives ONE artifact plus its accounting
(a ``TransformRecord`` per step), scans that artifact through ``defend()``,
and delivers that artifact. The composition layer itself never touches the
defense pipeline — the perimeter is the caller's job, and keeping this module
import-free of the detectors is what the architecture contract test checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from ..defense import Provenance
from ..logsafe import exc_kind, exc_where
from .base import (
    Applied,
    Cost,
    Failed,
    Transform,
    TransformContext,
    TransformRecord,
)

logger = logging.getLogger(__name__)

Strategy = Literal["none", "chain", "best_of", "auto"]


@dataclass(frozen=True)
class TransformOutcome:
    """The transformed artifact and all the perimeter should know about it."""

    content: str
    results: list[TransformRecord] = field(default_factory=list)
    bytes_in: int = 0
    bytes_out: int = 0

    @property
    def metered_used(self) -> bool:
        """True if any LLM touched the payload on its way here."""
        return any(r.cost is Cost.METERED and r.applied for r in self.results)

    def provenance(self, input_provenance: Provenance = Provenance.EXTERNAL) -> Provenance:
        """What the perimeter should treat the artifact as.

        Deterministic transformation preserves the input's provenance — petit
        deleting lines cannot compose a payload. An LLM rewriting the
        payload makes it model output, and model output gets unconditional
        L3 regardless of how innocent it scores.
        """
        if self.metered_used:
            return Provenance.MODEL_OUTPUT
        return input_provenance

    def sidecar(self) -> dict[str, object]:
        """Accounting for the token mandate.

        Intended for the audit log; today only ``describe_for_l3`` reaches the
        wire, and this method has no caller outside the tests.
        """
        return {
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "ratio": round(self.bytes_out / self.bytes_in, 4) if self.bytes_in else 1.0,
            "processors": [r.row() for r in self.results],
        }

    def describe_for_l3(self) -> str | None:
        """The sidecar as a briefing line for the Q-Agent's context.

        A judge should know it is reading a transformed artifact: an anomalous
        compression ratio, or a summarizer having rewritten the text, changes
        what suspicion looks like.
        """
        applied = [r for r in self.results if r.applied]
        if not applied:
            return None
        steps = ", ".join(
            f"{r.name} ({r.bytes_in}B -> {r.bytes_out}B"
            + (", LLM-generated output" if r.cost is Cost.METERED else "")
            + ")"
            for r in applied
        )
        return (
            "This payload was transformed by pre-processing before reaching "
            f"you: {steps}. You are judging the transformed artifact, which is "
            "exactly what will be delivered if it passes."
        )


async def run_transforms(
    content: str,
    *,
    processors: list[Transform],
    strategy: Strategy = "chain",
    ctx: TransformContext | None = None,
) -> TransformOutcome:
    """Transform ``content`` per ``strategy``. Never raises on hostile input —
    a processor that fails is logged and recorded as ``Failed``, and the
    payload is carried through unchanged (a floor call site refuses on it)."""
    ctx = ctx or TransformContext()
    bytes_in = len(content.encode("utf-8"))

    if strategy == "none" or not processors:
        return TransformOutcome(content=content, bytes_in=bytes_in, bytes_out=bytes_in)

    if strategy == "chain":
        records = await _chain(content, processors, ctx)
    elif strategy == "best_of":
        records = await _best_of(content, processors, ctx)
    elif strategy == "auto":
        records = await _auto(content, processors, ctx)
    else:  # pragma: no cover - Literal keeps this unreachable from typed code
        raise ValueError(f"unknown preprocess strategy: {strategy}")

    final = _final(content, records)
    return TransformOutcome(
        content=final,
        results=records,
        bytes_in=bytes_in,
        bytes_out=len(final.encode("utf-8")),
    )


def _final(original: str, records: list[TransformRecord]) -> str:
    """The artifact the composition produced: the last ``Applied`` content, or
    the original when nothing applied. ``best_of`` moves its winner last, so
    this is the winner there too."""
    final = original
    for rec in records:
        if isinstance(rec.result, Applied):
            final = rec.result.content
    return final


async def _run_one(processor: Transform, payload: str, ctx: TransformContext) -> TransformRecord:
    try:
        result = await processor.run(payload, ctx)
    except Exception as exc:
        logger.error(  # the message may carry the payload (#262)
            "preprocess: %s failed; passing payload through: %s at %s",
            processor.name,
            exc_kind(exc),
            exc_where(exc),
        )
        result = Failed("error")
    return TransformRecord.of(processor.name, processor.cost, payload, result)


def first_failure(records: list[TransformRecord]) -> TransformRecord | None:
    """The first step that FAILED (tried and could not finish), or None.

    A floor call site refuses on this; a decline is never here. The one
    definition both floor sites share, replacing three membership tests
    against the old ``FAILED_DECLINES`` set.
    """
    return next((r for r in records if isinstance(r.result, Failed)), None)


async def _chain(
    content: str, processors: list[Transform], ctx: TransformContext
) -> list[TransformRecord]:
    """Feed each processor the previous one's applied output."""
    records: list[TransformRecord] = []
    current = content
    for processor in processors:
        record = await _run_one(processor, current, ctx)
        records.append(record)
        if isinstance(record.result, Applied):
            current = record.result.content
    return records


async def _best_of(
    content: str, processors: list[Transform], ctx: TransformContext
) -> list[TransformRecord]:
    """Run every processor on the SAME input; keep the smallest artifact.

    Records still show every attempt (the sidecar shows what was tried), but
    the winner — the smallest applied result, or nothing when none improved —
    is moved last, because ``_final`` reads the last applied content.
    """
    attempts = [await _run_one(p, content, ctx) for p in processors]
    applied = [r for r in attempts if r.applied]
    if not applied:
        return attempts
    winner = min(applied, key=lambda r: r.bytes_out)
    return [r for r in attempts if r is not winner] + [winner]


async def _auto(
    content: str, processors: list[Transform], ctx: TransformContext
) -> list[TransformRecord]:
    """FREE processors always; METERED only while still over budget.

    With no target_bytes, METERED processors are never invoked — spending
    LLM money requires the caller to say what "small enough" means.
    """
    free = [p for p in processors if p.cost is Cost.FREE]
    metered = [p for p in processors if p.cost is Cost.METERED]

    records = await _chain(content, free, ctx)
    current = _final(content, records)

    if ctx.target_bytes is None:
        return records

    for processor in metered:
        if len(current.encode("utf-8")) <= ctx.target_bytes:
            break
        record = await _run_one(processor, current, ctx)
        records.append(record)
        if isinstance(record.result, Applied):
            current = record.result.content
    return records
