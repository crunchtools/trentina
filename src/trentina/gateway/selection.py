"""Run a document processor, report what it read, and fail open to reading more.

``gateway/drivers.py`` turns a configured name into a processor. This is the
call site: run it, degrade safely if it raises, and turn the coverage
accounting into the fields an operator reads.

This file held a second driver registry until #167, alongside a
mirror of the transform one. Two registries for two roles is how the
transform table ended up with no channel lock at all — the lock was
written once, in the half nobody copied it out of. Both tables now live in
``drivers.py``, and there is one role.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from ..jsonwalk import iter_leaves
from ..logsafe import exc_kind, exc_where, redact_source
from ..transforms import Selection

if TYPE_CHECKING:
    from ..transforms import DocumentProcessor, SelectionContext
    from .profile import MatrixPreProcessConfig

logger = logging.getLogger(__name__)


def read_everything(payload: Any, *, extractor: str, why: str) -> Selection:
    """The whole document, read, with nothing skipped.

    This is what the perimeter did before any selection existed, and it is
    what every failure falls back to. There used to be a ``full`` processor
    whose only job was this; under one driver role "read everything" is what
    an empty processor chain already means, so the behaviour stayed and the
    registry entry went.

    ``tests/test_full_is_defend_json.py`` is what made that deletion safe: it
    proves this walk and ``defend_json``'s reach the same verdict across the
    adversarial corpus. It is not a formality — the path below it is the one
    whose failure mode is "scanned nothing, looked clean".
    """
    leaves = iter_leaves(payload)
    total = sum(len(leaf) for leaf in leaves)
    return Selection(
        extractor=extractor,
        segments=tuple(leaves),
        chars_total=total,
        chars_scanned=total,
        skipped_chars={},
        degraded=why != "",
        details={"leaves": len(leaves), **({"fallback_from": why} if why else {})},
    )


async def run_l1(
    payload: Any,
    *,
    extractor: DocumentProcessor | None,
    ctx: SelectionContext,
) -> Selection:
    """Run the configured processor, or read everything if there is none.

    FAIL OPEN TO MORE READING, NEVER LESS. A processor that raises has told us
    nothing about the payload, and the only honest response to knowing nothing
    is to read all of it. No failure mode may result in "read nothing, looked
    clean" — which is the same rule as the text transforms', where failing
    open means delivering the original.
    """
    if extractor is None:
        return await asyncio.to_thread(read_everything, payload, extractor="none", why="")
    try:
        return await extractor.extract(payload, ctx)
    except Exception as exc:
        logger.error(  # the message may carry the payload (#262)
            "selection: processor %r failed for %s — reading everything instead: %s at %s",
            extractor.name,
            redact_source(ctx.path or ctx.source),
            exc_kind(exc),
            exc_where(exc),
        )
        return await asyncio.to_thread(
            read_everything, payload, extractor=extractor.name, why=extractor.name
        )


def describe(view: Selection, cfg: MatrixPreProcessConfig) -> dict[str, Any]:
    """The processor's contribution to `_trentina_warning`.

    Only reports when there is something to report: reading everything adds
    nothing, so the annotation stays quiet on the common path and an operator
    who sees these fields knows they mean something.
    """
    extras: dict[str, Any] = {}
    if view.coverage < 1.0:
        extras["scan_coverage"] = round(view.coverage, 4)
        extras["chars_scanned"] = view.chars_scanned
        extras["chars_total"] = view.chars_total
        extras["scan_processor"] = view.extractor
        extras["skipped"] = {r.value: n for r, n in view.skipped_chars.items() if n}
    if view.chars_total and view.coverage < cfg.min_coverage:
        extras["low_scan_coverage"] = True
    if view.degraded:
        extras["scan_degraded"] = True
        # The name alone plus this flag says what the old "<name>->full"
        # composite said, without a client having to parse a string.
        extras.setdefault("scan_processor", view.extractor)
    if view.undecryptable:
        extras["undecryptable_events"] = len(view.undecryptable)
    return extras
