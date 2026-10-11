"""The L2 benign gate: content a model must not refuse (#411, #404).

The obfuscation gate (``obfuscation.py``) selects for a model that reads
encoded text as possibly hostile. Nothing held the other side: the default
model went into production flagging routine operations output, and the first
measurement of it was the audit log. This gate is that other side. A model,
at the threshold it ships with, is run over benign content of the shapes the
gateway delivers (``corpora/benign_ops.py``), read as the gateway reads it,
and may flag at most :data:`BENIGN_MAX_RATE` of the held-out cases.

The result is recorded in the model's ``trentina-model.json``
(``benchmarks/l2_benign.py --record``, run by the image build beside the
obfuscation gate). ``classifier.resolve_model`` reads the record and
``posture.check_l2_gate`` acts on it at startup. Both gates must pass at one
threshold: raising it to pass this one can fail the other, and the build
runs both.
"""

from __future__ import annotations

import math
from typing import Any

BENIGN_KEY = "benign_gate"
"""The manifest key the record is written under."""

BENIGN_MAX_RATE = 0.02
"""The share of held-out benign cases a model may flag: the bar the model
comparison of #353 was read at (2 of 150 benign documents)."""

BENIGN_MIN_CASES = 100
"""Fewer held-out cases than this is not a measurement: one flag would move
the rate by more than a point."""


def allowed(cases: int) -> int:
    """How many of ``cases`` a model may flag and pass."""
    return int(cases * BENIGN_MAX_RATE)


def record_of(flagged_by_category: dict[str, tuple[int, int]], threshold: float) -> dict[str, Any]:
    """The record ``--record`` writes under :data:`BENIGN_KEY`.

    Args:
        flagged_by_category: ``(flagged, cases)`` for each category of the
            held-out split.
        threshold: The threshold the model was run at.

    Returns:
        ``cases`` and ``flagged`` over every category, ``allowed``
        (:func:`allowed` of ``cases``), ``threshold``, ``by_category`` and
        ``passed``.
    """
    cases = sum(of for _, of in flagged_by_category.values())
    flagged = sum(hit for hit, _ in flagged_by_category.values())
    return {
        "cases": cases,
        "flagged": flagged,
        "allowed": allowed(cases),
        "threshold": threshold,
        "by_category": {
            name: {"flagged": hit, "of": of} for name, (hit, of) in flagged_by_category.items()
        },
        "passed": _passes(cases, flagged),
    }


def _passes(cases: int, flagged: int) -> bool:
    return cases >= BENIGN_MIN_CASES and flagged <= allowed(cases)


def _count(value: object) -> int | None:
    """``value`` as a non-negative count, or None. A bool is not a count."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def benign_state(manifest: dict[str, Any], threshold: float | None = None) -> str:
    """``passed``, ``failed`` or ``unrecorded``, from a model manifest.

    Recomputed from the record's counts, never read from its ``passed``
    field, as ``obfuscation.gate_state`` is. A record taken at another
    threshold than the one in force says nothing about this one: a lower
    threshold flags more. It is ``unrecorded`` then, which is how an operator
    who sets ``CLASSIFIER_THRESHOLD`` learns the gate has not been run on it.

    Args:
        manifest: The model's ``trentina-model.json``.
        threshold: The threshold in force; None skips that comparison.
    """
    record = manifest.get(BENIGN_KEY)
    counts = _counts(record) if isinstance(record, dict) else None
    measured_at = _threshold(record.get("threshold")) if isinstance(record, dict) else None
    stale = (
        threshold is not None and measured_at is not None and abs(measured_at - threshold) > 1e-9
    )
    if counts is None or measured_at is None or stale:
        return "unrecorded"
    return "passed" if _passes(*counts) else "failed"


def _counts(record: dict[str, Any]) -> tuple[int, int] | None:
    """``(cases, flagged)`` from a record, or None when either is not a count
    or more are flagged than there are cases."""
    cases, flagged = _count(record.get("cases")), _count(record.get("flagged"))
    return None if cases is None or flagged is None or flagged > cases else (cases, flagged)


def _threshold(value: object) -> float | None:
    """A recorded threshold, or None for anything that is not one.

    ``json.loads`` reads NaN and Infinity, and every comparison with NaN is
    false: unchecked, a record at NaN matched any threshold in force.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    return float(value) if math.isfinite(value) and 0.0 < value <= 1.0 else None
