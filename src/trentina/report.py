"""The `scan` block: what ran, what was decided, where it came from.

Replaces the `trust` object, which was a lie in the literal sense — it was
named for a property no content in this system ever has. Content that crossed
the perimeter is untrusted, permanently, because the layers are DETECTORS and
a detector finding nothing has not made anything safe. It has failed to find
something, and the gap between those two claims is the false-negative rate:
Prompt Guard 2 missed social engineering 40% of the time and exfiltration
intent 20% (the default L2 model since 0.55.0 misses fewer, not none), and
L3 on the default model catches 86% of attacks written to evade L1 and L2,
dropping to 33% on attacks aimed at the detector itself.

So there is no trust ladder here and there must not be one. A label saying
`l3_trusted` would be wrong two times out of three on the attack class that
targets judges, and it would travel into the agent's context telling it to
relax. That converts "the attacker got through" into "the attacker got
promoted", and publishes what to aim at.

`trust.level` collapsed four unrelated questions into one enum, which is how
it ended up meaning nothing: `advisory` and `quarantined` described what was
PRODUCED, `l1-only` and `layer1-fallback` described what RAN, `trusted-l1`
described who VOUCHED, and `blocked` described what was DECIDED. Nothing in
the codebase ever branched on any of them — the value reached one cockpit
table cell, rendered as a text label hardcoded to the "low" risk style, so
not even the UI read it.

Three independent facts, never collapsed:

* **layers** — which layers ran and whether each COMPLETED. A scan that did
  not finish must never read like a scan that found nothing; that is the rule
  ``warning.py`` already enforces for findings, and it applies here too.
* **disposition** — what the caller did about it.
* **origin** — where the bytes came from, and whether an operator has
  allowlisted that source.

WHAT IT FOUND is deliberately NOT here. That is ``_trentina_warning``'s job
and duplicating it would give two answers that can disagree.

ALLOWLISTING CHANGES WHAT A FINDING COSTS; IT NEVER SKIPS A LAYER OR HIDES A
FLAG. Since 0.31.0 an allowlisted source runs all three layers and its flags
stand. What ``origin.allowlisted`` explains is a block that became a redact:
block_* on an allowlisted source hands a flagged payload to the redact path
instead of refusing it, and reports ``disposition: extracted``. A redact that
fails still refuses — allowlisting removes false-positive refusals, it does
not create a channel that survives the redact pipeline giving up.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from .modes import gaps_of

if TYPE_CHECKING:
    from .defense import DefenseVerdict


class LayerState(str, Enum):
    """Whether a layer ran, and whether it finished."""

    COMPLETE = "complete"
    """Ran over the whole input and returned a result."""

    PARTIAL = "partial"
    """flag only: ran over the head of a payload past the admission cap."""

    NOT_ADMITTED = "not_admitted"
    """block or redact: the payload was over the admission cap, so the layer
    was never asked (#225). Not UNAVAILABLE: nothing is missing."""

    UNAVAILABLE = "unavailable"
    """Could not run: no ONNX model for L2, no API key or a provider error
    for L3. Distinct from COMPLETE with nothing found, which is the confusion
    this whole module exists to prevent."""

    SKIPPED = "skipped"
    """L3 only: ``l3_escalation: l2_flagged`` did not ask it, because L1 found
    nothing and L2 read all of it and passed it (a962). A policy, so not
    UNAVAILABLE; never asked, so not COMPLETE."""

    NOT_APPLICABLE = "not_applicable"
    """There was nothing to judge — an empty payload, or a JSON body whose
    string leaves are all blank."""


class Disposition(str, Enum):
    """What the caller did with what the layers concluded."""

    DELIVERED = "delivered"
    """The bytes that arrived, unchanged, with nothing attached."""

    ANNOTATED = "annotated"
    """The bytes that arrived, unchanged, plus ``_trentina_warning``."""

    EXTRACTED = "extracted"
    """A Q-Agent extraction INSTEAD of the original bytes."""

    REFUSED = "refused"
    """Nothing delivered. The caller raised."""


def layer_states(verdict: DefenseVerdict) -> dict[str, str]:
    """Derive per-layer state from a verdict.

    L1 is always ``complete``: it is free, deterministic, has no off switch,
    and a profile that could disable it would only be hiding its own eyes.

    L2 is ``unavailable`` when there was text to read and no classification
    came back — ``classify_async`` returns None when the model is missing or
    failed to load, which used to be indistinguishable from a clean scan.
    """
    if not verdict.pipeline.content.strip():
        return {
            "l1": LayerState.COMPLETE.value,
            "l2": LayerState.NOT_APPLICABLE.value,
            "l3": LayerState.NOT_APPLICABLE.value,
        }
    gaps = gaps_of(verdict)
    if gaps.oversize:
        return {
            "l1": LayerState.COMPLETE.value,
            "l2": LayerState.NOT_ADMITTED.value,
            "l3": LayerState.NOT_ADMITTED.value,
        }
    l2 = (
        LayerState.UNAVAILABLE
        if gaps.l2_unavailable
        else LayerState.PARTIAL
        if gaps.l2_truncated
        else LayerState.COMPLETE
    )
    l3 = (
        LayerState.SKIPPED
        if gaps.l3_skipped
        else LayerState.UNAVAILABLE
        if gaps.l3_unavailable or gaps.l3_quota
        else LayerState.PARTIAL
        if gaps.l3_truncated
        else LayerState.COMPLETE
    )
    return {"l1": LayerState.COMPLETE.value, "l2": l2.value, "l3": l3.value}


def build_report(
    verdict: DefenseVerdict | None,
    *,
    disposition: Disposition,
    kind: str,
    ref: str,
    allowlisted: bool = False,
    extracted_by: str | None = None,
) -> dict[str, Any]:
    """Build the `scan` block.

    Args:
        verdict: What the layers concluded, or None when no layer ran — the
            advisory paths refuse a URL on its shape before fetching it.
        disposition: What the caller did.
        kind: What ``ref`` identifies: ``url``, ``file``, ``content``,
            ``search``.
        ref: The URL, path, query, or content hash.
        allowlisted: Whether an operator has vouched for this source. It
            turns a block into a redact; it neither skips a layer nor hides a
            flag.
        extracted_by: The model that produced an extraction, when there is
            one. Absent otherwise rather than null, because a key that is
            sometimes meaningless is read as meaningful.
    """
    layers = (
        layer_states(verdict)
        if verdict is not None
        else dict.fromkeys(("l1", "l2", "l3"), LayerState.NOT_APPLICABLE.value)
    )
    report: dict[str, Any] = {
        "layers": layers,
        "disposition": disposition.value,
        "origin": {"kind": kind, "ref": ref, "allowlisted": allowlisted},
    }
    if extracted_by is not None:
        report["extracted_by"] = extracted_by
    return report
