"""Petit — FREE log reduction: remove certainty, leave uncertainty.

Repetitive machine output (a syslog tail, a CI log, a Nagios burst) is
mostly the same line wearing different timestamps. Fingerprint each line by
normalizing its volatile tokens, group identical fingerprints, keep the
first few real samples of each group, and account for the rest.

Grouping is done by petit itself — the ``petit-log`` package, from
https://github.com/crunchtools/petit — rather than by a second
implementation living here. What this module owns is the part that is
Trentina's business and not a log tool's: the normalization POLICY, the
thresholds, the decline behaviour, and the shape of the artifact that
crosses the perimeter.

The load-bearing rule: **normalize only tokens that cannot carry meaning to
a model** — digits, hex runs, IPs, UUIDs, timestamps. Never words. Two lines
that differ in a single word have different fingerprints and both survive,
so a semantic payload buried in 10,000 lines of boilerplate cannot be
normalized into the boilerplate's group: it stays its own line and reaches
the perimeter scan. Conversely, an attacker who crafts a payload to collide
with a boilerplate group achieves only its deletion — dropped lines are
never delivered, and a line that is never delivered injects nothing.

That rule is why the library is called the way it is:

Both pins are gone as of 0.22.0, and the rule above moved with them.

``driver="RawEntry"`` and ``stopwords=VOLATILE`` used to pin petit's fallback
driver and override its normalization, because the rule was Trentina's to
enforce and petit handed the knob to the caller. petit 3.2.0 inverts that: a
hash driver declares its own ``DEFAULT_FILTER`` and its own generalizations,
so the policy lives with the format that needs it, is tested once, and is
shared with every consumer. If a driver merges too eagerly, it gets tuned
there rather than overridden here.

The rule itself was also mis-justified. It argued that keeping a buried
payload distinct meant it "reaches the perimeter scan" — but a payload that
collides into a group is DELETED, so it reaches nobody, scanner included. The
rule never prevented smuggling. What it bought was preserved distinctions for
the agent reading the output, which is signal quality rather than a security
boundary. See issue #95.

DETECTION IS NOW LOAD-BEARING, and that is a new attack surface worth naming.
With no ``driver=``, an attacker who controls part of a tool response controls
which driver petit SELECTS, and therefore which generalization table is
applied to the whole payload — splice sshd-shaped lines into a Jira comment
and ``SecureLogHash``'s rules may apply to content they were never designed
for. Three things bound it: ``SecureLogEntry.tally_logic`` demands unanimity
across the sample, ``sample_indices`` spreads evenly so a contiguous injected
block cannot dominate unless it is most of the payload, and the chosen driver
rides in the sidecar so a surprising reduction is attributable. Do not lower
any driver's ``tally_logic`` bar. Tested by
``test_detection_cannot_be_steered_by_an_injected_block``.

Known limitation (adversarial review, 2026-09-13): an attacker who can
WRITE to a shared log ahead of time can pre-seed sample slots — three lines
matching a predicted alert's fingerprint mean the real fourth line is
counted but not shown, and the samples the agent reads carry the attacker's
values. "Collision achieves only deletion" therefore holds against payload
SMUGGLING, not against suppression of a victim line by an attacker with
prior write access to the same stream. The group count still shows the line
existed, and the [petit] summary prefix is in-band (spoofable) — consumers
must treat petit output as untrusted, which the perimeter already assumes.

Honest scope (from the plan, deliberately): petit reduces log-shaped
content. It does ~nothing for prose, minified JS, base64 blobs, or extracted
PDF text, and it declines (applied=False) rather than pretend.

Hostile-input hardening, kept on this side of the boundary regardless of
what the library promises: every regex here is linear-time (character
classes and bounded repetition, no nested quantifiers), and only the first
``_FINGERPRINT_MAX_CHARS`` of a line are handed to the library, so one
enormous line costs O(cap) not O(line). Samples are then read back from the
ORIGINAL lines by index, so capping the fingerprint never truncates what is
delivered. The library is synchronous, so it runs on a worker thread —
a large payload must not stall the gateway's event loop.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from petit import PetitError, analyze_text

from ..channels import Channel, Kind
from .base import Applied, Cost, Declined, Failed, Transform, TransformContext, TransformResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from petit import Group

# Handed to petit as ``max_record_chars``, which caps the FINGERPRINT KEY and
# never the samples. It used to be applied here, by truncating every line
# before the call — which silently broke framing: a 60-element JSON array cut
# at 400 characters is no longer parseable JSON, so ``JsonFramer`` declines,
# the whole payload falls back to one raw line, and the grouping the
# structured driver exists to do never happens. The cap has to be inside the
# library, past framing and in front of the stopword scrub.
_FINGERPRINT_MAX_CHARS = 400

# Below this many RECORDS there is nothing worth grouping. Records, not lines:
# petit 4.x frames before it groups, so a single-line JSON array is hundreds
# of comparable units and twenty lines of a mail thread may be two.
_MIN_RECORDS = 20

# The cheap pre-check, and the only thing that can be known before framing.
# A payload under BOTH floors cannot hold _MIN_RECORDS of anything, so it is
# refused without paying for a thread hop. Under either floor alone it is
# handed to petit, because neither measure is sound on its own any more —
# lines miss minified JSON, bytes miss a long single record.
_MIN_LINES = 20
_MIN_BYTES = 1024

# Keep this many real sample lines per group.
_SAMPLES_PER_GROUP = 3

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.


def _samples(lines: list[str], groups: Sequence[Group]) -> list[str]:
    """Every group's sample lines, as they were written.

    In written order, so the artifact reads like the payload it came from,
    and by SPAN, not by first line. A record stopped being a line in 4.0.0:
    the first line of a pretty-printed JSON element is "{", and selecting by
    line hands the agent a brace where a record was promised. Spans index
    the ORIGINAL lines, so the fingerprint cap never reaches what is
    delivered.
    """
    spans = sorted(
        (start, end)
        for group in groups
        for start, end in group.sample_spans
        if 0 <= start < end <= len(lines)
    )
    out_lines: list[str] = []
    emitted = 0
    for start, end in spans:
        # Groups should not overlap, but a driver that ever emitted
        # overlapping spans would otherwise duplicate delivered content.
        first = max(start, emitted)
        if first >= end:
            continue
        out_lines.extend(lines[first:end])
        emitted = end
    return out_lines


class PetitProcessor(Transform):
    """FREE. Collapses repetitive records, keeps samples, accounts for the rest."""

    name = "petit"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, _ctx: TransformContext) -> TransformResult:
        # petit reduces by structure alone; it reads no job context. The
        # library is synchronous, so the whole reduction runs on a worker.
        return await asyncio.to_thread(self.reduce, payload)

    def reduce(self, payload: str, *, tag: str = "[petit] ") -> TransformResult:
        """The reduction itself, synchronous. ``run`` puts it on a worker
        thread; ``structured`` calls it from the worker it is already on, for
        a log held in a JSON string (#419), so a log is reduced by one rule
        wherever it was found.

        ``tag`` opens each summary line. ``structured`` passes none: a
        bracketed tag inside a document's data read to L2 as an injected
        note (#411), and measured on a journal in a JSON string it took one
        case of six from 0.55 to 0.94 (``docs/benchmark.md``).
        """
        bytes_in = len(payload.encode("utf-8"))
        lines = payload.split("\n")

        if len(lines) < _MIN_LINES and bytes_in < _MIN_BYTES:
            return Declined("too_small", {"lines_in": len(lines), "bytes_in": bytes_in})

        try:
            analysis = analyze_text(
                payload,
                max_samples=_SAMPLES_PER_GROUP,
                source_name="trentina",
                max_record_chars=_FINGERPRINT_MAX_CHARS,
            )
        except PetitError as exc:
            # The library raises rather than exits. A reducer cannot absolve,
            # so this is a Failure: a required petit refuses, and ``structured``
            # (which calls ``reduce`` directly) counts it and heals.
            return Failed("petit_error", {"error": type(exc).__name__})

        if analysis.records_in < _MIN_RECORDS:
            # Named for the condition, not for the size. A 1.6 MB payload that
            # frames into three records lands here, and calling that "too
            # small" sent an earlier analysis of the production sidecar
            # looking for short responses that were not there.
            return Declined(
                "not_enough_records",
                {
                    "records_in": analysis.records_in,
                    "lines_in": analysis.lines_in,
                    "bytes_in": bytes_in,
                    "petit_framer": analysis.framer,
                },
            )

        collapsed = [g for g in analysis.groups if g.count > _SAMPLES_PER_GROUP]
        if not collapsed:
            return Declined(
                "nothing_repetitive",
                {
                    "records_in": analysis.records_in,
                    "petit_driver": analysis.driver,
                    "petit_framer": analysis.framer,
                },
            )

        out_lines = _samples(lines, analysis.groups)
        summary = [
            "",
            (
                f"{tag}{analysis.records_in} records reduced to "
                f"{len(out_lines)} line(s); "
                f"{len(collapsed)} repetitive group(s) collapsed "
                f"(showing first {_SAMPLES_PER_GROUP} of each):"
            ),
        ]
        summary.extend(f"{tag}  {g.count}x: {g.pattern}" for g in collapsed)

        reduced = "\n".join(out_lines + summary)
        bytes_out = len(reduced.encode("utf-8"))

        if bytes_in > 0 and bytes_out >= bytes_in:
            # The work is already done and measured; report what it achieved.
            # Without this the log says 100% either way, so "missed the bar by
            # a hair" and "saved nothing at all" are the same word — and the
            # first means the floor is costing real savings while the second
            # means the data simply does not compress.
            return Declined(
                "not_smaller",
                {
                    "would_be_bytes": bytes_out,
                    "would_be_ratio": round(bytes_out / bytes_in, 4),
                },
            )

        return Applied(
            reduced,
            {
                "lines_in": analysis.lines_in,
                "lines_out": len(out_lines),
                "records_in": analysis.records_in,
                "records_grouped": analysis.records_grouped,
                "groups_collapsed": len(collapsed),
                # Lines petit scrubbed away to nothing (blanks, bare
                # markers) are counted by neither group nor sample, and a
                # framer leaves its structural lines — a JSON array's own
                # brackets — outside every record. Say so rather than let
                # the arithmetic look wrong.
                "lines_dropped": max(0, analysis.lines_in - analysis.lines_grouped),
                # Which driver petit chose, how it cut the payload into
                # records, and whether it had to fall back. Detection is
                # load-bearing now that we no longer pin it: the driver
                # decides the normalization and the framer decides what a
                # comparable unit even is, so an operator reading a
                # surprising reduction needs both. Scalar, so the whole dict
                # serializes into an audit row.
                "petit_driver": analysis.driver,
                "petit_framer": analysis.framer,
                "petit_degraded": analysis.degraded,
            },
        )
