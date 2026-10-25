"""Read what could be language; account for everything else.

The reducer for structured payloads. Where ``petit`` collapses repeated lines
and ``structured`` collapses repeated array elements, this one drops the
strings that cannot carry an instruction at all — ciphertext, identifiers,
enum constants, numbers, exact duplicates.

Why it exists: a measured Matrix initial sync was 68,092 characters reaching
the classifier, of which 45,552 were Megolm ciphertext, 13,352 were JSON key
names, 7,617 were key-backup material, and 245 were human-readable prose. The
scan took 46 seconds to read base64 it held no key for. Reading less is not a
shortcut here; it is the difference between a perimeter that runs and one that
times out and is skipped entirely. Takeda measured 17.6x.

Three mechanisms, in order of what they save on that sync:

1. STRUCTURAL SKIPPING (``shapes.classify_skip``) removes ciphertext,
   identifiers, enum constants and numbers — 53 KB of the measured 68 KB.
2. DEDUPLICATION removes repeats. 1,289 key names in that sync are about forty
   distinct strings; every distinct one is still read exactly once. A
   classifier learns nothing from the second ``"origin_server_ts"``, and
   nothing can hide in a duplicate, because hiding requires the string to be
   absent and it is not — it is right there, the first time.
3. SKIP SAMPLING puts the opening of every skipped string into one extra
   segment, so a payload hidden in a field the rules declined still gets its
   first bytes in front of L1 and L2. This is the backstop for the residual
   hole in ``shapes``, and it does not depend on any shape rule being right —
   which is exactly what a backstop should not do.

The sample is deterministic — first N by document order, never random — so an
incident is reproducible from the payload alone.

Two rules bind this processor specifically, and they are the reason it is safe
to skip bytes at all:

SKIPPING IS STRUCTURAL, NEVER SEMANTIC. A string may be skipped only on a
   property of its own shape: charset, length, absence of whitespace, a match
   against an identifier grammar. Never on its meaning, its sender, its room,
   or a classifier's opinion of it. The predicate is a pure function of the
   string. There is no trusted-sender list and there never will be, because
   the sender is the thing an attacker controls most cheaply.

SKIPPING IS ACCOUNTED, AND LOW COVERAGE IS ITSELF A FINDING. Every skipped
   byte is counted by reason. The histogram rides into the audit record and
   into L3's briefing, because "this is the 4% that survived selection" is
   context a judge should have. A scan that read 2% of a document must not
   look like a scan that read all of it.

``tests/test_preprocess_select.py`` is what earns the right to skip: for every
case in the corpus, no leaf is skipped, planted as a value, as a key, and
nested in an array.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ..channels import Channel, Kind
from ..jsonwalk import iter_leaves
from .shapes import MIN_SKIP_LEN, classify_skip
from .view import Selection, SelectionContext, SkipReason

if TYPE_CHECKING:
    from collections.abc import Iterable

DEFAULT_SKIP_SAMPLE_BYTES = 1024
"""Budget for the sampled-openings segment. Two L2 windows, near enough."""

_SAMPLE_HEAD_CHARS = 64
"""How much of each skipped string the sample carries."""


class SelectProcessor:
    """Read what could be language; account for everything else."""

    name = "select"
    kind = Kind.DOCUMENT
    # MATRIX only, because that is the only channel wired to hand a
    # processor a parsed document. It claimed all three as an extractor,
    # which was aspirational: the alert ingress defends structured payloads
    # but has never resolved a processor by name, and the tool channel
    # supplies strings.
    channels = frozenset({Channel.MATRIX})

    def __init__(self, *, skip_sample_bytes: int = DEFAULT_SKIP_SAMPLE_BYTES) -> None:
        self.skip_sample_bytes = skip_sample_bytes

    async def extract(self, payload: Any, _ctx: SelectionContext) -> Selection:
        # Linear in the payload, but a whole sync response on the loop stalls
        # every profile for its length (#295).
        return await asyncio.to_thread(lambda: self.select(iter_leaves(payload)))

    def select(
        self,
        leaves: Iterable[str],
        *,
        extra_segments: Iterable[str] = (),
        extra_skipped: dict[SkipReason, int] | None = None,
        encrypted_events: int = 0,
        decrypted_events: int = 0,
        undecryptable: tuple[Any, ...] = (),
        extractor_name: str | None = None,
    ) -> Selection:
        """Apply the rules to an already-collected leaf list.

        Split out from ``extract`` so the Matrix extractor can hand its
        decrypted message bodies through the same rules rather than trusting
        them — a base64 blob pasted inside a decrypted message is still a
        base64 blob, and plaintext recovered from ciphertext is no more
        trustworthy than plaintext that arrived in the clear.
        """
        segments: list[str] = []
        skipped: dict[SkipReason, int] = dict(extra_skipped or {})
        seen: set[str] = set()
        sample_parts: list[str] = []
        sample_budget = self.skip_sample_bytes
        total = 0
        scanned = 0

        def bump(reason: SkipReason, n: int) -> None:
            skipped[reason] = skipped.get(reason, 0) + n

        for leaf in list(leaves) + list(extra_segments):
            total += len(leaf)

            if leaf in seen:
                bump(SkipReason.DUPLICATE, len(leaf))
                continue

            reason = classify_skip(leaf)
            if reason is None:
                seen.add(leaf)
                segments.append(leaf)
                scanned += len(leaf)
                continue

            bump(reason, len(leaf))
            seen.add(leaf)
            if sample_budget > 0 and len(leaf) >= MIN_SKIP_LEN:
                head = leaf[:_SAMPLE_HEAD_CHARS]
                sample_parts.append(head)
                sample_budget -= len(head)

        if sample_parts:
            # One segment, not many: the classifier pays per window, so
            # sampled openings are cheapest concatenated.
            sample = "\n".join(sample_parts)
            segments.append(sample)
            # Sampled characters were already counted under their skip
            # reason. Counting them as scanned too would break S3's identity,
            # and the honest reading is that they WERE skipped — the sample
            # is a probe, not coverage.

        return Selection(
            extractor=extractor_name or self.name,
            segments=tuple(segments),
            chars_total=total,
            chars_scanned=scanned,
            skipped_chars=skipped,
            encrypted_events=encrypted_events,
            decrypted_events=decrypted_events,
            undecryptable=undecryptable,
            details={
                "distinct_leaves": len(seen),
                "sampled_openings": len(sample_parts),
            },
        )
