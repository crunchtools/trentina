"""Email — FREE reduction for mail-shaped tool output.

Phase 3 of the reduction plan, and the sleeper: mail was the highest
bytes-per-call of the three shapes in the sidecar, and almost all of that
weight is boilerplate the reader has already seen.

A reply quotes the message it answers. A thread of eight messages therefore
carries the first message eight times, the second seven times, and so on —
quadratic repetition that no line-level grouper catches, because the copies
are not identical lines: each nesting level adds another ``> ``.

Two rules, both deterministic, both deletion:

* **Quoted blocks.** A run of consecutive quoted lines keeps its first few
  and counts the rest. Where petit collapses lines that are the same, this
  collapses lines that are marked as already-said.
* **Signatures.** ``-- `` on a line of its own is the RFC 3676 §4.3 sign-off
  delimiter. What follows is contact details and legal boilerplate, repeated
  identically on every message its author ever sends.

Deliberately NOT here: collapsing footers and disclaimers that repeat across
the messages in a batch. Those are identical lines, which is exactly petit's
job — run this and then petit, which is what the ``chain`` strategy in
``compose.py`` is for. A reducer that reimplements the reducer next to it is
how two subtly different grouping rules end up in one pipeline.

Security. Everything here deletes; nothing rewrites. A payload hidden in a
quoted block or a signature is dropped, and a dropped line is never
delivered, so there is nothing to smuggle. The inverse is the real caveat
and it is the same one petit carries: an attacker who can shape the message
can get a victim's line classified as quotation or signature and thereby
SUPPRESSED. The bound on that is ``_MAX_SIGNATURE_LINES`` — a crafted ``-- ``
cannot swallow an unlimited tail — plus the counts, which still show that
lines existed. Every marker this module writes is in-band and therefore
spoofable; consumers must treat reduced output as untrusted, which the
perimeter already assumes.

Hostile-input hardening: every pattern is anchored and linear-time, each
line is examined once, and classification reads at most
``_CLASSIFY_MAX_CHARS`` of a line.
"""

from __future__ import annotations

import re

from ..channels import Channel, Kind
from .base import Applied, Cost, Declined, Transform, TransformContext, TransformResult

# A quoted line: any number of ">" markers, optionally spaced, at the start.
_QUOTE = re.compile(r"^\s{0,4}(?:>\s?){1,10}")

# Headers that make a payload mail-shaped. Anchored, so a line of prose
# mentioning "Subject:" mid-sentence does not count.
_HEADER = re.compile(
    r"^(?:From|To|Cc|Bcc|Subject|Date|Sent|Reply-To|Message-ID):\s",
    re.IGNORECASE,
)

# RFC 3676 §4.3: exactly "-- " on its own line. Accept the common "--"
# without the trailing space, which many clients emit.
_SIGNATURE = re.compile(r"^--\s?$")

_CLASSIFY_MAX_CHARS = 200

# Below this, the payload is not mail enough to be worth the risk.
_MIN_LINES = 20

# Quoted lines retained at the head of each quoted run.
_QUOTE_SAMPLE_LINES = 3

# A quoted run shorter than this is left alone — collapsing two lines into
# a marker saves nothing and costs the reader the text.
_MIN_QUOTE_RUN = 6

# The most lines one signature delimiter may remove. A signature is contact
# details, not a document, and this is what stops a crafted "-- " from
# suppressing an unbounded tail of the message.
_MAX_SIGNATURE_LINES = 20

# Evidence required before treating the payload as mail at all.
_MIN_HEADERS = 2
_MIN_QUOTED_LINES = 5

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.

_QUOTE_OMITTED = "[email] {count} more quoted line(s) omitted"
_SIGNATURE_OMITTED = "[email] signature omitted ({count} line(s))"


def _is_quoted(line: str) -> bool:
    return bool(_QUOTE.match(line[:_CLASSIFY_MAX_CHARS]))


def _looks_like_mail(lines: list[str]) -> bool:
    """Enough evidence to apply mail-specific rules.

    Either a header block or a substantial amount of quotation. Prose that
    happens to contain one ``>`` must not qualify, because every rule below
    deletes and a false positive deletes the wrong thing.
    """
    headers = 0
    quoted = 0
    for line in lines:
        head = line[:_CLASSIFY_MAX_CHARS]
        if _HEADER.match(head):
            headers += 1
            if headers >= _MIN_HEADERS:
                return True
        elif _is_quoted(line):
            quoted += 1
            if quoted >= _MIN_QUOTED_LINES:
                return True
    return False


def _collapse(lines: list[str]) -> tuple[list[str], int, int, int]:
    """Drop quoted tails and signatures.

    Returns the kept lines plus what was removed: quoted lines, quoted runs,
    and signature lines.
    """
    out: list[str] = []
    quoted_dropped = 0
    runs_collapsed = 0
    signature_dropped = 0

    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]

        if _SIGNATURE.match(line[:_CLASSIFY_MAX_CHARS]):
            # Everything to the end of the signature, bounded. A header line
            # means the next message has started, so the signature is over.
            end = index + 1
            limit = min(total, index + 1 + _MAX_SIGNATURE_LINES)
            while end < limit and not _HEADER.match(lines[end][:_CLASSIFY_MAX_CHARS]):
                end += 1
            removed = end - index
            signature_dropped += removed
            out.append(_SIGNATURE_OMITTED.format(count=removed))
            index = end
            continue

        if _is_quoted(line):
            end = index
            while end < total and _is_quoted(lines[end]):
                end += 1
            run = end - index
            if run < _MIN_QUOTE_RUN:
                out.extend(lines[index:end])
            else:
                out.extend(lines[index : index + _QUOTE_SAMPLE_LINES])
                dropped = run - _QUOTE_SAMPLE_LINES
                quoted_dropped += dropped
                runs_collapsed += 1
                out.append(_QUOTE_OMITTED.format(count=dropped))
            index = end
            continue

        out.append(line)
        index += 1

    return out, quoted_dropped, runs_collapsed, signature_dropped


class EmailProcessor(Transform):
    """FREE. Collapses quoted reply chains and strips signatures."""

    name = "email"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, _ctx: TransformContext) -> TransformResult:
        # Reduction is driven by the payload's shape; it reads no job context.
        bytes_in = len(payload.encode("utf-8"))
        lines = payload.split("\n")

        if len(lines) < _MIN_LINES:
            return Declined("not_line_structured", {"lines_in": len(lines), "bytes_in": bytes_in})

        if not _looks_like_mail(lines):
            return Declined("not_email")

        kept, quoted_dropped, runs, signature_dropped = _collapse(lines)

        if not quoted_dropped and not signature_dropped:
            return Declined("nothing_repetitive")

        reduced = "\n".join(kept)
        bytes_out = len(reduced.encode("utf-8"))

        if bytes_in > 0 and bytes_out >= bytes_in:
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
                "lines_in": len(lines),
                "lines_out": len(kept),
                "quoted_lines_dropped": quoted_dropped,
                "quoted_runs_collapsed": runs,
                "signature_lines_dropped": signature_dropped,
            },
        )
