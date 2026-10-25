"""Transform contract — payload TRANSFORMATION outside the perimeter.

Trentina has two mandates: defend the primary model, and save it tokens.
They are served by two mechanisms in two places, deliberately:

* Transforms (this package) TRANSFORM payloads. They run outside the
  perimeter, their output is exactly as untrusted as their input, and
  everything they emit crosses the defense pipeline on its way in.
* The guards make verdicts. Parameter guards, response guards, and the
  three-layer scanner (``defense.py``). Guards decide; nothing else does.
  They never transform what is delivered.

One driver role — the transform. The guards are fixed trust machinery, not a
pluggable driver role, and everything in a request path is one or the other.
There is no third.

Two INPUT SHAPES, not two roles. Most processors here are ``str -> str``
(``Transform``, below). ``select`` and ``matrix`` take parsed JSON and
return the strings worth reading out of it (``DocumentProcessor`` in
``view.py``), because ``m.room.encrypted`` is a structure rather than a
substring. They were a separate package with a separate contract until #167.

Reduction is the most common transformation, not the only one, and the
package has never been reduction-only. petit's ``strict.stopwords`` rewrites
timestamps and identifiers into placeholders — the fingerprinting policy
invariant 2 rests on, whose size effect is incidental and goes both ways.
``structured.py`` re-serializes with indentation. Normalizing, restructuring
and filtering are all in scope.

Three invariants, none negotiable:

1. A transform may SUBTRACT, never ABSOLVE. Dropping, collapsing,
   normalizing and restructuring are all permitted — deleting content is
   always safe, because a byte that is deleted reaches no one. What is
   forbidden is the other direction: never mark content clean, never shorten
   or skip ``defend()``, and never let output be trusted more than input.
2. A transform never bypasses ``defend()``. Everything it emits is
   scanned. What a processor DROPPED never reaches the agent at all, which is
   what makes fingerprint-collision games pointless — colliding your payload
   into a collapsed group deletes it, and a line that is never delivered
   injects nothing.

   That argument is about DELETION specifically, not about getting smaller. A
   processor that rearranges rather than deletes does not inherit it: its
   bytes are still delivered, so it must carry its own reasoning for why
   reshaping them is safe.

   Whether the DELIVERED bytes are this processor's output or the untouched
   original is the CALL SITE's decision, not the driver's.
   ``gateway/transform.py`` delivers what the chain returned;
   ``gateway/matrix_proxy.py`` forwards the upstream ciphertext, because the
   agent must decrypt for itself (issue #162). Where the two differ, the call
   site accounts for the gap — coverage, a skip histogram by reason, and
   ``low_scan_coverage`` below the floor.

   Scan-differs-from-deliver at a call site is not an anomaly to be designed
   out; the Matrix path cannot deliver plaintext it does not own. It is a
   call-site property only. INSIDE the perimeter every layer reads the bytes
   that are delivered (the Layer contract, ``docs/defense-pipeline.md``).
   This paragraph used to cite L1's normalized copy for L2 as precedent;
   #359 retired L2's read of that copy.

   A previous revision of this file (#163) ruled the opposite — that a
   transform may never open a gap between what is scanned and what is
   delivered — and used that to split this package in two. The rule did not
   survive contact with L1, and the split it justified is undone. It is
   recorded here because the reasoning was plausible and someone will
   reconstruct it.

3. Every transform accounts for itself, and FAILS OPEN. The sidecar (bytes in/out, ratio,
   what was collapsed) reaches L3's briefing, because "this artifact is the
   3% that survived transformation" is context a judge should have. Routing
   it to the audit log as token-mandate evidence is intended and not yet
   built — ``router.py`` reads the sidecar only for the briefing, and
   ``TransformOutcome.sidecar()`` has no caller in ``src/``.

COMPOSITION IS STILL SIZE-DRIVEN, even though this contract is not. A
transformation that does not shrink runs under ``chain`` and keeps its output,
runs under ``auto`` if FREE, and loses under ``best_of`` to any processor that
shrank more. Below ``min_bytes`` nothing runs at all, and every FREE processor
here self-declines on ``bytes_out >= bytes_in``. Read ``compose.py`` before
assuming a reshaping processor will survive the strategy you configured.

A FILTERING processor — one that drops records a policy names — is permitted
by invariant 1 and would be a better fit than a whole-response guard for
per-record cases. It is not safe to build on this framework yet: composition
fails OPEN by design (``compose.py`` swallows processor errors and passes the
original through), so a filter that raised would deliver exactly what it
exists to remove. That needs fail-closed handling first.

FAILING OPEN MEANS HIDING NOTHING, and which direction that points depends on
what the processor owns. A text processor that raises delivers and scans the
ORIGINAL — ``compose.py`` swallows the error and passes the payload through. A
document processor that raises causes its caller to read EVERYTHING
(``gateway/selection.py``). Both are the same rule: on failure, do the thing
that hides nothing. No failure mode may result in "read nothing, looked clean".

Transforms parse hostile bytes. Regexes here must be linear-time and
fingerprinting must cap the bytes it reads per line — an attacker choosing
the input must not be able to buy quadratic work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..channels import Channel, Kind


class Cost(str, Enum):
    """What running the processor spends.

    FREE is deterministic local compute. METERED calls an LLM — which is why
    the composition result tracks whether any METERED processor touched the
    payload: model output gets unconditional L3 (see ``defense.Provenance``),
    because a coerced summarizer emits exactly the fluent, syntax-free shape
    L2 is documented to miss.
    """

    FREE = "free"
    METERED = "metered"


@dataclass(frozen=True)
class TransformContext:
    """What the processor may know about the job. Not a policy channel."""

    source: str = ""
    # The size the caller is trying to get under, in bytes. None means
    # "smaller is better but nothing binds". auto-composition escalates to
    # METERED processors only while this is exceeded. A transformation whose
    # purpose is not size ignores this; it is a budget, not a mandate.
    target_bytes: int | None = None
    # The MIME type the payload's server declared, when it declared one.
    # ``detect`` treats a declared HTML page as HTML without sniffing.
    content_type: str | None = None


@dataclass(frozen=True)
class TransformResult:
    """One processor's accounting — the sidecar, per invariant 3.

    ``applied`` is False when the processor looked and declined (content not
    log-shaped, reduction below its floor). Its ``content`` then echoes the
    input and downstream composition treats it as a no-op.

    ``applied``, not a size comparison, is the signal that something happened:
    a transformation can reshape a payload without changing its length.
    """

    name: str
    cost: Cost
    content: str
    applied: bool
    bytes_in: int
    bytes_out: int
    # Processor-specific accounting: lines collapsed, groups formed, model
    # used, anything a human auditing token spend would want. Values stay
    # scalar so the whole thing serializes into an audit row.
    details: dict[str, int | float | str] = field(default_factory=dict)

    @property
    def ratio(self) -> float:
        """Output bytes per input byte.

        1.0 means the size did not change, which is NOT the same as nothing
        happening — check ``applied`` for that. Currently unread: the ``ratio``
        that ships in the sidecar is computed at the composition and gateway
        layers instead.
        """
        if self.bytes_in == 0:
            return 1.0
        return self.bytes_out / self.bytes_in

    @classmethod
    def declined(
        cls,
        name: str,
        cost: Cost,
        payload: str,
        *,
        reason: str,
        details: dict[str, int | float | str] | None = None,
    ) -> TransformResult:
        """The no-op variant: the processor looked and passed the payload
        through unchanged. `reason` records why (too small, not log-shaped,
        worker error); downstream composition treats it as a skip."""
        size = len(payload.encode("utf-8"))
        merged: dict[str, int | float | str] = {"declined": reason}
        if details:
            merged.update(details)
        return cls(
            name=name,
            cost=cost,
            content=payload,
            applied=False,
            bytes_in=size,
            bytes_out=size,
            details=merged,
        )


@runtime_checkable
class Transform(Protocol):
    """The shape of a transform. Implementations are stateless."""

    name: str
    cost: Cost
    kind: Kind
    # Which ingresses this processor understands. Enforced once, in
    # gateway/drivers.py — a processor tuned for one payload shape and
    # pointed at another declines forever and looks like it is working.
    channels: frozenset[Channel]

    async def run(self, payload: str, ctx: TransformContext) -> TransformResult:
        """Transform the payload. Must return the input unchanged
        (applied=False) rather than raise on content it cannot improve."""
        ...
