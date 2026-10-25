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

A transform returns one of three outcomes (``TransformResult``), and the type
says which:

* ``Applied`` — the transform rewrote the payload; its ``content`` is what the
  next stage reads. This is the only outcome that carries bytes.
* ``Declined`` — the payload was not this transform's shape, so it did
  nothing. A safe no-op: the original is carried forward unchanged, and even a
  floor (``required``) transform that declines does not refuse — declining to
  act on the wrong shape is correct.
* ``Failed`` — the transform tried and could not finish (a worker crashed, a
  payload too large to parse, an LLM refused). The TYPE is the fail-closed
  signal: a floor transform returning ``Failed`` refuses the call, because
  delivering the un-transformed original in place of a converter the operator
  pinned would be a silent substitution. A non-floor transform's ``Failed``
  passes the original through (fail-open) — a broken minifier costs the agent
  tokens, never content.

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

3. Every transform accounts for itself, and its failure mode is a TYPE, not a
   convention. The composition (``compose.py``) pairs each outcome with the
   transform that produced it into a ``TransformRecord``, whose sidecar (bytes
   in/out, ratio, what was collapsed) reaches L3's briefing — because "this
   artifact is the 3% that survived transformation" is context a judge should
   have. Routing it to the audit log as token-mandate evidence is intended and
   not yet built — ``router.py`` reads the sidecar only for the briefing, and
   ``TransformOutcome.sidecar()`` has no caller in ``src/``.

   What used to be a frozenset of "declines that really mean failure"
   (``policy.FAILED_DECLINES``) is now the ``Failed`` type. The floor call
   sites refuse on ``isinstance(result, Failed)``; nothing matches a decline
   reason string any more.

COMPOSITION IS STILL SIZE-DRIVEN, even though this contract is not. A
transformation that does not shrink runs under ``chain`` and keeps its output,
runs under ``auto`` if FREE, and loses under ``best_of`` to any processor that
shrank more. Below ``min_bytes`` nothing runs at all, and every FREE processor
here declines on ``bytes_out >= bytes_in``. Read ``compose.py`` before
assuming a reshaping processor will survive the strategy you configured.

A FILTERING processor — one that drops records a policy names — is permitted
by invariant 1, and is now safe to build: a filter that cannot complete
returns ``Failed`` and is pinned as ``required``, so its failure refuses the
call instead of delivering exactly what it exists to remove. Before the typed
outcome, composition swallowed every processor error into a pass-through of
the original, so only a reducer (whose fail-open loses tokens, not safety)
could be built on this framework.

FAILING MEANS HIDING NOTHING, and which direction that points depends on what
the processor owns. A text processor's ``Failed`` at a non-floor site delivers
and scans the ORIGINAL — the composition carries the payload through. A
document processor that raises causes its caller to read EVERYTHING
(``gateway/selection.py``). Both are the same rule: on failure, do the thing
that hides nothing. No failure mode may result in "read nothing, looked clean".

Transforms parse hostile bytes. Regexes here must be linear-time and
fingerprinting must cap the bytes it reads per line — an attacker choosing
the input must not be able to buy quadratic work.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..channels import Channel, Kind

#: Processor-specific accounting: lines collapsed, groups formed, model used,
#: anything a human auditing token spend would want. Values stay scalar so the
#: whole thing serializes into an audit row.
Details = Mapping[str, int | float | str]


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
class Applied:
    """The transform rewrote the payload. ``content`` is what the next stage
    reads; ``details`` is this step's accounting (lines collapsed, format,
    chain, hidden-element counts)."""

    content: str
    details: Details = field(default_factory=dict)


@dataclass(frozen=True)
class Declined:
    """The payload was not this transform's shape — a safe no-op.

    The original is carried forward unchanged. Even as a floor transform this
    never refuses: ``reason`` records why it did nothing (too small, not
    log-shaped, not markup), and ``details`` carries any evidence it measured
    before giving up (a would-be ratio, line counts) for the sidecar.
    """

    reason: str
    details: Details = field(default_factory=dict)


@dataclass(frozen=True)
class Failed:
    """The transform tried and could not finish.

    The TYPE is the fail-closed signal. A floor (``required``) transform
    returning this refuses the call (``tools/preprocess._floor``,
    ``gateway/transform._transform_block``); a non-floor one passes the
    original through. ``reason`` names what broke (a worker error, a payload
    too large for a pinned converter to parse), for the audit and the log.
    """

    reason: str
    details: Details = field(default_factory=dict)


#: What a transform's ``run`` returns. The type says which outcome, so no
#: caller matches a reason string to tell a safe no-op from a failure.
TransformResult = Applied | Declined | Failed


@dataclass(frozen=True)
class TransformRecord:
    """One transform's accounting — the sidecar, per invariant 3.

    The composition pairs the outcome a transform returned with the
    transform's own ``name`` and ``cost`` and the bytes measured around it.
    ``Declined`` and ``Failed`` do not carry content, so ``bytes_out`` equals
    ``bytes_in`` for them; only ``Applied`` changes the size.
    """

    name: str
    cost: Cost
    result: TransformResult
    bytes_in: int
    bytes_out: int

    @property
    def applied(self) -> bool:
        """Whether the transform rewrote the payload. The signal that
        something happened, not a size comparison: a transformation can reshape
        a payload without changing its length."""
        return isinstance(self.result, Applied)

    @property
    def details(self) -> Details:
        """The outcome's accounting, whichever outcome it was."""
        return self.result.details

    @property
    def reason(self) -> str | None:
        """The decline OR fail reason, or None when the transform applied.

        Named for what it is — a non-applied outcome's reason, which may be a
        shape decline or a failure; the caller keeps the two apart by the
        result's type, not by this string. It serializes to the ``declined``
        key in the sidecar row (``row()``), the shape operators grep for."""
        return None if isinstance(self.result, Applied) else self.result.reason

    @property
    def ratio(self) -> float:
        """Output bytes per input byte. 1.0 when the size did not change,
        which is NOT the same as nothing happening — check ``applied``."""
        if self.bytes_in == 0:
            return 1.0
        return self.bytes_out / self.bytes_in

    @classmethod
    def of(cls, name: str, cost: Cost, payload: str, result: TransformResult) -> TransformRecord:
        """Pair an outcome with the transform that produced it and the bytes
        around it. The one place bytes are measured, so every call site records
        them the same way."""
        size = len(payload.encode("utf-8"))
        out = len(result.content.encode("utf-8")) if isinstance(result, Applied) else size
        return cls(name=name, cost=cost, result=result, bytes_in=size, bytes_out=out)

    def row(self) -> dict[str, Any]:
        """This step's sidecar row. The ``declined`` key is present exactly
        when the step did not apply — the shape operators and tests grep for.
        The one definition the composition and the gateway accounting share."""
        row: dict[str, Any] = {
            "name": self.name,
            "cost": self.cost.value,
            "applied": self.applied,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            **self.details,
        }
        if self.reason is not None:
            row["declined"] = self.reason
        return row


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
        """Transform the payload. Returns ``Applied`` when it rewrote the
        payload, ``Declined`` when the payload was not its shape, or ``Failed``
        when it tried and could not finish — never raises on hostile input."""
        ...
