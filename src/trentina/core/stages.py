"""The response-edge stage carriers: Arrived → Transformed → Judged.

One crossing has two edges, and ``edge()`` is ``Arrived → Transformed →
Judged → Disposed`` (Trentina 3.0 plan §A/§B.2). This module carries the
response-edge stages the orchestrated ``tools/call`` path produces as it
reproduces ``gateway/router._assemble_call_result``: the backend result after
the gateway's reserved keys are stripped (``Arrived``), that content after the
pre-perimeter transform chain (``Transformed``), and the perimeter's verdict on
it (``Judged``). Each stage holds a back-reference to the one before it, so the
layer-contract identity assertions (``judged … is transformed …``) have real
objects to hold once the cutover lands.

These carry the ACTUAL gateway types (``TransformOutcome``, ``IngressDecision``),
not plan §B's idealized ``Verdict``/``Coverage``. Of the three, only ``Judged``
carries trust: it pairs a verdict with the exact bytes it was reached over, so
it is one of the four unforgeable types and its construction is confined to the
orchestrator's ``judge_response`` (``tests/test_seal.py``), which builds one only
after the gate has run. ``Arrived`` and ``Transformed`` are plain frozen carriers
— no check stands behind holding one — so they are not sealed. ``Assembled``
is the disposed result: a plain, mutable carrier of the finished result and
what the one audit row should say, so it is not sealed either.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from typing import TYPE_CHECKING, Any

from ..seal import UNSEALED, Seal, require

if TYPE_CHECKING:
    from ..defense import Provenance
    from ..gateway.ingress_defense import IngressDecision
    from ..gateway.transform import TransformOutcome
    from ..outcomes import Outcome


@dataclass(frozen=True)
class Arrived:
    """A backend result, stripped of the gateway's reserved keys, ready to judge.

    The reserved-key strip and the duplicate-``structuredContent`` drop have
    already run (``results._arrived``). ``is_error`` is the backend's own flag,
    coerced to ``bool`` as the paging hold reads it; the delivered result keeps
    the raw value. ``acted`` is ``_may_have_acted``: the backend has answered,
    so a tool that may write has written (#425).
    """

    content_blocks: list[Any] | None
    structured: Any
    stripped: int
    is_error: bool
    acted: bool


@dataclass(frozen=True)
class Transformed:
    """The arrived content after the pre-perimeter transform chain.

    ``content_blocks`` is what the perimeter scans and what is delivered —
    transforms run BEFORE the gate, never after, so nothing the agent receives
    went unjudged. ``reduced`` is ``None`` for an internal tool, which runs the
    pipeline at its own ingress and is neither transformed nor scanned here.
    """

    arrived: Arrived
    content_blocks: list[Any] | None
    provenance: Provenance
    reduced: TransformOutcome | None


@dataclass(frozen=True)
class Judged:
    """A transformed response and the perimeter's verdict on it.

    Built only for a remote backend's response, which the perimeter scans here;
    an internal tool is judged at its own ingress and reaches no ``Judged``
    stage. ``decision`` is what ``scan_tool_response`` returned, and the
    disposition — deliver, redact, or block — reads from it. Sealed to
    ``orchestrator.judge_response`` so holding one is proof the gate ran on
    ``transformed.content_blocks`` and no other bytes.
    """

    transformed: Transformed
    decision: IngressDecision
    _seal: InitVar[Seal] = UNSEALED

    def __post_init__(self, _seal: Seal) -> None:
        require(_seal, _JUDGED_SEAL, "Judged")


#: The token ``orchestrator.judge_response`` holds to build a ``Judged``; see ``core.seal``.
_JUDGED_SEAL = Seal("judge_response")


@dataclass
class Assembled:
    """A tools/call result and what the audit row should say about it.

    Assembly decides the outcome — the perimeter may block what the backend
    returned — so the one audit row is written after it, not before. Writing
    ``ok`` first and ``blocked_defense`` later counted every block twice.
    """

    result: dict[str, Any]
    outcome: Outcome
    error: str | None = None
    # The perimeter's own warning, kept apart from ``result`` so what
    # ``_deliver`` writes is built only from gateway parts (#265).
    warning: dict[str, Any] | None = None
    # Gateway-reserved keys the backend's response carried and lost (#265).
    stripped: int = 0
