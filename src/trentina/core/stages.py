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

Phase 4 state: these are frozen data carriers, not yet sealed. They carry the
ACTUAL gateway types (``TransformOutcome``, ``IngressDecision``), not plan §B's
idealized ``Verdict``/``Coverage``. The seal — construction confined to the one
rail that produces each — lands with the Phase 4 cutover (PR #4), when the
orchestrator is the sole constructor and ``tests/test_seal.py`` can fence them;
sealing them while ``router._assemble_call_result`` still runs the default path
would fence a type both paths build. The disposed result remains the router's
``Assembled`` until that cutover, for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..defense import Provenance
    from ..gateway.ingress_defense import IngressDecision
    from ..gateway.transform import TransformOutcome


@dataclass(frozen=True)
class Arrived:
    """A backend result, stripped of the gateway's reserved keys, ready to judge.

    The reserved-key strip and the duplicate-``structuredContent`` drop have
    already run (``router._arrived``). ``is_error`` is the backend's own flag,
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
    disposition — deliver, redact, or block — reads from it.
    """

    transformed: Transformed
    decision: IngressDecision
