"""The gate: one verdict disposed, with redact's extraction folded in.

``dispose()`` decides the fate of a judged payload, and for ``redact`` that fate
is a second act — turns 2 and 3, the L3 extraction and its verification
(``quarantine_redact``) — which can itself object. Before this the two response
ingresses ran that sequence by hand: ``gateway/response_edge.py`` for a
proxied tool response and ``tools/judged.py`` for an internal tool. The copies
carried the SAME redact-refusal construction verbatim —

    Disposition(Decision.REFUSE, reason=f"redact refused: {refused_by}",
                offer_alternatives=False)

— which is the drift class the 3.0 plan exists to delete (a flag that becomes a
refusal must look the same wherever it is raised). ``gate()`` is that one copy.

What each ingress still owns is its own wire shape (an ``IngressDecision``
carrier vs a tool-result dict, raised-or-returned) and its own accounting,
caching and paging; those legitimately differ and stay at the call site. What
is shared — the decision, the extraction, and the refusal the extraction may
raise — is here, so a verdict is disposed of one way whoever asks.

``dispose()`` stays pure (``core.dispose``); ``gate()`` is where ``core`` first
reaches the L3 layer, so it is async and performs that one call. ``render`` and
``dispose`` perform no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..quarantine.agent import quarantine_redact
from .dispose import DEFAULT_REDACT_PROMPT, Decision, Disposition, Posture, dispose

if TYPE_CHECKING:
    from ..defense import DefenseVerdict
    from ..quarantine.agent import CleanResult


@dataclass(frozen=True)
class Gated:
    """A verdict disposed of, and — for a redact that ran — its extraction.

    ``disposition`` is what ``dispose()`` concluded. When its decision is not
    ``REDACT`` the two extraction fields are ``None`` and the caller renders
    straight from the disposition. When it is ``REDACT`` the extraction has
    run:

    - ``extraction`` is the ``quarantine_redact`` result (``extraction.content``
      the verified answer, ``extraction.usage`` its cost); and
    - ``extraction_refusal`` is set iff that extraction objected — redact's own
      turn, which suggests nothing (no flag, no gap), so the caller refuses with
      it and reads ``extraction.refused_by`` for the reason.
    """

    verdict: DefenseVerdict
    disposition: Disposition
    extraction: CleanResult | None = None
    extraction_refusal: Disposition | None = None


async def gate(verdict: DefenseVerdict, posture: Posture, *, extra_unread: bool = False) -> Gated:
    """Dispose of ``verdict`` under ``posture``, running redact's extraction.

    ``verdict`` is what ``defend()`` already produced; the gate re-judges
    nothing. ``extra_unread`` folds binary an agent could open that no layer
    read, tracked beside the verdict rather than inside it (#367, the proxied
    path), into the gaps the disposition sees.

    For a ``REDACT`` decision — redact mode, or a block downgraded for an
    allowlisted source — it runs turns 2 and 3 over the text the layers judged
    (``verdict.read``) and, on an objection, builds the one redact-refusal every
    caller raises. It never raises on a detection itself; the caller renders the
    ``Gated``.
    """
    disposition = dispose(verdict, posture, extra_unread=extra_unread)
    if disposition.decision is not Decision.REDACT:
        return Gated(verdict, disposition)
    result = await quarantine_redact(
        verdict.read,
        disposition.prompt or DEFAULT_REDACT_PROMPT,
        detection=verdict.l3_assessment,
    )
    refusal = None
    if result.refused_by is not None:
        # redact's own turn objecting: nothing is suggested (no flag, no gap).
        refusal = Disposition(
            Decision.REFUSE,
            reason=f"redact refused: {result.refused_by}",
            offer_alternatives=False,
        )
    return Gated(verdict, disposition, extraction=result, extraction_refusal=refusal)
