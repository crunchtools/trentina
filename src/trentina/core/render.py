"""The only composer of a refusal body.

A refusal is gateway-authored: it names the layer or the gap, the mode, and the
modes the caller may try next, and it carries no payload and no L3 prose
(security-gateway profile III). Before Trentina 3.0 several ingresses built this
dict themselves — ``internal_edge.py``, ``response_edge.py``, the proxies — each
spelling the ``Mode`` and the alternatives in its own words. ``refusal_of`` is the
one composer now, so a face never spells a refusal and a new mode's wording lands
in a single place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..modes import Gaps, refusal_body, refusal_reason

if TYPE_CHECKING:
    from ..modes import Mode, ModePolicy
    from .dispose import Disposition, Posture


def refusal_of(disposition: Disposition, posture: Posture) -> dict[str, Any]:
    """The structured refusal body for a REFUSE disposition.

    Args:
        disposition: the REFUSE decision, carrying ``reason`` (why, naming a
            layer or gap — never the payload), ``flagged_by`` (the layer, or
            None), ``gaps`` (what could not be judged, or None), and
            ``offer_alternatives``.
        posture: supplies the ``mode`` the call ran in and the ``policy`` that
            decides which retry modes are offered.

    Returns:
        A gateway-authored dict: ``reason`` (str), ``mode`` (str), and
        ``alternatives`` (list of mode names to retry) always; ``flagged_by``
        (str) when a layer flagged it; ``gaps`` (list of gap names) when a layer
        could not finish. No payload and no L3 prose ever appear in it.
        ``offer_alternatives`` is False only when redact's own extraction turn
        objects — neither a flag nor a gap is the reason — so ``alternatives``
        is emptied.
    """
    body = refusal_body(
        disposition.reason or "refused by the defense pipeline",
        posture.mode,
        flagged_by=disposition.flagged_by,
        gaps=disposition.gaps,
        policy=posture.policy,
    )
    if not disposition.offer_alternatives:
        body["alternatives"] = []
    return body


def refusal_from_warning(
    warning: dict[str, Any] | None, mode: Mode, policy: ModePolicy
) -> dict[str, Any]:
    """Rebuild a refusal body from a (possibly cached) ``_trentina_warning``.

    The gateway caches warnings, not verdicts (``Gaps.of_warning``), so a block
    served from the cache renders its refusal from the warning's own flag and
    gap fields rather than re-judging.
    """
    warning = warning or {}
    flagged_by = warning.get("flagged_by") or None
    gaps = Gaps.of_warning(warning)
    reason = refusal_reason(flagged_by, gaps) or "refused by the defense pipeline"
    return refusal_body(reason, mode, flagged_by=flagged_by, gaps=gaps, policy=policy)
