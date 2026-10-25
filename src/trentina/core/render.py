"""The only composer of a refusal body.

A refusal is gateway-authored: it names the layer or the gap, the mode, and the
modes the caller may try next, and it carries no payload and no L3 prose
(security-gateway profile III). Before Trentina 3.0 several ingresses built this
dict themselves — ``tools/judged.py``, ``ingress_defense.py``, the proxies — each
spelling the ``Mode`` and the alternatives in its own words. ``refusal_of`` is the
one composer now, so a face never spells a refusal and a new mode's wording lands
in a single place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..modes import refusal_body

if TYPE_CHECKING:
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
