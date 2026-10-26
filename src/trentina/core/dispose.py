"""The one disposition decision, and the posture that drives it.

Every ingress — the content tools, a proxied tool response, an outbound LLM or
HTTP request, an alert, a Matrix event — judges with the same three layers and
then faces the same question: given this verdict, under this mode, what is
delivered? Before Trentina 3.0 each site answered it by hand, and the copies
drifted: ``gateway/outbound.py`` derived ``stop_on_partial`` from ``mode is
Mode.BLOCK`` (fail-open for any later non-BLOCK mode) where ``tools/judged.py``
and ``gateway/ingress_defense.py`` used ``mode is not Mode.FLAG`` (fail-closed).
Masked today only because ``redact`` cannot be an enforcement mode on the proxy
paths, it was the same drift class #167 and 0.31.0 each fixed by deleting a copy.

``dispose()`` is that one copy. It is pure — no I/O, no logging, no cache — so it
can be unit-tested exhaustively and reasoned about in isolation. A ``match`` over
``Mode`` with ``assert_never`` means a fourth mode fails type-checking here until
it is handled, rather than silently taking a non-FLAG site's fail-open branch.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, assert_never

from ..modes import Gaps, Mode, ModePolicy, gaps_of, refusal_reason

if TYPE_CHECKING:
    from ..defense import DefenseVerdict

DEFAULT_REDACT_PROMPT = "Extract the main content."
"""Used when block downgrades an allowlisted source to redact: the agent asked
for the bytes, so there is no extraction prompt of its own to use."""


@dataclass(frozen=True)
class Posture:
    """Who is asking and in what mode — everything the disposition depends on.

    The Phase 1 subset of the full Trentina 3.0 ``Posture`` (identity, edge and
    coverage join to it in later phases). What it already removes is every bare
    ``mode is X`` scattered across the ingresses: the two booleans a site used
    to derive for itself are now derived here, once.
    """

    mode: Mode
    policy: ModePolicy
    allowlisted: bool = False
    """An operator vouched for the source. Flags still stand, but block sends a
    flagged-or-partially-read payload to redact instead of refusing it. An
    ABSENT layer (not a partial read) still refuses even when allowlisted."""
    honeypot: bool = False
    """The caller is a honeypot (#357): flag delivers unmarked, telling it
    nothing about what the layers made of the content."""
    prompt: str | None = None
    """The redact extraction request, when the caller carries one."""

    @property
    def stop_on_partial(self) -> bool:
        """Whether a partial L2 scan should short-circuit before L3 runs.

        The ONE definition of the rule every ``defend()`` caller needs. ``flag``
        delivers a partial scan with a warning, so it pays for the scan; every
        other mode refuses it, so it does not. ``is not FLAG`` rather than ``is
        BLOCK`` so a mode added later fails closed until it is handled.
        """
        return self.mode is not Mode.FLAG

    def records_block(self, *, blocklists: bool = True) -> bool:
        """Whether this call's detection row is marked ``blocked``.

        Only a block refusal belongs on the blocklist: ``is_blocked`` reads that
        column, so a flag row marked blocked would refuse the next flag of the
        same source. ``blocklists`` is False for an allowlisted source, which is
        never put on the blocklist.
        """
        return self.mode is Mode.BLOCK and blocklists


class Decision(Enum):
    """What ``dispose()`` concluded. The caller renders each in its own wire shape."""

    DELIVER = "deliver"
    """Hand over the content, with any warning attached."""
    DELIVER_UNMARKED = "deliver_unmarked"
    """Honeypot flag: hand over the content with no warning at all."""
    REDACT = "redact"
    """Replace the content with a verified L3 extraction guided by ``prompt``."""
    REFUSE = "refuse"
    """Withhold the content; render a refusal from ``reason``/``flagged_by``/``gaps``."""


@dataclass(frozen=True)
class Disposition:
    """The decision plus everything a caller needs to carry it out.

    ``dispose()`` never builds a wire message; it reports the decision and the
    facts behind it. ``core.render.refusal_of`` turns a ``REFUSE`` into a body,
    and the caller wraps that in its own envelope.
    """

    decision: Decision
    reason: str | None = None
    flagged_by: str | None = None
    gaps: Gaps | None = None
    downgraded: bool = False
    """A block on an allowlisted source sent to redact rather than refused."""
    prompt: str | None = None
    """The extraction request for a REDACT decision."""
    offer_alternatives: bool = True
    """Whether a REFUSE offers retry modes. False only for redact's own
    extraction objecting — neither a flag nor a gap is the reason, so nothing
    is suggested."""


def _effective_gaps(verdict: DefenseVerdict, extra_unread: bool) -> Gaps:
    """The verdict's gaps, with binary-unread folded in from outside it.

    A proxied response tracks the blocks no layer could read (#367) beside the
    verdict, not inside it — the verdict judged only the response's text. The
    tools path already has it in ``verdict.unread``. Folding it here keeps one
    gap derivation for both and one refusal that names it.
    """
    gaps = gaps_of(verdict)
    if extra_unread and not gaps.binary_unread:
        return dataclasses.replace(gaps, binary_unread=True)
    return gaps


def dispose(
    verdict: DefenseVerdict, posture: Posture, *, extra_unread: bool = False
) -> Disposition:
    """Decide the fate of a judged payload. Pure; raises nothing on a detection.

    Args:
        verdict: What the three layers found and could not finish.
        posture: The mode, policy and source facts that drive delivery.
        extra_unread: The delivery also holds binary an agent could open that no
            layer read, tracked outside the verdict (the proxied-response path).

    Returns:
        The ``Disposition``. ``REDACT`` means "run the extraction"; if that
        extraction is itself refused, the caller raises its own ``REFUSE`` with
        ``offer_alternatives=False`` — redact refusing its own turn suggests
        nothing.
    """
    mode = posture.mode
    gaps = _effective_gaps(verdict, extra_unread)
    flagged_by = verdict.flagged_by.value if verdict.flagged_by is not None else None

    match mode:
        case Mode.FLAG:
            # flag never consults the gaps or the flag: it always delivers.
            return Disposition(Decision.DELIVER_UNMARKED if posture.honeypot else Decision.DELIVER)
        case Mode.BLOCK:
            reason = refusal_reason(flagged_by, gaps)
            if reason is None:
                return Disposition(Decision.DELIVER, gaps=gaps)
            absent = gaps.blocking() and not gaps.redactable_only()
            if posture.allowlisted and not absent:
                return Disposition(
                    Decision.REDACT,
                    prompt=DEFAULT_REDACT_PROMPT,
                    downgraded=True,
                    flagged_by=flagged_by,
                    gaps=gaps,
                )
            return Disposition(Decision.REFUSE, reason=reason, flagged_by=flagged_by, gaps=gaps)
        case Mode.REDACT:
            if gaps.blocking():
                reason = refusal_reason(flagged_by, gaps) or "not fully judged"
                return Disposition(Decision.REFUSE, reason=reason, flagged_by=flagged_by, gaps=gaps)
            return Disposition(
                Decision.REDACT,
                prompt=posture.prompt or DEFAULT_REDACT_PROMPT,
                flagged_by=flagged_by,
                gaps=gaps,
            )
        case _:  # pragma: no cover - exhaustiveness is the point
            assert_never(mode)
