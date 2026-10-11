"""The three modes, and the one rule for a layer that could not finish.

Every content tool and the gateway judge with the same three layers; the mode
decides only what is delivered:

* ``block`` — a flagged verdict is refused; the agent never sees it.
* ``flag`` — the bytes as they arrived, with the verdict attached. A
  researcher's grant: almost never the right mode for an assistant, a coding
  agent or a swarm.
* ``redact`` — an L3 extraction, verified, instead of the original.

The names are OpenRouter's guardrail actions (#200); until 0.35.0 flag was
``warn`` and redact was ``clean``, and 0.36.0 removed the old names. redact is NOT
OpenRouter's span substitution: L2 and L3 give verdicts, not spans, so there
is nothing to substitute. The whole payload is rewritten through L3 instead.

Before 0.31.0 the modes ran different pipelines — redact spent L3 on
extraction and got no detection verdict, search never called L3 — and each
ingress decided on its own what to do about a layer that could not run. The
tools delivered through an L3 outage while the gateway refused; the tools
refused a truncated L2 scan while the gateway's flag raised on it. Those were
two answers to one question, so the question lives here once.

**block and redact require every layer to produce a verdict; flag does not.**
A layer that is ABSENT (no ONNX model, no provider) can be excused per layer
with ``TRENTINA_REQUIRE_L2`` / ``TRENTINA_REQUIRE_L3``. A layer that ran but
read only PART of the payload is never excused: that is the padding attack,
where the payload hides past the cap and the head reads clean.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, fields
from enum import Enum
from typing import TYPE_CHECKING, Any

from .config import canonical_mode, get_config
from .errors import ModeNotPermittedError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .defense import DefenseVerdict

logger = logging.getLogger(__name__)

#: What a malformed ``trentina_mode`` is told it may send instead.
MODE_SHAPES = ["block", "flag", '{"redact": "<what you need>"}']


def parse_mode_arg(value: Any) -> tuple[str | None, str | None]:
    """``trentina_mode`` as (mode name, extraction question), unchecked by policy.

    Since 0.39.0 the question travels inside the mode, because it only means
    something there: ``"block"``, ``"flag"``, or ``{"redact": "<question>"}``.
    A bare ``"redact"`` keeps the tool's default question. The pre-0.39.0
    ``trentina_prompt`` beside it no longer exists (0.43.0).

    The dict may also arrive as its JSON text (#244). No tool declares
    ``trentina_mode`` unless the profile sets ``declare_modes``, and a client
    that marshals arguments against the declared schema sends an undeclared
    object as a string. A string that starts with ``{`` is therefore parsed,
    and one that does not parse is refused, never read as a mode name.

    Args:
        value: the call's ``trentina_mode``: None, a mode name, or
            ``{"redact": "<question>"}``.

    Returns:
        ``(mode name or None, question or None)``. The name is not yet checked
        against any policy: ``ModePolicy.resolve`` does that, after resolving
        None to the default.

    Raises:
        ModeNotPermittedError: a dict that is not exactly one ``redact`` key
            with a non-empty question, or a value of any other type.
    """
    if isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            raise ModeNotPermittedError(value, MODE_SHAPES) from None
    if isinstance(value, dict):
        items = list(value.items())
        question = items[0][1] if len(items) == 1 else None
        if (
            canonical_mode(str(items[0][0] if items else "")) != "redact"
            or not isinstance(question, str)
            or not question.strip()
        ):
            raise ModeNotPermittedError(str(value), MODE_SHAPES)
        return "redact", question
    if value is not None and not isinstance(value, str):
        raise ModeNotPermittedError(str(value), MODE_SHAPES)
    return value, None


class Mode(str, Enum):
    """What a caller does with a verdict. Never which layers run.

    Declared strictest first, OpenRouter's precedence: block > redact > flag.
    """

    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"

    @classmethod
    def _missing_(cls, value: object) -> Mode | None:
        """``Mode("BLOCK")`` is BLOCK; see ``canonical_mode``."""
        if isinstance(value, str) and (name := canonical_mode(value)) != value:
            return cls(name)
        return None


@dataclass(frozen=True)
class Gaps:
    """What the layers could not do, as distinct from what they found."""

    l2_unavailable: bool = False
    l2_truncated: bool = False
    l3_unavailable: bool = False
    l3_truncated: bool = False
    oversize: bool = False
    """Over the admission cap (#225): refused before L2 or L3 ran."""
    binary_unread: bool = False
    """The delivery holds binary an agent's tools could open (an image, a PDF,
    an archive) and no layer could read (#367). Never excused: the rule is
    that nothing is delivered that the layers did not read."""

    def names(self) -> list[str]:
        """The gaps that are true, by field name."""
        return [name for name, present in asdict(self).items() if present]

    def any(self) -> bool:
        return (
            self.l2_unavailable
            or self.l2_truncated
            or self.l3_unavailable
            or self.l3_truncated
            or self.oversize
            or self.binary_unread
        )

    def blocking(self) -> bool:
        """Whether block and redact must refuse. flag never consults this."""
        config = get_config()
        return (
            self.l2_truncated
            or self.l3_truncated
            or self.oversize
            or self.binary_unread
            or (self.l2_unavailable and config.require_l2)
            or (self.l3_unavailable and config.require_l3)
        )

    @classmethod
    def of_warning(cls, warning: dict[str, Any]) -> Gaps:
        """A cached ``_trentina_warning``'s gaps.

        The gateway caches warnings, not verdicts. Each field is a boolean key
        of the same name in the warning, so a gap added later is read back
        without touching this; a key an older perimeter did not write reads
        as absent.
        """
        return cls(**{f.name: bool(warning.get(f.name)) for f in fields(cls)})

    def redactable_only(self) -> bool:
        """Every gap is a partial read, none an absent layer or an oversize payload.

        The allowlist may send these to redact, whose output all three layers
        verify. An absent layer it may not excuse, an over-cap payload is
        refused at admission for every caller (#225), allowlisted or not, and
        unread binary is unread whoever asks (#367).
        """
        return (self.l2_truncated or self.l3_truncated) and not (
            self.l2_unavailable or self.l3_unavailable or self.oversize or self.binary_unread
        )


def _l3_answered(assessment: Mapping[str, Any] | None) -> bool:
    """L3 gave a verdict: it ran, and said yes or no.

    An assessment without a boolean ``injection_detected`` is not a clean
    one (#294). ``_call_gemini`` refuses such an answer at the source; this
    is the same rule where the gap is decided, so no other producer of an
    assessment can reopen it.
    """
    return (
        assessment is not None
        and not assessment.get("l3_unavailable")
        and isinstance(assessment.get("injection_detected"), bool)
    )


def gaps_of(verdict: DefenseVerdict) -> Gaps:
    """The one derivation of a verdict's gaps. warning, report and gateway read it."""
    has_text = bool(verdict.pipeline.content.strip())
    oversize = verdict.oversize is not None
    # A layer that was never asked is not a layer that is missing.
    asked = has_text and not oversize
    assessment = verdict.l3_assessment
    classification = verdict.classification
    l2_truncated = verdict.l2_truncated or bool(
        classification is not None and classification.truncated
    )
    return Gaps(
        l2_unavailable=asked and classification is None and not l2_truncated,
        l2_truncated=l2_truncated,
        l3_unavailable=bool(asked and not _l3_answered(assessment)),
        l3_truncated=verdict.l3_truncated,
        oversize=oversize,
        binary_unread=bool(verdict.unread),
    )


def refusal_reason(flagged_by: str | None, gaps: Gaps) -> str | None:
    """Why block or redact may not deliver the original, or None.

    The reason names layers and gaps only. It is ours, never the payload's.
    """
    if flagged_by is not None:
        return f"flagged by {flagged_by}"
    if not gaps.blocking():
        return None
    missing = [
        name
        for name, present in (
            ("L2 unavailable", gaps.l2_unavailable),
            ("L2 read only part of the payload", gaps.l2_truncated),
            ("L3 unavailable", gaps.l3_unavailable),
            ("L3 read only part of the payload", gaps.l3_truncated),
            # Not "token cap": scrub_credentials redacts whatever follows "token ".
            ("over the admission cap, so neither L2 nor L3 read it", gaps.oversize),
            ("holds an image, PDF or archive that no layer can read yet", gaps.binary_unread),
        )
        if present
    ]
    return "not fully judged: " + ", ".join(missing)


# The per-call mode (#193). The agent asks through `trentina_mode`; a POLICY
# decides whether it may. Under the gateway the policy is the calling
# profile's `defense.modes`, bound here around an internal tool call; a
# standalone server reads TRENTINA_MODE / TRENTINA_MODES.


@dataclass(frozen=True)
class ModePolicy:
    """Which modes a caller may use, and what an omitted mode means."""

    allowed: tuple[Mode, ...]
    default: Mode

    @classmethod
    def of(cls, allowed: Iterable[str], default: str) -> ModePolicy:
        return cls(tuple(Mode(m) for m in allowed), Mode(default))

    def resolve(self, requested: str | None) -> Mode:
        """The mode this call runs in. Omission resolves BEFORE the check.

        Checking the requested value and then defaulting would let an omitted
        mode skip the policy entirely — the parameter-guard trap, where a
        missing argument is simply not checked.
        """
        name = self.default.value if requested is None else canonical_mode(str(requested))
        allowed = [m.value for m in self.allowed]
        if name not in allowed:
            raise ModeNotPermittedError(name, allowed)
        return Mode(name)

    def alternatives(self, current: Mode, cause: str | None) -> list[str]:
        """What a refused call may try next, under this policy.

        Flagged content is offered redact and NEVER flag: "retry with flag"
        would be the gateway itself steering the agent to the verbatim bytes
        the attacker wanted delivered. flag in the policy is a grant for
        deliberate reading, not the gateway's retry path. Only a refusal for
        an unfinished read, with nothing found, may point at flag — redact
        refuses on the same gaps. Whatever is suggested is also what the
        blocklist lets through: redact proceeds on a blocklisted source.

        ``cause`` is ``"flagged"``, ``"gaps"``, or None for anything else.
        """
        candidates = {"flagged": [Mode.REDACT], "gaps": [Mode.FLAG]}.get(cause or "", [])
        return [m.value for m in candidates if m in self.allowed and m is not current]


def current_policy() -> ModePolicy:
    """The gateway's policy for this call, else the standalone one from the environment."""
    from .gateway.context import get_current_policy

    bound = get_current_policy()
    if bound is not None:
        return bound
    config = get_config()
    return ModePolicy.of(config.allowed_modes, config.default_mode)


BLOCKLIST_REASON = "on the blocklist"
"""Why a call on a source the caller's blocklist holds is refused. Constant
(#263): nothing in it depends on when or by whom the source was flagged."""


def refusal_body(
    reason: str,
    mode: Mode,
    *,
    flagged_by: str | None = None,
    gaps: Gaps | None = None,
    policy: ModePolicy | None = None,
) -> dict[str, Any]:
    """The structured refusal: gateway-authored fields, no payload, no L3 prose."""
    gap_names = [name for name, present in asdict(gaps).items() if present] if gaps else []
    cause = "flagged" if flagged_by is not None else "gaps" if gap_names else None
    policy = policy or current_policy()
    body: dict[str, Any] = {
        "reason": reason,
        "mode": mode.value,
        "alternatives": policy.alternatives(mode, cause),
    }
    if flagged_by is not None:
        body["flagged_by"] = flagged_by
    if gap_names:
        body["gaps"] = gap_names
    return body
