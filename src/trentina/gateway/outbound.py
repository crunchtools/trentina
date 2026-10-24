"""Judging an agent's own OUTBOUND request content (#511).

Shared by the ``/llm`` proxy and the terminating egress route. Both read the
request as one document and must answer the same question: does it carry a
credential the agent should not be sending out, or an injection the layers
catch? So both run this:

- a deterministic credential-shape scan (``credential_shapes``) over the raw
  document and, if that is clean, its percent-decoded form — the signal the
  prompt-injection layers do not look for;
- L1/L2/L3 over a credential-REDACTED copy (``judge_input``), so the secret
  never reaches the external judge while the injection content, which is what
  L3 is for, is read in full. The layers always run — the credential detector
  is an added signal, never a per-layer off switch (the layer contract).

It returns a verdict; the caller turns it into its own refusal or warning
shape (a JSON deny marker for ``/llm`` and egress, an HTTP status either way).
The ORIGINAL request is what each caller forwards upstream — never this copy.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import unquote

from ..credential_shapes import kinds as credential_kinds
from ..credential_shapes import redact as credential_redact
from ..logsafe import exc_kind, exc_where
from ..modes import Mode
from .context import profile_context

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

# The closed reason codes an outbound refusal carries. Credential first: it is
# the most specific and actionable.
REASON_CREDENTIAL = "credential_in_request"
REASON_FLAGGED = "flagged"
REASON_UNJUDGED = "not_fully_judged"

#: A JSON ``\\uXXXX`` escape — the other way a body hides a key from a raw scan,
#: which the destination's JSON parser decodes (`\\u0041` -> ``A``).
_JSON_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")


def reveal(document: str) -> str:
    """Decode every escaping the destination would, so a key cannot hide in one.

    Percent-escapes (``%41``, a URL/form/query evasion) and JSON ``\\uXXXX``
    escapes (a JSON-string evasion) are decoded — including a key split across
    literal and escaped characters, which neither a raw scan nor a whole-run
    mask would catch. The result is what the destination parses, so a credential
    in ANY encoding reads as a raw shape here, and a percent- or ``\\u``-encoded
    injection becomes readable to L2.
    """
    decoded = unquote(document)
    return _JSON_UESC.sub(lambda m: chr(int(m.group(1), 16)), decoded)


def judge_input(document: str) -> str:
    """The copy L1/L2/L3 read — NOT what is forwarded upstream.

    The document is REVEALED (every escaping decoded) and then every credential
    shape is cut, so a secret — raw, percent-encoded, ``\\u``-escaped or a mix —
    never reaches the external judge in any recoverable form, while injection
    content (now decoded) is read by every layer. The original bytes are what
    each caller forwards.
    """
    return credential_redact(reveal(document))


def body_text(body: bytes) -> str:
    """A request body as text the LAYERS can read.

    A JSON body re-serialized with ``ensure_ascii=True`` (as ``/llm`` admits it)
    arrives as ``\\uXXXX`` escapes L2 cannot read and L1 does not count; parse
    and re-dump unescaped for judging. The bytes FORWARDED upstream are the
    caller's own and are not touched here.
    """
    try:
        return json.dumps(json.loads(body), ensure_ascii=False)
    except (ValueError, TypeError):
        return body.decode("utf-8", errors="replace")


def detect_credentials(document: str) -> list[str]:
    """Credential kind names in ``document`` or its revealed form.

    A key the destination would decode — ``%41%4B...``, ``\\u0041...``, or a mix
    of literal and escaped characters — must not slip the check, so the revealed
    form (``reveal``) is scanned when the raw one is clean.
    """
    found = credential_kinds(document)
    if not found:
        revealed = reveal(document)
        if revealed != document:
            found = credential_kinds(revealed)
    return sorted(k.value for k in found)


@dataclass(frozen=True)
class OutboundVerdict:
    """What judging an outbound request concluded. Carries no policy; the
    caller applies the mode and builds its own refusal/warning."""

    kinds: list[str] = field(default_factory=list)
    flagged: bool = False
    flagged_by: str | None = None
    unjudged: bool = True
    # A ``modes.Gaps`` name, not a reason code: this is what a deny marker's
    # `gaps` field carries. l3_unavailable is the default while no verdict ran.
    gaps: list[str] = field(default_factory=lambda: ["l3_unavailable"])
    risk: str = "unknown"

    @property
    def reason(self) -> str | None:
        """The refusal reason code, by precedence credential > flagged > gap."""
        if self.kinds:
            return REASON_CREDENTIAL
        if self.flagged:
            return REASON_FLAGGED
        if self.unjudged:
            return REASON_UNJUDGED
        return None

    def blocks(self) -> bool:
        """True when ``block`` must refuse: a credential shape, a flag, or a
        blocking gap. ``flag`` consults ``warning`` instead."""
        return bool(self.kinds) or self.flagged or self.unjudged

    @property
    def warning(self) -> str | None:
        """The flag-mode annotation: a finding, never a gap list."""
        if self.kinds:
            return "credential"
        if self.flagged:
            return self.risk
        if self.unjudged:
            return "unjudged"
        return None


async def judge_outbound(
    document: str,
    *,
    source: str,
    source_type: str,
    backend: str,
    profile: Profile,
    mode: Mode,
    deadline: float,
) -> OutboundVerdict:
    """Scan ``document`` for credentials and judge a redacted copy through L1/L2/L3.

    The scan is deadline- and exception-bounded: a hung or failed judge is
    treated as unjudged (``block`` refuses, ``flag`` forwards with a warning),
    as the Matrix path does. ``source``/``source_type`` identify the detection
    row; ``backend`` is its backend column (``llm:<provider>``, ``egress:<name>``);
    ``mode`` is the caller's resolved mode, recorded in the attribution.
    """
    from ..defense import Provenance, defend  # heavy; deferred, and a test seam
    from ..modes import gaps_of  # resolved here so a test's monkeypatch is seen

    kinds = detect_credentials(document)
    flagged, unjudged, flagged_by, risk = False, True, None, "unknown"
    gaps = ["l3_unavailable"]
    try:
        with profile_context(profile):
            async with asyncio.timeout(deadline):
                verdict = await defend(
                    judge_input(document),
                    source=source,
                    source_type=source_type,
                    defense=profile.defense,
                    provenance=Provenance.MODEL_OUTPUT,
                    stop_on_partial=mode is Mode.BLOCK,
                    attribution={
                        "direction": "request",
                        "blocked": mode is Mode.BLOCK,
                        "profile": profile.name,
                        "backend": backend,
                    },
                )
        flagged = verdict.flagged
        flagged_by = verdict.flagged_by.value if verdict.flagged_by else None
        g = gaps_of(verdict)
        unjudged = g.blocking()
        gaps = g.names()
        risk = verdict.risk_level
    except Exception as exc:  # TimeoutError too: no verdict was reached
        logger.error(  # backend is server-configured (#262-safe); the message may carry the request
            "outbound: request scan failed backend=%s source_type=%s: %s at %s",
            backend,
            source_type,
            exc_kind(exc),
            exc_where(exc),
        )
    return OutboundVerdict(
        kinds=kinds, flagged=flagged, flagged_by=flagged_by, unjudged=unjudged, gaps=gaps, risk=risk
    )
