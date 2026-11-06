"""The trust core: the one place the fail-closed verdict is decided and rendered.

``dispose()`` is the single disposition decision every ingress shares — the rule
that a flagged or incompletely-judged payload is refused unless the mode is
``flag`` (Trentina 3.0, Phase 1). It replaces the hand-rolled copies that had
drifted apart across the gateway (``outbound.py`` failed open where the tools
failed closed). ``render`` is the only composer of a refusal body: no ingress
spells a refusal or names a ``Mode`` itself. ``gate()`` composes ``dispose()``
with the redact extraction it may trigger, so a verdict is disposed of one way
whoever asks.

``dispose()`` is pure: a verdict and a ``Posture`` in, a ``Disposition`` out,
no I/O — so is ``render``. The caller maps that ``Disposition`` to its own wire
shape (a JSON-RPC error, a ``_trentina_refusal`` field, a Matrix withhold).
``gate()`` is the one exception: redact's turns 2 and 3 are an L3 call, so it is
async and reaches the quarantine layer.
"""

from __future__ import annotations

from .dispose import (
    DEFAULT_REDACT_PROMPT,
    Decision,
    Disposition,
    Posture,
    dispose,
)
from .gate import Gated, gate
from .render import refusal_from_warning, refusal_of

__all__ = [
    "DEFAULT_REDACT_PROMPT",
    "Decision",
    "Disposition",
    "Gated",
    "Posture",
    "dispose",
    "gate",
    "refusal_from_warning",
    "refusal_of",
]
