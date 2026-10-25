"""The trust core: the one place the fail-closed verdict is decided and rendered.

``dispose()`` is the single disposition decision every ingress shares — the rule
that a flagged or incompletely-judged payload is refused unless the mode is
``flag`` (Trentina 3.0, Phase 1). It replaces the hand-rolled copies that had
drifted apart across the gateway (``outbound.py`` failed open where the tools
failed closed). ``render`` is the only composer of a refusal body: no ingress
spells a refusal or names a ``Mode`` itself.

Nothing here performs I/O. ``dispose()`` is pure: a verdict and a ``Posture`` in,
a ``Disposition`` out. The caller maps that ``Disposition`` to its own wire shape
(a JSON-RPC error, a ``_trentina_refusal`` field, a Matrix withhold).
"""

from __future__ import annotations

from .dispose import (
    DEFAULT_REDACT_PROMPT,
    Decision,
    Disposition,
    Posture,
    dispose,
)
from .render import refusal_from_warning, refusal_of

__all__ = [
    "DEFAULT_REDACT_PROMPT",
    "Decision",
    "Disposition",
    "Posture",
    "dispose",
    "refusal_from_warning",
    "refusal_of",
]
