"""Per-feature stability tiers: which surfaces may break in a minor release.

Trentina is one program with one version, so until now a breaking change
anywhere forced a major bump for everything. Federation (#592), shipped in
3.1.0, has since changed shape in nearly every release — and each time it did,
the whole gateway's version moved with it. An operator reading "5.0.0" could
not tell whether the break was in the defense pipeline they depend on or in a
feature they do not use.

A **preview surface** is a named feature whose configuration and wire shape are
not yet frozen. A breaking change *confined to* a preview surface is a MINOR
bump, listed in ``CHANGELOG.md`` under a ``### Preview`` heading that names the
surface. A change reaching anything outside every declared surface is a major,
exactly as before.

The tier is a promise about blast radius, not a licence for churn: a surface
carries the same test, lint and review bar as the rest of the gateway, and
leaving preview is a deliberate decision, not a side effect of time passing.
``docs/stability.md`` is the statement an operator reads.

Every name here is a module constant, so logging one satisfies the logging rule
(#262). Nothing in this module reads a profile's values — only whether a block
is present.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from .gateway.loader import GatewayConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreviewSurface:
    """One feature whose config and wire shape are not yet frozen.

    ``detect`` answers "is this deployment using it" from the loaded config. It
    tests for a block's PRESENCE and never reads a value, so a surface report
    discloses nothing a profile chose.
    """

    name: str
    issue: str
    doc: str
    summary: str
    detect: Callable[[GatewayConfig], bool]


def _federation_in_use(config: GatewayConfig) -> bool:
    """Either half of a federation link counts: offering or consuming."""
    return any(
        profile.federation is not None
        or any(backend.federated is not None for backend in profile.backends.values())
        for profile in config.profiles.values()
    )


#: The declared preview surfaces, by name.
#:
#: Federation alone. The other two features that have churned recently —
#: API-driven configuration (#633) and human approval (#637) — are deliberately
#: NOT here: both carry breaking changes in the release that introduces this
#: module, and declaring them preview in the same breath would re-characterise
#: those changes after the fact. Adding a surface is a product decision, made
#: before the release that would rely on it, never during one.
PREVIEW_SURFACES: Mapping[str, PreviewSurface] = {
    "federation": PreviewSurface(
        name="federation",
        issue="#592",
        doc="docs/federation.md",
        summary=(
            "gateway-to-gateway links: a seat's federation block, the derived "
            "ingress, the primary JWT and the signed verdict assertion"
        ),
        detect=_federation_in_use,
    ),
}


def in_use(config: GatewayConfig) -> list[str]:
    """The declared preview surfaces this configuration actually uses, sorted."""
    return sorted(name for name, surface in PREVIEW_SURFACES.items() if surface.detect(config))


def warn_preview_surfaces(config: GatewayConfig) -> list[str]:
    """WARN once per preview surface in use, and return the names.

    One line per surface rather than one summary line: an operator grepping for
    a feature name should find it, and a surface added later should not change
    the shape of an existing line.
    """
    names = in_use(config)
    for name in names:
        surface = PREVIEW_SURFACES[name]
        logger.warning(
            "stability: %s is a PREVIEW surface (%s) — its config and wire shape "
            "may change in a minor release; see %s and docs/stability.md",
            surface.name,
            surface.issue,
            surface.doc,
        )
    return names
