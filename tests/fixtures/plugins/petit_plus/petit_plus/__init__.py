"""petit-plus: a benign out-of-tree Trentina transform plugin.

This is the worked example a third-party author would write: a distribution
that implements the PUBLIC contract (`trentina.transforms.base`) and exposes a
factory in the `trentina.transforms.v1` entry-point group. It imports nothing
private — only the public base — and constructs no trust type. `dedupe`
collapses runs of identical adjacent lines; a real plugin would do more, but
the shape is the whole lesson.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from trentina.transforms.base import (
    Applied,
    Declined,
    Transform,
    TransformContext,
    TransformResult,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


class DedupeTransform(Transform):
    """Collapse runs of identical adjacent lines. FREE, text, tool channel —
    all inherited from the base; only ``name`` and ``run`` are declared."""

    name = "dedupe"

    async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
        lines = payload.split("\n")
        out: list[str] = []
        for line in lines:
            if out and out[-1] == line:
                continue
            out.append(line)
        collapsed = "\n".join(out)
        if collapsed == payload:
            return Declined("no adjacent duplicate lines")
        return Applied(collapsed, {"lines_in": len(lines), "lines_out": len(out)})


def make(_config: Mapping[str, object]) -> Transform:
    """The entry-point factory. Receives the chain's scalar config (ignored
    here) and returns a built transform."""
    return DedupeTransform()
