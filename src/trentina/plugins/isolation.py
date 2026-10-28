"""The in-process harness every plugin runs behind.

A plugin's ``run`` is not trusted to be well-behaved, so it never reaches the
composition raw: the registry wraps it in a ``Harnessed`` that bounds, on every
call, what a transform can do to its OUTPUT —

* a RESULT TYPE — anything but the three ``TransformResult`` outcomes, a raise,
  or an ``Applied`` whose ``content`` is not a string becomes ``Failed`` rather
  than a surprise flowing into the chain;
* an AMPLIFICATION cap — an ``Applied`` result far larger than its input is
  ``Failed("amplified")``; a transform subtracts or reshapes, it does not
  inflate.

What this tier does NOT bound is TIME and the HOST. An in-process
``asyncio`` timeout is cooperative — it cannot interrupt a CPU-bound or blocking
plugin, which would stall the event loop before any deadline fired — and nothing
in-process keeps a plugin from reading the environment or opening a socket. A
wall-clock kill, a CPU/memory limit and a credential-free environment are the
process-isolation tier's job (``docs/plugins.md``); this tier is the trusted
``inline`` opt-down and the shape that tier wraps. A plugin logging the payload
it was handed is caught by the load-time conformance canary
(``trentina.testing``), not here.

``Harnessed`` IS a ``Transform`` and passes the inner's contract attributes
through, so the channel/kind locks and the composition stay blind to whether a
processor is in-tree or a plugin — only ``registry`` knows, and only a plugin is
wrapped. In-tree transforms are trusted and run unwrapped.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .. import logsafe
from ..transforms.base import (
    Applied,
    Cost,
    Declined,
    Failed,
    Transform,
    TransformContext,
    TransformResult,
)

if TYPE_CHECKING:
    from ..channels import Kind

logger = logging.getLogger(__name__)

#: An ``Applied`` result may not exceed this multiple of the input size.
HARNESS_AMPLIFICATION = 4


class Harnessed(Transform):
    """One plugin transform, wrapped in the in-process output bounds. Its
    contract attributes pass through from the inner transform, so the channel
    and kind locks and the composition see exactly the plugin they would
    unwrapped."""

    def __init__(self, inner: Transform, *, amplification: int = HARNESS_AMPLIFICATION) -> None:
        self._inner = inner
        self._amplification = amplification
        self.name: str = inner.name
        self.cost: Cost = inner.cost
        self.kind: Kind = inner.kind
        self.channels = inner.channels
        self.api_version: int = inner.api_version

    async def run(self, payload: str, ctx: TransformContext, /) -> TransformResult:
        """Run the wrapped plugin and bound its output.

        Returns the plugin's ``Applied``/``Declined``/``Failed`` unchanged when
        it is well-formed; otherwise ``Failed`` with the reason: ``error`` when
        the plugin raised (logged by plugin name and exception kind, never its
        message), ``not_a_result`` when it returned something else or an
        ``Applied`` with non-string content, and ``amplified`` when an
        ``Applied`` result exceeds the amplification cap.
        """
        try:
            result = await self._inner.run(payload, ctx)
        except Exception as exc:
            logger.warning("plugin %s raised %s", self.name, logsafe.exc_kind(exc))
            return Failed("error")
        if isinstance(result, (Declined, Failed)):
            return result
        if not isinstance(result, Applied) or not isinstance(result.content, str):
            return Failed("not_a_result")
        cap = self._amplification * len(payload.encode("utf-8"))
        # Character count is a lower bound on UTF-8 byte length, so an output
        # whose character count already exceeds the cap is rejected WITHOUT
        # encoding it — a huge amplified output never materializes a bytes copy.
        # Only when the character count is within the cap (bounded) is the exact
        # byte length computed, to catch a multibyte output that crosses it.
        if len(result.content) > cap or len(result.content.encode("utf-8")) > cap:
            return Failed("amplified")
        return result
