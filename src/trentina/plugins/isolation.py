"""The two tiers a plugin runs behind.

A plugin's ``run`` is not trusted, so it never reaches the composition raw. Two
tiers wrap it; which one is chosen by the registry, and both share one set of
OUTPUT bounds (``_bound_output``):

* ``Isolated`` — the DEFAULT. The plugin runs in a child process
  (``plugins.worker`` via ``unpack.child.ask``): it sets its own CPU and
  address-space limits, holds no credential in its environment, runs under a
  slot cap, and is killed at a wall-clock deadline. That bounds TIME, CPU,
  MEMORY and ENVIRONMENT credentials — a plugin cannot exhaust the gateway or
  read a secret from its own ``environ``. It does NOT, on its own, stop the
  plugin reading a file the gateway's user can read or opening a socket:
  filesystem and network are bounded by the deployment's container hardening
  (read-only rootfs, network isolation; ``docs/deployment-hardening.md``), so
  an operator relying on isolation for an un-audited plugin runs the gateway
  hardened. The child rebuilds the plugin from its ref, so the parent never
  runs the plugin's ``run``.
* ``Harnessed`` — the ``inline`` opt-down, for a plugin the operator trusts as
  it trusts the gateway's own code. The plugin runs in the gateway process;
  only its output is bounded, and TIME/CPU/HOST are NOT (an in-process
  ``asyncio`` timeout is cooperative and cannot interrupt a CPU-bound plugin).

Both tiers apply the OUTPUT bounds: a result that is not one of the three
``TransformResult`` outcomes (or an ``Applied`` whose content is not a string)
is ``Failed``, and an ``Applied`` far larger than its input is
``Failed("amplified")`` — a transform subtracts or reshapes, it does not
inflate. A plugin logging the payload is caught by the load-time conformance
canary (``trentina.testing``), not here.

Each wrapper IS a ``Transform`` and passes the plugin's contract attributes
through, so the channel/kind locks and the composition stay blind to the
wrapping — only ``registry`` wraps, and only a plugin; in-tree transforms run
unwrapped.
"""

from __future__ import annotations

import json
import logging
import threading
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
from ..unpack import child

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..channels import Kind

logger = logging.getLogger(__name__)

#: An ``Applied`` result may not exceed this multiple of the input size.
HARNESS_AMPLIFICATION = 4

#: The worker module run per isolated call, and the bounds the parent imposes.
_WORKER = "trentina.plugins.worker"
#: Isolated plugin child processes allowed to run at once, gateway-wide.
PROCESS_SLOTS = 4
_SLOTS = threading.BoundedSemaphore(PROCESS_SLOTS)
#: Wall-clock seconds before the parent kills an isolated plugin.
PROCESS_DEADLINE = 10.0
#: Bytes of worker output accepted — a hard ceiling above the amplification cap.
PROCESS_MAX_OUTPUT = 16 * 1024 * 1024


def _bound_output(result: object, payload: str, amplification: int) -> TransformResult:
    """The OUTPUT bounds both tiers apply. A valid ``Declined``/``Failed`` passes
    through; a malformed result (not a ``TransformResult``, or an ``Applied``
    with non-string content) is ``Failed("not_a_result")``; an ``Applied`` over
    the amplification cap is ``Failed("amplified")``.

    The cap is checked against the character count first (a lower bound on UTF-8
    byte length), so a hugely amplified output is rejected without materializing
    a bytes copy; the exact byte length is computed only when the character count
    is already within the cap."""
    if isinstance(result, (Declined, Failed)):
        return result
    if not isinstance(result, Applied) or not isinstance(result.content, str):
        return Failed("not_a_result")
    cap = amplification * len(payload.encode("utf-8"))
    if len(result.content) > cap or len(result.content.encode("utf-8")) > cap:
        return Failed("amplified")
    return result


class Harnessed(Transform):
    """The ``inline`` tier: a trusted plugin run in-process, output bounded."""

    def __init__(self, inner: Transform, *, amplification: int = HARNESS_AMPLIFICATION) -> None:
        self._inner = inner
        self._amplification = amplification
        self.name: str = inner.name
        self.cost: Cost = inner.cost
        self.kind: Kind = inner.kind
        self.channels = inner.channels
        self.api_version: int = inner.api_version

    async def run(self, payload: str, ctx: TransformContext, /) -> TransformResult:
        """Run the inner plugin and bound its output. A raise becomes
        ``Failed("error")`` (logged by plugin name and exception kind, never its
        message); otherwise ``_bound_output`` enforces the result type and the
        amplification cap."""
        try:
            result = await self._inner.run(payload, ctx)
        except Exception as exc:
            logger.warning("plugin %s raised %s", self.name, logsafe.exc_kind(exc))
            return Failed("error")
        return _bound_output(result, payload, self._amplification)


#: Worker phrases (``unpack.child``) mapped to the failure reason an agent sees.
_PHRASE_REASON = {
    child.DEADLINE: "deadline",
    child.NO_SLOT: "no_slot",
    child.NOT_STARTED: "not_started",
    child.FAILED: "error",
    child.TOO_LARGE: "amplified",
}


def _result_from_worker(out: bytes | str) -> TransformResult:
    """Turn the worker's reply into a ``TransformResult``: a phrase into the
    matching ``Failed``, the JSON body into its outcome, anything malformed into
    ``Failed("error")`` — the parent trusts nothing the child printed."""
    if isinstance(out, str):
        return Failed(_PHRASE_REASON.get(out, "error"))
    try:
        body = json.loads(out)
        kind = body["kind"]
        details = body.get("details", {})
        if kind == "applied":
            return Applied(body["content"], details)
        if kind == "declined":
            return Declined(body["reason"], details)
        if kind == "failed":
            return Failed(body["reason"], details)
    except (ValueError, KeyError, TypeError):
        return Failed("error")
    return Failed("error")


class Isolated(Transform):
    """The ``process`` tier (default): a plugin run in a child with CPU/memory/
    wall-clock limits and no credential in its environment. Filesystem and
    network are bounded by the container's hardening, not here (see the module
    docstring). The child rebuilds the plugin from ``ref``; the parent passes
    the contract attributes through from the already-validated instance and
    never runs the plugin itself."""

    def __init__(
        self,
        ref: str,
        config: Mapping[str, object],
        contract: Transform,
        *,
        amplification: int = HARNESS_AMPLIFICATION,
        deadline: float = PROCESS_DEADLINE,
    ) -> None:
        """Args:
        ref: the plugin's ``dist:name``, which the worker rebuilds from.
        config: the chain's scalar config, passed to the plugin's factory.
        contract: the already-validated instance; its name/cost/kind/channels/
            api_version pass through so the locks and composition are unchanged.
        amplification: the ``Applied`` size cap, in multiples of the input.
        deadline: wall-clock seconds before the parent kills the child.
        """
        self._ref = ref
        self._config = dict(config)
        self._amplification = amplification
        self._deadline = deadline
        self.name: str = contract.name
        self.cost: Cost = contract.cost
        self.kind: Kind = contract.kind
        self.channels = contract.channels
        self.api_version: int = contract.api_version

    async def run(self, payload: str, ctx: TransformContext, /) -> TransformResult:
        """Run the plugin in the worker child and bound its output.

        Returns the worker's mapped ``Applied``/``Declined``/``Failed`` (through
        ``_bound_output``), or ``Failed`` when the request cannot be serialized
        (``bad_request``) or the worker produced no usable reply (a phrase mapped
        by ``_result_from_worker``). Never raises on a plugin's behaviour."""
        try:
            request = json.dumps(
                {
                    "ref": self._ref,
                    "config": self._config,
                    "payload": payload,
                    "ctx": {
                        "source": ctx.source,
                        "target_bytes": ctx.target_bytes,
                        "content_type": ctx.content_type,
                    },
                }
            ).encode("utf-8")
        except (TypeError, ValueError):
            # The config is _plugin_config's scalar output and should always
            # serialize; a plugin config that does not is refused, not raised.
            return Failed("bad_request")
        out = await child.run_unpacking(
            lambda: child.ask(
                _WORKER,
                request,
                slots=_SLOTS,
                deadline=self._deadline,
                max_output=PROCESS_MAX_OUTPUT,
            )
        )
        return _bound_output(_result_from_worker(out), payload, self._amplification)
