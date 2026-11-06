"""Run one plugin transform in a child process (Phase 6).

Run by ``plugins.isolation.Isolated`` and by nothing else:

    python -m trentina.plugins.worker   # JSON {ref, config, payload} on stdin

This is where an installed plugin's ``run`` executes — never in the gateway
process. The child sets its own CPU and address-space limits, holds no
credential in its environment (``unpack.child.environment`` gives it none),
resolves the plugin from its ref, builds it, runs it on the payload, and prints
the ``TransformResult`` as JSON. An exception from the factory or ``run`` is
caught and printed as a ``Failed`` result, so the parent always reads a clean
reply; a hard stop it cannot catch — the deadline kill, an ``RLIMIT`` kill, or a
non-zero exit — the parent reads as a failure too.

It imports no gateway machinery — only the public transform types and
``importlib.metadata`` — so a spawned worker stays lean. Its own stdout is
pointed at stderr while the plugin runs (the parent reads only stdout), so a
plugin that prints cannot corrupt the result channel.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata as im
import json
import logging
import resource
import sys
from typing import Any

from ..transforms.base import Applied, Declined, Failed, TransformContext

logger = logging.getLogger(__name__)

CPU_SECONDS = 10
MEMORY_BYTES = 1024 * 1024 * 1024

#: Must equal ``plugins.registry.TRANSFORM_GROUP`` — asserted by a test so the
#: two cannot drift. Duplicated (not imported) to keep the worker from pulling
#: the registry and its import chain into every spawned process.
_GROUP = "trentina.transforms.v1"


def _load(ref: str) -> Any:
    """The entry-point factory named by ``ref`` (``dist:name``), or None."""
    for ep in im.entry_points(group=_GROUP):
        dist = ep.dist.name if ep.dist is not None else ""
        if f"{dist}:{ep.name}" == ref:
            return ep.load()
    return None


def _encode(result: object) -> dict[str, Any]:
    """The TransformResult as the JSON the parent reads back."""
    if isinstance(result, Applied):
        return {"kind": "applied", "content": result.content, "details": dict(result.details)}
    if isinstance(result, Declined):
        return {"kind": "declined", "reason": result.reason, "details": dict(result.details)}
    if isinstance(result, Failed):
        return {"kind": "failed", "reason": result.reason, "details": dict(result.details)}
    return {"kind": "invalid"}


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    request = json.loads(sys.stdin.buffer.read())
    # The result goes on stdout, which the parent reads as JSON. A plugin that
    # prints would corrupt that channel, so the plugin's own stdout is pointed
    # at stderr for the duration (the parent ignores stderr); the result is
    # written to the real stdout afterward.
    out = sys.stdout
    body: dict[str, Any] = {"kind": "failed", "reason": "not_found"}
    with contextlib.redirect_stdout(sys.stderr):
        factory = _load(request["ref"])
        if factory is not None:
            # TRUST: running an operator-installed plugin's factory and run().
            #   bounded-by: RLIMIT_CPU/AS above, a credential-free env, the
            #     parent's wall-clock kill and output cap. NOT bounded here:
            #     filesystem and network (the plugin runs as the gateway's OS
            #     user) — the container's hardening bounds those; this is a
            #     resource+env bound, not a sandbox for hostile code.
            #   on-failure: a raise is caught and returned as a Failed result.
            #   owner: plugins.worker.main
            try:
                transform = factory(request["config"])
                ctx = TransformContext(**request.get("ctx", {}))
                body = _encode(asyncio.run(transform.run(request["payload"], ctx)))
            except Exception as exc:
                # The worker's contract is to always return a result: a plugin
                # that raises becomes a Failed, logged by exception KIND (never
                # its message) for whoever runs the worker directly.
                logger.warning("plugin raised %s", type(exc).__name__)
                body = {"kind": "failed", "reason": "error"}
    json.dump(body, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
