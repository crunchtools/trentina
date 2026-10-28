"""The transport registry — the second of Trentina's two plugin registries.

Deliberately separate from the transform registry (``gateway/drivers.py``),
with its own table and its own parity test (the #167 lesson: one table per role,
never one table for two). A transport speaks a wire protocol as a ``Face`` + a
``Carrier``; today the only one is ``mcp``, the gateway's own MCP in and out.

Transport PLUGINS are not accepted yet. The live MCP ``Face`` reaches the
gateway's own collaborators directly (``transports/mcp.py``); narrowing it to
the frozen public ``parse(wire) -> Parsed`` / ``carry`` contract is the 3.0.0
work. Publishing a ``Face``/``Carrier`` signature now that 3.0.0 will change
would make ``api_version`` a lie, so a ``dist:name`` transport is refused BY
NAME at load until the contract is frozen. The door is framed (this registry,
the versioned base) and locked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .mcp import mcp_transport

if TYPE_CHECKING:
    from .base import Transport

#: Name → built-in transport. One role, one table; kept apart from the transform
#: table on purpose. A ``Literal`` in ``gateway/profile.py`` mirrors the keys,
#: and ``tests/test_transport_registry.py`` holds the two in step.
TRANSPORTS: dict[str, Transport] = {"mcp": mcp_transport}


def build_transport(name: str) -> Transport:
    """The transport a profile named, or fail closed.

    ``mcp`` (the only built-in) resolves to the shared transport. A ``dist:name``
    reference is a transport PLUGIN, refused by name until the contract is frozen
    in 3.0.0. Any other unknown name is a config error naming what is available.
    """
    from ..gateway.errors import ProfileConfigError

    if name in TRANSPORTS:
        return TRANSPORTS[name]
    if ":" in name:
        raise ProfileConfigError(
            f"transport {name!r}: transport plugins are accepted from 3.0.0, "
            f"when the Face/Carrier contract is frozen; built-in transports: {sorted(TRANSPORTS)}"
        )
    raise ProfileConfigError(
        f"unknown transport {name!r}; built-in transports: {sorted(TRANSPORTS)}"
    )
