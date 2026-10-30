"""The transport registry — the second of Trentina's two plugin registries.

Deliberately separate from the transform registry (``gateway/drivers.py``),
with its own table and its own parity test (the #167 lesson: one table per role,
never one table for two). A transport speaks a wire protocol as a ``Face`` + a
``Carrier``; the one built-in is ``mcp``, the gateway's own MCP in and out.

A second transport may be REGISTERED in-process (``register_transport``), which
is what makes the registry protocol-agnostic rather than a hard-coded single
entry: the crossing resolves a registered transport by name and runs it through
the same parse → carry → deliver → wrap order. What is still refused is an
EXTERNAL ``dist:name`` transport PLUGIN: the public ``Face``/``Carrier``
contract in ``base.py`` is still all-``Any`` and ``api_version`` is the only
frozen part of it, so there is no entry-point group to discover against and
publishing one now would announce an ABI that #535 will change. Registration is
not dispatch: a profile still only reaches a transport the dispatcher wires, and
that wiring is ``mcp`` alone (``transports/mcp.py``) until #535 splits the face
from the carrier. ``TransportName`` in ``gateway/profile.py`` mirrors what is
dispatchable (``mcp``), not what is registered.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .base import Carrier, Face
from .mcp import mcp_transport

if TYPE_CHECKING:
    from .base import Transport

#: Guards the duplicate-name check and the insertion in ``register_transport`` as
#: one critical section, so "a name is never reassigned" holds even if two
#: callers register at once. Registration is import/startup-time today, but the
#: guarantee is the ``names.py`` rule and it costs one lock to make it real.
_REGISTER_LOCK = threading.Lock()

#: The ``api_version`` values this build's crossing can run. A registered
#: transport declaring anything else is refused: its contract is not this one.
#: Mirrors ``plugins.registry.SUPPORTED_TRANSFORM_API`` — one frozen anchor per
#: registry.
SUPPORTED_TRANSPORT_API: frozenset[int] = frozenset({1})

#: The transports this build ships. Frozen, and the source of truth the
#: ``TransportName`` Literal in ``gateway/profile.py`` mirrors;
#: ``tests/test_transport_registry.py`` holds the two in step. Registration adds
#: to ``TRANSPORTS`` (below), never to this set.
BUILTIN_TRANSPORTS: frozenset[str] = frozenset({"mcp"})

#: Name → transport. Seeded with the built-ins; ``register_transport`` adds to
#: it. One role, one table; kept apart from the transform table on purpose.
TRANSPORTS: dict[str, Transport] = {"mcp": mcp_transport}


def _supported_api(half: Face | Carrier) -> bool:
    """Whether ``half`` declares an ``api_version`` this build runs.

    ``type(version) is int`` rather than ``isinstance``: ``bool`` is an ``int``
    subclass and ``True == 1``, so an ``isinstance`` check would admit
    ``api_version = True`` as version 1. An exact ``int`` also guards the ``in``
    test against an unhashable or non-int version.
    """
    version = getattr(half, "api_version", None)
    return type(version) is int and version in SUPPORTED_TRANSPORT_API


def register_transport(name: str, transport: Transport) -> None:
    """Add a transport to the registry under ``name``, or fail closed.

    This is the in-process registration path (a bundled or test transport), NOT
    the external-plugin path: an external ``dist:name`` transport is refused at
    ``build_transport`` until #535 freezes the typed contract. Refuses, by name,

    * a ``dist:name`` reference — that is a plugin, not an in-process register;
    * a name already taken, including a built-in — the table is never
      reassigned, the ``names.py`` rule;
    * a half that is not a ``Face``/``Carrier``;
    * a half whose ``api_version`` this build does not run.

    Raises:
        TypeError: a half is not a ``Face``/``Carrier``.
        ValueError: a ``dist:`` name, a name already taken, or an unrunnable
            ``api_version``. The registry is unchanged in every case.
    """
    if ":" in name:
        raise ValueError(
            f"transport {name!r}: a 'dist:name' transport is an external plugin, "
            f"refused until #535 freezes the Face/Carrier contract; register an "
            f"in-process transport under a plain name"
        )
    if not isinstance(transport.face, Face):
        raise TypeError(f"transport {name!r}: face is not a Face")
    if not isinstance(transport.carrier, Carrier):
        raise TypeError(f"transport {name!r}: carrier is not a Carrier")
    if not _supported_api(transport.face) or not _supported_api(transport.carrier):
        raise ValueError(
            f"transport {name!r}: declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_TRANSPORT_API)}"
        )
    # The duplicate check and the insertion are one critical section: two
    # callers must not both pass the check and then overwrite each other.
    with _REGISTER_LOCK:
        if name in TRANSPORTS:
            raise ValueError(
                f"transport {name!r} is already registered; names are never reassigned"
            )
        TRANSPORTS[name] = transport


def build_transport(name: str) -> Transport:
    """The transport a profile named, or fail closed.

    A registered name (``mcp``, plus anything ``register_transport`` added)
    resolves to its transport. A ``dist:name`` reference is an EXTERNAL transport
    plugin, refused until #535 freezes the ``Face``/``Carrier`` contract: there
    is no entry-point group to discover against while the contract is still
    all-``Any``. Any other unknown name is a config error naming what is
    available.
    """
    from ..gateway.errors import ProfileConfigError

    if name in TRANSPORTS:
        return TRANSPORTS[name]
    if ":" in name:
        raise ProfileConfigError(
            f"transport {name!r}: external transport plugins have no entry-point group "
            f"yet — the Face/Carrier contract is untyped until #535; registered transports: "
            f"{sorted(TRANSPORTS)}"
        )
    raise ProfileConfigError(
        f"unknown transport {name!r}; registered transports: {sorted(TRANSPORTS)}"
    )
