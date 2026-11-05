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

import importlib
import re
import threading
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .base import Audit, Carrier, Face, Route

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..gateway.destination import DestinationKind
    from ..gateway.loader import GatewayConfig
    from ..gateway.profile import Profile
    from .base import Transport
    from .perimeter import Mount

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

#: Name → transport. Seeded with the built-ins on first use; ``register_transport``
#: adds to it. One role, one table; kept apart from the transform table on purpose.
#: Seeded lazily because the ``mcp`` transport imports the gateway, which imports
#: it back: importing this module must not start that chain.
_TRANSPORTS: dict[str, Transport] = {}


def _table() -> dict[str, Transport]:
    """The transport table, with the built-ins in it."""
    if "mcp" not in _TRANSPORTS:
        # The mcp transport and the gateway package import each other; the
        # gateway must finish loading first, as it does on every serving path.
        importlib.import_module("trentina.gateway")
        from .mcp import mcp_transport

        _TRANSPORTS.setdefault("mcp", mcp_transport)
    return _TRANSPORTS


def __getattr__(name: str) -> Any:
    """``TRANSPORTS`` is the seeded table, read on first use (PEP 562)."""
    if name == "TRANSPORTS":
        return _table()
    raise AttributeError(name)


def _supported_api(half: Face | Carrier | Route[Any, Any]) -> bool:
    """Whether ``half`` declares an ``api_version`` this build runs.

    ``type(version) is int`` rather than ``isinstance``: ``bool`` is an ``int``
    subclass and ``True == 1``, so an ``isinstance`` check would admit
    ``api_version = True`` as version 1. An exact ``int`` also guards the ``in``
    test against an unhashable or non-int version.
    """
    version = getattr(half, "api_version", None)
    return type(version) is int and version in SUPPORTED_TRANSPORT_API


def _insert(table: dict[str, Any], kind: str, name: str, value: Any) -> None:
    """Add ``value`` to ``table`` under a name nobody holds, or refuse.

    The duplicate check and the insertion are one critical section: two callers
    must not both pass the check and then overwrite each other.
    """
    with _REGISTER_LOCK:
        if name in table:
            raise ValueError(f"{kind} {name!r} is already registered; names are never reassigned")
        table[name] = value


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
    _insert(_table(), "transport", name, transport)


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

    table = _table()
    if name in table:
        return table[name]
    if ":" in name:
        raise ProfileConfigError(
            f"transport {name!r}: external transport plugins have no entry-point group "
            f"yet — the Face/Carrier contract is untyped until #535; registered transports: "
            f"{sorted(table)}"
        )
    raise ProfileConfigError(f"unknown transport {name!r}; registered transports: {sorted(table)}")


# ---- The perimeter routes (#535). ----------------------------------------------
#
# The gateway's own routes, seeded here and nowhere else. Being in this table is
# what makes a route in-tree: the spine hands it ``InTree`` (the profile and the
# operation) because it judges its own protocol. ``register_route`` and the
# ``dist:`` loader add entries that are NOT seeded and get a plain ``Context``;
# nothing exported adds to this table, so the privilege cannot be claimed.


def _seed() -> Mapping[str, tuple[Route[Any, Any], DestinationKind]]:
    from ..gateway.destination import DestinationKind
    from ..gateway.egress_http import HttpRoute
    from ..gateway.git_transport import GitRoute

    return MappingProxyType(
        {
            "http": (HttpRoute(), DestinationKind.EGRESS),
            "git": (GitRoute(), DestinationKind.GIT),
        }
    )


#: The built-in route names: what the seed holds, and no plugin may take.
BUILTIN_ROUTES: frozenset[str] = frozenset({"http", "git", "llm", "matrix", "forward", "egress"})

#: A route name: lower-case, a letter first, at most 32 characters. It is a URL
#: segment and an audit column, so nothing else is admitted.
_ROUTE_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")

#: Routes registered in-process or loaded from a ``dist:`` plugin: never seeded,
#: so never in-tree. One role, one table, beside ``TRANSPORTS``.
ROUTES: dict[str, Route[Any, Any]] = {}


def register_route(name: str, route: Route[Any, Any]) -> None:
    """Add a route that is not the gateway's own, or fail closed.

    Refuses, by name: anything that is not a ``Route`` (a ``Listener`` is built
    in only: a new port is a larger surface than a path); an ``api_version`` this
    build does not run; a name that is not a route name or is a built-in's; a
    path outside ``/proxy/<name>/``; and
    ``Audit.ON_FINDING``, since a route that is not ours does not get to leave
    its clean calls unrecorded. The table is unchanged on every refusal.

    Raises:
        TypeError: ``route`` is not a ``Route``.
        ValueError: any other refusal above.
    """
    if not isinstance(route, Route):
        raise TypeError(f"route {name!r}: not a Route (a Listener is built in only)")
    if not _supported_api(route):
        raise ValueError(
            f"route {name!r}: declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_TRANSPORT_API)}"
        )
    if not _ROUTE_NAME.fullmatch(name) or name in BUILTIN_ROUTES or route.name != name:
        raise ValueError(f"route {name!r}: not a free route name matching the route's own")
    if not route.path.startswith(f"/proxy/{name}/"):
        raise ValueError(f"route {name!r}: is served under /proxy/{name}/ and nowhere else")
    if route.audit is not Audit.ALWAYS:
        raise ValueError(f"route {name!r}: records every call; ON_FINDING is built in only")
    _insert(ROUTES, "route", name, route)


def configured(name: str, config: GatewayConfig) -> bool:
    """Whether the file configures any instance of the built-in route ``name``.
    A route with nothing to reach is not mounted, as before #535."""
    return bool({"http": config.egress_upstreams, "git": config.git_remotes}.get(name))


#: The routes this gateway serves, by name, as mounted at startup.
MOUNTED: dict[str, Mount] = {}


def mount_routes(server: Any, config: GatewayConfig, profiles: dict[str, Profile]) -> None:
    """Mount every built-in route the configuration uses on ``server``."""
    from .perimeter import Mount, mount

    for name, (route, kind) in _seed().items():
        if configured(name, config):
            MOUNTED[name] = Mount(route, kind, config, in_tree=True)
            mount(server, MOUNTED[name], profiles)
