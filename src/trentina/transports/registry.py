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
    from .base import Listener, Transport
    from .perimeter import ListenerMount, Mount

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
    from ..gateway.forward import ForwardRoute
    from ..gateway.git_transport import GitRoute
    from ..gateway.llm_proxy import LlmRoute
    from ..gateway.matrix_proxy import MatrixRoute

    return MappingProxyType(
        {
            "http": (HttpRoute(), DestinationKind.EGRESS),
            "git": (GitRoute(), DestinationKind.GIT),
            "llm": (LlmRoute(), DestinationKind.MODEL),
            "matrix": (MatrixRoute(), DestinationKind.MATRIX),
            "forward": (ForwardRoute(), DestinationKind.EGRESS),
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


#: The entry-point group a route plugin registers under: ``dist:name`` names one.
#: The version is part of the name; a v2 contract would be a new group.
ROUTE_GROUP = "trentina.transports.v1"


def resolve_route(ref: str, options: Mapping[str, Any]) -> Route[Any, Any]:
    """The route plugin ``ref`` (``dist:name``) names, checked, built and registered.

    ``check_route_plugin`` first: the source is held to the route lists BEFORE
    anything of it is imported, since loading an entry point runs the plugin's
    code. Then its factory is called with ``options``, and what it returns must
    be a ``Route`` calling itself ``name``, which ``register_route`` holds to
    the rest of the contract. Refused by name at startup, never at the first
    request.

    Raises:
        ProfileConfigError: any of the above.
    """
    from ..gateway.errors import ProfileConfigError
    from ..plugins.registry import discover

    check_route_plugin(ref)
    entry = ref.partition(":")[2]
    try:
        route = discover(ROUTE_GROUP)[ref].load()(options)
    except Exception as exc:
        raise ProfileConfigError(f"route plugin {ref!r} failed to load or build") from exc
    if not isinstance(route, Route):
        raise ProfileConfigError(
            f"route plugin {ref!r} did not return a trentina.transports.base.Route "
            f"(got {type(route).__name__}); a Listener is built in only"
        )
    try:
        register_route(entry, route)
    except (TypeError, ValueError) as exc:
        raise ProfileConfigError(f"route plugin {ref!r}: {exc}") from exc
    return route


def configured(name: str, config: GatewayConfig, providers: Mapping[str, Any]) -> bool:
    """Whether the file configures any instance of the built-in route ``name``.
    A route with nothing to reach is not mounted, as before #535."""
    instances = {
        "http": config.egress_upstreams,
        "git": config.git_remotes,
        "llm": providers,
        "matrix": config.matrix.get("enabled"),
        "forward": [i for i in config.route_instances.values() if i.type == "forward"],
    }
    return bool(instances.get(name))


def plugin_types(config: GatewayConfig) -> list[str]:
    """Every ``dist:name`` route type an instance in ``config`` names."""
    return sorted({i.type for i in config.route_instances.values() if ":" in i.type})


def check_route_plugin(ref: str) -> None:
    """At config load: the route plugin ``ref`` names is installed, exposes the
    entry point and passes the route scan. Nothing of it is imported: a
    configuration being validated, perhaps one no person has approved yet,
    must not run plugin code (cto, #535). ``resolve_route`` imports it at mount.

    Raises:
        ProfileConfigError: not installed, no such route, or the scan refused it.
    """
    from ..gateway.errors import ProfileConfigError
    from ..plugins.registry import discover, installed_version
    from ..testing.suite import scan_imports

    dist, _, entry = ref.partition(":")
    if installed_version(dist) is None:
        raise ProfileConfigError(f"route plugin {ref!r}: distribution {dist!r} is not installed")
    if violations := scan_imports(dist, route=True):
        raise ProfileConfigError(
            f"route plugin {ref!r}: refused before loading, it reaches past the "
            f"route contract: {sorted(set(violations))}"
        )
    if ref not in discover(ROUTE_GROUP):
        raise ProfileConfigError(f"route plugin {ref!r}: {dist!r} exposes no route {entry!r}")


#: The routes this gateway serves, by name, as mounted at startup.
MOUNTED: dict[str, Mount] = {}


def _listener_seed() -> Mapping[str, tuple[Listener, DestinationKind]]:
    from ..gateway.client_egress import ConnectListener
    from ..gateway.destination import DestinationKind

    return MappingProxyType({"egress": (ConnectListener(), DestinationKind.TUNNEL)})


#: The listeners this gateway serves, by name, once ``configure_listeners`` ran.
LISTENERS: dict[str, ListenerMount] = {}


def configure_listeners(host: str, port: int) -> None:
    """Record where the built-in listener binds. Called at startup, before
    serving; ``start_listeners`` binds it if a profile asked for it."""
    from .perimeter import ListenerMount

    for name, (listener, kind) in _listener_seed().items():
        LISTENERS[name] = ListenerMount(listener, kind, (host, port))


def listener_configured(config: GatewayConfig) -> bool:
    """Whether a profile asks for the CONNECT listener (#442). With none, there
    is no second socket."""
    return any(p.client_egress is not None for p in config.profiles.values())


async def start_listeners() -> None:
    """Bind each configured listener, if a profile has the block that uses it.

    With no such block anywhere there is no second socket. A block added by a
    later reload does not start one: ``reload_profiles`` says a restart is needed.
    """
    from ..gateway.loader import get_active_config

    active = get_active_config()
    if active is None or not active.egress_listener_configured:
        return
    for entry in LISTENERS.values():
        await entry.start()


async def stop_listeners() -> None:
    """Stop every listener and close what it is carrying."""
    for entry in LISTENERS.values():
        await entry.stop()


def mount_routes(
    server: Any,
    config: GatewayConfig,
    profiles: dict[str, Profile],
    providers: Mapping[str, Any] | None = None,
) -> None:
    """Mount every built-in route the configuration uses on ``server``.

    ``providers`` are the LLM providers loaded at startup, keys resolved.
    """
    from .perimeter import Mount, mount

    loaded = providers or {}
    for name, (route, kind) in _seed().items():
        if configured(name, config, loaded):
            MOUNTED[name] = Mount(route, kind, config, in_tree=True, providers=loaded)
            mount(server, MOUNTED[name], profiles)
    # A plugin route is mounted beside them, never seeded, so it is handed a
    # Context and nothing of the gateway's own (#535).
    from ..gateway.destination import DestinationKind

    for ref in plugin_types(config):
        plugin = ROUTES.get(ref.partition(":")[2]) or resolve_route(ref, {})
        MOUNTED[plugin.name] = Mount(plugin, DestinationKind.EGRESS, config)
        mount(server, MOUNTED[plugin.name], profiles)
