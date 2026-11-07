"""The transport registry — the second of Trentina's two plugin registries.

Deliberately separate from the transform registry (``gateway/drivers.py``),
with its own tables and its own parity tests (the #167 lesson: one table per
role, never one table for two). Three roles live here, one table each:

* A TRANSPORT speaks the agent-facing protocol as a ``Face`` + a ``Dispatch``;
  the one built-in is ``mcp``. One may be registered in-process
  (``register_transport``) and the crossing runs it through the same
  parse → carry → deliver → wrap order, but both halves stay in-tree (#740):
  a ``dist:name`` transport is refused by name. ``TransportName`` in
  ``gateway/profile.py`` mirrors what is dispatchable (``mcp``), not what is
  registered.
* A CARRIER is a backend's wire (#740), the frozen v1 plugin contract in
  ``base.py``. The built-ins are ``http`` and ``unix`` (#724); a ``dist:name`` carrier is an
  installed ``trentina.carriers.v1`` entry point, scanned before it is
  imported. ``carrier_for`` is the one place a backend's carrier is chosen.
* A ROUTE is a perimeter path (#535), below.
"""

from __future__ import annotations

import importlib
import re
import threading
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .base import Audit, Carrier, Dispatch, Face, Route

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..gateway.destination import DestinationKind
    from ..gateway.loader import GatewayConfig
    from ..gateway.profile import Backend, Profile
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


def _supported_api(half: Face | Dispatch | Carrier | Route[Any, Any]) -> bool:
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

    This is the in-process registration path (a bundled or test transport);
    there is no external one, since a transport's halves are in-tree only
    (#740). Refuses, by name,

    * a ``dist:name`` reference — that is a plugin, not an in-process register;
    * a name already taken, including a built-in — the table is never
      reassigned, the ``names.py`` rule;
    * a half that is not a ``Face``/``Dispatch``;
    * a half whose ``api_version`` this build does not run.

    Raises:
        TypeError: a half is not a ``Face``/``Dispatch``.
        ValueError: a ``dist:`` name, a name already taken, or an unrunnable
            ``api_version``. The registry is unchanged in every case.
    """
    if ":" in name:
        raise ValueError(
            f"transport {name!r}: a 'dist:name' transport is an external plugin, and "
            f"transports are in-tree only; register an in-process transport under a "
            f"plain name, or give the backend a 'carrier'"
        )
    if not isinstance(transport.face, Face):
        raise TypeError(f"transport {name!r}: face is not a Face")
    if not isinstance(transport.dispatch, Dispatch):
        raise TypeError(f"transport {name!r}: dispatch is not a Dispatch")
    if not _supported_api(transport.face) or not _supported_api(transport.dispatch):
        raise ValueError(
            f"transport {name!r}: declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_TRANSPORT_API)}"
        )
    _insert(_table(), "transport", name, transport)


def build_transport(name: str) -> Transport:
    """The transport a profile named, or fail closed.

    A registered name (``mcp``, plus anything ``register_transport`` added)
    resolves to its transport. A ``dist:name`` reference is an EXTERNAL
    transport plugin, refused: a transport's face is the judging edge and stays
    in-tree (#740). What a backend may name instead is its wire, ``carrier``.
    Any other unknown name is a config error naming what is available.
    """
    from ..gateway.errors import ProfileConfigError

    table = _table()
    if name in table:
        return table[name]
    if ":" in name:
        raise ProfileConfigError(
            f"transport {name!r}: transports are in-tree only; a backend's wire is "
            f"its 'carrier', which may be a plugin; registered transports: {sorted(table)}"
        )
    raise ProfileConfigError(f"unknown transport {name!r}; registered transports: {sorted(table)}")


# ---- The carriers (#740). ------------------------------------------------------

#: The ``api_version`` values a carrier may declare. A v2 contract would be a new
#: entry-point group beside ``CARRIER_GROUP``, not a second value here.
SUPPORTED_CARRIER_API: frozenset[int] = frozenset({1})

#: The carriers this build ships, the source of truth ``CarrierName`` in
#: ``gateway/profile.py`` mirrors; ``tests/test_transport_registry.py`` holds
#: the two in step.
BUILTIN_CARRIERS: frozenset[str] = frozenset({"http", "unix"})

#: The URL schemes a built-in carrier answers, and the two that name no wire
#: (``internal://`` is in-process, ``decoy://`` answers nothing). No plugin
#: carrier may be given a backend on one of them.
SCHEME_CARRIERS: Mapping[str, str] = MappingProxyType(
    {"http": "http", "https": "http", "unix": "unix"}
)
RESERVED_SCHEMES: frozenset[str] = frozenset({*SCHEME_CARRIERS, "internal", "decoy"})

#: The entry-point group a carrier plugin registers under: ``dist:name`` names one.
CARRIER_GROUP = "trentina.carriers.v1"

#: Name → carrier: the built-ins, then what ``register_carrier`` and
#: ``resolve_carrier`` added. Never reassigned.
_CARRIERS: dict[str, Carrier] = {}


def _carriers() -> dict[str, Carrier]:
    """The carrier table, with the built-ins in it."""
    if "http" not in _CARRIERS:
        from .http_carrier import HttpCarrier
        from .unix_carrier import UnixCarrier

        _CARRIERS.setdefault("http", HttpCarrier())
        _CARRIERS.setdefault("unix", UnixCarrier())
    return _CARRIERS


def _carrier_api(carrier: Carrier) -> bool:
    """``_supported_api`` against the carrier contract's versions."""
    version = getattr(carrier, "api_version", None)
    return type(version) is int and version in SUPPORTED_CARRIER_API


def register_carrier(name: str, carrier: Carrier) -> None:
    """Add a carrier under ``name``, in-process, or fail closed.

    Refuses a ``dist:name`` (that is ``resolve_carrier``'s), a name already
    taken, including a built-in, something that is not a ``Carrier``, and an
    ``api_version`` this build does not run. The table is unchanged on every
    refusal.

    Raises:
        TypeError: ``carrier`` is not a ``Carrier``.
        ValueError: any other refusal.
    """
    if ":" in name:
        raise ValueError(
            f"carrier {name!r}: a 'dist:name' carrier is a plugin, resolved from "
            f"{CARRIER_GROUP!r}; register an in-process carrier under a plain name"
        )
    if not isinstance(carrier, Carrier):
        raise TypeError(f"carrier {name!r}: not a Carrier")
    if not _carrier_api(carrier):
        raise ValueError(
            f"carrier {name!r}: declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_CARRIER_API)}"
        )
    _insert(_carriers(), "carrier", name, carrier)


def carrier_name(backend: Backend) -> str | None:
    """The carrier a backend rides: the one it names, else its URL scheme's.

    None for ``internal://`` and ``decoy://``, which ride no wire, and for a
    scheme no built-in answers, which the profile validator has already
    refused without an explicit ``carrier``."""
    if backend.carrier is not None:
        return backend.carrier
    return SCHEME_CARRIERS.get(backend.url.partition("://")[0].lower())


def carrier_for(backend: Backend) -> Carrier:
    """The carrier a backend's sessions ride on, for ``tools/list`` and
    ``tools/call`` alike. A ``dist:`` carrier is imported here the first time
    it is needed if startup has not already (``resolve_carrier``).

    Raises:
        ProfileConfigError: the backend rides no wire, or names a carrier that
            is not registered and is no installed plugin.
    """
    from ..gateway.errors import ProfileConfigError

    name = carrier_name(backend)
    if name is None:
        raise ProfileConfigError("backend rides no carrier")
    table = _carriers()
    if name in table:
        return table[name]
    if ":" in name:
        return resolve_carrier(name)
    raise ProfileConfigError(f"unknown carrier {name!r}; registered carriers: {sorted(table)}")


def check_carrier(name: str) -> None:
    """At config load: ``name`` is a registered carrier, or a plugin that is
    installed, exposes the entry point and passes the carrier scan. Nothing of
    a plugin is imported, as for a route (``check_route_plugin``).

    Raises:
        ProfileConfigError: none of those.
    """
    from ..gateway.errors import ProfileConfigError
    from ..plugins.registry import discover, installed_version
    from ..testing.suite import scan_imports

    table = _carriers()
    if name in table:
        return
    if ":" not in name:
        raise ProfileConfigError(f"unknown carrier {name!r}; registered carriers: {sorted(table)}")
    dist, _, entry = name.partition(":")
    if installed_version(dist) is None:
        raise ProfileConfigError(f"carrier plugin {name!r}: distribution {dist!r} is not installed")
    if violations := scan_imports(dist, carrier=True):
        raise ProfileConfigError(
            f"carrier plugin {name!r}: refused before loading, it reaches past the "
            f"carrier contract: {sorted(set(violations))}"
        )
    if name not in discover(CARRIER_GROUP):
        raise ProfileConfigError(f"carrier plugin {name!r}: {dist!r} exposes no carrier {entry!r}")


def resolve_carrier(ref: str) -> Carrier:
    """The carrier plugin ``ref`` (``dist:name``) names: checked, built, registered.

    ``check_carrier`` first, so the source is scanned before any of it runs;
    then the entry point's factory is called with no arguments, and what it
    returns must be a ``Carrier`` this build runs.

    Raises:
        ProfileConfigError: any of the above.
    """
    from ..gateway.errors import ProfileConfigError
    from ..plugins.registry import discover

    check_carrier(ref)
    table = _carriers()
    if ref in table:
        return table[ref]
    try:
        carrier = discover(CARRIER_GROUP)[ref].load()()
    except Exception as exc:
        raise ProfileConfigError(f"carrier plugin {ref!r} failed to load or build") from exc
    if not isinstance(carrier, Carrier):
        raise ProfileConfigError(
            f"carrier plugin {ref!r} did not return a trentina.transports.base.Carrier "
            f"(got {type(carrier).__name__})"
        )
    if not _carrier_api(carrier):
        raise ProfileConfigError(
            f"carrier plugin {ref!r}: declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_CARRIER_API)}"
        )
    with _REGISTER_LOCK:
        return table.setdefault(ref, carrier)


def resolve_carriers(profiles: Mapping[str, Profile]) -> None:
    """Import every ``dist:`` carrier a profile names, at startup, so a plugin
    that fails to build fails the start rather than the first call."""
    for profile in profiles.values():
        for backend in profile.backends.values():
            if backend.carrier is not None and ":" in backend.carrier:
                resolve_carrier(backend.carrier)


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


#: Each way a route breaks the contract a route that is not ours is held to,
#: by the reason code ``route_breaches`` and the conformance suite report.
_ROUTE_BREACHES: Mapping[str, str] = MappingProxyType(
    {
        "not-a-route": "not a Route (a Listener is built in only)",
        "api-version": (
            "declares an api_version this build does not run; "
            f"supported: {sorted(SUPPORTED_TRANSPORT_API)}"
        ),
        "name": "not a free route name matching the route's own",
        "path": "is served under /proxy/<name>/ and nowhere else",
        "audit": "records every call; ON_FINDING is built in only",
    }
)


def route_breaches(name: str, route: object) -> list[str]:
    """The contract breaches of ``route`` registered as ``name``, by reason code.

    A ``Listener`` is built in only: a new port is a larger surface than a path.
    The name must be a route name and not a built-in's, the path under
    ``/proxy/<name>/``, and the audit ``ALWAYS``: a route that is not ours does
    not get to leave its clean calls unrecorded.
    """
    if not isinstance(route, Route):
        return ["not-a-route"]
    found = [] if _supported_api(route) else ["api-version"]
    if not _ROUTE_NAME.fullmatch(name) or name in BUILTIN_ROUTES or route.name != name:
        found.append("name")
    if not route.path.startswith(f"/proxy/{name}/"):
        found.append("path")
    if route.audit is not Audit.ALWAYS:
        found.append("audit")
    return found


def register_route(name: str, route: Route[Any, Any]) -> None:
    """Add a route that is not the gateway's own, or fail closed on its first
    breach (``route_breaches``). The table is unchanged on every refusal.

    Raises:
        TypeError: ``route`` is not a ``Route``.
        ValueError: any other breach.
    """
    if breaches := route_breaches(name, route):
        error = TypeError if breaches[0] == "not-a-route" else ValueError
        raise error(f"route {name!r}: {_ROUTE_BREACHES[breaches[0]]}")
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
