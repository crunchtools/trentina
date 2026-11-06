"""The transport registry: its own table, its own parity test (the #167 lesson).

Phase 6 PR7 framed the registry; P7.5 (#579) unlocked registration. Transports
are Trentina's second plugin registry, kept apart from the transform registry
with a parity test of their own. The one dispatchable built-in is ``mcp``; a
second transport may be REGISTERED in-process and resolved by name, and the
crossing runs it through the same parse → carry → deliver → wrap order. An
EXTERNAL ``dist:name`` transport plugin stays refused: a transport's halves are
in-tree only (#740). What a backend may name is its carrier, tested below.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, ClassVar, cast, get_args

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.profile import Backend
from trentina.transports import registry
from trentina.transports.base import (
    Admitted,
    Audit,
    Bearer,
    Carrier,
    CarrierTarget,
    Context,
    Dispatch,
    Early,
    Face,
    Grant,
    Instance,
    OperatorOrigin,
    Reading,
    Refusal,
    RefusedError,
    Route,
    Transport,
    Wire,
)
from trentina.transports.http_carrier import HttpCarrier
from trentina.transports.mcp import mcp_transport
from trentina.transports.registry import (
    BUILTIN_TRANSPORTS,
    SUPPORTED_TRANSPORT_API,
    TRANSPORTS,
    build_transport,
    register_transport,
)

from .transport_doubles import RecordingDispatch, RecordingFace

if TYPE_CHECKING:
    from trentina.gateway.profile import Profile


@pytest.fixture
def clean_registry() -> Iterator[None]:
    """Restore ``TRANSPORTS`` after a test registers into it.

    The table is module-level mutable state; a test that registers a transport
    must not leak it into the next, or the parity invariant (and real loads)
    would see a phantom transport."""
    before = dict(TRANSPORTS)
    try:
        yield
    finally:
        TRANSPORTS.clear()
        TRANSPORTS.update(before)


def _double(*, carry_result: object = "carried") -> Transport:
    return Transport(
        face=RecordingFace(parse_result="parsed"),
        dispatch=RecordingDispatch(carry_result=carry_result),
    )


# --- Parity: what is nameable vs. what is registered ------------------------


def test_the_literal_mirrors_the_builtins_not_the_whole_table() -> None:
    """``TransportName`` declares what is DISPATCHABLE (the built-ins), and the
    built-ins are a subset of the registry table — a registered transport may
    extend the table without becoming nameable in a profile. A built-in that is
    nameable but not in the table, or vice versa, is dead on arrival."""
    from trentina.gateway.profile import TransportName

    assert set(get_args(TransportName)) == set(BUILTIN_TRANSPORTS)
    assert set(TRANSPORTS) >= BUILTIN_TRANSPORTS


def test_mcp_resolves_to_the_shared_transport() -> None:
    assert build_transport("mcp") is mcp_transport


def test_build_transport_refuses_an_external_dist_plugin() -> None:
    """A ``dist:name`` transport is refused at load with a ProfileConfigError
    that points at ``carrier``: transports are in-tree only (#740)."""
    with pytest.raises(ProfileConfigError, match=r"in-tree only.*carrier"):
        build_transport("acme-mcp:sse")


def test_build_transport_refuses_an_unknown_name() -> None:
    with pytest.raises(ProfileConfigError, match="unknown transport"):
        build_transport("sse")


# --- A registered transport crosses by name, in order ----------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("clean_registry")
async def test_a_registered_transport_resolves_and_crosses_in_order() -> None:
    """The point of the unlock: a non-mcp transport, resolved BY NAME through
    the registry, runs the same parse → carry → deliver → wrap order with each
    step's output handed to the next. The crossing — not the transport — owns
    that order (the security property)."""
    from trentina.orchestrator import crossing

    register_transport("recorder", _double())
    resolved = build_transport("recorder")
    assert resolved is not mcp_transport

    result = await crossing(resolved, ctx=object())
    assert resolved.dispatch.carried == "parsed"  # parse fed carry
    assert resolved.face.delivered == ("parsed", "carried")  # carry fed deliver
    assert result == {"wrapped": {"delivered": "carried"}}  # deliver fed wrap


@pytest.mark.asyncio
@pytest.mark.usefixtures("clean_registry")
async def test_a_registered_transport_short_circuits_on_early() -> None:
    """Early from the carry step ends the crossing before deliver/wrap, the same
    as for the built-in."""
    from trentina.orchestrator import crossing

    register_transport("early", _double(carry_result=Early({"backend": "error"})))
    resolved = build_transport("early")
    result = await crossing(resolved, ctx=object())
    assert result == {"backend": "error"}
    assert resolved.face.delivered is None  # deliver never ran
    assert resolved.face.wrapped is None


# --- register_transport fails closed ----------------------------------------


@pytest.mark.usefixtures("clean_registry")
def test_registering_a_dist_name_is_refused() -> None:
    with pytest.raises(ValueError, match="external plugin"):
        register_transport("acme:sse", _double())


@pytest.mark.usefixtures("clean_registry")
def test_registering_a_taken_name_is_refused() -> None:
    with pytest.raises(ValueError, match="already registered"):
        register_transport("mcp", _double())


@pytest.mark.usefixtures("clean_registry")
def test_registering_a_non_face_half_is_a_type_error() -> None:
    bad = Transport(face=cast("Face", object()), dispatch=RecordingDispatch(carry_result="x"))
    with pytest.raises(TypeError, match="face is not a Face"):
        register_transport("bad_face", bad)


@pytest.mark.usefixtures("clean_registry")
def test_registering_a_non_dispatch_half_is_a_type_error() -> None:
    bad = Transport(face=RecordingFace(parse_result="p"), dispatch=cast("Dispatch", object()))
    with pytest.raises(TypeError, match="dispatch is not a Dispatch"):
        register_transport("bad_dispatch", bad)


@pytest.mark.usefixtures("clean_registry")
def test_registering_an_unrunnable_api_version_is_refused() -> None:
    unsupported = max(SUPPORTED_TRANSPORT_API) + 1
    transport = _double()
    transport.face.api_version = unsupported  # instance override of the class default
    with pytest.raises(ValueError, match="api_version this build does not run"):
        register_transport("v_next", transport)


@pytest.mark.usefixtures("clean_registry")
def test_concurrent_registration_of_one_name_has_a_single_winner() -> None:
    """Two callers racing to register the same name: exactly one succeeds, the
    other raises, and the registry keeps the winner — the lock's guarantee. A
    barrier maximizes contention so a regression that drops the lock (check then
    set, last-wins) would show up as two successes or a reassigned entry."""
    start = threading.Barrier(2)
    outcomes: dict[int, tuple[str, Transport]] = {}

    def worker(key: int) -> None:
        transport = _double()
        start.wait()
        try:
            register_transport("rival", transport)
            outcomes[key] = ("ok", transport)
        except ValueError:
            outcomes[key] = ("refused", transport)

    threads = [threading.Thread(target=worker, args=(k,)) for k in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(o for o, _ in outcomes.values()) == ["ok", "refused"]
    winner = next(tr for o, tr in outcomes.values() if o == "ok")
    assert build_transport("rival") is winner


@pytest.mark.usefixtures("clean_registry")
def test_a_bool_api_version_is_not_mistaken_for_version_one() -> None:
    """``bool`` is an ``int`` subclass and ``True == 1``; an ``isinstance`` check
    would admit ``api_version = True`` as version 1. The exact-``int`` check
    refuses it."""
    transport = _double()
    transport.face.api_version = True
    with pytest.raises(ValueError, match="api_version this build does not run"):
        register_transport("boolish", transport)


@pytest.mark.usefixtures("clean_registry")
def test_a_registered_transport_does_not_become_a_dispatchable_name() -> None:
    """Registration is not dispatch: the ``TransportName`` Literal is unchanged,
    so a profile still cannot name the registered transport for a backend."""
    from trentina.gateway.profile import TransportName

    register_transport("recorder", _double())
    assert "recorder" not in set(get_args(TransportName))


# --- Dispatch stays wired to mcp by identity --------------------------------


@pytest.mark.asyncio
async def test_the_dispatch_path_uses_the_mcp_transport_by_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_crossing_call`` hands ``crossing`` the ``mcp_transport`` object itself,
    never a registry lookup — so registering another transport cannot change
    what a profile's tools/call dispatches over. A backend varies its carrier,
    below, never its protocol (#740)."""
    import trentina.transports.mcp as mcp_mod

    seen: dict[str, object] = {}

    async def _spy(transport: object, _ctx: object) -> dict[str, object]:
        seen["transport"] = transport
        return {}

    monkeypatch.setattr(mcp_mod, "crossing", _spy)
    await mcp_mod._crossing_call(profile=cast("Profile", object()), req_id=1, params={})
    assert seen["transport"] is mcp_transport


# --- The contract still carries a frozen api_version ------------------------


def test_the_contract_carries_an_api_version() -> None:
    """The compat anchor register_transport enforces."""
    assert mcp_transport.face.api_version == 1
    assert mcp_transport.dispatch.api_version == 1
    assert Face.api_version == 1
    assert Dispatch.api_version == 1


# --- Perimeter routes (#535 R4) ---------------------------------------------------


class _Toy(Route[Admitted, Context]):
    """A minimal route a plugin author would write."""

    name = "toy"
    methods = ("GET",)
    auth = Bearer()
    refusals: ClassVar[dict[str, Refusal]] = {}
    max_request_bytes = 1024

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> Admitted:
        return Admitted(OperatorOrigin("origin"))

    async def deliver(self, admitted: Admitted, ctx: Context) -> Any:
        return None

    def render(self, refused: RefusedError) -> Any:
        return refused.reason


@pytest.fixture
def _clean_routes() -> Iterator[None]:
    before = dict(registry.ROUTES)
    try:
        yield
    finally:
        registry.ROUTES.clear()
        registry.ROUTES.update(before)


@pytest.mark.usefixtures("_clean_routes")
class TestRegisterRoute:
    def test_a_well_formed_route_registers(self) -> None:
        route = _Toy()
        registry.register_route("toy", route)
        assert registry.ROUTES["toy"] is route

    def test_it_is_never_seeded(self) -> None:
        """Registering is not seeding: an in-process route is not in-tree."""
        registry.register_route("toy", _Toy())
        assert "toy" not in registry.BUILTIN_ROUTES

    @pytest.mark.parametrize("name", sorted(registry.BUILTIN_ROUTES))
    def test_a_built_in_name_is_refused(self, name: str) -> None:
        route = _Toy()
        route.name = name
        with pytest.raises(ValueError, match="free route name"):
            registry.register_route(name, route)

    @pytest.mark.parametrize("name", ["Toy", "1toy", "to_y", "t" * 33, ""])
    def test_a_name_that_is_not_a_route_name_is_refused(self, name: str) -> None:
        route = _Toy()
        route.name = name
        with pytest.raises(ValueError, match="free route name"):
            registry.register_route(name, route)

    def test_a_name_unlike_the_routes_own_is_refused(self) -> None:
        with pytest.raises(ValueError, match="free route name"):
            registry.register_route("other", _Toy())

    def test_on_finding_audit_is_refused(self) -> None:
        route = _Toy()
        route.audit = Audit.ON_FINDING
        with pytest.raises(ValueError, match="ON_FINDING"):
            registry.register_route("toy", route)

    def test_an_unrunnable_api_version_is_refused(self) -> None:
        route = _Toy()
        route.api_version = 2
        with pytest.raises(ValueError, match="api_version"):
            registry.register_route("toy", route)

    def test_a_listener_is_refused(self) -> None:
        not_a_route: Any = object()
        with pytest.raises(TypeError, match="Listener is built in only"):
            registry.register_route("toy", not_a_route)

    def test_a_name_is_never_reassigned(self) -> None:
        registry.register_route("toy", _Toy())
        with pytest.raises(ValueError, match="already registered"):
            registry.register_route("toy", _Toy())

    def test_a_route_is_served_under_its_own_name(self) -> None:
        assert _Toy().path == "/proxy/toy/{instance}/{path:path}"


# --- Carriers (#740) --------------------------------------------------------


class _Wire(Carrier):
    name = "wire"

    def connect(self, target: CarrierTarget, reading: Reading) -> Any:
        raise NotImplementedError


@pytest.fixture
def clean_carriers() -> Iterator[None]:
    """Each test sees the built-in carriers and nothing a neighbour added."""
    table = registry._carriers()
    before = dict(table)
    try:
        yield
    finally:
        table.clear()
        table.update(before)


class TestCarriers:
    def test_the_literal_mirrors_the_builtins(self) -> None:
        from trentina.gateway.profile import CarrierName

        assert set(get_args(CarrierName)) == set(registry.BUILTIN_CARRIERS)
        assert set(registry._carriers()) >= registry.BUILTIN_CARRIERS

    def test_every_built_in_scheme_names_a_built_in_carrier(self) -> None:
        assert set(registry.SCHEME_CARRIERS.values()) <= registry.BUILTIN_CARRIERS
        assert set(registry.SCHEME_CARRIERS) <= registry.RESERVED_SCHEMES

    def test_an_http_backend_rides_the_http_carrier(self) -> None:
        backend = Backend(url="https://mcp.example/mcp")
        assert registry.carrier_name(backend) == "http"
        assert isinstance(registry.carrier_for(backend), HttpCarrier)

    def test_an_internal_backend_rides_none(self) -> None:
        backend = Backend(url="internal://tools")
        assert registry.carrier_name(backend) is None
        with pytest.raises(ProfileConfigError, match="rides no carrier"):
            registry.carrier_for(backend)

    @pytest.mark.usefixtures("clean_carriers")
    def test_a_registered_carrier_resolves(self) -> None:
        wire = _Wire()
        registry.register_carrier("wire", wire)
        registry.check_carrier("wire")
        assert registry._carriers()["wire"] is wire

    @pytest.mark.usefixtures("clean_carriers")
    @pytest.mark.parametrize("name", ["http", "acme:wire"])
    def test_a_taken_or_dist_name_is_refused(self, name: str) -> None:
        with pytest.raises(ValueError, match=r"already registered|plugin"):
            registry.register_carrier(name, _Wire())

    @pytest.mark.usefixtures("clean_carriers")
    def test_a_non_carrier_is_a_type_error(self) -> None:
        with pytest.raises(TypeError, match="not a Carrier"):
            registry.register_carrier("wire", cast("Carrier", object()))

    @pytest.mark.usefixtures("clean_carriers")
    @pytest.mark.parametrize("version", [2, True, "1"])
    def test_an_unrunnable_api_version_is_refused(self, version: object) -> None:
        wire = type("_Versioned", (_Wire,), {"api_version": version})()
        with pytest.raises(ValueError, match="api_version"):
            registry.register_carrier("wire", wire)
        assert "wire" not in registry._carriers()

    def test_an_uninstalled_plugin_is_refused_without_importing(self) -> None:
        with pytest.raises(ProfileConfigError, match="is not installed"):
            registry.check_carrier("no-such-dist-740:wire")

    def test_an_unknown_plain_name_is_refused(self) -> None:
        with pytest.raises(ProfileConfigError, match="unknown carrier"):
            registry.check_carrier("smoke-signals")

    def test_a_plugin_is_scanned_before_it_is_imported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import trentina.plugins.registry as plugins
        from trentina.testing import suite

        loaded: list[str] = []

        class _Entry:
            def load(self) -> Any:
                loaded.append("loaded")
                return _Wire

        monkeypatch.setattr(plugins, "installed_version", lambda _d: "1.0")
        monkeypatch.setattr(plugins, "discover", lambda _g: {"acme:wire": _Entry()})
        monkeypatch.setattr(suite, "scan_imports", lambda _d, **_k: ["forbidden-import:os"])
        with pytest.raises(ProfileConfigError, match="refused before loading"):
            registry.resolve_carrier("acme:wire")
        assert loaded == []

    @pytest.mark.usefixtures("clean_carriers")
    def test_a_plugin_that_passes_is_built_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import trentina.plugins.registry as plugins
        from trentina.testing import suite

        class _Entry:
            def load(self) -> Any:
                return _Wire

        monkeypatch.setattr(plugins, "installed_version", lambda _d: "1.0")
        monkeypatch.setattr(plugins, "discover", lambda _g: {"acme:wire": _Entry()})
        monkeypatch.setattr(suite, "scan_imports", lambda _d, **_k: [])
        first = registry.resolve_carrier("acme:wire")
        assert isinstance(first, _Wire)
        assert registry.resolve_carrier("acme:wire") is first


class TestBackendCarrierField:
    def test_a_plugin_cannot_take_an_http_backend(self) -> None:
        with pytest.raises(ValueError, match="rides the 'http' carrier"):
            Backend(url="https://mcp.example/mcp", carrier="acme:wire")

    def test_an_unanswered_scheme_needs_a_carrier(self) -> None:
        with pytest.raises(ValueError, match="needs a carrier"):
            Backend(url="unix:///run/mcp/hub.sock")

    def test_the_http_carrier_answers_http_only(self) -> None:
        with pytest.raises(ValueError, match="answers"):
            Backend(url="unix:///run/mcp/hub.sock", carrier="http")

    def test_an_internal_backend_names_no_carrier(self) -> None:
        with pytest.raises(ValueError, match="carrier does not apply"):
            Backend(url="internal://tools", carrier="acme:wire")

    def test_a_plugin_scheme_is_remote(self) -> None:
        backend = Backend(url="unix:///run/mcp/hub.sock", carrier="acme:wire")
        assert backend.is_remote
        assert registry.carrier_name(backend) == "acme:wire"

    def test_a_url_without_a_scheme_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must start with a scheme"):
            Backend(url="mcp.example/mcp")
