"""The transport registry: its own table, its own parity test (the #167 lesson).

Phase 6 PR7 framed the registry; P7.5 (#579) unlocked registration. Transports
are Trentina's second plugin registry, kept apart from the transform registry
with a parity test of their own. The one dispatchable built-in is ``mcp``; a
second transport may be REGISTERED in-process and resolved by name, and the
crossing runs it through the same parse → carry → deliver → wrap order. An
EXTERNAL ``dist:name`` transport plugin stays refused until the Face/Carrier
contract is frozen (#535).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING, cast, get_args

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.transports.base import Carrier, Early, Face, Transport
from trentina.transports.mcp import mcp_transport
from trentina.transports.registry import (
    BUILTIN_TRANSPORTS,
    SUPPORTED_TRANSPORT_API,
    TRANSPORTS,
    build_transport,
    register_transport,
)

from .transport_doubles import RecordingCarrier, RecordingFace

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
        carrier=RecordingCarrier(carry_result=carry_result),
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
    """A ``dist:name`` reference is an external plugin — refused at load with a
    ProfileConfigError until #535 freezes the contract, not registered."""
    with pytest.raises(ProfileConfigError, match="no entry-point group yet"):
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
    assert resolved.carrier.carried == "parsed"  # parse fed carry
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
    bad = Transport(face=cast("Face", object()), carrier=RecordingCarrier(carry_result="x"))
    with pytest.raises(TypeError, match="face is not a Face"):
        register_transport("bad_face", bad)


@pytest.mark.usefixtures("clean_registry")
def test_registering_a_non_carrier_half_is_a_type_error() -> None:
    bad = Transport(face=RecordingFace(parse_result="p"), carrier=cast("Carrier", object()))
    with pytest.raises(TypeError, match="carrier is not a Carrier"):
        register_transport("bad_carrier", bad)


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
    what a profile's tools/call dispatches over (that wiring is #535)."""
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
    assert mcp_transport.carrier.api_version == 1
    assert Face.api_version == 1
    assert Carrier.api_version == 1
