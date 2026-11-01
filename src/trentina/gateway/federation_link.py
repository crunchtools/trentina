"""Derive a federation ingress from the seat that shares it (#592).

Until 5.0.0, federation had no first-class object. An operator wrote an ingress
profile on the secondary and a federated backend on the primary, and the only
things making them one link were that a URL path happened to equal a profile
name and that two keys happened to pair. Everything that went wrong followed
from that:

* The ingress re-listed backends, so the offered set was a hand-typed expansion
  of "this seat's tools" with no source of truth, and it drifted.
* The profile name IS the JWT audience and nothing said so, so an invented
  naming scheme named the peer machine rather than the seat.
* The ingress carried its own ``defense`` block, which could be weaker than the
  posture of the very seat whose tools it offered.
* A grant belongs to ``(profile, backend)`` and a federated call runs as the
  ingress, so a seat already signed in to a backend held nothing for the link
  and the human signed in twice.

Now a SEAT carries ``federation`` and this module derives the ingress from it.
The derived profile is ``<seat>-federation``, its offered set is exactly the
seat's non-federated remote backends with the seat's own guards and posture,
and it has no second way in. There is nothing to drift, nothing to name, and no
way to express a mismatch.

Two properties are structural rather than checked:

* **Loop-free.** The derived set excludes every ``federated`` backend, so a
  gateway can never re-export the next one — A to B to C is not refused, it is
  unsayable. This is what lets one seat both consume a federated backend and
  offer itself to a peer, which the old "one profile is one role" rule had to
  forbid because a single ``Profile`` serving both roles deadlocked its own
  single-flight aggregate build. Two objects, no deadlock.
* **Bounded internal surface.** ``internal://`` is one FastMCP server serving
  the whole native surface, admin tools included, so the derived ingress gets a
  fresh internal backend allowing exactly ``read_part_tool`` rather than a
  filtered copy of the seat's.

Every field of ``Profile`` is decided here, by name, in ``CARRIED`` or
``DROPPED`` or by construction. ``test_federation_link.py`` fails on a field
that is in none of them, so a field added to ``Profile`` later cannot reach a
peer because nobody thought about it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .paging import READ_PART_TOOL
from .profile import INGRESS_SUFFIX, INTERNAL_SCHEME, Backend, Profile

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The label of the internal backend the derived ingress gets. The seat's own
#: internal backend is never carried over: a peer reaches the paging reader and
#: nothing else.
INTERNAL_LABEL = "trentina"

#: Seat fields the derived ingress inherits, because they are the policy that
#: travels with a tool. Dropping any of them would make the link LOOSER than
#: the seat whose tools it offers, which is the one direction derivation must
#: never go: ``defense`` is the perimeter posture, the two ``semantic_*_guards``
#: read calls and responses against the operator's policy, ``preprocess`` shapes
#: the bytes (and a trusted response skips the primary's chain, so the
#: secondary's is the only one that runs), and ``llm_keys`` is what makes L3
#: resolve at all — without it ``block`` and ``redact`` refuse every call.
CARRIED = frozenset(
    {
        "defense",
        "preprocess",
        "llm_keys",
        "declare_modes",
        "short_names",
        "semantic_request_guards",
        "semantic_response_guards",
    }
)

#: Seat fields the derived ingress does NOT inherit, each for one of three
#: reasons: it is a second way in (``peers`` is the authentication, and
#: ``app.py`` tries a static bearer FIRST, so a bearer here would admit a caller
#: with no peer and no ``sub``); it is a route or listener bound at startup for
#: the seat and unreachable as a tool over an MCP link; or it belongs to the
#: seat as a thing it planted. A honeytoken re-planted in a second profile would
#: make a trip ambiguous about which seat leaked it, and a honeypot is not a
#: thing to mirror.
DROPPED = frozenset(
    {
        "auth",
        "oauth",
        "alert_ingress",
        "matrix_ingress",
        "matrix_bridge",
        "bridges",
        "client_egress",
        "git",
        "egress_http",
        "tool_discovery",
        "honeypot",
        "honeytokens",
        "orchestrated",
    }
)

#: Fields this module sets itself rather than carrying or dropping.
CONSTRUCTED = frozenset({"name", "role", "federation", "federation_of", "backends"})


def ingress_name(seat: str) -> str:
    """The derived ingress profile name for a seat, which is also its audience."""
    return f"{seat}{INGRESS_SUFFIX}"


def offers_federation(profile: Profile) -> bool:
    """Whether this profile is a seat that shares itself with a peer."""
    return profile.federation is not None


def offerable_backends(seat: Profile) -> dict[str, Backend]:
    """The seat's backends a peer may reach, by name.

    Remote only, and never a ``federated`` one. ``is_remote`` already excludes
    ``internal://`` (the whole native surface, admin tools included) and
    ``decoy://`` (a trap that belongs to the seat that set it, and whose trip
    should name that seat).
    """
    return {
        name: backend
        for name, backend in seat.backends.items()
        if backend.is_remote and backend.federated is None
    }


def derive_ingress(seat: Profile) -> Profile:
    """Build the federation ingress a seat shares, or raise if it shares none.

    The seat keeps everything; the ingress is a second, narrower view of it.
    """
    if seat.federation is None:
        raise ValueError(f"profile {seat.name!r} declares no federation block")

    offered = offerable_backends(seat)
    if not offered:
        # An empty link is a misconfiguration, not an empty offering: it mints
        # keys, admits a peer and costs an approval to set up, and then serves
        # that peer the paging reader for parts of responses no tool produced.
        raise ValueError(
            f"seat {seat.name!r} offers a peer no backend: a shared seat needs at "
            "least one non-federated remote backend. An internal:// backend is "
            "this gateway's own surface and a federated one would re-export the "
            "next gateway, so neither can be offered"
        )

    carried = {field: getattr(seat, field) for field in sorted(CARRIED)}
    return Profile(
        name=ingress_name(seat.name),
        # Always an agent. An operator ingress would offer a peer the gateway's
        # own admin tools, which is why this is set here rather than inherited.
        role="agent",
        federation=seat.federation,
        federation_of=seat.name,
        backends={
            **offered,
            # A fresh internal backend, not a filtered copy of the seat's:
            # ``internal://`` serves ``config_tool``, ``tool_pins`` and
            # ``reload_profiles`` from the same server as the paging reader.
            INTERNAL_LABEL: Backend(
                url=f"{INTERNAL_SCHEME}{INTERNAL_LABEL}", tools_allow=[READ_PART_TOOL]
            ),
        },
        **carried,
    )


def derive_all(registry: Mapping[str, Profile]) -> dict[str, Profile]:
    """Every ingress derived from the seats in ``registry``, by derived name."""
    return {
        ingress_name(name): derive_ingress(seat)
        for name, seat in registry.items()
        if offers_federation(seat)
    }
