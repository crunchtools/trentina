"""Derive a federation ingress from the source that shares it (#592).

Until 5.0.0, federation had no first-class object. An operator wrote an ingress
profile on the secondary and a federated backend on the primary, and the only
things making them one link were that a URL path happened to equal a profile
name and that two keys happened to pair. Everything that went wrong followed
from that:

* The ingress re-listed backends, so the offered set was a hand-typed expansion
  of "this source's tools" with no source of truth, and it drifted.
* The profile name IS the JWT audience and nothing said so, so an invented
  naming scheme named the peer machine rather than the source.
* The ingress carried its own ``defense`` block, which could be weaker than the
  posture of the very source whose tools it offered.
* A grant belongs to ``(profile, backend)`` and a federated call runs as the
  ingress, so a source already signed in to a backend held nothing for the link
  and the human signed in twice.

Now a PROFILE carries ``federation`` and this module derives the ingress from it.
The derived profile is ``<source>-federation``, its offered set is exactly the
source's non-federated remote backends with the source's own guards and posture,
and it has no second way in. There is nothing to drift, nothing to name, and no
way to express a mismatch.

Two properties are structural rather than checked:

* **Loop-free.** The derived set excludes every ``federated`` backend, so a
  gateway can never re-export the next one — A to B to C is not refused, it is
  unsayable. This is what lets one source both consume a federated backend and
  offer itself to a peer, which the old "one profile is one role" rule had to
  forbid because a single ``Profile`` serving both roles deadlocked its own
  single-flight aggregate build. Two objects, no deadlock.
* **Bounded internal surface.** ``internal://`` is one FastMCP server serving
  the whole native surface, admin tools included, so the derived ingress gets a
  fresh internal backend allowing exactly ``read_part_tool`` rather than a
  filtered copy of the source's.

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

#: The label of the internal backend the derived ingress gets. Constructed
#: under this name rather than carried, so a peer cannot reach ``internal://``
#: by whatever name the operator gave it. What the backend ALLOWS follows the
#: shared profile since 6.0.0 (``_internal_allow``).
INTERNAL_LABEL = "trentina"

#: Shared-profile fields the derived ingress inherits, because they are the
#: policy that travels with a tool. Dropping any would make the link LOOSER
#: than the profile whose tools it offers, the one direction derivation must
#: never go. ``role`` joined them in 6.0.0, which gives up half of the directed
#: edge: see "Sharing the operator role" in ``docs/federation.md`` and
#: ``config_guard.peer_becomes_operator``.
#:
#: Why each of the others, at length, is in ``derive_ingress``.
CARRIED = frozenset(
    {
        "defense",
        "preprocess",
        "llm_keys",
        "declare_modes",
        "short_names",
        "semantic_request_guards",
        "semantic_response_guards",
        "role",
    }
)

#: Profile fields the derived ingress does NOT inherit, each for one of three
#: reasons: it is a second way in (``peers`` is the authentication, and
#: ``app.py`` tries a static bearer FIRST, so a bearer here would admit a caller
#: with no peer and no ``sub``); it is a route or listener bound at startup for
#: the source and unreachable as a tool over an MCP link; or it belongs to the
#: source as a thing it planted. A honeytoken re-planted in a second profile would
#: make a trip ambiguous about which source leaked it, and a honeypot is not a
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
        "route_grants",
        "tool_discovery",
        "honeypot",
        "honeytokens",
        "orchestrated",
    }
)

#: Fields this module sets itself rather than carrying or dropping.
CONSTRUCTED = frozenset({"name", "federation", "federation_of", "backends"})


def ingress_name(source: str) -> str:
    """The derived ingress profile name for a source, which is also its audience."""
    return f"{source}{INGRESS_SUFFIX}"


def offers_federation(profile: Profile) -> bool:
    """Whether this profile is a source that shares itself with a peer."""
    return profile.federation is not None


def offerable_backends(source: Profile) -> dict[str, Backend]:
    """The source's backends a peer may reach, by name.

    Remote only, and never a ``federated`` one. ``is_remote`` already excludes
    ``internal://`` (the whole native surface, admin tools included) and
    ``decoy://`` (a trap that belongs to the source that set it, and whose trip
    should name that source).
    """
    return {
        name: backend
        for name, backend in source.backends.items()
        if backend.is_remote and backend.federated is None
    }


def derive_ingress(source: Profile) -> Profile:
    """Build the federation ingress a profile shares, or raise if it shares none.

    The shared profile keeps everything; the ingress is a second view of it.

    Why each ``CARRIED`` field is carried: ``defense`` is the perimeter
    posture; the two ``semantic_*_guards`` read calls and responses against the
    operator's policy; ``preprocess`` shapes the bytes, and a trusted response
    skips the primary's chain so the secondary's is the only one that runs;
    ``llm_keys`` is what makes L3 resolve at all, without which ``block`` and
    ``redact`` refuse every call; and ``role`` is Scott's 6.0.0 change, so that
    one agent administering a gateway administers its peer through the same
    link.
    """
    if source.federation is None:
        raise ValueError(f"profile {source.name!r} declares no federation block")

    offered = offerable_backends(source)
    if not offered:
        # An empty link is a misconfiguration, not an empty offering: it mints
        # keys, admits a peer and costs an approval to set up, and then serves
        # that peer the paging reader for parts of responses no tool produced.
        raise ValueError(
            f"source {source.name!r} offers a peer no backend: a shared source needs at "
            "least one non-federated remote backend. An internal:// backend is "
            "this gateway's own surface and a federated one would re-export the "
            "next gateway, so neither can be offered"
        )

    carried = {field: getattr(source, field) for field in sorted(CARRIED)}
    return Profile(
        name=ingress_name(source.name),
        federation=source.federation,
        federation_of=source.name,
        backends={
            **offered,
            INTERNAL_LABEL: Backend(
                url=f"{INTERNAL_SCHEME}{INTERNAL_LABEL}",
                tools_allow=sorted(_internal_allow(source)),
            ),
        },
        **carried,
    )


def _internal_allow(source: Profile) -> set[str]:
    """Which of this gateway's OWN tools the derived ingress serves a peer.

    Until 6.0.0 this was ``{read_part_tool}``, constructed rather than carried,
    and it was the second half of the directed edge: a peer reached no tool of
    the gateway but a paging continuation, whatever the shared profile declared.

    Scott asked for the operator role to cross the link (see ``CARRIED``), and
    carrying the role alone would have changed nothing — ``require_operator``
    would pass for the peer and every admin tool would still be unreachable,
    because they are served by ``internal://`` and that backend allowed one
    tool. So the surface has to follow the role, and this is where it does.

    The paging reader is unioned in rather than assumed, because ``parts.py``
    needs it on every link: a peer's paged response is delivered part by part
    through the derived ingress, and a shared profile whose own internal
    backend omits ``read_part_tool`` would otherwise break paging for its peer
    while looking fine.

    Carried ONLY for an operator profile. For an agent profile the derived
    surface stays the 5.x floor, because the role and the surface are one
    change: an agent profile's peer cannot call an admin tool anyway
    (``require_operator`` refuses it), so carrying the rest would widen every
    existing agent link -- the majority of them -- for no capability anybody
    asked for.

    A shared profile with no ``internal://`` backend gets the floor too, which
    is also the safe answer.
    """
    allowed = {READ_PART_TOOL}
    if source.role != "operator":
        return allowed
    for backend in source.backends.values():
        if backend.is_internal:
            allowed.update(backend.tools_allow or [])
    return allowed


def derive_all(registry: Mapping[str, Profile]) -> dict[str, Profile]:
    """Every ingress derived from the profiles in ``registry``, by derived name."""
    return {
        ingress_name(name): derive_ingress(source)
        for name, source in registry.items()
        if offers_federation(source)
    }
