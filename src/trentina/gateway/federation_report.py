"""What a federation link looks like from the inside, for an operator (#592).

Three audit passes over federation found twenty defects and none of us wrote
down that the operator had no way to SEE what they had built. `surface` is per
profile and `quarantine_stats`' `perimeter` is per gateway; neither is shaped
like a link. So the first signal of a drifted offered set, an orphaned pin or a
trust pin that had quietly stopped matching was an agent saying "I don't have
that tool" — or nothing at all, since a pin that matches nothing just costs a
full local re-judge and keeps working.

This answers the two questions an operator actually has:

* **What am I sharing, and with whom?** Per shared seat: the derived ingress,
  the peers by key fingerprint, which backends cross, which of those run on the
  seat's own sign-in, and whether the link signs a verdict at all.
* **Is the pin buying me anything?** Per federated backend: the audience it
  authenticates to, how its responses were handled over the audit window, and
  the commonest reason one was re-judged. A link whose `trusted` count is zero
  while `hash_mismatch` climbs is a pin that has stopped matching.

Operator-only, through `quarantine_stats`. Names here are the operator's own
configuration — profiles, backends, peers — and a peer's PUBLIC KEY is reduced
to a fingerprint rather than printed: it is not a secret, but the whole PEM is
a wall of base64 nobody reads, and the fingerprint is the thing the operator at
the other end can read down a phone. No backend URL appears; the audience says
which profile is reached, which is what identifies the link.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from . import tool_pins
from .federation_link import offerable_backends
from .profile import federation_audience

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .profile import Profile

#: How many days of audit rows the verdict counts cover. The same window
#: `quarantine_stats` uses for its other audit numbers.
VERDICT_WINDOW_DAYS = 30


def key_fingerprint(pem: str) -> str:
    """A short digest of a public key, for a person to compare by eye."""
    return f"sha256:{hashlib.sha256(pem.encode('utf-8')).hexdigest()[:16]}"


def _shared(seat: Profile, ingress: Profile) -> dict[str, Any]:
    """One seat this gateway shares, and the ingress derived from it."""
    federation = seat.federation
    if federation is None:  # pragma: no cover - a derived ingress carries it
        return {}
    offered = offerable_backends(seat)
    return {
        "seat": seat.name,
        "ingress": ingress.name,
        "peers": [
            {"peer": name, "key": key_fingerprint(peer.public_key)}
            for name, peer in sorted(federation.peers.items())
        ],
        "offers": sorted(offered),
        # Which offered backends run on the seat's sign-in. A derived ingress
        # spends the SEAT's grant, so these are the ones where a peer's calls
        # go out as the account a person authorized here.
        "uses_sign_in": sorted(
            name for name, backend in offered.items() if backend.auth is not None
        ),
        # Without a secondary key the link authenticates and signs nothing, so
        # the primary re-judges every response this gateway already judged. It
        # works; it costs twice, invisibly.
        "signs_verdicts": federation.secondary_key is not None,
        # Pins are keyed by a backend's URL, so what is held for this link is
        # held across the backends it offers. A tool waiting here is one the
        # peer is not being served.
        "held_for_approval": sum(
            len(tool_pins.pending(backend.url)) for backend in offered.values()
        ),
    }


def _consumed(
    profile: Profile, name: str, verdicts: Mapping[str, dict[str, int]]
) -> dict[str, Any]:
    """One federated backend this gateway uses, and how its responses went."""
    backend = profile.backends[name]
    counts = dict(verdicts.get(f"{profile.name}.{name}", {}))
    rejudged = {
        reason: count for reason, count in counts.items() if reason not in ("trusted", "incomplete")
    }
    return {
        "profile": profile.name,
        "backend": name,
        # The profile name a primary JWT is audience-pinned to, which is what
        # identifies the peer's link. Never the URL.
        "audience": federation_audience(backend.url),
        "trust_pinned": backend.federated is not None
        and backend.federated.trust_verdict is not None,
        "verdicts": counts,
        # The commonest reason a response was re-judged instead of trusted.
        # This is the number that says a pin has stopped matching.
        "top_rejudged_reason": max(rejudged, key=lambda r: rejudged[r]) if rejudged else None,
        "held_for_approval": len(tool_pins.pending(backend.url)),
    }


def link_report(
    profiles: Mapping[str, Profile], verdicts: Mapping[str, dict[str, int]]
) -> dict[str, Any]:
    """Every federation link this gateway is on, in both directions.

    Args:
        profiles: the loaded registry, by profile name, derived ingresses
            included — a link is reported by pairing each profile carrying
            ``federation_of`` with the seat it names.
        verdicts: how federated responses were handled, keyed
            ``"<profile>.<backend>"`` to a count per verdict, as
            ``database.get_federated_verdict_stats`` returns it. An absent key
            means no federated call in the window, not a failure.

    Returns:
        ``shared``: one entry per seat this gateway offers, with ``seat``,
        ``ingress``, ``peers`` (name and key fingerprint), ``offers``,
        ``uses_sign_in``, ``signs_verdicts`` and ``held_for_approval``.
        ``consumed``: one entry per federated backend this gateway uses, with
        ``profile``, ``backend``, ``audience``, ``trust_pinned``, ``verdicts``,
        ``top_rejudged_reason`` and ``held_for_approval``.
        ``verdict_window_days``: the window the counts cover.
    """
    return {
        "shared": [
            _shared(profiles[ingress.federation_of], ingress)
            for _, ingress in sorted(profiles.items())
            if ingress.federation_of is not None and ingress.federation_of in profiles
        ],
        "consumed": [
            _consumed(profile, name, verdicts)
            for _, profile in sorted(profiles.items())
            for name, backend in sorted(profile.backends.items())
            if backend.federated is not None
        ],
        "verdict_window_days": VERDICT_WINDOW_DAYS,
    }
