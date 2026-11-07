"""Pinning a federated peer from what it presented at the link (#640): operator only.

A trust pin is three values — the peer's key, its perimeter stamp and its
judge — and until now all three reached the approval page as the operator
agent's claim about the peer. This asks the peer instead: it sends a fresh
nonce over the backend's own signed link (``trentina/attest``), verifies the
answer against the key the OPERATOR supplied — never a key taken from the
link, which would let whoever answers vouch for itself — and stages the pin
with the stamp and judge the peer actually signed. The page says which it was.

It writes nothing. The pin goes through ``config_tool``'s own staging
(``tools.config.propose_trust``) and a person approves it, as before.

What happens when the peer does not attest is today's behaviour, never trust:
a peer that answers ``-32601`` may be older or may have nothing to sign, and
the two are the same answer, so the operator's own stamp and judge are staged
and the page says they were not checked. A peer that answers and does NOT
verify is different — a wrong key, or something between the gateways — and
stages nothing.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from ..gateway import attestation, pending
from ..gateway.backend import attest_backend
from ..gateway.errors import ScopeError
from ..gateway.federation_keys import FederationKeyError, load_public_key
from ..gateway.loader import get_active_config
from ..gateway.profile import federation_audience
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind
from .config import AS_SUPPLIED, propose_trust

if TYPE_CHECKING:
    from ..gateway.profile import Backend, Profile

logger = logging.getLogger(__name__)


class _RefusedError(Exception):
    """Why nothing was staged. ``verified`` is whether the peer's signature
    checked out, which the caller is told either way."""

    def __init__(self, message: str, *, verified: bool = False, **extra: Any) -> None:
        super().__init__(message)
        self.answer = {"error": message, "verified": verified, **extra}


def _peer_version(version: str | None) -> str:
    """The peer's ``serverInfo.version`` for the page. Peer-chosen, so shown
    only in a shape that is safe to show."""
    if version is None:
        return "unknown"
    try:
        return pending.checked_display(version, what="the peer's version")
    except pending.PendingError:
        return "not displayable"


async def federation_trust(
    profile: str,
    backend: str,
    public_key: str,
    expect_hash: str | None,
    perimeter_stamp: str | None = None,
    judge: str | None = None,
) -> dict[str, Any]:
    """Probe a federated backend and stage its trust pin for a person.

    Args:
        profile: The profile whose federated backend is to be trusted.
        backend: That backend's name in the profile.
        public_key: The peer's Ed25519 public key, PEM — from its operator,
            not from the link.
        expect_hash: The ``hash`` a ``config_tool`` read or write returned.
        perimeter_stamp: What to pin if the peer does not attest. When it does,
            it must match or be left out.
        judge: Likewise, for the judge.
    """
    try:
        require_operator(require_caller("federation_trust"), "federation_trust")
        written, target = _federated_backend(profile, backend, public_key)
        nonce = secrets.token_hex(32)
        attested = await attest_backend(backend, target, written, nonce)
        version = _peer_version(attested.server_version)
        if attested.withheld is None:
            pin = _presented(attested.envelope, public_key, nonce, target, perimeter_stamp, judge)
            learned = (
                "Verified at the link: the peer signed them with the key above, in answer "
                f"to a challenge this gateway had just made. It reports version {version}."
            )
        elif perimeter_stamp and judge:
            pin = {"public_key": public_key, "perimeter_stamp": perimeter_stamp, "judge": judge}
            learned = (
                f"{AS_SUPPLIED} The peer did not attest ({attested.withheld}); "
                f"it reports version {version}."
            )
        else:
            pin, learned = None, ""
    except ScopeError as exc:
        logger.warning("federation_trust refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    except _RefusedError as refused:
        return refused.answer
    if pin is None:
        return {
            "error": (
                f"the peer did not attest ({attested.withheld}), so its scanner and judge "
                "could not be read from the link. Pass perimeter_stamp and judge as its "
                "operator gave them to stage the pin as supplied"
            ),
            "verified": False,
        }
    answer = await propose_trust(profile, backend, pin, expect_hash, learned)
    verified = attested.withheld is None
    return {
        **answer,
        "verified": verified,
        **({} if verified else {"not_attested": attested.withheld}),
    }


def _federated_backend(profile: str, backend: str, public_key: str) -> tuple[Profile, Backend]:
    """The written profile and its federated backend, with a key that loads.

    The names are the caller's, so a refusal describes and never echoes them.
    """
    active = get_active_config()
    written = active.config.profiles.get(profile) if active is not None else None
    target = written.backends.get(backend) if written is not None else None
    if written is None or written.federation_of is not None or target is None:
        raise _RefusedError("no written profile has a backend of that name")
    if target.federated is None:
        raise _RefusedError("that backend is not federated, so there is no peer to trust")
    try:
        load_public_key(public_key)
    except FederationKeyError:
        raise _RefusedError("public_key is not an Ed25519 public key in PEM") from None
    return written, target


def _presented(
    envelope: Any,
    public_key: str,
    nonce: str,
    target: Backend,
    perimeter_stamp: str | None,
    judge: str | None,
) -> dict[str, str]:
    """The pin the peer signed for, or a refusal that stages nothing.

    A peer that answers and does not verify is not the fallback case: it is a
    wrong key, or something between the gateways answering for it.
    """
    assertion, reason = attestation.check_attestation(
        envelope,
        public_key=public_key,
        nonce=nonce,
        verifier=federation_audience(target.url) or "",
        now=int(time.time()),
    )
    if assertion is None:
        logger.warning("federation_trust: the peer's attestation did not verify (%s)", reason)
        raise _RefusedError(
            f"the peer attested, and its attestation does not verify ({reason}) against the "
            "key supplied. Either the key is not this peer's or something between the "
            "gateways answered for it. Nothing was staged"
        )
    presented = {"perimeter_stamp": assertion["perimeter_stamp"], "judge": assertion["judge"]}
    supplied = {"perimeter_stamp": perimeter_stamp, "judge": judge}
    differs = sorted(k for k, v in supplied.items() if v is not None and v != presented[k])
    if differs:
        raise _RefusedError(
            f"the peer signed a different {' and '.join(differs)} from the one supplied. "
            "Leave them out to pin what the peer presented. Nothing was staged",
            verified=True,
            presented=presented,
        )
    return {"public_key": public_key, **presented}
