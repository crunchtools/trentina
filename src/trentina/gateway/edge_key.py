"""Per-edge Ed25519 signing for gateway federation (#592, C1).

A downstream gateway signs a short-lived JWT with its per-edge Ed25519 private
key; the upstream verifies it against the public key it holds for that peer and
learns which peer signed (the matching key's name is the actor) plus the real
caller (``sub``). No shared static bearer, no token-exchange round-trip, no
stored state.

The verifier is a CLOSED-SHAPE parser, deliberately not a general JWT library
(cto ruling, and ``authlib.jose`` is deprecated): exactly three segments, the
header compared by EQUALITY to the one header we ever issue — so ``alg``/``jwk``/
``jku`` confusion cannot arise, ``alg:none`` is simply a different string and is
rejected — and a closed claim set. Ed25519 only.

The same primitives (`load_private_key`, `load_public_key`, `sign`, `verify`)
sign D1's verdict assertions, which are not JWTs.
"""

from __future__ import annotations

import base64
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_TTL_SECONDS = 60
"""A token may not claim a longer life than this; a downstream bug cannot mint a
long-lived credential."""

CLOCK_SKEW_SECONDS = 10


class EdgeKeyError(ValueError):
    """An edge key failed to load, or a token failed to verify. The message is a
    fixed reason code, never the token or a claim value."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, TypeError) as exc:
        raise EdgeKeyError("malformed") from exc


#: The one header we issue and the only one we accept. Canonical, compact,
#: sorted — compared by byte-equality, so the algorithm is never taken from the
#: token.
_HEADER = {"alg": "EdDSA", "typ": "JWT"}
_HEADER_B64 = _b64url(json.dumps(_HEADER, separators=(",", ":"), sort_keys=True).encode())

_CLAIMS = frozenset({"sub", "aud", "iat", "exp"})

#: `sub` is a profile name the upstream has not resolved yet (C2 does); bound its
#: shape here and never log it raw (#262).
_SUB_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def load_private_key(pem: str) -> Ed25519PrivateKey:
    """Load a PEM PKCS#8 Ed25519 private key, or raise ``EdgeKeyError``."""
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise EdgeKeyError("private key not valid PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EdgeKeyError("private key is not Ed25519")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    """Load a PEM SubjectPublicKeyInfo Ed25519 public key, or raise ``EdgeKeyError``."""
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError) as exc:
        raise EdgeKeyError("public key not valid PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EdgeKeyError("public key is not Ed25519")
    return key


def sign(key: Ed25519PrivateKey, payload: bytes) -> bytes:
    """Ed25519 signature over ``payload`` (reused by D1 for verdict assertions)."""
    return key.sign(payload)


def verify(public_key: Ed25519PublicKey, signature: bytes, payload: bytes) -> bool:
    """True iff ``signature`` is ``public_key``'s over ``payload``. Never raises."""
    try:
        public_key.verify(signature, payload)
    except InvalidSignature:
        return False
    return True


def sign_edge_jwt(key: Ed25519PrivateKey, *, sub: str, aud: str, now: int | None = None) -> str:
    """A 60-second EdDSA JWT carrying the real caller (``sub``) for ``aud``."""
    issued = int(time.time()) if now is None else now
    payload = {"sub": sub, "aud": aud, "iat": issued, "exp": issued + MAX_TTL_SECONDS}
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{_HEADER_B64}.{body}"
    return f"{signing_input}.{_b64url(sign(key, signing_input.encode()))}"


def _checked_claims(payload_b64: str, *, aud: str, now: int | None) -> str:
    """Decode the payload and hold it to the closed claim set; return ``sub``.

    Every branch is a distinct fail-closed reject reason: a malformed payload,
    an unexpected claim set, the wrong audience, non-integer or over-long
    lifetimes, an expired or not-yet-valid token, or a mis-shapen subject.
    """
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except ValueError as exc:
        raise EdgeKeyError("payload not json") from exc
    if not isinstance(claims, dict) or frozenset(claims) != _CLAIMS:
        raise EdgeKeyError("claim set")
    if claims["aud"] != aud:
        raise EdgeKeyError("audience")
    iat, exp = claims["iat"], claims["exp"]
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (iat, exp)):
        raise EdgeKeyError("iat/exp not integers")
    if exp - iat > MAX_TTL_SECONDS:
        raise EdgeKeyError("ttl too long")
    moment = int(time.time()) if now is None else now
    if not iat - CLOCK_SKEW_SECONDS <= moment <= exp + CLOCK_SKEW_SECONDS:
        raise EdgeKeyError("expired or not yet valid")
    sub = claims["sub"]
    if not isinstance(sub, str) or not _SUB_RE.match(sub):
        raise EdgeKeyError("sub shape")
    return sub


def verify_edge_jwt(
    token: str,
    peers: dict[str, Ed25519PublicKey],
    *,
    aud: str,
    now: int | None = None,
) -> tuple[str, str]:
    """Verify an edge JWT against the peers' public keys.

    Returns ``(peer_name, sub)`` — the name of the peer whose key verified the
    signature (the actor) and the real caller. Fail-closed: any malformation,
    unknown header, unverifiable signature, wrong audience, over-long TTL, or
    expiry raises ``EdgeKeyError`` with a fixed reason.
    """
    segments = token.split(".")
    if len(segments) != 3:
        raise EdgeKeyError("not three segments")
    header_b64, payload_b64, sig_b64 = segments
    # Equality against the one header we issue: the algorithm is ours, never the
    # token's, so alg:none / jwk / jku confusion cannot arise.
    if header_b64 != _HEADER_B64:
        raise EdgeKeyError("unexpected header")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url_decode(sig_b64)
    actor = next(
        (name for name, pub in peers.items() if verify(pub, signature, signing_input)), None
    )
    if actor is None:
        raise EdgeKeyError("no peer key verifies the signature")
    return actor, _checked_claims(payload_b64, aud=aud, now=now)
