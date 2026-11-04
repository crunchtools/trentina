"""Checking a passkey (#639): registration and assertion, with no CBOR.

A passkey is the second way to answer ``approver.verify``'s one question. The
gateway holds a public key and nothing else, so reading its data directory
yields nothing that can be presented, and the browser binds every signature to
the origin it was made on, so a phished or replayed one does not verify.

**Why there is no CBOR parser here.** A WebAuthn registration arrives as an
``attestationObject`` — CBOR — carrying a COSE key, and the usual library for
reading it is a dependency on the route that gates root. None of it is needed.
The browser already hands over the key as SubjectPublicKeyInfo
(``getPublicKey()``) and the raw authenticator data (``getAuthenticatorData()``);
attestation is ``none``, so there is no statement to check. What is left to
read is a fixed binary layout and a small JSON document. The fixed layout is
read by offset and stops before the COSE key, and the JSON is length-capped
before it is parsed, so neither can hang or grow — which is why this runs in
process rather than in a child (constitution VII names formats with grammars).

**Why the SPKI is not cross-checked against the COSE key.** That would need the
CBOR parser. The registrant is already authorised by the time the key is read
(an enrolment code, or a fresh approval session), so a browser that lied about
its own key harms only its own enrolment.

**The origin is pinned at registration and compared exactly afterwards.** It is
read from the signed client data, checked against the host the page was served
as, and stored with the credential. An assertion is then held to the stored
string, never to anything derived from the request, because the request's Host
is whatever its sender chose.

Nothing here does I/O or holds state; ``approval_session`` holds the challenges
and ``approver`` the credentials.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

#: COSE algorithm identifiers offered, and the only ones accepted: ES256,
#: EdDSA (Ed25519) and RS256. Every platform authenticator makes one of these.
ES256 = -7
EDDSA = -8
RS256 = -257
ALGORITHMS = (ES256, EDDSA, RS256)

#: Bounds checked before anything else reads the bytes. Authenticator data is
#: 37 bytes plus a credential of at most 1023 and its key; 2 KiB is generous.
MAX_AUTH_DATA = 2048
MAX_SPKI = 1024
MAX_CLIENT_DATA = 4096
MAX_CREDENTIAL_ID = 1023
MAX_SIGNATURE = 1024
RSA_MIN_BITS = 2048
RSA_MAX_BITS = 4096

CHALLENGE_BYTES = 32

FLAG_UP = 0x01  # a person was present
FLAG_UV = 0x04  # and verified (PIN, biometric)
FLAG_AT = 0x40  # attested credential data follows

_RP_HASH = 32
_FLAGS = 32
_COUNT = 33
_FIXED = 37
_AAGUID = 16

#: The two ceremonies, and the ``type`` the browser writes into client data
#: for each. A registration's client data can never pass as an assertion's.
REGISTER = "register"
SIGN_IN = "signin"
_CLIENT_TYPE = {REGISTER: "webauthn.create", SIGN_IN: "webauthn.get"}


class WebAuthnError(Exception):
    """A ceremony that did not verify. The message is a closed reason code,
    never anything the caller sent, so it is safe to log (#262)."""


@dataclass(frozen=True)
class Credential:
    """What registration produced and the gateway keeps: a public key and the
    place it may be used from."""

    credential_id: bytes
    spki: bytes
    alg: int
    rp_id: str
    origin: str
    sign_count: int


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


#: The unpadded base64url alphabet, whole. The stdlib decoder silently DROPS
#: characters outside its alphabet, so it is never handed one.
_B64URL = re.compile(r"\A[A-Za-z0-9_-]+\Z")


def from_b64url(text: object, *, limit: int) -> bytes:
    """Decode a base64url field, refusing anything that is not one or is too
    long. ``limit`` bounds the DECODED size and is checked on the text first."""
    if (
        not isinstance(text, str)
        or not text
        or len(text) > (limit * 4) // 3 + 4
        or not _B64URL.match(text)
    ):
        raise WebAuthnError("malformed")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise WebAuthnError("malformed") from exc
    if len(raw) > limit:
        raise WebAuthnError("malformed")
    return raw


@dataclass(frozen=True)
class _AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None


# TRUST: authenticator data, bytes a browser (or anyone posting to the route) chose
#   untrusted: every byte of `raw`
#   judged-by: length cap first, then fixed offsets only; the credential id's
#     length is bounded and checked against what remains; nothing past it (the
#     COSE key, extensions) is read at all
#   on-failure: fail-closed; WebAuthnError, which the route answers like any
#     other failed sign-in
#   owner: webauthn._auth_data, the only reader of the layout
#   evidence: T1 tests/test_webauthn.py truncation and length cases
def _auth_data(raw: bytes, *, attested: bool) -> _AuthData:
    if not _FIXED <= len(raw) <= MAX_AUTH_DATA:
        raise WebAuthnError("auth_data_size")
    flags = raw[_FLAGS]
    count = int.from_bytes(raw[_COUNT:_FIXED], "big")
    if not attested:
        return _AuthData(raw[:_RP_HASH], flags, count, None)
    if not flags & FLAG_AT:
        raise WebAuthnError("no_credential")
    start = _FIXED + _AAGUID
    if len(raw) < start + 2:
        raise WebAuthnError("auth_data_size")
    length = int.from_bytes(raw[start : start + 2], "big")
    if not 1 <= length <= MAX_CREDENTIAL_ID or len(raw) < start + 2 + length:
        raise WebAuthnError("auth_data_size")
    return _AuthData(raw[:_RP_HASH], flags, count, raw[start + 2 : start + 2 + length])


# TRUST: client data JSON, written by the browser and posted by anyone
#   untrusted: every byte of `raw`
#   judged-by: a length cap before json.loads, then three fields compared to
#     values the gateway chose (type, challenge) or pinned (origin); any other
#     field is ignored, and crossOrigin true is refused
#   on-failure: fail-closed; WebAuthnError with a closed reason
#   owner: webauthn._client_origin
#   evidence: T1 tests/test_webauthn.py client-data cases
def _client_origin(raw: bytes, *, ceremony: str, challenge: bytes) -> str:
    """The origin the browser signed for, once type and challenge match."""
    if len(raw) > MAX_CLIENT_DATA:
        raise WebAuthnError("client_data_size")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebAuthnError("client_data") from exc
    if not isinstance(data, dict):
        raise WebAuthnError("client_data")
    if data.get("type") != _CLIENT_TYPE[ceremony]:
        raise WebAuthnError("ceremony")
    presented = data.get("challenge")
    if not isinstance(presented, str) or not hmac.compare_digest(
        presented.encode("ascii", "replace"), b64url(challenge).encode("ascii")
    ):
        raise WebAuthnError("challenge")
    if data.get("crossOrigin") is True:
        raise WebAuthnError("cross_origin")
    origin = data.get("origin")
    if not isinstance(origin, str) or len(origin) > 300:
        raise WebAuthnError("origin")
    return origin


def pin_origin(origin: str, served_as: str | None) -> tuple[str, str]:
    """``(rp_id, origin)`` for a registration, or refuse.

    The origin must be a bare scheme://host[:port] whose host is the one this
    page was served as. https always; http only for ``localhost``, which
    browsers treat as a secure context and which is how a gateway on the
    same machine is reached.
    """
    if served_as is None:
        raise WebAuthnError("no_host")
    parts = urlsplit(origin)
    try:
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises on a malformed port
    except ValueError as exc:
        raise WebAuthnError("origin") from exc
    if (
        parts.path
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
        or host != served_as
    ):
        raise WebAuthnError("origin")
    if parts.scheme != "https" and not (parts.scheme == "http" and host == "localhost"):
        raise WebAuthnError("origin")
    return host, f"{parts.scheme}://{parts.netloc.lower()}"


def _flags_hold(flags: int, needed: int) -> None:
    if flags & needed != needed:
        raise WebAuthnError("user_not_verified")


def _public_key(spki: bytes, alg: int) -> Any:
    """Load ``spki`` and hold it to ``alg``. Bounded before the library sees it."""
    if alg not in ALGORITHMS:
        raise WebAuthnError("algorithm")
    if not spki or len(spki) > MAX_SPKI:
        raise WebAuthnError("public_key")
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise WebAuthnError("public_key") from exc
    if not _key_fits(key, alg):
        raise WebAuthnError("public_key")
    return key


def _key_fits(key: object, alg: int) -> bool:
    """Whether ``key`` is the kind ``alg`` names: P-256, Ed25519, or RSA of a
    sane size. Anything else the library could load is refused."""
    if alg == ES256:
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
    if alg == EDDSA:
        return isinstance(key, ed25519.Ed25519PublicKey)
    return isinstance(key, rsa.RSAPublicKey) and RSA_MIN_BITS <= key.key_size <= RSA_MAX_BITS


def _verify_signature(key: Any, signature: bytes, signed: bytes) -> None:
    if not signature or len(signature) > MAX_SIGNATURE:
        raise WebAuthnError("signature")
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        else:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError) as exc:
        raise WebAuthnError("signature") from exc


def _rp_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode("ascii")).digest()


# TRUST: a registration: credential id, client data, authenticator data and
#   SubjectPublicKeyInfo, all posted by the browser
#   untrusted: every argument but `challenge` and `served_as`
#   judged-by: the caller has ALREADY authorised the registrant (enrolment code
#     or a fresh approval session) before this runs; then each field is bounded,
#     the origin pinned to the served host, the rpId hash matched, UP+UV+AT
#     required, the credential id matched to the authenticator's, and the key
#     held to an offered algorithm before `cryptography` loads it
#   on-failure: fail-closed; WebAuthnError, nothing stored
#   owner: webauthn.verify_registration
#   evidence: T1 tests/test_webauthn.py TestRegistration
def verify_registration(
    *,
    raw_id: bytes,
    client_data: bytes,
    auth_data: bytes,
    spki: bytes,
    alg: int,
    challenge: bytes,
    served_as: str | None,
) -> Credential:
    """The credential a person just made, once every check holds."""
    origin = _client_origin(client_data, ceremony=REGISTER, challenge=challenge)
    rp_id, origin = pin_origin(origin, served_as)
    parsed = _auth_data(auth_data, attested=True)
    if not hmac.compare_digest(parsed.rp_id_hash, _rp_hash(rp_id)):
        raise WebAuthnError("rp_id")
    _flags_hold(parsed.flags, FLAG_UP | FLAG_UV | FLAG_AT)
    if parsed.credential_id is None or not hmac.compare_digest(parsed.credential_id, raw_id):
        raise WebAuthnError("credential_id")
    _public_key(spki, alg)
    return Credential(raw_id, spki, alg, rp_id, origin, parsed.sign_count)


def verify_assertion(
    credential: Credential,
    *,
    client_data: bytes,
    auth_data: bytes,
    signature: bytes,
    challenge: bytes,
) -> int:
    """The new signature counter, once ``credential`` signed this challenge.

    Everything compared against is what was pinned at registration. A counter
    that has counted before must go up: a stored 0 always passes, because a
    synced passkey never counts, and anything else that does not climb is the
    signal of a cloned authenticator.
    """
    origin = _client_origin(client_data, ceremony=SIGN_IN, challenge=challenge)
    if not hmac.compare_digest(origin.encode("utf-8"), credential.origin.encode("utf-8")):
        raise WebAuthnError("origin")
    parsed = _auth_data(auth_data, attested=False)
    if not hmac.compare_digest(parsed.rp_id_hash, _rp_hash(credential.rp_id)):
        raise WebAuthnError("rp_id")
    _flags_hold(parsed.flags, FLAG_UP | FLAG_UV)
    key = _public_key(credential.spki, credential.alg)
    _verify_signature(key, signature, auth_data + hashlib.sha256(client_data).digest())
    if credential.sign_count != 0 and parsed.sign_count <= credential.sign_count:
        raise WebAuthnError("sign_count")
    return parsed.sign_count
