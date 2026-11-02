"""C1: the edge-key Ed25519 JWT signer/verifier (#592).

The closed-shape verifier is the federation link's authentication, so every
rejection path is exercised: a good token round-trips, and a tampered, expired,
future, over-long, wrong-audience, wrong-key, malformed, or alg-confused token
is refused.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina.gateway import federation_keys
from trentina.gateway.federation_keys import (
    FederationKeyError,
    load_private_key,
    load_public_key,
    sign_primary_jwt,
    verify_primary_jwt,
)

AUD = "lotor-fed"


def _keypair() -> tuple[Ed25519PrivateKey, object]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def _b64(obj: dict[str, object]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
        .rstrip(b"=")
        .decode()
    )


def _craft(priv: Ed25519PrivateKey, header: dict[str, object], claims: dict[str, object]) -> str:
    signing_input = f"{_b64(header)}.{_b64(claims)}"
    sig = base64.urlsafe_b64encode(priv.sign(signing_input.encode())).rstrip(b"=").decode()
    return f"{signing_input}.{sig}"


def test_round_trip() -> None:
    priv, pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud=AUD, now=1000)
    actor, sub = verify_primary_jwt(token, {"breetai": pub}, aud=AUD, now=1005)
    assert actor == "breetai"
    assert sub == "josui"


def test_the_right_peer_is_named_among_several() -> None:
    a_priv, a_pub = _keypair()
    _, b_pub = _keypair()
    token = sign_primary_jwt(a_priv, sub="josui", aud=AUD, now=1000)
    actor, _ = verify_primary_jwt(token, {"other": b_pub, "breetai": a_pub}, aud=AUD, now=1000)
    assert actor == "breetai"


def test_pem_round_trip() -> None:
    priv, _ = _keypair()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    token = sign_primary_jwt(load_private_key(private_pem), sub="josui", aud=AUD, now=1000)
    actor, sub = verify_primary_jwt(token, {"p": load_public_key(public_pem)}, aud=AUD, now=1000)
    assert (actor, sub) == ("p", "josui")


def test_no_peer_key_verifies() -> None:
    priv, _ = _keypair()
    _, other_pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud=AUD, now=1000)
    with pytest.raises(FederationKeyError, match="no peer key"):
        verify_primary_jwt(token, {"other": other_pub}, aud=AUD, now=1000)


def test_tampered_payload_fails() -> None:
    priv, pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud=AUD, now=1000)
    head, _body, sig = token.split(".")
    forged = f"{head}.{_b64({'sub': 'root', 'aud': AUD, 'iat': 1000, 'exp': 1060})}.{sig}"
    with pytest.raises(FederationKeyError, match="no peer key"):
        verify_primary_jwt(forged, {"p": pub}, aud=AUD, now=1000)


def test_wrong_audience() -> None:
    priv, pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud="someone-else", now=1000)
    with pytest.raises(FederationKeyError, match="audience"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


def test_expired() -> None:
    priv, pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud=AUD, now=1000)
    with pytest.raises(FederationKeyError, match="expired"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000 + 60 + 11)


def test_not_yet_valid() -> None:
    priv, pub = _keypair()
    token = sign_primary_jwt(priv, sub="josui", aud=AUD, now=2000)
    with pytest.raises(FederationKeyError, match="not yet valid"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=2000 - 11)


def test_over_long_ttl_is_refused() -> None:
    # A validly-signed token that claims a > 60s life is still refused.
    priv, pub = _keypair()
    token = _craft(
        priv,
        {"alg": "EdDSA", "typ": "JWT"},
        {"sub": "josui", "aud": AUD, "iat": 1000, "exp": 1000 + 3600},
    )
    with pytest.raises(FederationKeyError, match="ttl too long"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


def test_alg_none_is_refused() -> None:
    priv, pub = _keypair()
    token = _craft(
        priv, {"alg": "none", "typ": "JWT"}, {"sub": "josui", "aud": AUD, "iat": 1000, "exp": 1060}
    )
    with pytest.raises(FederationKeyError, match="unexpected header"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


def test_extra_claim_is_refused() -> None:
    priv, pub = _keypair()
    token = _craft(
        priv,
        {"alg": "EdDSA", "typ": "JWT"},
        {"sub": "josui", "aud": AUD, "iat": 1000, "exp": 1060, "role": "admin"},
    )
    with pytest.raises(FederationKeyError, match="claim set"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


def test_bad_sub_shape_is_refused() -> None:
    priv, pub = _keypair()
    token = _craft(
        priv,
        {"alg": "EdDSA", "typ": "JWT"},
        {"sub": "../etc/passwd", "aud": AUD, "iat": 1000, "exp": 1060},
    )
    with pytest.raises(FederationKeyError, match="sub shape"):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "only-one-segment"])
def test_malformed_segment_count(token: str) -> None:
    _, pub = _keypair()
    with pytest.raises(FederationKeyError):
        verify_primary_jwt(token, {"p": pub}, aud=AUD, now=1000)


def test_a_non_ed25519_key_will_not_load() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(FederationKeyError, match="not Ed25519"):
        load_private_key(rsa_pem)


def test_sign_verify_blob_primitives() -> None:
    # D1 reuses these on a non-JWT payload.
    priv, pub = _keypair()
    sig = federation_keys.sign(priv, b"verdict-bytes")
    assert federation_keys.verify(pub, sig, b"verdict-bytes") is True
    assert federation_keys.verify(pub, sig, b"other-bytes") is False


def test_the_loaders_memoize_by_pem() -> None:
    # The signing/verifying hot paths parse a key once, not per call: the same
    # PEM returns the same object (functools.lru_cache). A different key is a
    # different entry.
    priv, _ = _keypair()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    assert load_private_key(private_pem) is load_private_key(private_pem)
    assert load_public_key(public_pem) is load_public_key(public_pem)

    other = Ed25519PrivateKey.generate()
    other_pem = other.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    assert load_private_key(other_pem) is not load_private_key(private_pem)


def test_a_name_cannot_carry_a_trailing_newline() -> None:
    """`^...$` with `re.match` admits a trailing newline, because `$` matches
    before one. Four names were spelled that way: a key name, a profile name,
    a backend name and a federation `sub`.

    A `sub` is the audited actor and part of a paging owner's identity, and a
    key name becomes a filename under `<data>/keys/`, so "name" and "name\\n"
    reading as the same shape is a way to write two records that look like one
    in anything that renders them. `\\Z` matches only at the end.
    """
    from trentina.gateway.federation_keys import _SUB_RE
    from trentina.gateway.key_store import KEY_NAME_RE
    from trentina.gateway.profile import BACKEND_NAME_RE, PROFILE_NAME_RE

    for pattern in (_SUB_RE, KEY_NAME_RE, PROFILE_NAME_RE, BACKEND_NAME_RE):
        assert pattern.match("agent1"), pattern.pattern
        assert not pattern.match("agent1\n"), pattern.pattern
        assert not pattern.match("agent1\nagent2"), pattern.pattern
