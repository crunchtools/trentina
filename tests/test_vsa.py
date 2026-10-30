"""D1 foundation: the federated verdict assertion is pure and tamper-evident (#592).

These cover the primitives the emission (rest of D1) and the trust site (D2a)
build on — the delivered-form digest, the sign/verify round trip, and that
every malformed or tampered envelope verifies as None (fail-closed) — without
any gateway state.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina.gateway import vsa


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
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
    return private_pem, public_pem


def _assertion(digest: str = "abc") -> dict[str, Any]:
    return vsa.build_assertion(
        verifier="lotor",
        content_sha256=digest,
        verdict={"clean": True, "mode": "flag"},
        perimeter_stamp="v1:model@rev:0.7",
        ts=1_000_000,
    )


# --- content_digest ---


def test_content_digest_is_deterministic_and_order_independent() -> None:
    blocks = [{"type": "text", "text": "hello"}]
    a = vsa.content_digest(blocks, {"k": 1, "j": 2}, False)
    b = vsa.content_digest(blocks, {"j": 2, "k": 1}, False)
    assert a == b  # RFC 8785 canonicalization sorts keys
    assert len(a) == 64  # sha256 hex


def test_content_digest_changes_with_content_or_error_flag() -> None:
    base = vsa.content_digest([{"type": "text", "text": "x"}], None, False)
    assert base != vsa.content_digest([{"type": "text", "text": "y"}], None, False)
    assert base != vsa.content_digest([{"type": "text", "text": "x"}], None, True)
    assert base != vsa.content_digest([{"type": "text", "text": "x"}], {"s": 1}, False)


def test_content_digest_treats_absent_and_empty_blocks_alike() -> None:
    assert vsa.content_digest(None, None, False) == vsa.content_digest([], None, False)


# --- sign / verify round trip ---


def test_a_signed_assertion_verifies_with_the_matching_public_key() -> None:
    priv, pub = _keypair()
    envelope = vsa.sign_assertion(_assertion(), priv)
    assert envelope["assertion"] == _assertion()
    assert vsa.verify_assertion(envelope, pub) == _assertion()


def test_a_wrong_public_key_does_not_verify() -> None:
    priv, _ = _keypair()
    _, other_pub = _keypair()
    assert vsa.verify_assertion(vsa.sign_assertion(_assertion(), priv), other_pub) is None


def test_a_tampered_assertion_does_not_verify() -> None:
    priv, pub = _keypair()
    envelope = vsa.sign_assertion(_assertion(), priv)
    envelope["assertion"]["content_sha256"] = "tampered"  # the whole point of binding
    assert vsa.verify_assertion(envelope, pub) is None


# --- verify_assertion fails closed on anything malformed ---


def test_verify_is_none_for_malformed_envelopes() -> None:
    _, pub = _keypair()
    for bad in [None, {}, "nope", {"assertion": "x", "signature": "aa"},
                {"assertion": {}, "signature": 5}, {"assertion": {}, "signature": "zz-not-hex"}]:
        assert vsa.verify_assertion(bad, pub) is None


def test_verify_is_none_for_a_bad_public_key() -> None:
    priv, _ = _keypair()
    assert vsa.verify_assertion(vsa.sign_assertion(_assertion(), priv), "not a pem") is None
