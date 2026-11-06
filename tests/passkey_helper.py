"""A software authenticator for the passkey tests (#639).

It does what a browser and a platform authenticator do between them: makes a
key pair, writes client data, lays out authenticator data, and signs. Every
field can be overridden so a test can break exactly one thing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from trentina.gateway import webauthn

UP_UV = webauthn.FLAG_UP | webauthn.FLAG_UV
RSA_PUBLIC_EXPONENT = 65537
DEFAULT_RSA_BITS = webauthn.RSA_MIN_BITS


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class Authenticator:
    rp_id: str = "gw.example"
    origin: str = "https://gw.example"
    alg: int = webauthn.ES256
    rsa_bits: int = DEFAULT_RSA_BITS
    counter: int = 0
    credential_id: bytes = field(default_factory=lambda: os.urandom(16))
    key: Any = None

    def __post_init__(self) -> None:
        makers = {
            webauthn.ES256: lambda: ec.generate_private_key(ec.SECP256R1()),
            webauthn.EDDSA: ed25519.Ed25519PrivateKey.generate,
            webauthn.RS256: lambda: rsa.generate_private_key(
                public_exponent=RSA_PUBLIC_EXPONENT, key_size=self.rsa_bits
            ),
        }
        if self.key is None:
            self.key = makers[self.alg]()

    @property
    def spki(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def client_data(self, ceremony: str, challenge: bytes, **over: Any) -> bytes:
        data = {
            "type": "webauthn.create" if ceremony == webauthn.REGISTER else "webauthn.get",
            "challenge": b64url(challenge),
            "origin": self.origin,
            "crossOrigin": False,
        }
        data.update(over)
        return json.dumps(data).encode()

    def auth_data(
        self, *, flags: int, attested: bool, rp_id: str | None = None, count: int | None = None
    ) -> bytes:
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        body = (
            rp_hash + bytes([flags]) + (self.counter if count is None else count).to_bytes(4, "big")
        )
        if attested:
            # AAGUID, credential id, then a stand-in for the COSE key, which the
            # gateway never reads.
            body += bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id
            body += b"\xa5\x01\x02\x03\x26"
        return body

    def sign(self, signed: bytes) -> bytes:
        """Sign as the key's own algorithm does: ECDSA, Ed25519 or PKCS#1 v1.5."""
        signers = {
            webauthn.ES256: lambda: self.key.sign(signed, ec.ECDSA(hashes.SHA256())),
            webauthn.EDDSA: lambda: self.key.sign(signed),
            webauthn.RS256: lambda: self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256()),
        }
        return signers[self.alg]()

    def registration(
        self, challenge: bytes, *, flags: int | None = None, **client: Any
    ) -> dict[str, Any]:
        """The keyword arguments ``webauthn.verify_registration`` takes, minus
        challenge and served_as."""
        return {
            "raw_id": self.credential_id,
            "client_data": self.client_data(webauthn.REGISTER, challenge, **client),
            "auth_data": self.auth_data(
                flags=UP_UV | webauthn.FLAG_AT if flags is None else flags, attested=True
            ),
            "spki": self.spki,
            "alg": self.alg,
        }

    def assertion(
        self, challenge: bytes, *, flags: int = UP_UV, rp_id: str | None = None, **client: Any
    ) -> dict[str, bytes]:
        self.counter += 1 if self.counter else 0
        client_data = self.client_data(webauthn.SIGN_IN, challenge, **client)
        auth_data = self.auth_data(flags=flags, attested=False, rp_id=rp_id)
        signature = self.sign(auth_data + hashlib.sha256(client_data).digest())
        return {"client_data": client_data, "auth_data": auth_data, "signature": signature}

    # The JSON the page's script posts to /approve/webauthn/finish.

    def register_json(self, challenge_b64: str, **extra: Any) -> dict[str, Any]:
        parts = self.registration(unb64url(challenge_b64))
        return {
            "ceremony": "register",
            "challenge": challenge_b64,
            "id": b64url(parts["raw_id"]),
            "clientDataJSON": b64url(parts["client_data"]),
            "authenticatorData": b64url(parts["auth_data"]),
            "publicKey": b64url(parts["spki"]),
            "publicKeyAlgorithm": parts["alg"],
            **extra,
        }

    def sign_in_json(self, challenge_b64: str, **extra: Any) -> dict[str, Any]:
        parts = self.assertion(unb64url(challenge_b64))
        return {
            "ceremony": "signin",
            "challenge": challenge_b64,
            "id": b64url(self.credential_id),
            "clientDataJSON": b64url(parts["client_data"]),
            "authenticatorData": b64url(parts["auth_data"]),
            "signature": b64url(parts["signature"]),
            **extra,
        }
