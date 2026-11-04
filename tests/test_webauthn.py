"""The passkey ceremony, checked with no CBOR and no new dependency (#639).

Each test breaks one thing a real attacker controls and expects the closed
reason that names it; the ones that pass use all three offered algorithms.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

from tests.passkey_helper import UP_UV, Authenticator
from trentina.gateway import webauthn
from trentina.gateway.webauthn import WebAuthnError

CHALLENGE = os.urandom(32)
HOST = "gw.example"


def _register(
    auth: Authenticator, challenge: bytes = CHALLENGE, **over: Any
) -> webauthn.Credential:
    served = over.pop("served_as", HOST)
    parts = {**auth.registration(challenge), **over}
    return webauthn.verify_registration(**parts, challenge=challenge, served_as=served)


def _reason(fn: Any) -> str:
    with pytest.raises(WebAuthnError) as caught:
        fn()
    return str(caught.value)


@pytest.mark.parametrize("alg", webauthn.ALGORITHMS)
def test_a_passkey_registers_and_signs_in(alg: int) -> None:
    auth = Authenticator(alg=alg)
    credential = _register(auth)
    assert credential.rp_id == HOST
    assert credential.origin == "https://gw.example"
    sign_in = os.urandom(32)
    assert webauthn.verify_assertion(credential, **auth.assertion(sign_in), challenge=sign_in) == 0


class TestRegistration:
    def test_the_challenge_must_be_the_one_issued(self) -> None:
        auth = Authenticator()
        parts = auth.registration(os.urandom(32))
        assert (
            _reason(
                lambda: webauthn.verify_registration(**parts, challenge=CHALLENGE, served_as=HOST)
            )
            == "challenge"
        )

    def test_sign_in_client_data_cannot_register(self) -> None:
        auth = Authenticator()
        bad = auth.client_data(webauthn.REGISTER, CHALLENGE, type="webauthn.get")
        assert _reason(lambda: _register(auth, client_data=bad)) == "ceremony"

    def test_the_origin_must_be_the_host_the_page_was_served_as(self) -> None:
        auth = Authenticator(origin="https://evil.example", rp_id="evil.example")
        assert _reason(lambda: _register(auth)) == "origin"

    def test_no_host_means_no_registration(self) -> None:
        assert _reason(lambda: _register(Authenticator(), served_as=None)) == "no_host"

    @pytest.mark.parametrize(
        "origin",
        [
            "http://gw.example",
            "https://gw.example/path",
            "https://user@gw.example",
            "https://gw.example?x=1",
            "https://gw.example:notaport",
            "ftp://gw.example",
        ],
    )
    def test_only_a_bare_https_origin_pins(self, origin: str) -> None:
        assert _reason(lambda: _register(Authenticator(origin=origin))) == "origin"

    def test_plain_http_is_only_for_localhost(self) -> None:
        auth = Authenticator(rp_id="localhost", origin="http://localhost:8020")
        credential = _register(auth, served_as="localhost")
        assert credential.origin == "http://localhost:8020"

    def test_a_non_default_port_is_kept_in_the_pin(self) -> None:
        auth = Authenticator(origin="https://gw.example:8443")
        assert _register(auth).origin == "https://gw.example:8443"

    def test_cross_origin_is_refused(self) -> None:
        auth = Authenticator()
        bad = auth.client_data(webauthn.REGISTER, CHALLENGE, crossOrigin=True)
        assert _reason(lambda: _register(auth, client_data=bad)) == "cross_origin"

    def test_the_rp_id_hash_must_match(self) -> None:
        auth = Authenticator()
        bad = auth.auth_data(flags=UP_UV | webauthn.FLAG_AT, attested=True, rp_id="other.example")
        assert _reason(lambda: _register(auth, auth_data=bad)) == "rp_id"

    @pytest.mark.parametrize(
        "flags", [webauthn.FLAG_UP | webauthn.FLAG_AT, webauthn.FLAG_UV | webauthn.FLAG_AT]
    )
    def test_presence_and_verification_are_both_required(self, flags: int) -> None:
        auth = Authenticator()
        bad = auth.auth_data(flags=flags, attested=True)
        assert _reason(lambda: _register(auth, auth_data=bad)) == "user_not_verified"

    def test_no_attested_credential_is_refused(self) -> None:
        auth = Authenticator()
        bad = auth.auth_data(flags=UP_UV, attested=True)
        assert _reason(lambda: _register(auth, auth_data=bad)) == "no_credential"

    def test_the_credential_id_must_be_the_authenticators(self) -> None:
        assert _reason(lambda: _register(Authenticator(), raw_id=os.urandom(16))) == "credential_id"

    @pytest.mark.parametrize("cut", [10, 37, 54, 60])
    def test_truncated_authenticator_data_is_refused(self, cut: int) -> None:
        auth = Authenticator()
        whole = auth.auth_data(flags=UP_UV | webauthn.FLAG_AT, attested=True)
        assert _reason(lambda: _register(auth, auth_data=whole[:cut])) == "auth_data_size"

    def test_oversized_authenticator_data_is_refused_before_reading(self) -> None:
        auth = Authenticator()
        huge = auth.auth_data(flags=UP_UV | webauthn.FLAG_AT, attested=True) + bytes(4096)
        assert _reason(lambda: _register(auth, auth_data=huge)) == "auth_data_size"

    def test_oversized_client_data_is_refused_before_parsing(self) -> None:
        auth = Authenticator()
        assert _reason(lambda: _register(auth, client_data=b"{" * 5000)) == "client_data_size"

    @pytest.mark.parametrize("raw", [b"not json", b"[]", b'"x"', b"\xff\xfe"])
    def test_client_data_that_is_not_an_object_is_refused(self, raw: bytes) -> None:
        assert _reason(lambda: _register(Authenticator(), client_data=raw)) == "client_data"

    def test_a_key_that_is_not_the_named_algorithm_is_refused(self) -> None:
        auth = Authenticator(alg=webauthn.ES256)
        assert _reason(lambda: _register(auth, alg=webauthn.EDDSA)) == "public_key"

    def test_an_unoffered_algorithm_is_refused(self) -> None:
        assert _reason(lambda: _register(Authenticator(), alg=-36)) == "algorithm"

    def test_a_p384_key_is_not_es256(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        auth = Authenticator(key=ec.generate_private_key(ec.SECP384R1()))
        assert _reason(lambda: _register(auth)) == "public_key"

    def test_a_small_rsa_key_is_refused(self) -> None:
        auth = Authenticator(alg=webauthn.RS256, rsa_bits=1024)
        assert _reason(lambda: _register(auth)) == "public_key"

    @pytest.mark.parametrize("spki", [b"", b"\x30\x03garbage", bytes(2000)])
    def test_a_malformed_or_huge_key_is_refused(self, spki: bytes) -> None:
        assert _reason(lambda: _register(Authenticator(), spki=spki)) == "public_key"


@pytest.fixture
def enrolled() -> tuple[Authenticator, webauthn.Credential]:
    auth = Authenticator()
    return auth, _register(auth)


def _assert(credential: webauthn.Credential, parts: dict[str, bytes], challenge: bytes) -> int:
    return webauthn.verify_assertion(credential, **parts, challenge=challenge)


class TestAssertion:
    def test_another_challenge_is_refused(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(os.urandom(32))
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "challenge"

    def test_registration_client_data_cannot_sign_in(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE, type="webauthn.create")
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "ceremony"

    def test_the_origin_is_held_to_the_pin_not_the_request(self, enrolled: Any) -> None:
        """A phishing page on another origin gets a signature for ITS origin."""
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE, origin="https://gw.example.evil.test")
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "origin"

    def test_a_port_change_is_another_origin(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE, origin="https://gw.example:8443")
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "origin"

    def test_the_rp_id_hash_is_held_to_the_pin(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE, rp_id="other.example")
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "rp_id"

    def test_an_unverified_user_is_refused(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE, flags=webauthn.FLAG_UP)
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "user_not_verified"

    def test_a_signature_from_another_key_is_refused(self, enrolled: Any) -> None:
        _, credential = enrolled
        impostor = Authenticator()
        parts = impostor.assertion(CHALLENGE)
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "signature"

    def test_tampered_client_data_breaks_the_signature(self, enrolled: Any) -> None:
        auth, credential = enrolled
        parts = auth.assertion(CHALLENGE)
        data = json.loads(parts["client_data"])
        data["extra"] = "x"
        parts["client_data"] = json.dumps(data).encode()
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "signature"

    @pytest.mark.parametrize("signature", [b"", bytes(2000)])
    def test_an_empty_or_huge_signature_is_refused(self, enrolled: Any, signature: bytes) -> None:
        auth, credential = enrolled
        parts = {**auth.assertion(CHALLENGE), "signature": signature}
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "signature"


class TestTheCounter:
    def _counting(self, start: int) -> tuple[Authenticator, webauthn.Credential]:
        auth = Authenticator(counter=start)
        return auth, _register(auth)

    def test_a_synced_passkey_never_counts_and_always_passes(self, enrolled: Any) -> None:
        auth, credential = enrolled
        for _ in range(3):
            challenge = os.urandom(32)
            assert _assert(credential, auth.assertion(challenge), challenge) == 0

    def test_a_counting_key_must_climb(self) -> None:
        auth, credential = self._counting(5)
        challenge = os.urandom(32)
        assert _assert(credential, auth.assertion(challenge), challenge) == 6

    def test_a_counter_that_goes_back_is_a_clone(self) -> None:
        auth, credential = self._counting(5)
        auth.counter = 3
        parts = auth.assertion(CHALLENGE)
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "sign_count"

    def test_a_counter_that_falls_to_zero_is_a_clone_too(self) -> None:
        """'Both nonzero' would let a key that counted to 5 present 0 and pass."""
        auth, credential = self._counting(5)
        auth.counter = 0
        parts = auth.assertion(CHALLENGE)
        assert _reason(lambda: _assert(credential, parts, CHALLENGE)) == "sign_count"


class TestBase64Fields:
    @pytest.mark.parametrize("value", [None, 5, "", "!!!", "a" * 5000])
    def test_a_field_that_is_not_bounded_base64url_is_refused(self, value: object) -> None:
        with pytest.raises(WebAuthnError):
            webauthn.from_b64url(value, limit=1024)

    def test_round_trip(self) -> None:
        raw = os.urandom(33)
        assert webauthn.from_b64url(webauthn.b64url(raw), limit=64) == raw


class TestHostileClientData:
    def test_nested_client_data_is_refused_not_raised(self) -> None:
        nested = b"[" * 2000 + b"]" * 2000
        assert _reason(lambda: _register(Authenticator(), client_data=nested)) == "client_data"

    def test_an_origin_that_cannot_be_parsed_is_refused_not_raised(self) -> None:
        assert _reason(lambda: _register(Authenticator(origin="https://["))) == "origin"
