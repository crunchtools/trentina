"""`trentina/attest` and `federation_trust` (#640): a pin filled in from the link.

Two real gateways on loopback (``tests/federation_harness.py``): the primary
asks the secondary's derived ingress to attest, over the same signed link a
tool call takes, and checks the answer against a key the test holds. The pure
checks are below them, and the tool's staging last.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from trentina.gateway import attestation, vsa
from trentina.gateway.backend import attest_backend
from trentina.gateway.federation_link import ingress_name
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.gateway.service import judge_stamp
from trentina.perimeter_db import perimeter_stamp
from trentina.transports.mcp import route_jsonrpc

from .federation_harness import federated_pair, serving_mcp_backend

SHARED = "peergw"
PEER = "mypeer"
NONCE = "ab" * 32


def keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
    )


def shared_profile(peer_public: str, secondary_private: str | None, port: int) -> Profile:
    """A profile that shares itself, signing with ``secondary_private`` or not at all.

    ``port`` is the remote backend it offers: an ingress offering nothing is
    refused, and attesting is no reason to offer anything else."""
    profile = Profile(
        name=SHARED,
        auth=AuthConfig(bearer_token_env="SHARED_TOKEN"),
        federation=FederationConfig(
            peers={PEER: FederationPeer(public_key=peer_public)},
            secondary_key=SecretStr(secondary_private) if secondary_private else None,
        ),
        backends={"wiki": Backend(url=f"http://127.0.0.1:{port}/mcp")},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("shared-token")
    return profile


class Primary:
    """Builds the primary for the harness and keeps it, so a test can probe
    the link the way `federation_trust` does."""

    def __init__(self, private_pem: str) -> None:
        self.private_pem = private_pem
        self.profile: Profile | None = None

    def __call__(self, secondary_port: int) -> Profile:
        backend = Backend(
            url=f"http://127.0.0.1:{secondary_port}/{ingress_name(SHARED)}/mcp",
            federated=FederatedConfig(primary_key_env="PEER_KEY"),
        )
        assert backend.federated is not None
        backend.federated.primary_key = SecretStr(self.private_pem)
        profile = Profile(
            name=PEER,
            auth=AuthConfig(bearer_token_env="PEER_TOKEN"),
            backends={SHARED: backend},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("peer-token")
        self.profile = profile
        return profile

    async def attest(self, nonce: str = NONCE) -> Any:
        assert self.profile is not None
        return await attest_backend(SHARED, self.profile.backends[SHARED], self.profile, nonce)


async def _probe(*, signing: bool, admitted: bool = True) -> tuple[Any, str | None]:
    """Stand a pair up, attest once; the answer and the secondary's public key.

    ``admitted=False`` pins some other key for the peer, so the secondary
    refuses the primary's JWT."""
    primary_private, primary_public = keypair()
    if not admitted:
        primary_public = keypair()[1]
    secondary_private, secondary_public = keypair()
    primary = Primary(primary_private)
    async with serving_mcp_backend() as port:
        secondary = shared_profile(primary_public, secondary_private if signing else None, port)
        async with federated_pair(secondary=secondary, primary=primary):
            attested = await primary.attest()
    return attested, secondary_public if signing else None


class TestOverTheLink:
    async def test_a_signing_ingress_attests_and_it_verifies(self) -> None:
        attested, public = await _probe(signing=True)
        assert attested.withheld is None
        assert attested.server_version  # the peer's serverInfo, for the page
        assert public is not None
        assertion, reason = attestation.check_attestation(
            attested.envelope,
            public_key=public,
            nonce=NONCE,
            verifier=ingress_name(SHARED),
            now=attested.envelope["assertion"]["ts"],
        )
        assert reason == "verified"
        assert assertion is not None
        # What the link signs on every response, so the pin will match them.
        assert assertion["perimeter_stamp"] == perimeter_stamp()

    async def test_an_ingress_with_nothing_to_sign_answers_as_an_older_gateway(self) -> None:
        """-32601, the same answer a gateway without the method gives."""
        attested, _ = await _probe(signing=False)
        assert attested.withheld == "not_offered"
        assert attested.envelope is None
        assert attested.server_version

    async def test_the_wrong_key_does_not_verify(self) -> None:
        attested, _ = await _probe(signing=True)
        _, someone_else = keypair()
        assertion, reason = attestation.check_attestation(
            attested.envelope,
            public_key=someone_else,
            nonce=NONCE,
            verifier=ingress_name(SHARED),
            now=attested.envelope["assertion"]["ts"],
        )
        assert (assertion, reason) == (None, "bad_signature")

    async def test_a_peer_refusing_our_credential_is_unauthorized(self) -> None:
        """Not unreachable: it answered, and the operator's fix is a key."""
        attested, _ = await _probe(signing=True, admitted=False)
        assert attested.withheld == "unauthorized"
        assert attested.envelope is None

    async def test_an_unreachable_peer_is_withheld_not_raised(self) -> None:
        primary = Primary(keypair()[0])
        primary(1)  # port 1: nothing listens
        attested = await primary.attest()
        assert attested.withheld == "unreachable"


def _ingress(secondary_private: str | None) -> Profile:
    return Profile(
        name=ingress_name(SHARED),
        federation_of=SHARED,
        federation=FederationConfig(
            peers={PEER: FederationPeer(public_key=keypair()[1])},
            secondary_key=SecretStr(secondary_private) if secondary_private else None,
        ),
        backends={"web": Backend(url="internal://web", tools_allow=["read_part_tool"])},
    )


class TestTheMethod:
    async def _call(self, profile: Profile, params: Any) -> dict[str, Any]:
        request = {"jsonrpc": "2.0", "id": 7, "method": "trentina/attest", "params": params}
        return await route_jsonrpc(profile, request)

    async def test_it_signs_the_same_stamp_and_judge_a_response_carries(self) -> None:
        private, public = keypair()
        ingress = _ingress(private)
        answer = await self._call(ingress, {"nonce": NONCE})
        assertion = vsa.verify_assertion(answer["result"], public)
        assert assertion is not None
        assert assertion["perimeter_stamp"] == perimeter_stamp()
        assert assertion["judge"] == judge_stamp(ingress)
        assert assertion["verifier"] == ingress.name
        assert assertion["nonce"] == NONCE

    @pytest.mark.parametrize("nonce", [None, "", "AB" * 32, "ab" * 8, "ab" * 65, 12, ["ab" * 32]])
    async def test_a_nonce_out_of_shape_is_invalid_params(self, nonce: Any) -> None:
        answer = await self._call(_ingress(keypair()[0]), {"nonce": nonce})
        assert answer["error"]["code"] == -32602

    async def test_a_profile_that_is_not_an_ingress_does_not_have_it(self) -> None:
        plain = Profile(
            name="josui",
            auth=AuthConfig(bearer_token_env="JOSUI_TOKEN"),
            backends={"web": Backend(url="internal://web")},
        )
        answer = await self._call(plain, {"nonce": NONCE})
        assert answer["error"]["code"] == -32601


class TestCheckAttestation:
    def _signed(self, private: str, **overrides: Any) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "verifier": "peergw-federation",
            "perimeter_stamp": "stamp-v1",
            "judge": "openrouter/m/pack",
            "nonce": NONCE,
            "ts": 1_000_000,
        }
        fields.update(overrides)
        return vsa.sign_assertion(fields, private)

    def _check(self, envelope: Any, public: str, **kw: Any) -> tuple[Any, str]:
        args: dict[str, Any] = {
            "public_key": public,
            "nonce": NONCE,
            "verifier": "peergw-federation",
            "now": 1_000_000,
        }
        args.update(kw)
        return attestation.check_attestation(envelope, **args)

    def test_verified(self) -> None:
        private, public = keypair()
        assertion, reason = self._check(self._signed(private), public)
        assert reason == "verified"
        assert assertion is not None
        assert assertion["judge"] == "openrouter/m/pack"

    @pytest.mark.parametrize(
        ("overrides", "kw", "reason"),
        [
            ({"nonce": "cd" * 32}, {}, "nonce_mismatch"),
            ({"verifier": "elsewhere-federation"}, {}, "verifier_mismatch"),
            ({}, {"now": 1_000_000 + vsa.MAX_AGE_SECONDS + 1}, "stale"),
            ({"ts": True}, {}, "stale"),
            ({"judge": ""}, {}, "malformed"),
            ({"perimeter_stamp": ["x"]}, {}, "malformed"),
        ],
    )
    def test_each_refusal(self, overrides: dict[str, Any], kw: dict[str, Any], reason: str) -> None:
        private, public = keypair()
        assert self._check(self._signed(private, **overrides), public, **kw) == (None, reason)

    @pytest.mark.parametrize("envelope", [None, {}, "x", {"assertion": {}, "signature": "zz"}])
    def test_garbage_is_a_bad_signature_never_a_raise(self, envelope: Any) -> None:
        assert self._check(envelope, keypair()[1]) == (None, "bad_signature")

    def test_a_response_verdict_is_not_an_attestation(self) -> None:
        """Signed by the right key, but it answers no challenge."""
        private, public = keypair()
        verdict = vsa.sign_assertion(
            vsa.build_assertion(
                verifier="peergw-federation",
                content_sha256="0" * 64,
                verdict={},
                perimeter_stamp="stamp-v1",
                judge="j",
                ts=1_000_000,
            ),
            private,
        )
        assert self._check(verdict, public) == (None, "nonce_mismatch")

    def test_an_attestation_is_not_a_response_verdict(self) -> None:
        """And the other way: `check_trust` cannot be handed one."""
        private, public = keypair()
        assertion, reason = vsa.check_trust(
            self._signed(private),
            public_key=public,
            content_sha256="0" * 64,
            perimeter_stamp="stamp-v1",
            judge="openrouter/m/pack",
            mode="flag",
            now=1_000_000,
        )
        assert (assertion, reason) == (None, "hash_mismatch")


# --- federation_trust: the operator tool --------------------------------------

TRUST_YAML = """\
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
  ag:
    auth:
      bearer_token_env: AG_TOKEN
    backends:
      peergw:
        url: "https://peergw.example/gateway/peergw-federation/mcp"
        headers:
          Authorization: "Bearer static"
        federated: {}
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
"""

PEER_STAMP = "v7:guard-small@abc123:0.5"
PEER_JUDGE = "openrouter/google/gemini-3.5-flash-lite/pack-1"


@pytest.fixture
def trust_gateway(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    from trentina import config as config_mod
    from trentina.gateway import approver, pending
    from trentina.gateway.compress import set_profiles
    from trentina.gateway.loader import load_profiles, register_active_config

    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.setenv("OP_TOKEN", "o" * 20)
    monkeypatch.setenv("AG_TOKEN", "a" * 20)
    monkeypatch.setenv(
        "TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier("correct horse battery staple")
    )
    pending.clear()
    config_mod._config = None
    path = tmp_path / "config" / "profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(TRUST_YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield path
    pending.clear()
    config_mod._config = None


class Peer:
    """Stands in for `attest_backend`: answers the nonce it is sent, as a real
    peer would, signing with ``private`` — or withholds."""

    def __init__(
        self,
        private: str | None,
        *,
        withheld: str | None = None,
        version: str = "6.12.0",
        stamp: str = PEER_STAMP,
    ) -> None:
        self.private, self.withheld, self.version, self.stamp = private, withheld, version, stamp
        self.calls = 0

    async def __call__(self, name: str, backend: Any, profile: Any, nonce: str) -> Any:
        from trentina.gateway.backend import Attested

        self.calls += 1
        if self.withheld is not None or self.private is None:
            return Attested(withheld=self.withheld, server_version=self.version)
        assertion = attestation.build_attestation(
            verifier="peergw-federation",
            perimeter_stamp=self.stamp,
            judge=PEER_JUDGE,
            nonce=nonce,
            ts=int(time.time()),
        )
        return Attested(
            envelope=vsa.sign_assertion(assertion, self.private), server_version=self.version
        )


async def _trust(peer: Peer, monkeypatch: pytest.MonkeyPatch, **kw: Any) -> dict[str, Any]:
    from trentina.gateway.context import profile_context
    from trentina.gateway.loader import get_active_config
    from trentina.tools import config as config_tool
    from trentina.tools import trust

    monkeypatch.setattr(trust, "attest_backend", peer)
    active = get_active_config() or pytest.fail("no active config")
    with profile_context(active.config.profiles[kw.pop("caller", "op")]):
        if "expect_hash" not in kw:
            kw["expect_hash"] = (await config_tool.manage_config("get"))["hash"]
        args = {"profile": "ag", "backend": "peergw", **kw}
        return await trust.federation_trust(**args)


def _staged() -> dict[str, str] | None:
    from trentina.gateway import pending

    return pending.outstanding().get(pending.Kind.FEDERATION_TRUST)


class TestFederationTrust:
    async def test_a_verified_pin_is_staged_and_says_so(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.tools.config import LEARNED_FACT

        before = trust_gateway.read_text(encoding="utf-8")
        private, public = keypair()
        result = await _trust(Peer(private), monkeypatch, public_key=public)
        assert result["staged"] is True
        assert result["verified"] is True
        shown = result["shown_for_approval"]
        # Filled in from the link, not supplied.
        assert shown["Its scanner"] == PEER_STAMP
        assert shown["Its judge"] == PEER_JUDGE
        assert shown[LEARNED_FACT].startswith("Verified at the link")
        assert "6.12.0" in shown[LEARNED_FACT]
        assert _staged() == shown
        # It writes nothing: a person approves, as before.
        assert trust_gateway.read_text(encoding="utf-8") == before

    async def test_the_verified_pin_applies_when_a_person_approves_it(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.gateway import pending

        private, public = keypair()
        await _trust(Peer(private), monkeypatch, public_key=public)
        facts = _staged() or pytest.fail("nothing staged")
        applied = await pending.approve(pending.Kind.FEDERATION_TRUST, pending.digest_of(facts))
        assert applied["applied"] is True
        assert PEER_STAMP in trust_gateway.read_text(encoding="utf-8")

    async def test_an_older_peer_falls_back_to_as_supplied(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.tools.config import LEARNED_FACT

        _, public = keypair()
        result = await _trust(
            Peer(None, withheld="not_offered", version="6.11.0"),
            monkeypatch,
            public_key=public,
            perimeter_stamp="their-stamp",
            judge="their-judge",
        )
        assert result["staged"] is True
        assert result["verified"] is False
        assert result["not_attested"] == "not_offered"
        learned = result["shown_for_approval"][LEARNED_FACT]
        assert learned.startswith("As supplied")
        assert "not_offered" in learned
        assert "6.11.0" in learned
        assert result["shown_for_approval"]["Its scanner"] == "their-stamp"

    async def test_no_attestation_and_nothing_supplied_stages_nothing(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, public = keypair()
        result = await _trust(Peer(None, withheld="unreachable"), monkeypatch, public_key=public)
        assert "did not attest (unreachable)" in result["error"]
        assert _staged() is None

    async def test_an_attestation_that_does_not_verify_never_falls_back(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even with a stamp and judge supplied: this is a wrong key or a
        man in the middle, not an older peer."""
        someone_else, _ = keypair()
        _, public = keypair()
        result = await _trust(
            Peer(someone_else),
            monkeypatch,
            public_key=public,
            perimeter_stamp=PEER_STAMP,
            judge=PEER_JUDGE,
        )
        assert "does not verify (bad_signature)" in result["error"]
        assert result["verified"] is False
        assert _staged() is None

    async def test_a_supplied_stamp_the_peer_did_not_sign_is_refused(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private, public = keypair()
        result = await _trust(
            Peer(private), monkeypatch, public_key=public, perimeter_stamp="what-i-was-told"
        )
        assert "different perimeter_stamp" in result["error"]
        assert result["presented"]["perimeter_stamp"] == PEER_STAMP
        assert _staged() is None

    async def test_matching_supplied_values_are_fine(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private, public = keypair()
        result = await _trust(
            Peer(private),
            monkeypatch,
            public_key=public,
            perimeter_stamp=PEER_STAMP,
            judge=PEER_JUDGE,
        )
        assert result["verified"] is True

    async def test_a_peer_version_that_cannot_be_shown_is_not(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.tools.config import LEARNED_FACT

        private, public = keypair()
        result = await _trust(
            Peer(private, version="<script>approve()</script>"), monkeypatch, public_key=public
        )
        assert "not displayable" in result["shown_for_approval"][LEARNED_FACT]

    async def test_a_peer_stamp_that_cannot_be_shown_stages_nothing(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private, public = keypair()
        result = await _trust(Peer(private, stamp="<b>ok</b>"), monkeypatch, public_key=public)
        assert "error" in result
        assert _staged() is None

    @pytest.mark.parametrize(
        ("kw", "says"),
        [
            ({"profile": "nobody"}, "no written profile"),
            ({"backend": "elsewhere"}, "no written profile"),
            ({"backend": "web"}, "not federated"),
            ({"public_key": "not a key"}, "not an Ed25519"),
        ],
    )
    async def test_refusals_name_nothing_the_caller_sent(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch, kw: dict[str, Any], says: str
    ) -> None:
        peer = Peer(keypair()[0])
        args = {"public_key": keypair()[1], **kw}
        result = await _trust(peer, monkeypatch, **args)
        assert says in result["error"]
        for sent in kw.values():
            assert sent not in result["error"]
        assert peer.calls == 0

    async def test_an_agent_cannot(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        peer = Peer(keypair()[0])
        result = await _trust(
            peer, monkeypatch, caller="ag", public_key=keypair()[1], expect_hash="0" * 64
        )
        assert "error" in result
        assert peer.calls == 0

    async def test_a_stale_hash_stages_nothing(
        self, trust_gateway: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private, public = keypair()
        result = await _trust(Peer(private), monkeypatch, public_key=public, expect_hash="0" * 64)
        assert "changed since that hash" in result["error"]
        assert _staged() is None


@pytest.mark.usefixtures("trust_gateway")
async def test_config_tool_pins_say_they_were_supplied() -> None:
    """The page distinguishes the two, so the old path has to say which it is."""
    from trentina.gateway.context import profile_context
    from trentina.gateway.loader import get_active_config
    from trentina.tools.config import AS_SUPPLIED, LEARNED_FACT, manage_config

    active = get_active_config() or pytest.fail("no active config")
    with profile_context(active.config.profiles["op"]):
        current = (await manage_config("get"))["hash"]
        result = await manage_config(
            "set",
            "profiles.ag.backends.peergw.federated.trust_verdict",
            {"public_key": keypair()[1], "perimeter_stamp": PEER_STAMP, "judge": PEER_JUDGE},
            current,
        )
    assert result["shown_for_approval"][LEARNED_FACT] == AS_SUPPLIED


@pytest.mark.usefixtures("trust_gateway")
async def test_config_tool_refuses_a_stamp_it_cannot_show_rather_than_raising() -> None:
    from trentina.gateway.context import profile_context
    from trentina.gateway.loader import get_active_config
    from trentina.tools.config import manage_config

    active = get_active_config() or pytest.fail("no active config")
    with profile_context(active.config.profiles["op"]):
        current = (await manage_config("get"))["hash"]
        result = await manage_config(
            "set",
            "profiles.ag.backends.peergw.federated.trust_verdict",
            {"public_key": keypair()[1], "perimeter_stamp": "<b>x</b>", "judge": PEER_JUDGE},
            current,
        )
    assert "shown for approval" in result["error"]
    assert _staged() is None


class TestProvenanceOnlyOnTheCheckedPin:
    """`_with_provenance` is what keeps "verified" off anything the peer did
    not sign: no proposal, another kind, or a pin loading did not reproduce."""

    KEYS = ("profiles", "ag", "backends", "peergw", "federated", "trust_verdict")

    def test_the_checked_pin_gets_the_row(self) -> None:
        from trentina.gateway import pending
        from trentina.tools import config as config_tool

        pin = {"public_key": keypair()[1], "perimeter_stamp": PEER_STAMP, "judge": PEER_JUDGE}
        proposal = (pending.Kind.FEDERATION_TRUST, config_tool._trust_facts("ag.peergw", pin))
        _, facts = config_tool._with_provenance(proposal, self.KEYS, pin, "verified!")
        assert facts[config_tool.LEARNED_FACT] == "verified!"

    @pytest.mark.parametrize(
        ("kind", "where", "spoiled"),
        [
            (None, "ag.peergw", {}),
            ("FEDERATION_PEERS", "ag.peergw", {}),
            ("FEDERATION_TRUST", "ag.peergw", {"perimeter_stamp": "something-else"}),
            ("FEDERATION_TRUST", "ag.peergw", {"public_key": keypair()[1]}),
            ("FEDERATION_TRUST", "ag.otherpeer", {}),
        ],
    )
    def test_anything_else_is_refused(
        self, kind: str | None, where: str, spoiled: dict[str, str]
    ) -> None:
        from trentina.gateway import pending
        from trentina.tools import config as config_tool

        pin = {"public_key": keypair()[1], "perimeter_stamp": PEER_STAMP, "judge": PEER_JUDGE}
        staged = config_tool._trust_facts(where, {**pin, **spoiled})
        proposal = None if kind is None else (pending.Kind[kind], staged)
        with pytest.raises(config_tool.ConfigWriteError):
            config_tool._with_provenance(proposal, self.KEYS, pin, "verified!")
