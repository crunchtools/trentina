"""D2b close-out: the federation topology is held at load (#592).

One profile is one role (an ingress does not also consume a federated
secondary — that would deadlock two single-flight builds), and a federated
backend must be reached over https (the 60 s primary JWT has no replay nonce).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr, ValidationError

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import (
    _check_federation_audience,
    _check_federation_topology,
    _check_renamed_federation_keys,
)
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    OAuthConfig,
    Profile,
)

HTTPS = "https://lotor.example/gateway/josui/mcp"
HTTP = "http://lotor.example/gateway/josui/mcp"


def _peers() -> dict[str, FederationPeer]:
    """An ingress names at least one peer: `peers` IS what authenticates a
    primary, so a block without one is not an ingress (`profile.py`)."""
    priv = Ed25519PrivateKey.generate()
    pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return {"breetai": FederationPeer(public_key=pem)}


def _profile(*, ingress: bool, federated_url: str | None) -> Profile:
    backends = {}
    if federated_url is not None:
        backends["up"] = Backend(url=federated_url, tools_allow=["*"], federated=FederatedConfig())
    # An ingress carries no `auth`: `peers` is its authentication, and the
    # profile model refuses a second way in. A consumer still needs one.
    return Profile(
        name="breetai",
        auth=None if ingress else AuthConfig(bearer_token_env="B"),
        federation=FederationConfig(peers=_peers()) if ingress else None,
        backends=backends,
    )


def test_an_ingress_that_also_consumes_is_refused() -> None:
    profile = _profile(ingress=True, federated_url=HTTPS)
    with pytest.raises(ProfileConfigError, match="one role"):
        _check_federation_topology("breetai", profile)


def test_an_ingress_alone_is_fine() -> None:
    _check_federation_topology("breetai", _profile(ingress=True, federated_url=None))


def test_a_consumer_alone_over_https_is_fine() -> None:
    _check_federation_topology("breetai", _profile(ingress=False, federated_url=HTTPS))


def test_a_federated_backend_over_http_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRENTINA_FEDERATION_ALLOW_INSECURE", raising=False)
    profile = _profile(ingress=False, federated_url=HTTP)
    with pytest.raises(ProfileConfigError, match="https"):
        _check_federation_topology("breetai", profile)


def test_http_is_allowed_with_the_insecure_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_FEDERATION_ALLOW_INSECURE", "1")
    # Must not raise; the loader warns instead.
    _check_federation_topology("breetai", _profile(ingress=False, federated_url=HTTP))


# --- The 4.0.0 rename (#637): the old field names are refused by name ---


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("edge_key_env", "primary_key_env"),
        ("edge_key_name", "primary_key_name"),
    ],
)
def test_a_pre_4_0_0_backend_key_name_is_refused_with_its_replacement(old: str, new: str) -> None:
    """Scott chose no deprecation shim, so the error IS the migration aid.

    ``extra="forbid"`` already refuses these, but pydantic's own message is
    "Extra inputs are not permitted" against a key that no longer exists —
    true and useless to whoever has to edit the file.
    """
    body = {
        "auth": {"bearer_token_env": "T"},
        "backends": {"lotor": {"url": HTTPS, "federated": {old: "A_KEY"}}},
    }
    with pytest.raises(ProfileConfigError, match=f"{old!r} was renamed to {new!r}"):
        _check_renamed_federation_keys("breetai", body)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("signing_key_env", "secondary_key_env"),
        ("signing_key_name", "secondary_key_name"),
    ],
)
def test_a_pre_4_0_0_ingress_key_name_is_refused_with_its_replacement(old: str, new: str) -> None:
    body = {"auth": {"bearer_token_env": "T"}, "federation": {old: "A_KEY"}}
    with pytest.raises(ProfileConfigError, match=f"{old!r} was renamed to {new!r}"):
        _check_renamed_federation_keys("breetai", body)


def test_the_new_names_pass_the_rename_check() -> None:
    _check_renamed_federation_keys(
        "breetai",
        {
            "backends": {"lotor": {"url": HTTPS, "federated": {"primary_key_env": "A"}}},
            "federation": {"secondary_key_env": "B"},
        },
    )


def test_the_check_does_not_fire_on_an_unrelated_block() -> None:
    """Only the two places the schema ever took these keys are read, so a
    same-named key somewhere else is not a false positive."""
    _check_renamed_federation_keys(
        "breetai", {"backends": {"plain": {"url": HTTPS, "headers": {"edge_key_env": "x"}}}}
    )


class TestOneDefinitionOfAnIngress:
    """ "Is this a federation ingress?" had two answers.

    The auth path and the directed-ingress rule read `federation.peers`; the
    topology check, the refusal mirror and the VSA emit site read
    `federation is not None`. A block carrying only a `secondary_key_name`
    fell in the gap: outside the directed-ingress rule, so it could be
    `role: operator` with unrestricted internal tools, and still signing
    verdict assertions over its responses.
    """

    def test_a_federation_block_without_peers_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must name at least one peer"):
            FederationConfig()

    def test_an_operator_ingress_is_refused(self) -> None:
        """What the gap allowed: an ingress offering the gateway's admin tools."""
        with pytest.raises(ValidationError, match="role must be agent"):
            Profile(
                name="op",
                role="operator",
                auth=AuthConfig(bearer_token_env="B"),
                federation=FederationConfig(peers=_peers()),
                backends={},
            )

    def test_an_ingress_may_not_widen_its_internal_tools(self) -> None:
        with pytest.raises(ValidationError, match="may offer a peer only"):
            Profile(
                name="fed",
                auth=AuthConfig(bearer_token_env="B"),
                federation=FederationConfig(peers=_peers()),
                backends={"web": Backend(url="internal://web", tools_allow=["*"])},
            )

    def test_two_peers_may_not_share_a_key(self) -> None:
        """`verify_primary_jwt` returns the first peer whose key verifies, so a
        shared key made the audited actor a matter of YAML order."""
        peers = _peers()
        shared = next(iter(peers.values())).public_key
        peers["other"] = FederationPeer(public_key=shared)
        with pytest.raises(ValidationError, match="share a public key"):
            FederationConfig(peers=peers)


class TestOnePrimaryKeyPerSecondary:
    """The primary JWT's audience is the ingress PROFILE NAME, and nothing in
    it names which gateway it was minted for. Two federated backends sharing a
    primary key and deriving the same audience therefore mint tokens each
    secondary accepts: secondary B replays one at secondary A inside the
    60-second window and A audits a call the primary never made. No on-path
    position, and HTTPS does not help.
    """

    def _profile(self, urls: dict[str, str], *, keys: dict[str, str]) -> Profile:
        profile = Profile(
            name="breetai",
            auth=AuthConfig(bearer_token_env="B"),
            backends={
                name: Backend(url=url, tools_allow=["*"], federated=FederatedConfig())
                for name, url in urls.items()
            },
        )
        for name, key in keys.items():
            federated = profile.backends[name].federated
            assert federated is not None
            federated.primary_key = SecretStr(key)
        return profile

    def test_the_pair_split_across_profiles_is_refused(self) -> None:
        """Two profiles can each hold one half, and a per-profile pass sees
        one backend and accepts it."""
        prod = self._profile({"prod": "https://prod.example/gateway/fed/mcp"}, keys={"prod": "K"})
        staging = Profile(
            name="other",
            auth=AuthConfig(bearer_token_env="B"),
            backends={
                "staging": Backend(
                    url="https://staging.example/gateway/fed/mcp",
                    tools_allow=["*"],
                    federated=FederatedConfig(),
                )
            },
        )
        federated = staging.backends["staging"].federated
        assert federated is not None
        federated.primary_key = SecretStr("K")
        with pytest.raises(ProfileConfigError, match="could replay the other's token"):
            _check_federation_audience({"breetai": prod, "other": staging})

    def test_one_host_with_two_path_prefixes_is_refused(self) -> None:
        """Comparing origins would read two independent gateways behind one
        host as the same gateway."""
        profile = self._profile(
            {
                "a": "https://shared.example/one/gateway/fed/mcp",
                "b": "https://shared.example/two/gateway/fed/mcp",
            },
            keys={"a": "K", "b": "K"},
        )
        with pytest.raises(ProfileConfigError, match="could replay the other's token"):
            _check_federation_audience({"breetai": profile})

    def test_the_same_key_to_two_gateways_with_one_audience_is_refused(self) -> None:
        profile = self._profile(
            {
                "prod": "https://prod.example/gateway/fed/mcp",
                "staging": "https://staging.example/gateway/fed/mcp",
            },
            keys={"prod": "K", "staging": "K"},
        )
        with pytest.raises(ProfileConfigError, match="could replay the other's token"):
            _check_federation_audience({"breetai": profile})

    def test_a_key_each_is_fine(self) -> None:
        """Different keys already fail at the secondary: A holds only its own
        peer key, so B's token does not verify."""
        profile = self._profile(
            {
                "prod": "https://prod.example/gateway/fed/mcp",
                "staging": "https://staging.example/gateway/fed/mcp",
            },
            keys={"prod": "K1", "staging": "K2"},
        )
        _check_federation_audience({"breetai": profile})

    def test_different_ingress_names_are_fine(self) -> None:
        """A distinct audience is the other way out: the token names the
        profile it was minted for and the wrong secondary refuses it."""
        profile = self._profile(
            {
                "prod": "https://prod.example/gateway/fed-prod/mcp",
                "staging": "https://staging.example/gateway/fed-staging/mcp",
            },
            keys={"prod": "K", "staging": "K"},
        )
        _check_federation_audience({"breetai": profile})

    def test_two_backends_at_one_gateway_are_fine(self) -> None:
        """The same gateway twice is not a replay: it is the audience it is."""
        profile = self._profile(
            {
                "a": "https://prod.example/gateway/fed/mcp",
                "b": "https://prod.example/gateway/fed/mcp",
            },
            keys={"a": "K", "b": "K"},
        )
        _check_federation_audience({"breetai": profile})


class TestOneSecondarySpelledTwoWays:
    """One secondary written two ways is one secondary.

    Comparing raw URLs refused a correct configuration: `:443`, a trailing
    slash or a capitalised host read as two gateways sharing an audience, and
    the message says "pointing at different URLs" without showing either.
    """

    def _profile(self, urls: dict[str, str]) -> Profile:
        profile = Profile(
            name="breetai",
            auth=AuthConfig(bearer_token_env="B"),
            backends={
                name: Backend(url=url, tools_allow=["*"], federated=FederatedConfig())
                for name, url in urls.items()
            },
        )
        for backend in profile.backends.values():
            assert backend.federated is not None
            backend.federated.primary_key = SecretStr("K")
        return profile

    @pytest.mark.parametrize(
        "other",
        [
            pytest.param("https://prod.example:443/gateway/fed/mcp", id="default-port"),
            pytest.param("https://PROD.example/gateway/fed/mcp", id="host-case"),
        ],
    )
    def test_the_same_gateway_spelled_differently_is_fine(self, other: str) -> None:
        profile = self._profile({"a": "https://prod.example/gateway/fed/mcp", "b": other})
        _check_federation_audience({"breetai": profile})

    def test_two_prefixes_on_one_host_are_still_two_gateways(self) -> None:
        """The path is kept: reading those as one endpoint is the mistake in
        the other direction."""
        profile = self._profile(
            {
                "a": "https://shared.example/one/gateway/fed/mcp",
                "b": "https://shared.example/two/gateway/fed/mcp",
            }
        )
        with pytest.raises(ProfileConfigError, match="could replay the other's token"):
            _check_federation_audience({"breetai": profile})


def test_an_ingress_may_not_also_take_a_static_bearer() -> None:
    """`peers` IS a federation ingress's authentication, and `app.py` tries a
    static bearer FIRST — so an ingress carrying `auth` as well would admit a
    caller through that instead, with no peer and no `sub`.

    Everything downstream then reads a null caller: the audit records no actor,
    docs/federation.md's claim that every federated call names its peer is
    false for that profile, and since a held part is owned by
    `(profile, peer, sub)` every such caller shares ONE paging owner — the
    isolation hole this release closed, reopened through the front door.
    """
    with pytest.raises(ValidationError, match="auth does not apply"):
        Profile(
            name="breetai",
            auth=AuthConfig(bearer_token_env="B"),
            federation=FederationConfig(peers=_peers()),
            backends={},
        )


def test_an_ingress_may_not_take_oauth_either() -> None:
    with pytest.raises(ValidationError, match="oauth does not apply"):
        Profile(
            name="breetai",
            oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
            federation=FederationConfig(peers=_peers()),
            backends={},
        )
