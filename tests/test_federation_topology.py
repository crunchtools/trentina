"""D2b close-out: the federation topology is held at load (#592).

One profile is one role (an ingress does not also consume a federated
secondary — that would deadlock two single-flight builds), and a federated
backend must be reached over https (the 60 s primary JWT has no replay nonce).
"""

from __future__ import annotations

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import (
    _check_federation_topology,
    _check_renamed_federation_keys,
)
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederatedConfig,
    FederationConfig,
    Profile,
)

HTTPS = "https://lotor.example/gateway/josui/mcp"
HTTP = "http://lotor.example/gateway/josui/mcp"


def _profile(*, ingress: bool, federated_url: str | None) -> Profile:
    backends = {}
    if federated_url is not None:
        backends["up"] = Backend(url=federated_url, tools_allow=["*"], federated=FederatedConfig())
    return Profile(
        name="breetai",
        auth=AuthConfig(bearer_token_env="B"),
        federation=FederationConfig() if ingress else None,
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
def test_a_pre_4_0_0_backend_key_name_is_refused_with_its_replacement(
    old: str, new: str
) -> None:
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
def test_a_pre_4_0_0_ingress_key_name_is_refused_with_its_replacement(
    old: str, new: str
) -> None:
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
