"""D2b close-out: the federation topology is held at load (#592).

One profile is one role (an ingress does not also consume a federated
upstream — that would deadlock two single-flight builds), and a federated
backend must be reached over https (the 60 s edge JWT has no replay nonce).
"""

from __future__ import annotations

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import _check_federation_topology
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
