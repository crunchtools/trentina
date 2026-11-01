"""D2b: the interim static-bearer federation path is refused (#592).

Mounting another gateway over a shared static bearer was the pre-3.1
arrangement. First-class federation superseded it in 3.1.0, it was deprecated
with removal announced for 3.2.0, and through 4.2.3 it only warned.

It is refused in 5.0.0 because the warning was load-bearing for a promise it
could not keep: docs/federation.md says federation is loop-free by
construction, and `_check_federation_topology` enforces that only for a
`federated:` block. An ingress profile could mount the next gateway's ingress
over a bearer and re-export it — A to B to C — which is the loop the design
says cannot exist.

Refusals name the profile and backend, never the URL (the logging rule, #262).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import _check_interim_federation
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile

GATEWAY_URL = "https://lotor.example/gateway/josui/mcp"


def _profile(backend: Backend) -> Profile:
    return Profile(
        name="breetai",
        auth=AuthConfig(bearer_token_env="B"),
        backends={"lotor": backend},
    )


def test_a_static_bearer_gateway_backend_is_refused() -> None:
    profile = _profile(Backend(url=GATEWAY_URL, tools_allow=["*"]))
    with pytest.raises(ProfileConfigError, match="without a 'federated:' block") as caught:
        _check_interim_federation("breetai", profile)
    # The profile and backend are config and loggable; the URL is not (#262).
    assert "lotor.example" not in str(caught.value)
    assert "breetai" in str(caught.value) and "lotor" in str(caught.value)


def test_a_federated_block_is_fine() -> None:
    profile = _profile(Backend(url=GATEWAY_URL, tools_allow=["*"], federated=FederatedConfig()))
    _check_interim_federation("breetai", profile)


def test_a_plain_mcp_backend_is_fine() -> None:
    # No "gateway" segment: an ordinary MCP server, not a Trentina federation
    # endpoint, must not be mistaken for the interim path.
    _check_interim_federation("breetai", _profile(Backend(url="https://api.example/foo/mcp")))


def test_gateway_elsewhere_in_the_path_is_fine() -> None:
    # "gateway" present but NOT the antepenultimate segment: not the
    # .../gateway/<profile>/mcp shape, so not the interim path (detection is exact).
    _check_interim_federation(
        "breetai", _profile(Backend(url="https://api.example/gateway/a/b/mcp"))
    )


def test_the_re_export_that_made_this_worth_removing() -> None:
    """An ingress mounting the next gateway over a bearer: the A-to-B-to-C the
    topology check never saw, because it only refuses a `federated:` block on
    an ingress."""
    from trentina.gateway.profile import FederationConfig, FederationPeer

    pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    # No `auth`: an ingress is authenticated by `peers` and the model refuses
    # a second way in.
    profile = Profile(
        name="middle",
        federation=FederationConfig(peers={"a": FederationPeer(public_key=pem)}),
        backends={"onward": Backend(url="https://c.example/gateway/fed/mcp", tools_allow=["*"])},
    )
    with pytest.raises(ProfileConfigError, match="re-exports the next gateway"):
        _check_interim_federation("middle", profile)
