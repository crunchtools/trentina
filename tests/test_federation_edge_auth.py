"""C1: a federated link authenticates with an edge JWT, no shared bearer (#592).

End to end on the two-gateway harness: the downstream signs a per-edge JWT, the
upstream (a federation ingress with the peer's public key and NO static bearer)
verifies it, and a tool call crosses the link. A wrong key is refused.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from tests.federation_harness import INTERNAL_KEY, UPSTREAM_PROFILE, federated_pair
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.tools.reload import _hold_perimeter_fields

pytestmark = pytest.mark.asyncio


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


def _upstream(public_pem: str) -> Profile:
    # A federation ingress: peers only, NO static bearer (peers-only authenticates).
    return Profile(
        name=UPSTREAM_PROFILE,
        federation=FederationConfig(peers={"breetai": FederationPeer(public_key=public_pem)}),
        backends={INTERNAL_KEY: Backend(url="internal://web")},
    )


def _downstream_factory(private_pem: str):
    def down(up_port: int) -> Profile:
        backend = Backend(
            url=f"http://127.0.0.1:{up_port}/{UPSTREAM_PROFILE}/mcp",
            federated=FederatedConfig(edge_key_env="BREETAI_EDGE_KEY"),
        )
        # The loader would resolve edge_key_env -> edge_key; set it directly here.
        assert backend.federated is not None
        backend.federated.edge_key = SecretStr(private_pem)
        profile = Profile(
            name="downstream", auth=AuthConfig(bearer_token_env="D"), backends={"fed": backend}
        )
        profile.auth.bearer_token = SecretStr("down-token")
        return profile

    return down


async def test_a_federated_call_authenticates_with_an_edge_jwt() -> None:
    private_pem, public_pem = _keypair()
    async with (
        federated_pair(
            upstream=_upstream(public_pem), downstream=_downstream_factory(private_pem)
        ) as fed,
        fed.downstream_client() as client,
    ):
        names = {t["name"] for t in await client.list_tools()}
        assert any(n.endswith("echo") for n in names), names
        echo = next(t["name"] for t in (await client.list_tools()) if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "signed-hello"})
    # The whole round trip was authenticated by the edge JWT; the upstream holds
    # no shared bearer for the downstream.
    assert "echo:signed-hello" in json.dumps(result), result


async def test_a_wrong_edge_key_is_refused() -> None:
    # The downstream signs with a key whose public half the upstream does not trust.
    _, trusted_pub = _keypair()
    wrong_priv, _ = _keypair()
    async with (
        federated_pair(
            upstream=_upstream(trusted_pub), downstream=_downstream_factory(wrong_priv)
        ) as fed,
        fed.downstream_client() as client,
    ):
        names = {t["name"] for t in await client.list_tools()}
    # The upstream rejected the edge JWT, so the federated backend served nothing.
    assert not any(n.endswith("echo") for n in names), names


# --- reload holds (#592, C1): url and federation.peers are perimeter ---


def _fed_backend(url: str) -> Backend:
    backend = Backend(url=url, federated=FederatedConfig(edge_key_env="K"))
    assert backend.federated is not None
    backend.federated.edge_key = SecretStr("pem")
    return backend


def _down(url: str) -> Profile:
    profile = Profile(
        name="downstream",
        auth=AuthConfig(bearer_token_env="D"),
        backends={"fed": _fed_backend(url)},
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


class TestReloadHolds:
    def test_a_federated_backends_url_is_held(self) -> None:
        # Repointing a federated backend would send the edge key to a new host.
        before = _down("https://lotor.example/gateway/fed/mcp")
        after = _down("https://evil.example/gateway/fed/mcp")
        held = _hold_perimeter_fields(before, after)
        assert "backends.fed.url" in held
        assert after.backends["fed"].url == "https://lotor.example/gateway/fed/mcp"

    def test_the_federation_block_is_held(self) -> None:
        _, pub = _keypair()
        before = Profile(
            name="up",
            federation=None,
            backends={"x": Backend(url="internal://web")},
            auth=AuthConfig(bearer_token_env="A"),
        )
        before.auth.bearer_token = SecretStr("t")
        after = Profile(
            name="up",
            federation=FederationConfig(peers={"breetai": FederationPeer(public_key=pub)}),
            backends={"x": Backend(url="internal://web")},
            auth=AuthConfig(bearer_token_env="A"),
        )
        after.auth.bearer_token = SecretStr("t")
        held = _hold_perimeter_fields(before, after)
        assert "federation" in held
        assert after.federation is None
