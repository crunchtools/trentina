"""C1: a federated link authenticates with an primary JWT, no shared bearer (#592).

End to end on the two-gateway harness: the primary signs a primary JWT, the
secondary (a federation ingress with the peer's public key and NO static bearer)
verifies it, and a tool call crosses the link. A wrong key is refused.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from tests.federation_harness import (
    INTERNAL_KEY,
    SECONDARY_PROFILE,
    federated_pair,
    serving_mcp_backend,
)
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


def _secondary(public_pem: str, demo_port: int) -> Profile:
    # A federation ingress: peers only, NO static bearer (peers-only
    # authenticates). The directed edge (#592, C2): its OFFERED tools are a real
    # REMOTE backend (the demo server, behind the secondary's perimeter), and its
    # internal surface is limited to read_part_tool — never the gateway's own
    # fetch/search/admin tools.
    return Profile(
        name=SECONDARY_PROFILE,
        federation=FederationConfig(peers={"breetai": FederationPeer(public_key=public_pem)}),
        backends={
            "demo": Backend(url=f"http://127.0.0.1:{demo_port}/mcp"),
            INTERNAL_KEY: Backend(url="internal://web", tools_allow=["read_part_tool"]),
        },
    )


def _primary_factory(private_pem: str):
    def down(up_port: int) -> Profile:
        backend = Backend(
            url=f"http://127.0.0.1:{up_port}/{SECONDARY_PROFILE}/mcp",
            federated=FederatedConfig(primary_key_env="BREETAI_EDGE_KEY"),
        )
        # The loader would resolve primary_key_env -> primary_key; set it directly here.
        assert backend.federated is not None
        backend.federated.primary_key = SecretStr(private_pem)
        profile = Profile(
            name="primary", auth=AuthConfig(bearer_token_env="D"), backends={"fed": backend}
        )
        profile.auth.bearer_token = SecretStr("down-token")
        return profile

    return down


async def test_a_federated_call_authenticates_with_an_edge_jwt() -> None:
    private_pem, public_pem = _keypair()
    async with (
        serving_mcp_backend() as demo_port,
        federated_pair(
            secondary=_secondary(public_pem, demo_port), primary=_primary_factory(private_pem)
        ) as fed,
        fed.primary_client() as client,
    ):
        names = {t["name"] for t in await client.list_tools()}
        assert any(n.endswith("echo") for n in names), names
        echo = next(t["name"] for t in (await client.list_tools()) if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "signed-hello"})
    # The whole round trip was authenticated by the primary JWT; the secondary holds
    # no shared bearer for the primary.
    assert "echo:signed-hello" in json.dumps(result), result


async def test_a_wrong_primary_key_is_refused() -> None:
    # The primary signs with a key whose public half the secondary does not trust.
    _, trusted_pub = _keypair()
    wrong_priv, _ = _keypair()
    async with (
        serving_mcp_backend() as demo_port,
        federated_pair(
            secondary=_secondary(trusted_pub, demo_port), primary=_primary_factory(wrong_priv)
        ) as fed,
        fed.primary_client() as client,
    ):
        names = {t["name"] for t in await client.list_tools()}
    # The secondary rejected the primary JWT, so the federated backend served nothing.
    assert not any(n.endswith("echo") for n in names), names


# --- reload holds (#592, C1): url and federation.peers are perimeter ---


def _fed_backend(url: str) -> Backend:
    backend = Backend(url=url, federated=FederatedConfig(primary_key_env="K"))
    assert backend.federated is not None
    backend.federated.primary_key = SecretStr("pem")
    return backend


def _down(url: str) -> Profile:
    profile = Profile(
        name="primary",
        auth=AuthConfig(bearer_token_env="D"),
        backends={"fed": _fed_backend(url)},
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


class TestReloadHolds:
    def test_a_federated_backends_url_is_held(self) -> None:
        # Repointing a federated backend would send the primary key to a new host.
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
            backends={"x": Backend(url="internal://web", tools_allow=["read_part_tool"])},
            auth=AuthConfig(bearer_token_env="A"),
        )
        before.auth.bearer_token = SecretStr("t")
        after = Profile(
            name="up",
            federation=FederationConfig(peers={"breetai": FederationPeer(public_key=pub)}),
            backends={"x": Backend(url="internal://web", tools_allow=["read_part_tool"])},
            auth=AuthConfig(bearer_token_env="A"),
        )
        after.auth.bearer_token = SecretStr("t")
        held = _hold_perimeter_fields(before, after)
        assert "federation" in held
        assert after.federation is None
