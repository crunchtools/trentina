"""D1 emission: a federation ingress signs a verdict beside a delivered response (#592).

End to end on the harness: a federation-ingress upstream with a signing key serves
a tool (from a real remote backend, behind its perimeter) and attaches
``_meta._trentina_vsa`` — a signature a downstream that pins the public key and
the perimeter stamp verifies and binds to the exact delivered bytes (D2a trusts
it). Observed by calling the upstream directly: a downstream strips ``_trentina_*``
from a backend response, so the VSA is read off the upstream's own output.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from tests.federation_harness import (
    INTERNAL_KEY,
    UPSTREAM_PROFILE,
    UPSTREAM_TOKEN,
    MCPClient,
    bound_internal_server,
    internal_server,
    serving,
    serving_mcp_backend,
)
from trentina.gateway.app import gateway_app
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.gateway.sessions import SessionRegistry
from trentina.gateway.vsa import VSA_KEY, content_digest, verify_assertion

pytestmark = pytest.mark.asyncio

_PEER_PUB = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PUBLIC KEY-----\n"
)


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


def _ingress(demo_port: int, *, private_pem: str | None) -> Profile:
    # A directed federation ingress that ALSO holds a bearer (C1's opt-in
    # coexistence), so a test client reaches it directly. Its offered tools are a
    # real remote backend; its internal surface is read_part only. With a
    # private key it signs verdicts; without one it emits none.
    federation = FederationConfig(peers={"breetai": FederationPeer(public_key=_PEER_PUB)})
    if private_pem is not None:
        federation.signing_key = SecretStr(private_pem)
    profile = Profile(
        name=UPSTREAM_PROFILE,
        auth=AuthConfig(bearer_token_env="UP"),
        federation=federation,
        backends={
            "demo": Backend(url=f"http://127.0.0.1:{demo_port}/mcp"),
            INTERNAL_KEY: Backend(url="internal://web", tools_allow=["read_part_tool"]),
        },
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr(UPSTREAM_TOKEN)
    return profile


@contextlib.asynccontextmanager
async def _serving_ingress(profile: Profile) -> Any:
    with bound_internal_server(internal_server()):
        app = gateway_app({profile.name: profile}, sessions=SessionRegistry())
        async with serving(app) as port:
            yield port


async def test_a_delivered_response_carries_a_verifiable_signed_verdict() -> None:
    private_pem, public_pem = _keypair()
    async with (
        serving_mcp_backend() as demo_port,
        _serving_ingress(_ingress(demo_port, private_pem=private_pem)) as up_port,
        MCPClient(f"http://127.0.0.1:{up_port}/{UPSTREAM_PROFILE}/mcp", UPSTREAM_TOKEN) as client,
    ):
        echo = next(t["name"] for t in (await client.list_tools()) if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "vouched-hello"})

    envelope = result.get("_meta", {}).get(VSA_KEY)
    assert envelope is not None, result
    assertion = verify_assertion(envelope, public_pem)
    assert assertion is not None  # signed by the ingress's key
    assert assertion["verifier"] == UPSTREAM_PROFILE
    assert assertion["content_sha256"] == content_digest(
        result["content"], result.get("structuredContent"), result["isError"]
    )
    assert assertion["verdict"]["flagged_by"] is None  # a clean echo
    assert assertion["perimeter_stamp"] and isinstance(assertion["ts"], int)
    # A key the ingress did not sign with does not verify.
    _, other_pub = _keypair()
    assert verify_assertion(envelope, other_pub) is None


async def test_no_signing_key_means_no_assertion() -> None:
    # Same ingress shape but without a signing key: nothing is emitted, and a
    # downstream re-judges exactly as today.
    async with (
        serving_mcp_backend() as demo_port,
        _serving_ingress(_ingress(demo_port, private_pem=None)) as up_port,
        MCPClient(f"http://127.0.0.1:{up_port}/{UPSTREAM_PROFILE}/mcp", UPSTREAM_TOKEN) as client,
    ):
        echo = next(t["name"] for t in (await client.list_tools()) if t["name"].endswith("echo"))
        result = await client.call_tool(echo, {"text": "unsigned"})
    assert VSA_KEY not in result.get("_meta", {})
