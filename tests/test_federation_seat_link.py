"""A seat shares itself, over the wire, between two real gateways (#592, 5.0.0).

`test_federation_link.py` proves the derivation as a function and
`test_federation_grants.py` proves a link spends its seat's grant. Neither of
them puts bytes on a socket, and the claim this release makes is an end-to-end
one: write ONE `federation` block on a seat and a peer gateway serves that
seat's tools. This is that claim over the wire — two real gateways on loopback,
a real primary JWT, a real remote MCP backend behind the secondary's perimeter,
and a tool call that comes back with its answer.

It is deliberately ONE test, and it is the only test in the suite that stands a
gateway pair up in front of a real remote MCP backend. The narrower properties
— that the seat's own native surface does not cross, that a consumed federated
backend is not re-exported, that several peers share one seat, that a backend
added to the seat needs no second edit — are each covered at the loader and
model level in `test_federation_link.py`. Asserting them over the wire as well
needs several pairs in one process, and a defect in the in-process MCP server
stack (#657) makes a later pair's `tools/list` fail. Those tests are written
and wait on that: a test that passes only when pytest-xdist happens to give it
a fresh worker is worse than no test, because it reports coverage it does not
have.

The assertion is about what the PEER is served, which is the only view that
matters: a derivation that is right in the registry and wrong on the wire is
still wrong.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from tests.federation_harness import federated_pair, serving_mcp_backend
from trentina.gateway.federation_link import ingress_name
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    Profile,
)

pytestmark = pytest.mark.asyncio

SEAT = "josui"
PEER = "breetai"


def wiki_tools() -> list:
    """The seat's remote backend, named so no assertion can confuse its tools
    with the gateway's own internal surface."""

    def wiki_read(page: str) -> str:
        """Read a wiki page."""
        return f"wiki:{page}"

    return [wiki_read]


def gateway_surface() -> list:
    """What `internal://` serves — the gateway's whole native surface, admin
    tools included. The derived ingress gets a FRESH internal backend allowing
    `read_part_tool` alone rather than a filtered copy of the seat's, and these
    names are how the test can tell the two apart on the wire.
    """

    def read_part_tool(handle: str, part: int) -> str:
        """Deliver one part of a held response."""
        return f"part {part} of {handle}"

    def config(action: str) -> str:
        """Read and write profiles.yaml. Operator only, and never a peer's."""
        return action

    def reload_profiles() -> str:
        """Re-read profiles.yaml and apply it."""
        return "reloaded"

    return [read_part_tool, config, reload_profiles]


def peer_gateway(private_pem: str):
    """A primary that mounts the ingress DERIVED from the seat.

    The URL names `<seat>-federation` through `ingress_name`, the same function
    the loader derives with — nothing wrote that profile. The primary JWT is
    audience-pinned to that name, so getting it wrong fails to authenticate
    rather than 404ing, which is why the test asserts on the tools served and
    on a call's answer rather than on a status code.
    """

    def build(secondary_port: int) -> Profile:
        backend = Backend(
            url=f"http://127.0.0.1:{secondary_port}/{ingress_name(SEAT)}/mcp",
            federated=FederatedConfig(primary_key_env="PEER_KEY"),
        )
        assert backend.federated is not None
        # The loader resolves primary_key_env -> primary_key on load; this
        # profile is built directly, so set the resolved value.
        backend.federated.primary_key = SecretStr(private_pem)
        profile = Profile(
            name=PEER,
            auth=AuthConfig(bearer_token_env="PEER_TOKEN"),
            backends={"lotor": backend},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("peer-token")
        return profile

    return build


async def test_one_block_shares_the_seat_and_the_peer_can_call_it() -> None:
    """The whole configuration is `federation` on the seat.

    No ingress profile, no hand-listed offered set, no second bearer, no static
    token on the wire. The peer signs a primary JWT for an audience only the
    derivation names, is served the seat's remote backend, and calls a tool on
    it — so the answer came back through two perimeters.
    """
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )

    async with serving_mcp_backend(wiki_tools()) as wiki_port:
        # A plain agent seat that happens to share itself: its own `auth`, so
        # it is still reachable by its own agent, and one `federation` block.
        seat = Profile(
            name=SEAT,
            auth=AuthConfig(bearer_token_env="SEAT_TOKEN"),
            federation=FederationConfig(peers={PEER: FederationPeer(public_key=public_pem)}),
            backends={"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")},
        )
        assert seat.auth is not None
        seat.auth.bearer_token = SecretStr("seat-token-only-the-agent-holds")

        async with (
            federated_pair(
                tools=gateway_surface(), secondary=seat, primary=peer_gateway(private_pem)
            ) as fed,
            fed.primary_client() as peer,
        ):
            names = {tool["name"] for tool in await peer.list_tools()}
            served = sorted(name for name in names if name.endswith("wiki_read"))
            assert len(served) == 1, f"expected one wiki_read, got {sorted(names)}"
            result = await peer.call_tool(served[0], {"page": "Federation"})

    assert "wiki:Federation" in json.dumps(result), result

    # The ingress's internal backend is CONSTRUCTED, allowing the paging reader
    # alone, rather than carried from the seat — so the gateway's native
    # surface reaches a peer nowhere. This is the failure only the wire shows:
    # a derived `internal://trentina` allowing `*` would hand the peer the
    # operator's own tools, and the loader would have nothing to object to,
    # because the profile it was derived from is perfectly valid.
    for admin in ("config", "reload_profiles"):
        assert not any(name.endswith(admin) for name in names), (admin, sorted(names))
    # And the peer's own part reader does not reach this agent either, from the
    # other side of the same link: `parts.py` proxies a peer's paged response
    # itself, with the lead-in, in order, stopping at a flagged part, so
    # offering that reader here would be a second and unjudged way to the same
    # parts — `filter._withheld`, which no allowlist can override.
    assert not any(name.endswith("read_part") for name in names), sorted(names)
