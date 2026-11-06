"""A profile shares itself, over the wire, between two real gateways (#592, 5.0.0).

`test_federation_link.py` proves the derivation as a function and
`test_federation_grants.py` proves a link spends its profile's grant. Neither of
them puts bytes on a socket, and the claim this release makes is an end-to-end
one: write ONE `federation` block on a profile and a peer gateway serves that
profile's tools. This is that claim over the wire — two real gateways on loopback,
a real primary JWT, a real remote MCP backend behind the secondary's perimeter,
and a tool call that comes back with its answer.

Four narrower properties follow it, each standing its own pair: that the profile's
own native surface does not cross, that a consumed `federated:` backend is not
re-exported, that several peers authenticate to one profile, and that a backend
added to the profile reaches the peer with no second edit. Each is also covered at
the loader and model level in `test_federation_link.py`; the value of asserting
them again here is that a derivation which is right in the registry and wrong
on the wire is still wrong.

They were written for 5.0.0 and withheld, because a second pair in one process
could not list its tools and #657 recorded that as a defect in the in-process
MCP server stack needing a test boundary. It was neither. It was
`sse_starlette.sse.AppStatus.should_exit`, a process-global latch that every
uvicorn teardown sets and nothing clears, after which an MCP server's SSE
response is cut short before it is written — see
`conftest._sse_drain_latch_is_not_held`. A test that passes only when xdist
happens to give it a fresh worker is worse than no test, so these waited for
the cause rather than shipping around it.

The assertion is about what the PEER is served, which is the only view that
matters: a derivation that is right in the registry and wrong on the wire is
still wrong.
"""

from __future__ import annotations

import contextlib
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

PROFILE = "josui"
PEER = "mypeer"


def wiki_tools() -> list:
    """The profile's remote backend, named so no assertion can confuse its tools
    with the gateway's own internal surface."""

    def wiki_read(page: str) -> str:
        """Read a wiki page."""
        return f"wiki:{page}"

    return [wiki_read]


def gateway_surface() -> list:
    """What `internal://` serves — the gateway's whole native surface, admin
    tools included. The derived ingress gets a FRESH internal backend allowing
    `read_part_tool` alone rather than a filtered copy of the profile's, and these
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


def keypair() -> tuple[str, str]:
    """An Ed25519 (private PEM, public PEM) pair, as a peer and a profile hold it."""
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


def peer_gateway(private_pem: str, name: str = PEER):
    """A primary that mounts the ingress DERIVED from the profile.

    The URL names `<profile>-federation` through `ingress_name`, the same function
    the loader derives with — nothing wrote that profile. The primary JWT is
    audience-pinned to that name, so getting it wrong fails to authenticate
    rather than 404ing, which is why the test asserts on the tools served and
    on a call's answer rather than on a status code.

    `name` is the peer's own profile name, and it is load-bearing rather than
    cosmetic: the primary signs its JWT as the calling profile, and the profile
    looks that name up in `federation.peers` to find the key to verify with. A
    second peer is a second name, which is what the multi-peer test turns on.
    """

    def build(secondary_port: int) -> Profile:
        backend = Backend(
            url=f"http://127.0.0.1:{secondary_port}/{ingress_name(PROFILE)}/mcp",
            federated=FederatedConfig(primary_key_env="PEER_KEY"),
        )
        assert backend.federated is not None
        # The loader resolves primary_key_env -> primary_key on load; this
        # profile is built directly, so set the resolved value.
        backend.federated.primary_key = SecretStr(private_pem)
        profile = Profile(
            name=name,
            auth=AuthConfig(bearer_token_env="PEER_TOKEN"),
            backends={"peergw": backend},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("peer-token")
        return profile

    return build


def shared_profile(peers: dict[str, str], backends: dict[str, Backend]) -> Profile:
    """A plain agent profile that happens to share itself.

    Its own `auth`, so it is still reachable by its own agent, and one
    `federation` block. Nothing else: the ingress is derived.
    """
    profile = Profile(
        name=PROFILE,
        auth=AuthConfig(bearer_token_env="PROFILE_TOKEN"),
        federation=FederationConfig(
            peers={name: FederationPeer(public_key=pem) for name, pem in peers.items()}
        ),
        backends=backends,
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("profile-token-only-the-agent-holds")
    return profile


async def test_one_block_shares_the_profile_and_the_peer_can_call_it() -> None:
    """The whole configuration is `federation` on the profile.

    No ingress profile, no hand-listed offered set, no second bearer, no static
    token on the wire. The peer signs a primary JWT for an audience only the
    derivation names, is served the profile's remote backend, and calls a tool on
    it — so the answer came back through two perimeters.
    """
    private_pem, public_pem = keypair()

    async with serving_mcp_backend(wiki_tools()) as wiki_port:
        profile = shared_profile(
            {PEER: public_pem}, {"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")}
        )

        async with (
            federated_pair(
                tools=gateway_surface(), secondary=profile, primary=peer_gateway(private_pem)
            ) as fed,
            fed.primary_client() as peer,
        ):
            names = {tool["name"] for tool in await peer.list_tools()}
            served = sorted(name for name in names if name.endswith("wiki_read"))
            assert len(served) == 1, f"expected one wiki_read, got {sorted(names)}"
            result = await peer.call_tool(served[0], {"page": "Federation"})

    assert "wiki:Federation" in json.dumps(result), result

    # The ingress's internal backend is CONSTRUCTED, allowing the paging reader
    # alone, rather than carried from the profile — so the gateway's native
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


async def test_the_gateways_own_native_surface_does_not_cross() -> None:
    """The directed edge, on its own pair.

    The profile's `internal://` backend is its whole native surface, admin tools
    included. The derived ingress gets a FRESH internal backend allowing
    `read_part_tool` alone rather than a filtered copy of the profile's — and the
    paging reader is then withheld from what is SERVED (`filter._withheld`),
    because `parts.py` proxies a peer's paged response itself, in order, with
    the lead-in, stopping at a flagged part. Offering the reader to the peer as
    well would be a second and unjudged way to the same parts.

    This is the failure only the wire shows. A derived `internal://trentina`
    allowing `*` would hand the peer the operator's own tools and the loader
    would have nothing to object to, because the profile it was derived from is
    perfectly valid.
    """
    private_pem, public_pem = keypair()
    async with serving_mcp_backend(wiki_tools()) as wiki_port:
        profile = shared_profile(
            {PEER: public_pem}, {"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")}
        )
        async with (
            federated_pair(
                tools=gateway_surface(), secondary=profile, primary=peer_gateway(private_pem)
            ) as fed,
            fed.primary_client() as peer,
        ):
            names = {tool["name"] for tool in await peer.list_tools()}

    assert any(name.endswith("wiki_read") for name in names), sorted(names)
    for withheld in ("config", "reload_profiles", "read_part"):
        assert not any(name.endswith(withheld) for name in names), (withheld, sorted(names))


async def test_a_consumed_federated_backend_is_not_re_exported() -> None:
    """A -> B -> C is unsayable, over the wire and not merely in the registry.

    One profile may both consume a peer and share itself (5.0.0 dropped the
    one-profile-one-role clause). What keeps that from chaining is structural:
    `offerable_backends` excludes every `federated` backend, so a profile's own
    upstream link is never in the set its own peers are offered.

    The consumed link here points at a port nothing is listening on, and that
    is the point — if the derivation offered it, the ingress would try to list
    it and the test would see either its tools or a failure. It sees neither.
    """
    private_pem, public_pem = keypair()
    unreachable = Backend(
        url="http://127.0.0.1:1/some-other-gateway/mcp",
        headers={"Authorization": "Bearer not-used"},
        federated=FederatedConfig(),
    )
    async with serving_mcp_backend(wiki_tools()) as wiki_port:
        profile = shared_profile(
            {PEER: public_pem},
            {
                "wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp"),
                "upstream-peer": unreachable,
            },
        )
        async with (
            federated_pair(
                tools=gateway_surface(), secondary=profile, primary=peer_gateway(private_pem)
            ) as fed,
            fed.primary_client() as peer,
        ):
            names = {tool["name"] for tool in await peer.list_tools()}

    # The profile's own remote backend crosses; the one it consumes from elsewhere
    # does not, under any namespacing.
    assert any(name.endswith("wiki_read") for name in names), sorted(names)
    assert not any("upstream" in name or "peer" in name for name in names), sorted(names)


async def test_two_peers_authenticate_to_one_profile() -> None:
    """One `federation` block, two peers, each with its own key.

    The single-peer rule is gone in 5.0.0, and the thing worth asserting is that
    the SECOND peer is served by the same derived ingress rather than needing a
    second one: both sign for the same audience and are told apart by the
    profile name their JWT carries.

    Two pairs in one test, which is what #657 made impossible.
    """
    alpha_private, alpha_public = keypair()
    beta_private, beta_public = keypair()
    peers = {PEER: alpha_public, "kagetora": beta_public}

    served: dict[str, set[str]] = {}
    for peer_name, peer_private in ((PEER, alpha_private), ("kagetora", beta_private)):
        async with serving_mcp_backend(wiki_tools()) as wiki_port:
            profile = shared_profile(
                peers, {"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")}
            )
            async with (
                federated_pair(
                    tools=gateway_surface(),
                    secondary=profile,
                    primary=peer_gateway(peer_private, name=peer_name),
                ) as fed,
                fed.primary_client() as peer,
            ):
                served[peer_name] = {tool["name"] for tool in await peer.list_tools()}

    for peer_name, names in served.items():
        assert any(name.endswith("wiki_read") for name in names), (peer_name, sorted(names))


async def test_a_backend_added_to_the_profile_needs_no_second_edit() -> None:
    """The property the whole release is for.

    Before 5.0.0 the offered set was hand-listed on a separate ingress profile,
    so adding a backend to a profile and expecting a peer to see it was the most
    natural mistake an operator could make, and it failed silently. Now the set
    is derived, so the second edit does not exist.

    Asserted as before-and-after on the SAME peer: one pair with one backend,
    one with two, and nothing between them but the profile's `backends` mapping.
    """
    private_pem, public_pem = keypair()

    def extra_tools() -> list:
        def ledger_read(entry: str) -> str:
            """Read a ledger entry."""
            return f"ledger:{entry}"

        return [ledger_read]

    async def served(with_ledger: bool) -> set[str]:
        async with contextlib.AsyncExitStack() as stack:
            wiki_port = await stack.enter_async_context(serving_mcp_backend(wiki_tools()))
            backends = {"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")}
            if with_ledger:
                ledger_port = await stack.enter_async_context(serving_mcp_backend(extra_tools()))
                backends["ledger"] = Backend(url=f"http://127.0.0.1:{ledger_port}/mcp")
            profile = shared_profile({PEER: public_pem}, backends)
            fed = await stack.enter_async_context(
                federated_pair(
                    tools=gateway_surface(),
                    secondary=profile,
                    primary=peer_gateway(private_pem),
                )
            )
            peer = await stack.enter_async_context(fed.primary_client())
            return {tool["name"] for tool in await peer.list_tools()}

    before = await served(with_ledger=False)
    after = await served(with_ledger=True)

    assert not any(name.endswith("ledger_read") for name in before), sorted(before)
    assert any(name.endswith("ledger_read") for name in after), sorted(after)
    # And the first backend is still there: adding one is not replacing the set.
    assert any(name.endswith("wiki_read") for name in after), sorted(after)


async def test_an_operator_profiles_peer_calls_an_admin_tool_over_the_wire() -> None:
    """6.0.0, Scott's instruction, and the only test that proves it reaches a
    peer rather than merely reaching the registry.

    The two halves have to arrive together. Carrying `role` alone would change
    nothing, because the admin tools are served by `internal://` and the
    derived backend allowed one tool; carrying the surface alone would leave
    `require_operator` refusing the call. So this asserts the end that matters:
    the peer lists an admin tool AND gets its answer back.

    Compare `test_the_gateways_own_native_surface_does_not_cross` directly
    above, which is the same wire with an AGENT profile and shows the admin
    tools absent. The two together are the whole of what Scott changed.
    """
    private_pem, public_pem = keypair()
    async with serving_mcp_backend(wiki_tools()) as wiki_port:
        shared = shared_profile(
            {PEER: public_pem}, {"wiki": Backend(url=f"http://127.0.0.1:{wiki_port}/mcp")}
        )
        # The one difference from the agent case next door.
        shared = shared.model_copy(
            update={
                "role": "operator",
                "backends": {
                    **shared.backends,
                    "web": Backend(
                        url="internal://web",
                        tools_allow=["read_part_tool", "reload_profiles"],
                    ),
                },
            }
        )

        async with (
            federated_pair(
                tools=gateway_surface(), secondary=shared, primary=peer_gateway(private_pem)
            ) as fed,
            fed.primary_client() as peer,
        ):
            names = {tool["name"] for tool in await peer.list_tools()}
            served = sorted(name for name in names if name.endswith("reload_profiles"))
            assert len(served) == 1, f"expected one reload_profiles, got {sorted(names)}"
            result = await peer.call_tool(served[0], {})

    # The answer came back, so the call was not merely offered but admitted:
    # `require_operator` saw an operator, and the internal backend served it.
    assert "reloaded" in json.dumps(result), result
    # `config` is NOT on the shared profile's internal allowlist, so it does
    # not cross. The surface follows the profile; it is not simply opened.
    assert not any(name.endswith("config") for name in names), sorted(names)
