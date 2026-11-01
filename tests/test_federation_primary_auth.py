"""C1: a federated link authenticates with an primary JWT, no shared bearer (#592).

The happy path — a primary JWT verified by the secondary and a tool call
crossing the link — is asserted end to end in
`test_federation_seat_link.py`, through the ingress DERIVED from a seat, which
is the shape 5.0.0 ships. It lives there rather than here because only one
test per process may stand up a gateway pair in front of a real remote MCP
backend (#657), and a second one reports coverage it does not have.

What is here is the refusal and the two reload holds. The refusal is asserted
POSITIVELY, on the error the gateway raises, and needs no remote backend: a
wrong primary key is refused by the secondary's ingress before any backend is
reached. It used to be an end-to-end assertion that no tool was served — which
is satisfied by a link that failed for any reason at all, including the #657
defect, so for most of its life it passed without testing anything.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from tests.federation_harness import (
    INTERNAL_KEY,
    SECONDARY_PROFILE,
    federated_pair,
)
from trentina.gateway import backend as backend_mod
from trentina.gateway.backend import ResponseCap, call_backend_tool, list_backend_tools
from trentina.gateway.circuit import DEFAULT_FAILURE_THRESHOLD, State, breaker
from trentina.gateway.context import profile_context
from trentina.gateway.errors import FederationUnauthorizedError
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


#: The seat this ingress was derived from. The harness serves the ingress at
#: `/<SECONDARY_PROFILE>/mcp` and the audience is the profile NAME, so the two
#: stay as they were; what `federation_of` adds is that the profile reads as
#: derived rather than hand-written, which is what the model now requires.
SECONDARY_SEAT = "shared-seat"

#: A loopback port nothing listens on. The secondary's offered backend has to
#: exist for the profile to be valid, and this file never dials it: a refused
#: primary key is refused at the ingress, before any backend is reached.
_DEAD_PORT = 1


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


async def test_a_wrong_primary_key_is_refused() -> None:
    """The secondary refuses a primary JWT it cannot verify, and the primary
    says so rather than reporting an empty offering.

    The assertion is on `FederationUnauthorizedError` from the primary's own
    listing call, not on the peer's served tool list: an empty list is what a
    refusal looks like AND what every other failure looks like, so it told the
    two apart only by luck. The secondary's backend is deliberately a port
    nothing listens on — the refusal happens at its ingress, before a backend
    is reached, which this test now also proves by never needing one.
    """
    _, trusted_pub = _keypair()
    wrong_priv, _ = _keypair()
    # The ingress DERIVED from a shared seat: peers only, NO static bearer,
    # since the peer list is what authenticates. Its internal surface is the
    # paging reader — never the gateway's own fetch/search/admin tools, which
    # the seat itself still has.
    secondary = Profile(
        name=SECONDARY_PROFILE,
        federation_of=SECONDARY_SEAT,
        federation=FederationConfig(peers={"breetai": FederationPeer(public_key=trusted_pub)}),
        backends={
            "demo": Backend(url=f"http://127.0.0.1:{_DEAD_PORT}/mcp"),
            INTERNAL_KEY: Backend(url="internal://web", tools_allow=["read_part_tool"]),
        },
    )
    async with federated_pair(secondary=secondary, primary=_primary_factory(wrong_priv)) as fed:
        primary = _primary_factory(wrong_priv)(fed.secondary_port)
        backend = primary.backends["fed"]
        with profile_context(primary), pytest.raises(FederationUnauthorizedError) as refused:
            await list_backend_tools("fed", backend, primary)

    assert "federation_unauthorized" in str(refused.value)


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
        # A seat that starts sharing itself KEEPS its `auth`: `federation` is
        # declared on the seat now, and the ingress is derived from it. What
        # matters here is that an agent-triggered reload may not add the block.
        after = Profile(
            name="up",
            auth=AuthConfig(bearer_token_env="A"),
            federation=FederationConfig(peers={"breetai": FederationPeer(public_key=pub)}),
            backends={"x": Backend(url="internal://web", tools_allow=["read_part_tool"])},
        )
        held = _hold_perimeter_fields(before, after)
        assert "federation" in held
        assert after.federation is None


class TestAPeersRefusalDoesNotOpenTheCircuit:
    """A federated 401 is a signature or a clock, not an unreachable peer.

    `_with_reauth` only excuses a 401 when there is an OAuth grant to refresh,
    and a federated backend has none — it signs a primary JWT per call. So the
    refusal used to fall through to `record_failure` on a breaker keyed by URL,
    which means one rotated key or a little clock drift took the peer down for
    EVERY profile federating to it, reported as unreachability.
    """

    @staticmethod
    def _primary(url: str) -> Profile:
        """A primary with a REAL signing key: `_down` carries a placeholder, and
        the JWT is signed before the call is made, so the call would never reach
        the peer to be refused."""
        private_pem, _ = _keypair()
        profile = _down(url)
        federated = profile.backends["fed"].federated
        assert federated is not None
        federated.primary_key = SecretStr(private_pem)
        return profile

    @pytest.fixture
    def refusing_peer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def refuse(
            _url: str,
            _headers: dict[str, str] | None,
            *_: object,
            cap: ResponseCap | None = None,
            **__: object,
        ) -> object:
            # What a 401 looks like from the session layer: the cap records it,
            # the transport raises.
            if cap is not None:
                cap.unauthorized = True
            raise RuntimeError("Server returned an error response")

        monkeypatch.setattr(backend_mod, "_do_call_tool", refuse)
        breaker.reset()

    async def test_the_breaker_stays_closed_however_often_the_peer_refuses(
        self, refusing_peer: None
    ) -> None:
        del refusing_peer
        profile = self._primary("https://peer.example/gateway/fed/mcp")
        fed = profile.backends["fed"]

        # More refusals than the failure threshold, so a counted failure would
        # have opened it well before the loop ended.
        for _ in range(DEFAULT_FAILURE_THRESHOLD + 2):
            with profile_context(profile), pytest.raises(FederationUnauthorizedError):
                await call_backend_tool("fed", fed, "echo", {})

        assert breaker.get_state(fed.url) is State.CLOSED
        assert breaker.allow(fed.url)

    async def test_the_reason_names_the_three_causes_and_not_the_peer(
        self, refusing_peer: None
    ) -> None:
        """A reason code is a closed set, not a relay for what the other end
        said, and the message is what an operator reads to fix it."""
        del refusing_peer
        profile = self._primary("https://peer.example/gateway/fed/mcp")

        with profile_context(profile), pytest.raises(FederationUnauthorizedError) as refused:
            await call_backend_tool("fed", profile.backends["fed"], "echo", {})

        message = str(refused.value)
        assert "federation_unauthorized" in message
        assert "public key" in message and "audience" in message and "clocks" in message
        assert "peer.example" not in message

    async def test_a_refusal_on_tools_list_does_not_count_either(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 401 arrives on tools/list as readily as on a call, and
        `list_backend_tools` has its own broad catch that re-wraps and records
        a failure. The re-raise clause had to be added in BOTH places."""

        async def refuse(
            _url: str, _headers: dict[str, str] | None, cap: ResponseCap | None = None
        ) -> object:
            if cap is not None:
                cap.unauthorized = True
            raise RuntimeError("Server returned an error response")

        monkeypatch.setattr(backend_mod, "_do_list_tools", refuse)
        breaker.reset()
        backend_mod._tool_list_cache.clear()
        profile = self._primary("https://peer.example/gateway/fed/mcp")
        fed = profile.backends["fed"]

        for _ in range(DEFAULT_FAILURE_THRESHOLD + 2):
            with profile_context(profile), pytest.raises(FederationUnauthorizedError):
                await list_backend_tools("fed", fed, profile)

        assert breaker.get_state(fed.url) is State.CLOSED
