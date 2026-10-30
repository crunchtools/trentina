"""B1: the inert ``federated:`` Backend block (#592).

The block marks a backend as a federated upstream Trentina. In B1 it is inert —
the link still runs as a plain MCP backend — but it earns two behaviours now:
it is refused where there is no peer to federate (internal/decoy, honeypot), and
an agent-triggered reload may not apply or drop it (it names a trust boundary).
Later items read it (edge-key auth, verdict trust).
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile
from trentina.tools.reload import _hold_perimeter_fields

UP = "https://lotor.example/gateway/x/mcp"


class TestSchema:
    def test_a_remote_backend_may_be_federated(self) -> None:
        backend = Backend(url=UP, federated=FederatedConfig())
        assert backend.federated is not None
        assert backend.is_remote

    def test_the_block_is_empty(self) -> None:
        # B1: the block's presence is the whole signal; no field is read yet.
        assert set(FederatedConfig.model_fields) == set()

    def test_a_premature_field_is_refused(self) -> None:
        # trust_verdict arrives with D2a, edge_key_env with C1 — not before.
        with pytest.raises(ValidationError):
            FederatedConfig(trust_verdict=True)

    def test_absent_by_default(self) -> None:
        assert Backend(url=UP).federated is None

    def test_an_internal_backend_cannot_be_federated(self) -> None:
        with pytest.raises(ValidationError, match="does not apply to an internal"):
            Backend(url="internal://web", federated=FederatedConfig())

    def test_a_decoy_backend_cannot_be_federated(self) -> None:
        with pytest.raises(ValidationError, match="does not apply to a decoy"):
            Backend(
                url="decoy://trap",
                decoys={"send": {"description": "sends", "result": "ok"}},
                federated=FederatedConfig(),
            )


class TestHoneypot:
    def test_a_honeypot_cannot_hold_a_federated_backend(self) -> None:
        # A federated backend is a real server, which a honeypot never holds.
        with pytest.raises(ValidationError, match="real server"):
            Profile(
                name="hp",
                auth=AuthConfig(bearer_token_env="TOK"),
                honeypot=True,
                backends={"up": Backend(url=UP, federated=FederatedConfig())},
            )


def _profile(*, federated: bool) -> Profile:
    profile = Profile(
        name="agent1",
        auth=AuthConfig(bearer_token_env="TOK"),
        backends={"up": Backend(url=UP, federated=FederatedConfig() if federated else None)},
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


class TestAnAgentCannotReloadItsOwnFederation:
    def test_adding_federation_is_held(self) -> None:
        before, after = _profile(federated=False), _profile(federated=True)
        assert "backends.up.federated" in _hold_perimeter_fields(before, after)
        assert after.backends["up"].federated is None

    def test_removing_federation_is_held(self) -> None:
        before, after = _profile(federated=True), _profile(federated=False)
        assert "backends.up.federated" in _hold_perimeter_fields(before, after)
        assert after.backends["up"].federated is not None

    def test_a_backend_new_to_the_reload_cannot_bring_federation(self) -> None:
        before = Profile(name="agent1", auth=AuthConfig(bearer_token_env="TOK"), backends={})
        after = _profile(federated=True)
        assert "backends.up.federated" in _hold_perimeter_fields(before, after)
        assert after.backends["up"].federated is None

    def test_an_unchanged_block_is_not_reported(self) -> None:
        held = _hold_perimeter_fields(_profile(federated=True), _profile(federated=True))
        assert "backends.up.federated" not in held


async def test_a_federated_backend_still_federates_inertly() -> None:
    # Inert: marking the downstream's backend federated changes nothing in B1 —
    # it still federates like a plain MCP backend (proven on the harness).
    from tests.federation_harness import downstream_profile, federated_pair

    def down(up_port: int) -> Profile:
        profile = downstream_profile(upstream_port=up_port)
        next(iter(profile.backends.values())).federated = FederatedConfig()
        return profile

    async with federated_pair(downstream=down) as fed, fed.downstream_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert any(n.endswith("echo") for n in names), names
