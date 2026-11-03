"""An operator profile may share itself, and its peer is an operator (6.0.0).

Scott's instruction, over my objection, so that one agent administering a
gateway can administer its peer through the link it already has.
`docs/federation.md` carries what it costs. These tests carry that it works,
and — more importantly — that the two things it would otherwise break stay
fixed.

Both are worth stating plainly, because neither is caught by the change that
causes them:

* ``_check_operator`` refuses more than one operator in a file. A shared
  operator profile and the ingress derived from it are BOTH operators, so
  counting derivations refuses every such file outright. Loud, at least.
* ``find_operator`` returns the first match, and the gateway's own model calls
  run as whatever it returns. With two matches, dict order decides the
  gateway's service identity — which is exactly the defect #138 removed when
  it replaced a search with an explicit profile. This one is SILENT: the wrong
  identity still has a provider and a key, so the calls succeed and bill to
  the wrong place with the wrong model.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.federation_link import derive_ingress, ingress_name
from trentina.gateway.loader import (
    _check_federation_internal_surface,
    load_profiles,
)
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.gateway.service import find_operator

PEER_PEM = (
    Ed25519PrivateKey.generate()
    .public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)

_PEM_BLOCK = "\n".join(f"            {line}" for line in PEER_PEM.strip().splitlines())

SHARED_OPERATOR_YAML = f"""\
profiles:
  josui:
    role: operator
    defense:
      provider: ollama  # keyless, so the operator pays for its own work
    auth:
      bearer_token_env: TEST_JOSUI_TOKEN
    federation:
      secondary_key_env: TEST_SIGNING_KEY
      peers:
        mypeer:
          public_key: |
{_PEM_BLOCK}
    backends:
      wiki:
        url: https://wiki.example/mcp
        tools_allow: ["*"]
      web:
        url: internal://web
        tools_allow: [read_part_tool, reload_profiles_tool, tool_pins_tool]
"""


def _shared_operator() -> Profile:
    shared = Profile(
        name="josui",
        role="operator",
        auth=AuthConfig(bearer_token_env="TOK"),
        defense=DefenseConfig(provider="ollama"),
        federation=FederationConfig(peers={"mypeer": FederationPeer(public_key=PEER_PEM)}),
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(
                url="internal://web",
                tools_allow=["read_part_tool", "reload_profiles_tool"],
            ),
        },
    )
    assert shared.auth is not None
    return shared


class TestTheRoleAndTheSurfaceBothCross:
    def test_the_derived_profile_is_an_operator(self) -> None:
        assert derive_ingress(_shared_operator()).role == "operator"

    def test_and_the_admin_tools_are_actually_reachable(self) -> None:
        """The half that makes the other half mean anything.

        Carrying the role alone would change nothing: `require_operator` would
        pass for the peer and every admin tool would still be unreachable,
        because they are served by `internal://` and that backend used to allow
        one tool. A test asserting only the role would have passed against a
        gateway that gave the peer no new capability at all.
        """
        offered = derive_ingress(_shared_operator()).backends["trentina"].tools_allow
        assert "reload_profiles_tool" in offered
        assert "read_part_tool" in offered

    def test_an_agent_profile_still_derives_an_agent(self) -> None:
        """The default did not move. A profile that is not the operator shares
        no more than it did in 5.x."""
        shared = _shared_operator()
        agent = shared.model_copy(update={"role": "agent"})
        assert derive_ingress(agent).role == "agent"


class TestTheFileStillLoads:
    def test_a_shared_operator_profile_and_its_derivation_are_one_operator(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mutation check: drop the `federation_of is None` filter from
        `loader._check_operator` and this raises "at most one profile may
        declare role: operator, found 2: josui, josui-federation"."""
        monkeypatch.setenv("TEST_JOSUI_TOKEN", "a-token")
        monkeypatch.setenv(
            "TEST_SIGNING_KEY",
            Ed25519PrivateKey.generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode(),
        )
        path = tmp_path / "profiles.yaml"
        path.write_text(SHARED_OPERATOR_YAML, encoding="utf-8")

        profiles = load_profiles(path).profiles

        assert profiles["josui"].role == "operator"
        assert profiles[ingress_name("josui")].role == "operator"
        # Still exactly one WRITTEN operator, which is the rule that matters.
        written = [p for p in profiles.values() if p.role == "operator" and not p.federation_of]
        assert [p.name for p in written] == ["josui"]

    def test_the_derivation_cannot_be_named_as_the_service_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`gateway.service_identity` must name a WRITTEN operator (#661).

        The derivation carries the role since 6.0.0, so it passes a role test
        and would otherwise be nameable — and it is not a profile anybody wrote,
        so nobody chose it. Asserted through `load_profiles` rather than through
        `find_operator`: the loader is where the name is checked, and
        `find_operator` deliberately falls back rather than raising.
        """
        monkeypatch.setenv("TEST_JOSUI_TOKEN", "a-token")
        monkeypatch.setenv(
            "TEST_SIGNING_KEY",
            Ed25519PrivateKey.generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode(),
        )
        path = tmp_path / "profiles.yaml"
        path.write_text(
            f"gateway:\n  service_identity: {ingress_name('josui')}\n" + SHARED_OPERATOR_YAML,
            encoding="utf-8",
        )

        with pytest.raises(ProfileConfigError, match=r"gateway\.service_identity names"):
            load_profiles(path)


class TestTheServiceIdentityIsTheWrittenProfile:
    """The silent one. `service_profile` runs the gateway's own model calls as
    whatever `find_operator` returns, and with the role carried there are two
    matches."""

    def test_the_written_profile_wins_even_when_the_derivation_comes_first(self) -> None:
        """Dict order is the whole bug, so the derivation is inserted FIRST.

        Mutation check: drop the `federation_of is None` filter from
        `find_operator` and this returns `josui-federation`. Nothing fails
        loudly after that — the derived profile carries the same `llm_keys` and
        `defense`, so every centralized call still succeeds, just attributed to
        a profile nobody wrote.
        """
        shared = _shared_operator()
        ingress = derive_ingress(shared)
        registry = {ingress.name: ingress, shared.name: shared}

        found = find_operator(registry)

        assert found is not None
        assert found.name == "josui"
        assert found.federation_of is None

    def test_and_in_the_other_order(self) -> None:
        shared = _shared_operator()
        ingress = derive_ingress(shared)

        found = find_operator({shared.name: shared, ingress.name: ingress})

        assert found is not None and found.name == "josui"

    def test_a_registry_of_only_derivations_has_no_operator(self) -> None:
        """A derived profile is never the service identity, even alone. It
        cannot be: it is not a profile anybody wrote, so nobody chose it."""
        ingress = derive_ingress(_shared_operator())

        assert find_operator({ingress.name: ingress}) is None


class TestTheRegistryLevelSecondOpinion:
    """`loader._check_federation_internal_surface`, which exists because the
    per-profile validator can no longer do this job.

    Through 5.x `a_derived_ingress_is_bounded` held the derived internal
    backend to a constant, so one profile was enough to check it. Now the
    allowlist follows the source, and whether a widened one is right depends on
    a profile the model validator cannot see. The cost of a derivation bug is a
    peer holding an admin tool nobody offered it, so the check moved rather than
    being dropped — and it re-reads both profiles instead of calling
    `_internal_allow`, so it is a genuinely separate opinion.
    """

    @staticmethod
    def _pair(
        source_tools: list[str], ingress_tools: list[str], *, role: str = "operator"
    ) -> dict[str, Profile]:
        """A source and a HAND-BUILT ingress, so the ingress can disagree with
        its source in ways `derive_ingress` would never produce."""
        source = Profile(
            name="josui",
            role=role,
            auth=AuthConfig(bearer_token_env="TOK"),
            defense=DefenseConfig(provider="ollama"),
            federation=FederationConfig(peers={"mypeer": FederationPeer(public_key=PEER_PEM)}),
            backends={
                "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
                "web": Backend(url="internal://web", tools_allow=source_tools),
            },
        )
        ingress = Profile(
            name=ingress_name("josui"),
            role=role,
            federation_of="josui",
            defense=DefenseConfig(provider="ollama"),
            federation=source.federation,
            backends={
                "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
                "trentina": Backend(url="internal://trentina", tools_allow=ingress_tools),
            },
        )
        return {source.name: source, ingress.name: ingress}

    def test_an_ingress_offering_a_tool_its_source_does_not_is_refused(self) -> None:
        registry = self._pair(["read_part_tool"], ["read_part_tool", "config_tool"])

        with pytest.raises(ProfileConfigError, match=r"offers internal tool\(s\).*config_tool"):
            _check_federation_internal_surface(registry)

    def test_the_message_says_it_is_our_bug_not_the_operators(self) -> None:
        """Nothing a person writes reaches this: the loader refuses a file that
        sets `federation_of` at all. So the message should not send an operator
        looking through their own config for a mistake they did not make."""
        registry = self._pair(["read_part_tool"], ["read_part_tool", "profile_token_tool"])

        with pytest.raises(ProfileConfigError, match="bug in the derivation, not in the file"):
            _check_federation_internal_surface(registry)

    def test_a_faithful_derivation_passes(self) -> None:
        registry = self._pair(["read_part_tool", "config_tool"], ["read_part_tool", "config_tool"])

        _check_federation_internal_surface(registry)  # does not raise

    def test_a_narrower_ingress_passes(self) -> None:
        """Narrower than its source is the safe direction, and `_internal_allow`
        produces it for an agent profile."""
        registry = self._pair(["read_part_tool", "config_tool"], ["read_part_tool"])

        _check_federation_internal_surface(registry)

    def test_an_agent_sources_own_allowlist_does_not_permit_anything(self) -> None:
        """Only an OPERATOR profile's internal allowlist crosses the link.

        An agent's derivation gets `FEDERATION_INTERNAL_REQUIRED` and nothing
        else, whatever its own internal backend allows, so comparing an agent
        ingress against its source's list would accept a widened one. The check
        restates the role rule rather than only the list.
        """
        registry = self._pair(
            ["read_part_tool", "config_tool"],
            ["read_part_tool", "config_tool"],
            role="agent",
        )

        with pytest.raises(ProfileConfigError, match=r"offers internal tool\(s\).*config_tool"):
            _check_federation_internal_surface(registry)

    def test_a_star_on_an_agent_source_is_not_permission(self) -> None:
        """`tools_allow: ["*"]` is the common spelling on an agent's internal
        backend, and an earlier version of this check skipped the comparison
        whenever it saw one — so exactly the widening worth catching was the one
        it went quiet on. Gatehouse caught it. A shared OPERATOR cannot write a
        glob at all (`a_shared_profile_is_shareable` refuses it while the model
        is built), so a glob reaching here can only be an agent's, and it grants
        nothing."""
        registry = self._pair(["*"], ["read_part_tool", "config_tool"], role="agent")

        with pytest.raises(ProfileConfigError, match=r"offers internal tool\(s\).*config_tool"):
            _check_federation_internal_surface(registry)

    def test_a_star_on_an_agent_source_still_passes_a_faithful_derivation(self) -> None:
        """The other half: the floor itself is always allowed, so a glob on the
        source is not a false refusal either."""
        registry = self._pair(["*"], ["read_part_tool"], role="agent")

        _check_federation_internal_surface(registry)

    def test_a_registry_with_no_derivation_is_left_alone(self) -> None:
        source = self._pair(["read_part_tool"], ["read_part_tool"])["josui"]

        _check_federation_internal_surface({source.name: source})
