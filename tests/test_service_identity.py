"""The operator as the gateway's service identity (#138), and the #137 insulation.

The gateway's own model calls — compressing a shared description, judging it
at the perimeter — used to run as whoever was nearby: the first profile in the
file for compression, the env-global key for the perimeter. These tests pin
the replacement rule, the load-time constraints that make it safe, and the
cross-profile couplings #137 found alongside it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from trentina import orchestrator as orch
from trentina.config import get_config
from trentina.gateway import aggregate
from trentina.gateway import tool_list_edge as ing
from trentina.gateway import verdict_cache as vc
from trentina.gateway.compress import _call_compress_model
from trentina.gateway.context import get_current_profile, profile_context
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    Profile,
)
from trentina.gateway.scope import current_scope
from trentina.gateway.service import (
    find_operator,
    judge_of,
    log_service_identity,
    service_context,
    service_profile,
    written_operators,
)
from trentina.gateway.sessions import SessionRegistry
from trentina.quarantine.providers.base import ProviderResult
from trentina.transports import mcp

# A tenant holds its OWN key since 6.1.0: it pays to judge and compress its
# own tool descriptions, and `resolve_profile_llm` refuses to bill the
# operator's on its behalf. Through 6.0.0 this section had no `llm_keys` at
# all, because the operator covered it.
_TENANT = """\
  tenant:
    auth:
      bearer_token_env: TEST_TENANT_TOKEN
    llm_keys:
      gemini:
        api_key: tenant-key
    defense:
      model: tenant-model
"""

_OPERATOR = """\
  ops:
    role: operator
    auth:
      bearer_token_env: TEST_OPS_TOKEN
    llm_keys:
      gemini:
        api_key: ops-key
    defense:
      model: ops-model
"""


#: A second operator, written so it differs from `_OPERATOR` only in its name
#: and token. Both hold a key for their own judge, which the load rule requires
#: of EVERY operator since 6.4.0 and not only the bound one.
_OPERATOR_TWO = """\
  ops2:
    role: operator
    auth:
      bearer_token_env: TEST_OPS2_TOKEN
    llm_keys:
      gemini:
        api_key: ops2-key
    defense:
      model: ops2-model
"""


def _load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *sections: str,
    service_identity: str | None = None,
) -> Path:
    monkeypatch.setenv("TEST_TENANT_TOKEN", "t")
    monkeypatch.setenv("TEST_OPS_TOKEN", "o")
    monkeypatch.setenv("TEST_OPS2_TOKEN", "o2")
    path = tmp_path / "profiles.yaml"
    gateway = (
        f"gateway:\n  service_identity: {service_identity}\n"
        if service_identity is not None
        else ""
    )
    path.write_text(gateway + "profiles:\n" + "".join(sections), encoding="utf-8")
    return path


def _live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *sections: str,
    service_identity: str | None = None,
) -> dict[str, Profile]:
    path = _load(tmp_path, monkeypatch, *sections, service_identity=service_identity)
    config = load_profiles(path)
    register_active_config(path, config, {})
    return config.profiles


class TestLoadRules:
    def test_two_operators_with_no_service_identity_refuse_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """6.4.0 inverted this rule rather than deleting it (#661).

        Two operators are allowed; two operators and no name for the one the
        gateway reports as ITSELF is not, because the alternative is taking the
        first in dict order — the defect #138 removed, under a new spelling.
        Both names are asserted: the fix is to choose between them, and a
        refusal naming neither does not say what there is to choose from.
        """
        path = _load(tmp_path, monkeypatch, _OPERATOR, _OPERATOR_TWO)

        with pytest.raises(ProfileConfigError, match=r"set gateway\.service_identity") as caught:
            load_profiles(path)

        message = str(caught.value)
        assert "ops," in message and "ops2" in message

    def test_an_operator_without_a_key_for_its_provider_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refused for the admin surface, not for anyone else's bill (6.1.1).

        Since 6.1.0 the operator pays for nobody else's judging, so the reason
        this is stricter than the warning every other keyless profile gets is
        that the operator's own tools are the ADMIN set: withheld under block,
        and then there is no way to repair the gateway through the API. The
        message is asserted, not just the failure, because the rule outlived
        the reason it was written for and a reader needs the live one.
        """
        keyless = _OPERATOR.replace("    llm_keys:\n      gemini:\n        api_key: ops-key\n", "")
        path = _load(tmp_path, monkeypatch, keyless)

        with pytest.raises(ProfileConfigError, match="no llm_keys") as caught:
            load_profiles(path)

        message = str(caught.value)
        assert "config_tool" in message
        assert "administered through the API" in message
        # The pre-6.1.0 reason, which stopped being true when judging went
        # per profile. It must not come back.
        assert "gateway's own model calls" not in message

    def test_a_key_for_another_provider_does_not_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key must be for the provider the operator's judge RESOLVES to."""
        elsewhere = _OPERATOR.replace("    defense:\n", "    defense:\n      provider: openai\n")
        path = _load(tmp_path, monkeypatch, elsewhere)

        with pytest.raises(ProfileConfigError, match=r"no llm_keys\.openai"):
            load_profiles(path)

    def test_a_key_for_the_overridden_provider_is_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        matching = _OPERATOR.replace("      gemini:", "      openai:").replace(
            "    defense:\n", "    defense:\n      provider: openai\n"
        )
        path = _load(tmp_path, monkeypatch, matching)

        assert load_profiles(path).profiles["ops"].defense.provider == "openai"

    def test_an_ollama_operator_needs_no_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ollama = """\
  ops:
    role: operator
    auth:
      bearer_token_env: TEST_OPS_TOKEN
    defense:
      provider: ollama
"""
        path = _load(tmp_path, monkeypatch, ollama)

        assert load_profiles(path).profiles["ops"].role == "operator"

    def test_no_operator_loads(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        path = _load(tmp_path, monkeypatch, _TENANT)

        assert "tenant" in load_profiles(path).profiles


class TestMoreThanOneOperator:
    """#661: two agents administer one gateway, and the gateway says which it is.

    The one-operator rule existed because the operator was also whose key the
    gateway's own model calls ran on, so a second one would have let dict order
    decide whose key paid (#138). 6.1.0 moved every such call onto the listing
    profile's own key. What is left to decide is which operator the gateway
    binds and REPORTS as itself: the profile in an approved config write's audit
    row, and `quarantine_stats`' `perimeter.judge`.
    """

    def test_two_operators_load_when_one_is_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _OPERATOR, _OPERATOR_TWO, service_identity="ops2")

        assert [p.name for p in written_operators(profiles)] == ["ops", "ops2"]
        assert service_profile().name == "ops2"

    @pytest.mark.parametrize("named", ["ops", "ops2"])
    def test_either_one_can_be_the_named_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: str
    ) -> None:
        _live(tmp_path, monkeypatch, _OPERATOR, _OPERATOR_TWO, service_identity=named)

        assert service_profile().name == named

    @pytest.mark.parametrize("order", [(_OPERATOR, _OPERATOR_TWO), (_OPERATOR_TWO, _OPERATOR)])
    def test_file_order_does_not_move_the_bound_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: tuple[str, str]
    ) -> None:
        """The regression the whole setting exists to prevent.

        Mutation check: make `find_operator` ignore `service_identity` and the
        second parametrisation returns `ops2`. Both orders are run because dict
        order here IS file order — `load_profiles` builds the registry by
        iterating the `profiles` mapping — so one order alone would pass with
        the setting doing nothing.
        """
        _live(tmp_path, monkeypatch, *order, service_identity="ops")

        assert service_profile().name == "ops"

    @pytest.mark.parametrize("order", [(_OPERATOR, _OPERATOR_TWO), (_OPERATOR_TWO, _OPERATOR)])
    def test_the_judge_reported_to_an_operator_is_the_named_ones(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: tuple[str, str]
    ) -> None:
        """`quarantine_stats`' `perimeter.judge`, which is `judge_stamp(service_profile())`.

        The two operators differ in `defense.model`, so a judge resolved from
        the wrong one is visible in the value rather than only in the name.
        """
        _live(tmp_path, monkeypatch, *order, service_identity="ops")

        assert judge_of(service_profile()) == (get_config().provider, "ops-model")

    @pytest.mark.parametrize("caller", ["ops", "ops2"])
    def test_both_operators_hold_the_gateway_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caller: str
    ) -> None:
        """Admin scope never read the service identity — it reads `role` — and
        that is what makes this issue cheap. Asserted anyway: "either agent can
        administer the gateway" is the feature, and it would be a silent loss if
        a later change keyed scope on the bound profile instead.
        """
        profiles = _live(tmp_path, monkeypatch, _OPERATOR, _OPERATOR_TWO, service_identity="ops")

        with profile_context(profiles[caller]):
            assert current_scope().is_operator is True

    def test_a_keyless_second_operator_is_refused_by_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The keyless rule is per-PROFILE, so it applies to every operator.

        6.1.1's reasoning: the admin tools are `internal://` and are judged, so
        under `block` a keyless operator is served none of them. Each operator
        reaches those tools on its own credential and judges them on its own
        key, so a keyless second operator is an admin seat that cannot
        administer. Mutation check: check only the named identity and this
        loads.
        """
        keyless = _OPERATOR_TWO.replace(
            "    llm_keys:\n      gemini:\n        api_key: ops2-key\n", ""
        )
        path = _load(tmp_path, monkeypatch, _OPERATOR, keyless, service_identity="ops")

        with pytest.raises(ProfileConfigError, match="no llm_keys") as caught:
            load_profiles(path)

        assert "'ops2'" in str(caught.value)

    def test_one_operator_needs_no_setting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No file written before 6.4.0 changes meaning."""
        _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        assert service_profile().name == "ops"

    def test_naming_a_profile_that_is_not_here_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _load(tmp_path, monkeypatch, _OPERATOR, service_identity="nobody")

        with pytest.raises(ProfileConfigError, match=r"gateway\.service_identity names"):
            load_profiles(path)

    def test_naming_a_tenant_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A profile that does not hold the role cannot be the identity: the
        gateway's own work applies a whole config file, which `reload_profiles`
        does only for an operator."""
        path = _load(tmp_path, monkeypatch, _TENANT, _OPERATOR, service_identity="tenant")

        with pytest.raises(ProfileConfigError, match="role: operator"):
            load_profiles(path)

    def test_a_non_string_setting_is_fatal_rather_than_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A list here is somebody naming two identities. Falling back to the
        one-operator default would bind a profile they did not choose."""
        monkeypatch.setenv("TEST_OPS_TOKEN", "o")
        path = tmp_path / "profiles.yaml"
        path.write_text(
            "gateway:\n  service_identity:\n    - ops\n    - ops2\nprofiles:\n" + _OPERATOR,
            encoding="utf-8",
        )

        with pytest.raises(ProfileConfigError, match="must be the name of one profile"):
            load_profiles(path)

    def test_the_startup_line_names_the_bound_one_and_counts_the_rest(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """With two operators, the line saying which one is bound reads as
        though it were the only one unless the others are in the same record."""
        profiles = _live(tmp_path, monkeypatch, _OPERATOR, _OPERATOR_TWO, service_identity="ops")

        with caplog.at_level(logging.WARNING, logger="trentina.gateway.service"):
            log_service_identity(profiles, "ops")

        messages = [record.getMessage() for record in caplog.records]
        assert any("operator profile=ops," in text for text in messages)
        assert any("also hold role: operator (ops2)" in text for text in messages)

    def test_a_derived_ingress_is_not_counted_and_cannot_be_named(self) -> None:
        """A shared operator and its derivation are ONE operator, and the
        derivation is never the identity even when named: it is not a profile
        anybody wrote, so nobody chose it."""
        from tests.test_operator_across_federation import _shared_operator
        from trentina.gateway.federation_link import derive_ingress, ingress_name

        shared = _shared_operator()
        ingress = derive_ingress(shared)
        registry = {ingress.name: ingress, shared.name: shared}

        assert [p.name for p in written_operators(registry)] == ["josui"]
        found = find_operator(registry, ingress_name("josui"))
        assert found is not None and found.name == "josui"


class TestServiceContext:
    def test_binds_the_operator(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        with service_context() as bound:
            assert bound is not None
            assert get_current_profile() is bound
            assert bound.name == "ops"

    def test_a_tenant_bound_above_does_not_leak_in(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No operator: the gateway's work runs as the synthesized operator, never as the caller."""
        profiles = _live(tmp_path, monkeypatch, _TENANT)

        with profile_context(profiles["tenant"]):
            with service_context() as bound:
                assert bound.name == "standalone"
                assert get_current_profile() is bound
                assert get_current_profile() is not profiles["tenant"]
            assert get_current_profile() is profiles["tenant"]

    def test_an_explicit_operator_is_bound_without_resolving_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        chosen = profiles["tenant"]  # any Profile: the point is it is not re-resolved

        with (
            patch("trentina.gateway.service.service_profile") as resolve,
            service_context(chosen) as bound,
        ):
            assert bound is chosen
            assert get_current_profile() is chosen
        resolve.assert_not_called()

    def test_standalone_has_a_synthesized_operator_service_profile(self) -> None:
        assert service_profile().name == "standalone"
        assert service_profile().role == "operator"


class TestPerimeterRunsAsTheListingProfile:
    """6.1.0: a tool description is judged for the profile listing it, on that
    profile's own key.

    It ran as the service identity through 6.0.0, which meant one tenant's key
    paid to judge another tenant's tool list and the verdict was shareable.
    Scott's instruction: "Everything that a user's account touches should be
    done by its own key."
    """

    async def test_description_l3_sees_the_listing_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        seen: list[str | None] = []

        async def fake_defend(*_a: Any, **_k: Any) -> Any:
            bound = get_current_profile()
            seen.append(bound.name if bound else None)
            return MagicMock(flagged=False)

        with (
            patch.object(orch, "defend", fake_defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            tools = [{"name": "t", "description": "Lists things."}]
            await ing.scan_tool_list(profiles["tenant"], "b", tools, tools)

        assert seen == ["tenant"]

    async def test_the_operator_is_not_bound_even_when_it_is_the_caller(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A caller bound further up does not decide whose key pays: the profile
        whose list is being judged does, and it is bound here explicitly because
        warm-up reaches the same build with nothing bound at all."""
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        seen: list[str | None] = []

        async def fake_defend(*_a: Any, **_k: Any) -> Any:
            bound = get_current_profile()
            seen.append(bound.name if bound else None)
            return MagicMock(flagged=False)

        with (
            patch.object(orch, "defend", fake_defend),
            patch.object(ing, "build_warning", return_value=None),
            profile_context(profiles["ops"]),
        ):
            tools = [{"name": "t", "description": "Lists things."}]
            await ing.scan_tool_list(profiles["tenant"], "b", tools, tools)

        assert seen == ["tenant"]

    async def test_the_judge_is_the_listing_profiles_and_the_key_agrees(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One judge per list, and the verdict is filed under the judge that
        reached it — the listing profile's, not the operator's."""
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        tenant = profiles["tenant"]
        seen: list[str | None] = []

        async def fake_defend(*_a: Any, **_k: Any) -> Any:
            bound = get_current_profile()
            seen.append(bound.name if bound else None)
            return MagicMock(flagged=False)

        with (
            patch.object(orch, "defend", fake_defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            tools = [
                {"name": "a", "description": "Lists things."},
                {"name": "b", "description": "Counts things."},
            ]
            await ing.scan_tool_list(tenant, "b", tools, tools)

        assert seen == ["tenant", "tenant"]
        for tool in tools:
            surface = ing._tool_surface_text(tool)
            filed = ing._cache_key(tenant, "tool:external", surface, judge_of(tenant))
            assert filed in vc._descriptions
            # And NOT under the operator's judge, which is what used to pay.
            stale = ing._cache_key(tenant, "tool:external", surface, judge_of(profiles["ops"]))
            assert stale not in vc._descriptions

    def test_description_verdicts_are_keyed_by_the_listing_profiles_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        assert judge_of(service_profile()) == (get_config().provider, "ops-model")
        assert judge_of(profiles["tenant"]) == (get_config().provider, "tenant-model")

    def test_no_verdict_crosses_between_two_profiles(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same text, the same thresholds and the same judge still key
        apart, because the owner is in the key. This is the isolation Scott
        asked for: "These caches need to be insulated from each other."
        """
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        tenant, ops = profiles["tenant"], profiles["ops"]
        judge = judge_of(tenant)

        mine = vc._cache_key(tenant, "tool:external", "Lists things.", judge)
        theirs = vc._cache_key(ops, "tool:external", "Lists things.", judge)

        assert mine != theirs


class TestVerdictKey:
    def _profile(self) -> Profile:
        return Profile(name="p", auth=AuthConfig(bearer_token_env="T"))

    def test_the_judge_is_always_written_now(self) -> None:
        """The env-default judge used to be left out of the key so that rows
        persisted before #137 stayed reachable. 6.1.0 drops that: the owner
        makes every key new anyway and ``PERIMETER_VERSION`` sweeps the old
        rows, so a conditional spelling would only hide what the key holds."""
        provider, model = judge_of(None)
        explicit = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            defense=DefenseConfig(l2_threshold=0.5),
        )

        key = ing._cache_key(explicit, "tool:external", "some text", judge_of(None))

        assert (
            key
            == hashlib.sha256(
                f"tool:external:owner=p:0.5:{provider}/{model}:some text".encode()
            ).hexdigest()
        )

    def test_an_unset_l2_threshold_is_keyed_apart_from_an_explicit_one(self) -> None:
        """Unset means the model's own threshold (#350), not 0.5."""
        provider, model = judge_of(None)
        unset = ing._cache_key(self._profile(), "tool:external", "x", judge_of(None))
        explicit = ing._cache_key(
            Profile(
                name="p",
                auth=AuthConfig(bearer_token_env="T"),
                defense=DefenseConfig(l2_threshold=0.5),
            ),
            "tool:external",
            "x",
            judge_of(None),
        )

        assert (
            unset
            == hashlib.sha256(
                f"tool:external:owner=p:model:{provider}/{model}:x".encode()
            ).hexdigest()
        )
        assert unset != explicit

    def test_the_owner_is_in_the_key_and_a_derivation_shares_it(self) -> None:
        """A derived federation ingress spends its source's credential and key,
        so it reads its source's verdicts; anything else is its own.

        Built by the real ``derive_ingress`` rather than by hand — a derivation
        carries no ``auth`` of its own (``federation.peers`` is how a primary
        authenticates), so a hand-built one does not validate.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from trentina.gateway.federation_link import derive_ingress
        from trentina.gateway.profile import FederationConfig, FederationPeer

        peer_pem = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        source = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            # A shared source needs at least one offerable remote backend, or
            # the derivation is an empty link and `derive_ingress` refuses it.
            backends={"wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"])},
            federation=FederationConfig(peers={"peer": FederationPeer(public_key=peer_pem)}),
        )
        derived = derive_ingress(source)
        other = Profile(name="q", auth=AuthConfig(bearer_token_env="T"))

        mine = ing._cache_key(source, "tool:external", "x", judge_of(source))
        theirs = ing._cache_key(derived, "tool:external", "x", judge_of(derived))
        stranger = ing._cache_key(other, "tool:external", "x", judge_of(other))

        assert derived.grant_owner == source.name
        assert mine == theirs
        assert mine != stranger

    def test_a_different_model_is_a_different_verdict(self) -> None:
        provider, model = judge_of(None)
        default = ing._cache_key(self._profile(), "tool:external", "x", (provider, model))
        other = ing._cache_key(self._profile(), "tool:external", "x", (provider, model + "-b"))

        assert default != other

    def test_a_tool_response_is_keyed_by_the_tenants_model(self) -> None:
        plain = self._profile()
        custom = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            defense=DefenseConfig(model="tenant-model"),
        )

        assert ing._cache_key(plain, "response", "x", judge_of(plain)) != ing._cache_key(
            custom, "response", "x", judge_of(custom)
        )


class TestCompressionRunsAsTheListingProfile:
    """6.1.0: shortening a description is the listing profile's work, on its
    key, and the result lands in its own partition."""

    def _mock_provider(self) -> MagicMock:
        prov = MagicMock()
        prov.generate = AsyncMock(
            return_value=ProviderResult(
                text=json.dumps({"compressed": [{"id": "h", "text": "Short."}]}),
                input_tokens=1,
                output_tokens=1,
            )
        )
        return prov

    async def test_the_listing_profiles_key_and_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=self._mock_provider(),
        ) as get:
            await _call_compress_model([("h", "A long description.")], profiles["tenant"])

        (name,), kwargs = get.call_args
        assert name == get_config().provider
        assert kwargs["model"] == "tenant-model"
        assert kwargs["api_key"].get_secret_value() == "tenant-key"

    async def test_two_profiles_each_bill_their_own_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same description, two profiles, two keys — not one key twice.
        This is the billing half of Scott's instruction."""
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=self._mock_provider(),
        ) as get:
            await _call_compress_model([("h", "A long description.")], profiles["tenant"])
            await _call_compress_model([("h", "A long description.")], profiles["ops"])

        billed = [call.kwargs["api_key"].get_secret_value() for call in get.call_args_list]
        assert billed == ["tenant-key", "ops-key"]

    async def test_a_profile_with_no_key_of_its_own_compresses_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``resolve_profile_llm`` refuses to bill anyone else's key, so there is
        no quiet fallback to the operator's — the batch simply comes back
        empty and the original description is kept."""
        _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        keyless = Profile(name="broke", auth=AuthConfig(bearer_token_env="T"))

        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=self._mock_provider(),
        ) as get:
            result = await _call_compress_model([("h", "A long description.")], keyless)

        assert result == []
        get.assert_not_called()


class TestPerProfileGeneration:
    def _profile(self, name: str) -> Profile:
        return Profile(
            name=name,
            auth=AuthConfig(bearer_token_env="T"),
            backends={"b": Backend(url=f"http://{name}:1/mcp")},
        )

    async def test_another_profiles_flush_does_not_discard_this_build(self) -> None:
        gate = asyncio.Event()

        async def slow_list(*_a: Any, **_k: Any) -> list[dict[str, Any]]:
            await gate.wait()
            return [{"name": "t", "description": "d", "inputSchema": {}}]

        async def passthrough(_p: Any, _b: Any, _before: Any, tools: Any) -> Any:
            return tools

        beta = self._profile("beta")
        with (
            patch.object(aggregate, "list_backend_tools", slow_list),
            patch.object(aggregate, "scan_tool_list", passthrough),
            patch.object(aggregate, "maybe_trigger_compression", AsyncMock()),
        ):
            build = asyncio.create_task(mcp._route_tools_list(beta, 1))
            await asyncio.sleep(0)
            aggregate.invalidate_profile_cache("alpha")
            gate.set()
            await build

        assert "beta" in aggregate._profile_tools_cache

    def test_invalidating_one_profile_leaves_the_others_generation(self) -> None:
        before = aggregate._cache_generation.get("beta", 0)

        aggregate.invalidate_profile_cache("alpha")

        assert aggregate._cache_generation.get("beta", 0) == before


class TestExplainMissing:
    def test_a_foreign_tombstone_reads_as_never_issued(self) -> None:
        registry = SessionRegistry()
        sid = registry.create_session("alpha")
        registry.delete_session(sid)

        scoped = registry.explain_missing(sid, for_profile="beta")
        full = registry.explain_missing(sid, None)

        assert "alpha" not in scoped
        assert "never issued" in scoped
        assert "profile=alpha" in full

    def test_the_owner_still_gets_the_cause(self) -> None:
        registry = SessionRegistry()
        sid = registry.create_session("alpha")
        registry.delete_session(sid)

        assert "profile=alpha" in registry.explain_missing(sid, for_profile="alpha")
