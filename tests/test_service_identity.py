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
from trentina.gateway.service import (
    judge_of,
    service_context,
    service_profile,
)
from trentina.gateway.sessions import SessionRegistry
from trentina.quarantine.providers.base import ProviderResult
from trentina.transports import mcp

_TENANT = """\
  tenant:
    auth:
      bearer_token_env: TEST_TENANT_TOKEN
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


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *sections: str) -> Path:
    monkeypatch.setenv("TEST_TENANT_TOKEN", "t")
    monkeypatch.setenv("TEST_OPS_TOKEN", "o")
    path = tmp_path / "profiles.yaml"
    path.write_text("profiles:\n" + "".join(sections), encoding="utf-8")
    return path


def _live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *sections: str) -> dict[str, Profile]:
    path = _load(tmp_path, monkeypatch, *sections)
    config = load_profiles(path)
    register_active_config(path, config, {})
    return config.profiles


class TestLoadRules:
    def test_two_operators_refuse_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        second = _OPERATOR.replace("  ops:", "  ops2:")
        path = _load(tmp_path, monkeypatch, _OPERATOR, second)

        with pytest.raises(ProfileConfigError, match="at most one profile"):
            load_profiles(path)

    def test_an_operator_without_a_key_for_its_provider_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        keyless = _OPERATOR.replace("    llm_keys:\n      gemini:\n        api_key: ops-key\n", "")
        path = _load(tmp_path, monkeypatch, keyless)

        with pytest.raises(ProfileConfigError, match="no llm_keys"):
            load_profiles(path)

    def test_a_key_for_another_provider_does_not_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key must be for the provider the service identity RESOLVES to."""
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
        """No operator: the gateway's work runs env-global, never as the caller."""
        profiles = _live(tmp_path, monkeypatch, _TENANT)

        with profile_context(profiles["tenant"]):
            with service_context() as bound:
                assert bound is None
                assert get_current_profile() is None
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

    def test_an_explicit_none_binds_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        with profile_context(profiles["tenant"]), service_context(None) as bound:
            assert bound is None
            assert get_current_profile() is None

    def test_standalone_has_no_service_profile(self) -> None:
        assert service_profile() is None


class TestPerimeterRunsAsTheOperator:
    async def test_description_l3_sees_the_operator(
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
            profile_context(profiles["tenant"]),
        ):
            tools = [{"name": "t", "description": "Lists things."}]
            await ing.scan_tool_list(profiles["tenant"], "b", tools, tools)

        assert seen == ["ops"]

    async def test_a_reload_mid_scan_does_not_split_key_and_judge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The operator is resolved once per list; a later resolution is ignored."""
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)
        first, second = profiles["ops"], profiles["tenant"]
        seen: list[str | None] = []

        async def fake_defend(*_a: Any, **_k: Any) -> Any:
            bound = get_current_profile()
            seen.append(bound.name if bound else None)
            return MagicMock(flagged=False)

        with (
            patch.object(ing, "service_profile", side_effect=[first, second, second]),
            patch.object(orch, "defend", fake_defend),
            patch.object(ing, "build_warning", return_value=None),
        ):
            tools = [
                {"name": "a", "description": "Lists things."},
                {"name": "b", "description": "Counts things."},
            ]
            await ing.scan_tool_list(profiles["tenant"], "b", tools, tools)

        assert seen == ["ops", "ops"]
        # ...and the verdicts are filed under the same judge that reached them.
        for tool in tools:
            surface = ing._tool_surface_text(tool)
            filed = ing._cache_key(profiles["tenant"], "tool:external", surface, judge_of(first))
            assert filed in vc._verdicts

    def test_description_verdicts_are_keyed_by_the_operators_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profiles = _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        assert judge_of(service_profile()) == (get_config().provider, "ops-model")
        assert judge_of(profiles["tenant"]) == (get_config().provider, "tenant-model")


class TestVerdictKey:
    def _profile(self) -> Profile:
        return Profile(name="p", auth=AuthConfig(bearer_token_env="T"))

    def test_the_env_default_judge_keeps_the_legacy_key(self) -> None:
        """The env-default judge adds nothing to the key, as before #137."""
        legacy = hashlib.sha256(b"tool:external:0.5:some text").hexdigest()
        explicit = Profile(
            name="p",
            auth=AuthConfig(bearer_token_env="T"),
            defense=DefenseConfig(l2_threshold=0.5),
        )

        key = ing._cache_key(explicit, "tool:external", "some text", judge_of(None))

        assert key == legacy

    def test_an_unset_l2_threshold_is_keyed_apart_from_an_explicit_one(self) -> None:
        """Unset means the model's own threshold (#350), not 0.5."""
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

        assert unset == hashlib.sha256(b"tool:external:model:x").hexdigest()
        assert unset != explicit

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


class TestCompressionRunsAsTheOperator:
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

    async def test_the_operators_key_and_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The tenant sorts first; that must not matter any more.
        _live(tmp_path, monkeypatch, _TENANT, _OPERATOR)

        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=self._mock_provider(),
        ) as get:
            await _call_compress_model([("h", "A long description.")])

        (name,), kwargs = get.call_args
        assert name == get_config().provider
        assert kwargs["model"] == "ops-model"
        assert kwargs["api_key"].get_secret_value() == "ops-key"

    async def test_no_operator_uses_the_env_global_provider(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _live(tmp_path, monkeypatch, _TENANT)

        with patch(
            "trentina.gateway.compress.get_provider",
            return_value=self._mock_provider(),
        ) as get:
            await _call_compress_model([("h", "A long description.")])

        get.assert_called_with()


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
