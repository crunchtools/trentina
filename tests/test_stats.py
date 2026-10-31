"""Tests for tools/stats.py — what quarantine_stats discloses, to whom.

The audit and the blocklist are one database for the whole gateway, so this
tool is the widest of the four. Two rows written by another profile are enough
to prove the filter: an unfiltered read names that profile, its backends, its
tools and the URLs it fetched.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from trentina.database import record_detection, record_gateway_call
from trentina.gateway import compress
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import (
    load_profiles,
    register_active_config,
)
from trentina.outcomes import Outcome
from trentina.perimeter_db import perimeter_stamp
from trentina.tools.stats import get_trentina_stats

pytestmark = pytest.mark.asyncio

YAML = """\
profiles:
  alpha:
    role: operator
    defense:
      provider: ollama  # the operator runs the gateway's own calls; keyless
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      jira:
        url: http://jira:1/mcp
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    defense:
      l2_threshold: 0.7
    backends:
      wiki:
        url: http://wiki:1/mcp
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    """Two profiles, and one audit row plus one detection each."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "trentina.db"))
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)

    record_gateway_call("alpha", "jira", "jira_delete_issue", Outcome.OK.value, 5)
    record_gateway_call("beta", "wiki", "wiki_get_page_tool", Outcome.OK.value, 5)
    record_detection(
        source_type="url",
        source="alpha:jira:jira_get_issue",
        domain="alpha-secret-intranet.example",
        layer1_stats={},
        risk_level="high",
        profile="alpha",
    )
    record_detection(
        source_type="url",
        source="beta:wiki:wiki_get_page_tool",
        domain="beta-wiki.example",
        layer1_stats={},
        risk_level="high",
        profile="beta",
    )
    yield config.profiles
    compress._profiles = None


class TestAgentScope:
    async def test_the_audit_holds_only_the_callers_calls(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        audit = result["gateway_audit"]
        assert audit["profile_filter"] == "beta"
        assert [e["tool"] for e in audit["by_tool"]] == ["wiki_get_page_tool"]

    async def test_another_profiles_detections_do_not_appear(self, gateway: dict) -> None:
        """A detection's source is 'profile:backend:tool' — it names names."""
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        assert result["blocklist"]["total_blocked"] == 1
        assert "alpha" not in str(result)
        assert "alpha-secret-intranet.example" not in str(result)

    async def test_the_config_block_is_the_profiles_own_defense(self, gateway: dict) -> None:
        """The process defaults never described a profile with overrides."""
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        assert result["scope"] == "beta"
        assert result["config"]["l2_threshold"] == 0.7
        # The mode policy it runs under (#193): unset, it is the default alone.
        assert result["config"]["modes"] == [result["config"]["enforcement"]]

    async def test_no_host_path_and_no_fleet_aggregate(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        assert "classifier_model_path" not in result["config"]
        assert "model_path" not in result["classifier"]
        assert "compression" not in result


class TestOperatorScope:
    async def test_the_whole_gateway_is_reported(self, gateway: dict) -> None:
        with profile_context(gateway["alpha"]):
            result = await get_trentina_stats()

        assert result["scope"] == "gateway"
        assert result["gateway_audit"]["profile_filter"] is None
        assert {e["tool"] for e in result["gateway_audit"]["by_tool"]} == {
            "jira_delete_issue",
            "wiki_get_page_tool",
        }
        assert result["blocklist"]["total_blocked"] == 2
        assert "compression" in result
        # 0.41.0: availability follows the provider chain, not Gemini's key.
        assert {"provider", "llm_available", "admission_tokens"} <= set(result["config"])
        assert "has_api_key" not in result["config"]

    async def test_the_operator_can_read_what_this_gateway_scans_under(
        self, gateway: dict
    ) -> None:
        """#637. Nothing exposed these before, so an operator asked to vet
        another gateway's scanner could not read its own for comparison, and
        could not tell a peer what to pin. Both are identities, not secrets."""
        with profile_context(gateway["alpha"]):
            result = await get_trentina_stats()

        assert result["perimeter"]["stamp"] == perimeter_stamp()
        # provider/model/pack, the shape a federated trust_verdict pins.
        assert result["perimeter"]["judge"].count("/") >= 2

    async def test_an_agent_does_not_get_the_perimeter_identity(
        self, gateway: dict
    ) -> None:
        """It is the gateway's, not a tenant's, and an agent's slice says only
        what that profile runs under."""
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        assert "perimeter" not in result


class TestUnknownCaller:
    async def test_a_live_gateway_with_no_caller_gets_nothing(self, gateway: dict) -> None:
        result = await get_trentina_stats()

        assert result["scope"] == "none"
        assert "gateway_audit" not in result


class TestSurface:
    @pytest.fixture
    def surfaces(self, gateway: dict) -> Iterator[dict]:
        from trentina.gateway import surface as s

        def one(offered: int, allowed: int, shaped: int) -> s.BackendSurface:
            return s.BackendSurface(s.Stage(10, offered), s.Stage(4, allowed), s.Stage(4, shaped))

        s.record_surface("alpha", s.Surface({"jira": one(8000, 4000, 3000)}, s.Stage(4, 2800)))
        s.record_surface("beta", s.Surface({"wiki": one(4000, 2000, 1600)}, s.Stage(4, 1500)))
        yield gateway
        s._surfaces.clear()

    async def test_an_agent_sees_its_own_surface_only(self, surfaces: dict) -> None:
        with profile_context(surfaces["beta"]):
            result = await get_trentina_stats()

        surface = result["surface"]
        assert list(surface["by_backend"]) == ["wiki"]
        assert surface["by_backend"]["wiki"]["shaped"]["bytes"] == 1600
        assert surface["offered"]["bytes"] == 4000
        assert surface["served"]["bytes"] == 1500
        assert surface["saved"]["by_allowlist"]["bytes"] == 2000
        assert surface["saved"]["by_shaping"]["bytes"] == 400
        assert surface["saved"]["by_short_names"]["bytes"] == 100
        assert surface["saved"]["total"]["est_tokens"] == 625
        assert "jira" not in str(surface)

    async def test_the_operator_sees_every_profile(self, surfaces: dict) -> None:
        with profile_context(surfaces["alpha"]):
            result = await get_trentina_stats()

        assert set(result["surface"]) == {"alpha", "beta"}

    async def test_an_unbuilt_profile_says_so(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await get_trentina_stats()

        assert "error" in result["surface"]
