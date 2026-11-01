"""Tests for tools/cache.py — flushing within the caller's role.

This tool had no behavioral test at all, which is how it kept a substring
match over every cached URL in the process: `cache_flush("gw")` evicted
gw-work and gw-personal together, in whatever profile they lived.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from trentina.gateway import compress
from trentina.gateway.aggregate import _profile_tools_cache
from trentina.gateway.backend import _tool_list_cache
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import (
    load_profiles,
    register_active_config,
)
from trentina.tools.cache import cache_flush

pytestmark = pytest.mark.asyncio

WORK_URL = "http://gw-work:1/mcp"
PERSONAL_URL = "http://gw-personal:1/mcp"
WIKI_URL = "http://wiki:1/mcp"

YAML = f"""\
profiles:
  alpha:
    role: operator
    defense:
      provider: ollama  # the operator runs the gateway's own calls; keyless
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      gw-work:
        url: {WORK_URL}
      wiki:
        url: {WIKI_URL}
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      gw-personal:
        url: {PERSONAL_URL}
      wiki:
        url: {WIKI_URL}
  gamma:
    auth:
      bearer_token_env: TEST_GAMMA_TOKEN
    backends:
      gw-personal:
        url: {PERSONAL_URL}
      wiki:
        url: {WIKI_URL}
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    """Two profiles, all three backends cached, both aggregates warm."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    monkeypatch.setenv("TEST_GAMMA_TOKEN", "c")
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    for url in (WORK_URL, PERSONAL_URL, WIKI_URL):
        _tool_list_cache[url] = [{"name": "a_tool"}]
    _profile_tools_cache["alpha"] = [{"name": "x"}]
    _profile_tools_cache["beta"] = [{"name": "y"}]
    yield config.profiles
    compress._profiles = None


class TestAgentScope:
    async def test_no_argument_drops_only_the_callers_aggregate(self, gateway: dict) -> None:
        """#263: the shared per-URL cache is left alone."""
        with profile_context(gateway["beta"]):
            result = await cache_flush()

        assert result == {"flushed": "profile", "scope": "beta", "profile_cache_cleared": True}
        assert set(_tool_list_cache) == {WORK_URL, PERSONAL_URL, WIKI_URL}
        assert "beta" not in _profile_tools_cache
        assert "alpha" in _profile_tools_cache

    async def test_a_named_backend_evicts_nothing_shared(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await cache_flush("wiki")

        assert result == {"flushed": "profile", "scope": "beta", "profile_cache_cleared": True}
        assert WIKI_URL in _tool_list_cache

    async def test_a_backend_in_another_profile_is_refused(self, gateway: dict) -> None:
        """The substring bug, as the caller would have hit it."""
        with profile_context(gateway["beta"]):
            result = await cache_flush("gw-work")

        assert result["flushed"] == "nothing"
        assert "not in this profile" in result["error"]
        assert WORK_URL in _tool_list_cache

    async def test_a_prefix_flushes_nothing(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await cache_flush("gw")

        assert result["flushed"] == "nothing"
        assert PERSONAL_URL in _tool_list_cache

    async def test_no_other_profile_is_named_or_counted(self, gateway: dict) -> None:
        """It used to report how many other profiles were still warm."""
        with profile_context(gateway["beta"]):
            result = await cache_flush()

        assert "alpha" not in str(result)
        assert "gw-work" not in str(result)

    async def test_the_callers_aggregate_goes_but_the_others_stays(self, gateway: dict) -> None:
        """A shared backend's eviction is felt; another profile's cache is not
        cleared by the caller's own flush of a backend it alone holds."""
        with profile_context(gateway["beta"]):
            await cache_flush("gw-personal")

        assert "beta" not in _profile_tools_cache
        assert "alpha" in _profile_tools_cache


def _bytes(result: dict) -> str:
    return json.dumps(result, sort_keys=True)


class TestNoChannelBetweenAgents:
    """#263's done-when: nothing gamma does changes a byte of beta's result."""

    async def test_beta_reads_the_same_bytes_whatever_gamma_did(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            baseline = _bytes(await cache_flush())
            named = _bytes(await cache_flush("wiki"))

        # Every move gamma has, each followed by beta's read, with the shared
        # cache entries warm and cold and gamma's own aggregate warm.
        for target in (None, "wiki", "gw-personal"):
            for warm in (True, False):
                for url in (PERSONAL_URL, WIKI_URL):
                    if warm:
                        _tool_list_cache[url] = [{"name": "a_tool"}]
                    else:
                        _tool_list_cache.pop(url, None)
                _profile_tools_cache["gamma"] = [{"name": "z"}]
                with profile_context(gateway["gamma"]):
                    await cache_flush(target)
                with profile_context(gateway["beta"]):
                    assert _bytes(await cache_flush()) == baseline
                    assert _bytes(await cache_flush("wiki")) == named

    async def test_betas_own_aggregate_state_is_not_reported(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            warm = _bytes(await cache_flush())
            cold = _bytes(await cache_flush())
        assert warm == cold


class TestTheEvictionCascadeSurvivesATestReset:
    """Evicting a backend's tool list must drop every profile aggregate built
    from it. ``aggregate`` wires that up by registering ``_on_backend_evicted``
    when the module is IMPORTED, and nothing re-registers it.

    ``reset_tool_list_cache`` used to clear the listener list along with the
    cached data, and ``tests/conftest.py`` calls it before every test — so the
    first test in a process unwired the cascade for the whole session. Every
    test of ``cache_flush``, ``reconnect_backend`` and tool pinning that ran
    second or later was exercising a gateway whose caches cannot cascade,
    which is not the gateway that ships. These two hold the wiring: the first
    on the registration, the second on the behaviour that depends on it.
    """

    async def test_the_listener_is_still_registered_after_a_reset(self) -> None:
        from trentina.gateway.aggregate import _on_backend_evicted
        from trentina.gateway.backend import _on_evict_callbacks, reset_tool_list_cache

        reset_tool_list_cache()

        assert _on_backend_evicted in _on_evict_callbacks, (
            "reset_tool_list_cache cleared import-time wiring, not just cached data"
        )

    async def test_an_eviction_still_drops_the_aggregates_built_from_it(self) -> None:
        from trentina.gateway.aggregate import _profile_backend_urls
        from trentina.gateway.backend import (
            evict_backend_cache_url,
            reset_tool_list_cache,
        )

        reset_tool_list_cache()
        # The state the cascade reads: one backend cached, and two profiles
        # whose aggregates were built from it.
        _tool_list_cache[WIKI_URL] = [{"name": "a_tool"}]
        for name in ("alpha", "beta"):
            _profile_tools_cache[name] = [{"name": "x"}]
            _profile_backend_urls[name] = {WIKI_URL}
        _profile_tools_cache["unrelated"] = [{"name": "z"}]
        _profile_backend_urls["unrelated"] = {PERSONAL_URL}

        assert evict_backend_cache_url(WIKI_URL) == 1

        assert "alpha" not in _profile_tools_cache
        assert "beta" not in _profile_tools_cache
        # Only the profiles holding that URL: the cascade is targeted, not a
        # flush of everything.
        assert "unrelated" in _profile_tools_cache


class TestOperatorScope:
    async def test_no_argument_flushes_the_gateway(self, gateway: dict) -> None:
        with profile_context(gateway["alpha"]):
            result = await cache_flush()

        assert result["scope"] == "gateway"
        assert result["backend_caches_evicted"] == 3
        assert not _tool_list_cache
        assert not _profile_tools_cache

    async def test_a_name_resolves_through_the_registry_not_the_cache_keys(
        self, gateway: dict
    ) -> None:
        """'gw' is a substring of two cached URLs and the name of neither."""
        with profile_context(gateway["alpha"]):
            result = await cache_flush("gw")

        assert result["evicted"] == 0
        assert len(_tool_list_cache) == 3

    async def test_a_name_in_another_profile_is_reachable(self, gateway: dict) -> None:
        with profile_context(gateway["alpha"]):
            result = await cache_flush("gw-personal")

        assert result["evicted"] == 1
        assert PERSONAL_URL not in _tool_list_cache


class TestUnknownCaller:
    async def test_a_live_gateway_with_no_caller_flushes_nothing(self, gateway: dict) -> None:
        result = await cache_flush()

        assert result["flushed"] == "nothing"
        assert len(_tool_list_cache) == 3
