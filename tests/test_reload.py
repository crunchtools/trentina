"""Tests for tools/reload.py — apply a profiles.yaml edit without a restart.

The reload is exercised against a real YAML file on disk and the real loader,
because the bug it fixes lived exactly in the gap between the file and the
in-memory registry: a test that hands the tool a pre-built Profile would
never notice that gap reopening.

Two properties get the most attention here, because they are the two that
make the tool worth having rather than merely present:

* a refused reload leaves the running config untouched, and
* a reload re-judges nothing, so it costs seconds instead of the forty
  minutes a restart spends re-running ingress defense over every tool
  description.

Reloads are run through ``_reload_as`` rather than calling the tool bare,
because the gateway binds the calling profile around every internal dispatch
and both what the reload APPLIES and what it REPORTS follow from that caller's
role. A bare call is the no-caller case, which has its own test.

``alpha`` is the operator in these fixtures and ``beta`` an ordinary agent, so
a whole-file reload is ``_reload_as("alpha")`` and a self-scoped one is
``_reload_as("beta")``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from trentina.gateway import compress
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.filter import filter_tools
from trentina.gateway.loader import (
    get_active_config,
    load_profiles,
    register_active_config,
    replace_active_config,
    reset_active_config,
)
from trentina.gateway.router import (
    _profile_tools_cache,
    invalidate_profile_cache,
    invalidate_profile_cache_for_backend,
    route_jsonrpc,
)
from trentina.gateway.sessions import session_registry
from trentina.quarantine.classifier import ClassifierResult
from trentina.tools.reload import AGENT_SCOPE_NOTE, reload_profiles

pytestmark = pytest.mark.asyncio

_ROUTER = "trentina.gateway.router"

_BENIGN = ClassifierResult(label="BENIGN", score=0.01, latency_ms=1.0)

BASE_YAML = """\
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
        tools_allow: ["*"]
        tools_deny: []
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      wiki:
        url: http://wiki:1/mcp
        tools_allow: ["*"]
"""

BETA_MATRIX_YAML = BASE_YAML.replace(
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n",
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n"
    "    matrix_ingress:\n"
    "      source_networks: ['10.89.2.0/24']\n"
    "      preprocess:\n"
    "        processors: []\n"
    "        deadline_seconds: 20.0\n",
)

BETA_BRIDGE_YAML = BASE_YAML.replace(
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n",
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n"
    "    matrix_bridge:\n"
    "      public_user_id: '@beta:matrix.org'\n"
    "      bridge_url: http://127.0.0.1:8471\n"
    "      bridge_token_env: TEST_BETA_BRIDGE\n"
    "      ingress_token_env: TEST_BETA_INGRESS\n"
    "      enforcement: block\n"
    "      local:\n"
    "        homeserver: http://127.0.0.1:6167\n"
    "        server_name: beta.local\n"
    "        as_token_env: TEST_BETA_AS\n"
    "        hs_token_env: TEST_BETA_HS\n"
    "        agent_localpart: beta\n",
)

BETA_BRIDGE_FLAG_YAML = BETA_BRIDGE_YAML.replace("enforcement: block", "enforcement: flag")

# The same, with BOTH an operator-only field and an agent-settable one moved.
BETA_MATRIX_NARROWED_YAML = BETA_MATRIX_YAML.replace(
    "        processors: []\n        deadline_seconds: 20.0\n",
    "        processors: [select]\n        deadline_seconds: 5.0\n",
)

# The pre-0.21.0 spelling, which still has to load. `extractor: generic` is
# `processors: [select]`; `extractor: full` is the empty list.
BETA_MATRIX_OLD_SPELLING_YAML = BETA_MATRIX_YAML.replace(
    "      preprocess:\n        processors: []\n",
    "      scan_view:\n        extractor: full\n",
)

# alpha alone: the tail of the file, from "  beta:" on, cut off.
ALPHA_ONLY_YAML = BASE_YAML.split("  beta:", maxsplit=1)[0]

DENIED_YAML = BASE_YAML.replace(
    "        tools_deny: []\n",
    '        tools_deny: ["jira_delete_issue"]\n',
)

# Both profiles move at once: alpha gains a deny, beta swaps wiki for rt.
SWAPPED_BACKEND_YAML = DENIED_YAML.replace(
    '      wiki:\n        url: http://wiki:1/mcp\n        tools_allow: ["*"]\n',
    '      rt:\n        url: http://rt:1/mcp\n        tools_allow: ["rt_get*"]\n',
)

# beta alone gains a guard on a tool alpha has never heard of.
BETA_GUARDED_YAML = BASE_YAML.replace(
    '      wiki:\n        url: http://wiki:1/mcp\n        tools_allow: ["*"]\n',
    '      wiki:\n        url: http://wiki:1/mcp\n        tools_allow: ["*"]\n'
    "        request_guards:\n"
    "          wiki_delete_page_tool:\n"
    "            title:\n"
    '              deny: ["Runbook*"]\n',
)


@pytest.fixture
def profiles_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A running gateway: profiles on disk, loaded, and registered as live."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "alpha-secret")
    monkeypatch.setenv("TEST_BETA_TOKEN", "beta-secret")
    path = tmp_path / "profiles.yaml"
    path.write_text(BASE_YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield path
    reset_active_config()
    compress._profiles = None
    session_registry.reset()


def _registry() -> dict[str, Any]:
    active = get_active_config()
    assert active is not None
    return active.config.profiles


def _tools_result(names: list[str]) -> list[dict[str, Any]]:
    return [{"name": n, "description": f"{n} does a thing", "inputSchema": {}} for n in names]


async def _reload_as(profile_name: str, operator: bool | None = None) -> dict[str, Any]:
    """Reload the way the gateway does: with the caller's profile bound.

    The bound object is the pre-reload `Profile`, exactly as in production —
    the router looked it up before dispatching and the swap does not reach
    into that local. Pass ``operator=False`` to bind a copy of that profile
    demoted to agent, for the cases that need alpha's backends without
    alpha's role.
    """
    caller = _registry()[profile_name]
    if operator is not None:
        caller = caller.model_copy(update={"role": "operator" if operator else "agent"})
    with profile_context(caller):
        return await reload_profiles()


async def _list_tools(profile_name: str) -> list[str]:
    """Run a real tools/list against a mocked backend, returning tool names."""
    response = await route_jsonrpc(
        _registry()[profile_name],
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    return [t["name"] for t in response["result"]["tools"]]


class TestRefusedReload:
    async def test_uninitialized_gateway_reports_instead_of_raising(self) -> None:
        """A reload before startup is an answerable question, not a crash."""
        reset_active_config()
        result = await reload_profiles()
        assert result["reloaded"] is False
        assert result["error"] == "gateway not initialized"

    async def test_invalid_yaml_keeps_the_running_config(self, profiles_path: Path) -> None:
        """A file that does not parse changes nothing and says why."""
        profiles_path.write_text("profiles: [this is not a mapping]", encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is False
        assert "profiles" in result["error"]
        assert result["note"] == "running configuration left unchanged"
        assert sorted(_registry()) == ["alpha", "beta"]

    async def test_missing_env_var_keeps_the_running_config(self, profiles_path: Path) -> None:
        """Half a config is never installed: the unresolvable secret refuses it."""
        profiles_path.write_text(
            BASE_YAML
            + """\
  gamma:
    auth:
      bearer_token_env: TEST_GAMMA_TOKEN_NOT_SET
    backends:
      wiki:
        url: http://wiki:1/mcp
""",
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is False
        assert "TEST_GAMMA_TOKEN_NOT_SET" in result["error"]
        assert "gamma" not in _registry()

    async def test_dangling_llm_provider_reference_is_refused(self, profiles_path: Path) -> None:
        """Startup's cross-validation is re-run, or the 502 arrives later instead."""
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n    llm_keys:\n      anthropic:\n        api_key: sk-test\n",
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is False
        assert "anthropic" in result["error"]
        assert not _registry()["beta"].llm_keys


class TestAppliedReload:
    async def test_deny_edit_is_in_force_immediately(self, profiles_path: Path) -> None:
        """The edit that used to be inert: a new deny pattern, applied."""
        backend = _registry()["alpha"].backends["jira"]
        assert filter_tools([{"name": "jira_delete_issue"}], backend)

        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        reloaded_backend = _registry()["alpha"].backends["jira"]
        assert not filter_tools([{"name": "jira_delete_issue"}], reloaded_backend)

    async def test_registry_dict_identity_survives_the_swap(self, profiles_path: Path) -> None:
        """Every route holds THIS dict; replacing it would strand them all."""
        before = _registry()
        compress_view = compress.get_profiles()

        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        await _reload_as("alpha")

        assert _registry() is before
        assert compress_view is before

    async def test_diff_reports_allow_and_deny_moves(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["profiles"]["changed"] == ["alpha", "beta"]
        alpha = result["changes"]["alpha"]["backends_changed"]["jira"]
        assert alpha["tools_deny"] == {"added": ["jira_delete_issue"], "removed": []}

    async def test_diff_reports_backend_moves(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert result["changes"]["beta"]["backends_added"] == ["rt"]
        assert result["changes"]["beta"]["backends_removed"] == ["wiki"]

    async def test_diff_names_guard_parameters_without_echoing_patterns(
        self, profiles_path: Path
    ) -> None:
        """The motivating edit: a destructive tool gets a request guard."""
        profiles_path.write_text(
            BASE_YAML.replace(
                "        tools_deny: []\n",
                "        tools_deny: []\n"
                "        request_guards:\n"
                "          jira_delete_issue:\n"
                "            key:\n"
                '              deny: ["PROD-*"]\n',
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        guards = result["changes"]["alpha"]["backends_changed"]["jira"]["request_guards"]
        assert guards == {"jira_delete_issue": {"parameters_added": ["key"]}}
        assert "PROD-" not in str(result)

    async def test_diff_names_response_guard_fields_without_echoing_patterns(
        self, profiles_path: Path
    ) -> None:
        """The egress case: a backend gains a guard on what it may return."""
        profiles_path.write_text(
            BASE_YAML.replace(
                "        tools_deny: []\n",
                "        tools_deny: []\n"
                "        response_guards:\n"
                "          jira_get_issue:\n"
                "            content:\n"
                '              deny: ["*NIGHTJAR*"]\n',
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        guards = result["changes"]["alpha"]["backends_changed"]["jira"]["response_guards"]
        assert guards == {"jira_get_issue": {"fields_added": ["content"]}}
        assert "NIGHTJAR" not in str(result)

    async def test_added_and_removed_profiles_are_reported_and_applied(
        self, profiles_path: Path
    ) -> None:
        swapped_yaml = (
            ALPHA_ONLY_YAML
            + """\
  gamma:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      wiki:
        url: http://wiki:1/mcp
"""
        )
        profiles_path.write_text(swapped_yaml, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["profiles"]["added"] == ["gamma"]
        assert result["profiles"]["removed"] == ["beta"]
        assert sorted(_registry()) == ["alpha", "gamma"]

    async def test_unchanged_profiles_are_left_alone(self, profiles_path: Path) -> None:
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["profiles"]["unchanged"] == ["beta"]
        assert list(result["changes"]) == ["alpha"]

    async def test_sessions_for_a_removed_profile_are_dropped(self, profiles_path: Path) -> None:
        """A session whose profile no longer exists can only 404 from here."""
        session_registry.create_session("beta")
        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")

        result = await _reload_as("alpha")

        assert result["sessions_dropped"] == 1
        assert not session_registry.get_sessions_for_profile("beta")

    async def test_changed_profile_notifies_its_sessions(self, profiles_path: Path) -> None:
        """Clients refresh their tool list without a manual /mcp reconnect."""
        session_id = session_registry.create_session("alpha")
        queue = session_registry.subscribe(session_id)
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")

        result = await _reload_as("alpha")

        assert result["sessions_notified"] == {"alpha": 1}
        assert queue.get_nowait()["method"] == "notifications/tools/list_changed"


class TestOperatorScope:
    """The operator seat reloads the file and is told everything that moved."""

    async def test_every_profile_that_moved_is_reported(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        result = await _reload_as("alpha")

        assert result["scope"] == "gateway"
        assert result["profiles"]["changed"] == ["alpha", "beta"]
        assert sorted(result["changes"]) == ["alpha", "beta"]
        assert result["changes"]["beta"]["backends_added"] == ["rt"]

    async def test_the_whole_file_is_applied(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        await _reload_as("alpha")

        assert sorted(_registry()["beta"].backends) == ["rt"]
        assert not filter_tools(
            [{"name": "jira_delete_issue"}], _registry()["alpha"].backends["jira"]
        )


class TestAgentScope:
    """An agent profile reloads itself: its own section, its own diff.

    The gateway serves several agents from one file. What the others hold —
    their backend names, allowlist deltas, guarded parameter names — is the
    shape of their permissions, and a routine config reload is not an occasion
    to hand it over. Nor is it an occasion to put their edits into force.
    """

    async def test_only_the_callers_section_is_applied(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        result = await _reload_as("beta")

        assert result["applied"] == ["beta"]
        assert sorted(_registry()["beta"].backends) == ["rt"]
        # alpha's deny edit sat in the same file and stays on disk.
        assert filter_tools([{"name": "jira_delete_issue"}], _registry()["alpha"].backends["jira"])

    async def test_the_note_is_fixed_text_naming_nobody(self, profiles_path: Path) -> None:
        """Saying 'others were skipped' must not say WHO, or how many."""
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        result = await _reload_as("beta")

        assert result["note"] == AGENT_SCOPE_NOTE
        assert "alpha" not in str(result)
        assert "jira" not in str(result)

    async def test_the_callers_own_diff_comes_back(self, profiles_path: Path) -> None:
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        result = await _reload_as("beta")

        assert result["scope"] == "beta"
        assert result["changes"]["beta"]["backends_added"] == ["rt"]
        assert result["changes"]["beta"]["backends_removed"] == ["wiki"]

    async def test_a_guard_on_another_profile_leaks_nothing(self, profiles_path: Path) -> None:
        """beta gains a guard; alpha's own reload learns neither tool nor parameter."""
        profiles_path.write_text(BETA_GUARDED_YAML, encoding="utf-8")

        result = await _reload_as("alpha", operator=False)

        assert result["changes"] == {}
        assert "wiki_delete_page_tool" not in str(result)
        assert "beta" not in str(result)

    async def test_gateway_wide_settings_are_left_alone(self, profiles_path: Path) -> None:
        """Session limits are the terms every profile runs under, not beta's."""
        profiles_path.write_text(
            SWAPPED_BACKEND_YAML + "gateway:\n  session_ttl_seconds: 11\n",
            encoding="utf-8",
        )
        before_ttl = session_registry.session_ttl

        await _reload_as("beta")

        assert session_registry.session_ttl == before_ttl

    async def test_a_profile_cannot_apply_its_own_promotion(self, profiles_path: Path) -> None:
        """Promotion costs an operator reload or a restart, never one call."""
        profiles_path.write_text(
            # alpha steps down in the same edit: two operators is a load error.
            BASE_YAML.replace("  alpha:\n    role: operator\n", "  alpha:\n").replace(
                "  beta:\n    auth:",
                "  beta:\n    role: operator\n    defense:\n      provider: ollama\n    auth:",
            ),
            encoding="utf-8",
        )

        result = await _reload_as("beta")

        assert result["reloaded"] is False
        assert "role" in result["error"]
        assert _registry()["beta"].role == "agent"

    async def test_a_profile_missing_from_the_file_is_refused(self, profiles_path: Path) -> None:
        """Adding or removing a profile is a gateway-wide edit."""
        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")

        result = await _reload_as("beta")

        assert result["reloaded"] is False
        assert "beta" in _registry()

    async def test_a_refused_file_names_no_profiles(self, profiles_path: Path) -> None:
        """The error path hands an agent the parse error and nothing else."""
        profiles_path.write_text("profiles: [not, a, mapping]", encoding="utf-8")

        result = await _reload_as("beta")

        assert result["reloaded"] is False
        assert "profiles" not in result
        assert "path" not in result


class TestPerimeterIsOperatorOnly:
    """An agent may retune its own performance; it may not decide how much of
    a payload gets scanned."""

    async def test_agent_cannot_narrow_its_own_scan(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_MATRIX_YAML, encoding="utf-8")
        await _reload_as("alpha")  # operator puts the ingress in force

        profiles_path.write_text(BETA_MATRIX_NARROWED_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert result["reloaded"] is True
        ingress = _registry()["beta"].matrix_ingress
        assert ingress.preprocess.processors == [], (
            "an agent reload must not reshape its own perimeter"
        )
        assert ingress.preprocess.deadline_seconds == 5.0, (
            "but it may still retune its own performance"
        )
        held = result["not_applied"]["operator_only"]
        assert "matrix_ingress.preprocess.processors" in held

    async def test_agent_cannot_move_its_own_matrix_network(self, profiles_path: Path) -> None:
        """#330: the network is the proxy's credential; moved, an agent could
        answer for another agent's network."""
        profiles_path.write_text(BETA_MATRIX_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(
            BETA_MATRIX_YAML.replace("10.89.2.0/24", "10.89.0.0/16"), encoding="utf-8"
        )
        result = await _reload_as("beta")

        assert [str(n) for n in _registry()["beta"].matrix_ingress.source_networks] == [
            "10.89.2.0/24"
        ]
        assert "matrix_ingress.source_networks" in result["not_applied"]["operator_only"]

    async def test_agent_cannot_give_itself_a_matrix_ingress(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_MATRIX_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert _registry()["beta"].matrix_ingress is None
        assert "matrix_ingress" in result["not_applied"]["operator_only"]

    async def test_operator_reload_applies_it(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_MATRIX_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BETA_MATRIX_NARROWED_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert _registry()["beta"].matrix_ingress.preprocess.processors == ["select"]

    async def test_the_pre_0_21_spelling_is_refused(self, profiles_path: Path) -> None:
        """The old `scan_view.extractor` block is gone as of 0.29.0.

        It was migrated with a warning for eight minor releases. Every
        profile model is `extra="forbid()`, so a config still carrying it now
        fails the reload rather than loading as something the operator did
        not write — which is the outcome a removal is FOR.
        """
        profiles_path.write_text(BETA_MATRIX_OLD_SPELLING_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is False


BETA_GIT_YAML = (
    BASE_YAML.replace(
        "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n",
        "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n"
        "    git:\n"
        "      forge:\n"
        "        token_env: TEST_BETA_TOKEN\n"
        "        fetch: [acme/*]\n"
        "        push: [acme/widgets]\n"
        "        push_refs: ['refs/heads/beta/*']\n",
    )
    + "git_remotes:\n  forge:\n    upstream: https://git.example.com\n"
)

# The edit a talked-round agent would want: every repository, every branch.
BETA_GIT_WIDENED_YAML = BETA_GIT_YAML.replace(
    "        push: [acme/widgets]\n        push_refs: ['refs/heads/beta/*']\n",
    "        push: ['*/*']\n        push_refs: ['refs/heads/*']\n",
)


class TestGitIsOperatorOnly:
    """#453: which repositories and branches an agent may push to is not the
    agent's to reload. ``llm_keys`` is not held; this block is."""

    async def test_agent_cannot_widen_its_own_grant(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        await _reload_as("alpha")  # the operator puts the grant in force

        profiles_path.write_text(BETA_GIT_WIDENED_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert result["reloaded"] is True
        grant = _registry()["beta"].git["forge"]
        assert grant.push == ["acme/widgets"]
        assert grant.push_refs == ["refs/heads/beta/*"]
        assert not grant.may_move("refs/heads/main")
        assert "git" in result["not_applied"]["operator_only"]

    async def test_agent_cannot_give_itself_a_grant(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert _registry()["beta"].git == {}
        assert "git" in result["not_applied"]["operator_only"]

    async def test_agent_cannot_drop_its_own_deny(self, profiles_path: Path) -> None:
        denied = BETA_GIT_YAML.replace(
            "        fetch: [acme/*]\n", "        fetch: [acme/*]\n        deny: ['*-private']\n"
        )
        profiles_path.write_text(denied, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert _registry()["beta"].git["forge"].deny == ["*/*-private"]
        assert "git" in result["not_applied"]["operator_only"]

    async def test_operator_reload_applies_it(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BETA_GIT_WIDENED_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert _registry()["beta"].git["forge"].push == ["*/*"]
        assert "git" in result["changes"]["beta"]["fields_changed"]

    async def test_operator_reload_applies_an_edited_remote(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        await _reload_as("alpha")
        active = get_active_config()
        assert active is not None
        assert active.config.git_remotes["forge"].host == "git.example.com"

        profiles_path.write_text(
            BETA_GIT_YAML.replace("git.example.com", "git.example.org"), encoding="utf-8"
        )
        await _reload_as("alpha")
        active = get_active_config()
        assert active is not None
        assert active.config.git_remotes["forge"].host == "git.example.org"

    async def test_a_first_remote_on_a_gateway_started_without_one_needs_a_restart(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(BETA_GIT_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert any("git_remotes" in note and "restart" in note for note in result["not_applied"])

    async def test_a_dangling_remote_refuses_the_reload(self, profiles_path: Path) -> None:
        profiles_path.write_text(
            BETA_GIT_YAML.replace("  forge:\n    upstream", "  other:\n    upstream"),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is False
        assert "git_remotes" in result["error"]
        assert _registry()["beta"].git == {}


class TestDefenseIsOperatorOnly:
    """An agent cannot loosen its own defense block by reloading (#298)."""

    BETA_BLOCK_YAML = BASE_YAML.replace(
        "  beta:\n    auth:",
        "  beta:\n    defense:\n      enforcement: block\n      audit: true\n    auth:",
    )
    BETA_LOOSE_YAML = BASE_YAML.replace(
        "  beta:\n    auth:",
        "  beta:\n    defense:\n      enforcement: flag\n      modes: [flag, block]\n"
        "      audit: false\n      l2_threshold: 0.99\n    auth:",
    )

    async def test_agent_cannot_loosen_its_own_defense(self, profiles_path: Path) -> None:
        profiles_path.write_text(self.BETA_BLOCK_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(self.BETA_LOOSE_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert result["reloaded"] is True
        defense = _registry()["beta"].defense
        assert defense.enforcement == "block"
        assert defense.modes == ["block"]
        assert defense.audit is True
        assert defense.l2_threshold is None
        held = result["not_applied"]["operator_only"]
        for field in ("enforcement", "modes", "audit", "l2_threshold"):
            assert f"defense.{field}" in held

    async def test_operator_reload_applies_it(self, profiles_path: Path) -> None:
        profiles_path.write_text(self.BETA_BLOCK_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(self.BETA_LOOSE_YAML, encoding="utf-8")
        await _reload_as("alpha")

        assert _registry()["beta"].defense.audit is False


class TestProxyOAuthIsRestartOnly:
    """The OAuth proxy binds clients, redirects and resources at startup (#298)."""

    @staticmethod
    def _yaml(redirects: str, emails: str = "[alice@example.com]") -> str:
        return BASE_YAML.replace(
            "  beta:\n",
            "  beta:\n"
            "    oauth:\n"
            "      enabled: true\n"
            f"      allowed_emails: {emails}\n"
            f"      allowed_redirect_uris: {redirects}\n",
        )

    async def test_a_redirect_edit_is_reported_not_claimed(self, profiles_path: Path) -> None:
        profiles_path.write_text(self._yaml("[]"), encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(self._yaml("['https://new.example/cb']"), encoding="utf-8")
        operator = await _reload_as("alpha")
        assert any("allowed_redirect_uris" in note for note in operator["not_applied"])

        profiles_path.write_text(self._yaml("['https://newer.example/cb']"), encoding="utf-8")
        agent = await _reload_as("beta")
        notes = agent["not_applied"]["restart_required"]
        assert any("allowed_redirect_uris" in note for note in notes)

    async def test_an_allowlist_edit_applies_live(self, profiles_path: Path) -> None:
        profiles_path.write_text(self._yaml("[]"), encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(
            self._yaml("[]", emails="[alice@example.com, bob@example.com]"), encoding="utf-8"
        )
        result = await _reload_as("beta")

        assert "not_applied" not in result
        assert "bob@example.com" in _registry()["beta"].oauth.allowed_emails


class TestBridgeIsOperatorOnly:
    """Every field of matrix_bridge shapes the perimeter (#162)."""

    async def test_agent_cannot_move_its_own_bridge(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_BRIDGE_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BETA_BRIDGE_FLAG_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert result["reloaded"] is True
        assert _registry()["beta"].matrix_bridge.enforcement == "block"
        assert "matrix_bridge" in result["not_applied"]["operator_only"]

    async def test_agent_cannot_remove_its_own_bridge(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_BRIDGE_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BASE_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        assert _registry()["beta"].matrix_bridge is not None
        assert "matrix_bridge" in result["not_applied"]["operator_only"]

    async def test_removing_a_bridged_profile_says_so(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_BRIDGE_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert any("bridges changed for ['beta']" in n for n in result["not_applied"])

    async def test_a_profile_with_no_bridge_moves_no_bridge(self, profiles_path: Path) -> None:
        """Adding or removing a profile that has no bridge is not a bridge change."""
        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")
        await _reload_as("alpha")
        profiles_path.write_text(BASE_YAML, encoding="utf-8")
        added = await _reload_as("alpha")
        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")
        removed = await _reload_as("alpha")

        for result in (added, removed):
            assert not any("bridges changed" in str(n) for n in result["not_applied"])

    async def test_operator_reload_says_a_restart_is_needed(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_BRIDGE_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("bridges changed for ['beta']" in n for n in result["not_applied"])


class TestUnknownCaller:
    async def test_no_bound_profile_is_refused_outright(self, profiles_path: Path) -> None:
        """A live gateway with no caller is a path nobody designed."""
        profiles_path.write_text(SWAPPED_BACKEND_YAML, encoding="utf-8")

        result = await reload_profiles()

        assert result["reloaded"] is False
        assert "no calling profile" in result["error"]
        # And nothing moved.
        assert sorted(_registry()["beta"].backends) == ["wiki"]


class TestUnappliedSections:
    async def test_llm_providers_change_is_reported_as_restart_only(
        self, profiles_path: Path
    ) -> None:
        """The section bound into a route closure at startup cannot reload."""
        profiles_path.write_text(
            BASE_YAML
            + """\
llm_providers:
  anthropic:
    base_url: https://api.anthropic.com
    api_key_env: TEST_ALPHA_TOKEN
""",
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("llm_providers" in note for note in result["not_applied"])

    async def test_matrix_section_change_is_reported_as_restart_only(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(
            BASE_YAML + "matrix:\n  enabled: true\n",
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("matrix section" in note for note in result["not_applied"])

    async def test_new_alert_ingress_without_a_route_is_reported(
        self, profiles_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The route is registered at startup only if some profile had one."""
        monkeypatch.setenv("TEST_ALERT_TOKEN", "alert-secret")
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n"
                "    alert_ingress:\n"
                "      token_env: TEST_ALERT_TOKEN\n"
                "      forward_url: https://hermes.example/hook\n",
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("alert_ingress" in note for note in result["not_applied"])

    async def test_new_matrix_ingress_without_a_route_is_reported(
        self, profiles_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A matrix_ingress is inert while matrix.enabled is off."""
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n    matrix_ingress:\n      source_networks: ['10.89.2.0/24']\n",
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("matrix_ingress" in note for note in result["not_applied"])

    async def test_a_plain_profile_edit_reports_nothing_unapplied(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await _reload_as("alpha")
        assert result["not_applied"] == []

    async def test_new_delegated_profile_is_reported_as_restart_only(
        self, profiles_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A delegated verifier is built once at startup and bound into the
        OAuthContext the route closures hold. Reporting success over this would
        leave the profile 401ing while the operator believed it applied."""
        monkeypatch.setenv("TEST_GEMINI_AUD", "client.apps.googleusercontent.com")
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n"
                "    oauth:\n"
                "      enabled: true\n"
                "      allowed_emails: [alice@example.com]\n"
                "      issuer: https://accounts.google.com\n"
                "      audience_env: TEST_GEMINI_AUD\n",
            ),
            encoding="utf-8",
        )
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert any("delegates OAuth" in note for note in result["not_applied"])

    async def test_agent_scope_reports_its_own_delegated_change(
        self, profiles_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The agent path applies only its own section, so it has to carry the
        same warning — otherwise the note depends on who called."""
        monkeypatch.setenv("TEST_GEMINI_AUD", "client.apps.googleusercontent.com")
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n"
                "    oauth:\n"
                "      enabled: true\n"
                "      allowed_emails: [alice@example.com]\n"
                "      issuer: https://accounts.google.com\n"
                "      audience_env: TEST_GEMINI_AUD\n",
            ),
            encoding="utf-8",
        )
        result = await _reload_as("beta", operator=False)

        assert result["reloaded"] is True
        assert any("delegates OAuth" in note for note in result["not_applied"]["restart_required"])

    async def test_replacing_a_config_before_startup_is_a_programming_error(
        self, profiles_path: Path
    ) -> None:
        """A reload cannot precede startup; the holder refuses to invent one."""
        config = load_profiles(profiles_path)
        reset_active_config()
        with pytest.raises(RuntimeError, match="before register_active_config"):
            replace_active_config(config)


class TestCacheBehaviour:
    async def test_changed_profile_rebuilds_and_unchanged_one_does_not(
        self, profiles_path: Path
    ) -> None:
        """Only the edited profile's aggregate is thrown away."""
        with (
            patch(
                f"{_ROUTER}.list_backend_tools",
                AsyncMock(return_value=_tools_result(["jira_get_issue"])),
            ),
            patch(
                "trentina.defense.classify_async",
                AsyncMock(return_value=_BENIGN),
            ),
        ):
            await _list_tools("alpha")
            await _list_tools("beta")
            assert set(_profile_tools_cache) == {"alpha", "beta"}

            profiles_path.write_text(DENIED_YAML, encoding="utf-8")
            result = await _reload_as("alpha")

        assert result["caches_invalidated"] == ["alpha"]
        assert set(_profile_tools_cache) == {"beta"}

    async def test_reload_rejudges_no_tool_descriptions(self, profiles_path: Path) -> None:
        """The whole point: a profile edit costs zero defense-pipeline runs.

        A restart re-judges every description through L1/L2/L3 because the
        process loses the verdict cache. A reload keeps it, and the verdict
        key is (kind, thresholds, text) — none of which a tools_deny edit
        touches — so the rebuilt aggregate is a pure cache read.
        """
        from trentina import orchestrator

        judged: list[str] = []
        real_defend = orchestrator.defend

        async def counting_defend(*args: Any, **kwargs: Any) -> Any:
            judged.append(str(kwargs.get("source")))
            return await real_defend(*args, **kwargs)

        # A working L3 matters here, not as scenery: a verdict reached while
        # L3 was unavailable is deliberately NOT cached (see
        # ingress_defense._cache_put — an outage's "clean" must not outlive
        # the outage), and this test is about the cache holding across a
        # reload. Without a judge there is nothing to cache and nothing to
        # measure.
        with (
            patch(
                f"{_ROUTER}.list_backend_tools",
                AsyncMock(return_value=_tools_result(["jira_get_issue", "jira_delete_issue"])),
            ),
            patch(
                "trentina.defense.classify_async",
                AsyncMock(return_value=_BENIGN),
            ),
            patch("trentina.defense.get_config") as _cfg,
            patch(
                "trentina.defense.quarantine_detect",
                AsyncMock(return_value={"injection_detected": False, "risk_level": "low"}),
            ),
            patch("trentina.orchestrator.defend", counting_defend),
        ):
            _cfg.return_value.has_api_key = True
            _cfg.return_value.admission_tokens = 32_768
            assert await _list_tools("alpha") == ["get_issue", "delete_issue"]
            after_warmup = len(judged)
            assert after_warmup == 2

            profiles_path.write_text(DENIED_YAML, encoding="utf-8")
            await _reload_as("alpha")

            assert await _list_tools("alpha") == ["get_issue"]

        assert len(judged) == after_warmup

    async def test_backend_change_rearms_compression_and_a_deny_edit_does_not(
        self, profiles_path: Path
    ) -> None:
        """A newly added backend has uncompressed descriptions; a deny does not."""
        compress._compress_triggered = True
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        await _reload_as("alpha")
        assert compress._compress_triggered is True

        profiles_path.write_text(
            DENIED_YAML.replace(
                "      wiki:\n",
                "      rt:\n        url: http://rt:1/mcp\n      wiki:\n",
            ),
            encoding="utf-8",
        )
        await _reload_as("alpha")
        assert compress._compress_triggered is False

    async def test_an_inflight_build_is_not_cached_across_a_backend_eviction(
        self, profiles_path: Path
    ) -> None:
        """Same window, reached the other way: a backend evicted mid-build.

        The eviction cascade runs while the aggregation is still fanning out,
        so without the generation bump the result it writes would reinstate
        the very list the eviction was meant to discard.
        """
        gate = asyncio.Event()

        async def slow_list(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
            await gate.wait()
            return _tools_result(["jira_get_issue"])

        with patch(
            "trentina.defense.classify_async",
            AsyncMock(return_value=_BENIGN),
        ):
            # The eviction cascade only knows a profile's backend URLs once an
            # aggregate has been cached, so warm one first — with a fast list.
            with patch(
                f"{_ROUTER}.list_backend_tools",
                AsyncMock(return_value=_tools_result(["jira_get_issue"])),
            ):
                await _list_tools("alpha")

            # What cache_flush leaves behind: the aggregate gone, the
            # backend-URL map still mapping alpha to jira.
            _profile_tools_cache.pop("alpha")
            with patch(f"{_ROUTER}.list_backend_tools", slow_list):
                build = asyncio.create_task(_list_tools("alpha"))
                await asyncio.sleep(0)
                invalidate_profile_cache_for_backend("http://jira:1/mcp")
                gate.set()
                await build

        assert "alpha" not in _profile_tools_cache

    async def test_an_inflight_build_is_not_cached_across_an_invalidation(
        self, profiles_path: Path
    ) -> None:
        """An aggregate assembled from the pre-reload profile must not land.

        Popping the cache key is not enough on its own: the build already
        running writes after the pop, and would reinstate the allowlist the
        reload just replaced.
        """
        gate = asyncio.Event()

        async def slow_list(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
            await gate.wait()
            return _tools_result(["jira_delete_issue"])

        with (
            patch(f"{_ROUTER}.list_backend_tools", slow_list),
            patch(
                "trentina.defense.classify_async",
                AsyncMock(return_value=_BENIGN),
            ),
        ):
            build = asyncio.create_task(_list_tools("alpha"))
            await asyncio.sleep(0)
            invalidate_profile_cache("alpha")
            gate.set()
            assert await build == ["delete_issue"]

        assert "alpha" not in _profile_tools_cache


class TestServiceIdentityMoves:
    """Every profile's descriptions are judged on the operator's model (#138)."""

    async def test_a_new_operator_model_invalidates_every_profile(
        self, profiles_path: Path
    ) -> None:
        _profile_tools_cache["beta"] = []
        profiles_path.write_text(
            BASE_YAML.replace(
                "      provider: ollama  # the operator runs the gateway's own calls; keyless\n",
                "      provider: ollama\n      model: another-model\n",
            ),
            encoding="utf-8",
        )

        result = await _reload_as("alpha")

        assert result["service_identity_moved"] is True
        # beta's own section did not change; its verdicts' judge did.
        assert "beta" in result["caches_invalidated"]
        assert "beta" not in _profile_tools_cache

    async def test_a_new_operator_model_notifies_every_profiles_sessions(
        self, profiles_path: Path
    ) -> None:
        """Withheld tools may come back, or go, under the new judge."""
        sid = session_registry.create_session("beta")
        queue = session_registry.subscribe(sid)
        profiles_path.write_text(
            BASE_YAML.replace(
                "      provider: ollama  # the operator runs the gateway's own calls; keyless\n",
                "      provider: ollama\n      model: another-model\n",
            ),
            encoding="utf-8",
        )

        await _reload_as("alpha")

        assert queue.get_nowait()["method"] == "notifications/tools/list_changed"

    async def test_an_unrelated_edit_leaves_the_others_cached(self, profiles_path: Path) -> None:
        _profile_tools_cache["beta"] = []
        profiles_path.write_text(
            BASE_YAML.replace("tools_deny: []", 'tools_deny: ["jira_delete*"]', 1),
            encoding="utf-8",
        )

        result = await _reload_as("alpha")

        assert result["service_identity_moved"] is False
        assert "beta" in _profile_tools_cache


BETA_GUARDED_EXECUTION_YAML = BASE_YAML.replace(
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n",
    "  beta:\n    auth:\n      bearer_token_env: TEST_BETA_TOKEN\n"
    "    intent_guards:\n"
    "      policy: Edits stay on our own pages.\n"
    "      tools:\n"
    "        wiki: [edit_page]\n",
)


class TestGuardedExecutionIsOperatorOnly:
    """#456: which calls are judged, and by what rule, is not the agent's to reload."""

    async def test_agent_cannot_drop_its_own_gatekeeper(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GUARDED_EXECUTION_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(BASE_YAML, encoding="utf-8")
        result = await _reload_as("beta")

        guarded = _registry()["beta"].intent_guards
        assert guarded is not None
        assert guarded.guards("wiki", "edit_page")
        assert "intent_guards" in result["not_applied"]["operator_only"]

    async def test_agent_cannot_rewrite_the_policy(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GUARDED_EXECUTION_YAML, encoding="utf-8")
        await _reload_as("alpha")

        profiles_path.write_text(
            BETA_GUARDED_EXECUTION_YAML.replace(
                "Edits stay on our own pages.", "Every call is within policy."
            ),
            encoding="utf-8",
        )
        await _reload_as("beta")

        guarded = _registry()["beta"].intent_guards
        assert guarded is not None
        assert guarded.policy == "Edits stay on our own pages."

    async def test_operator_reload_applies_it(self, profiles_path: Path) -> None:
        profiles_path.write_text(BETA_GUARDED_EXECUTION_YAML, encoding="utf-8")
        result = await _reload_as("alpha")

        assert result["reloaded"] is True
        assert _registry()["beta"].intent_guards is not None
