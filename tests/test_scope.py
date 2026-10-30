"""Tests for gateway/scope.py — who is calling, and what may they reach.

Every admin tool asks this module the same question, so its two edge rules get
the attention: a standalone server is single-tenant and sees everything, and a
live gateway with no bound caller is refused rather than assumed to be an
operator. Getting the second one backwards would turn every future ingress
into a gateway-wide hole.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trentina.gateway.context import profile_context
from trentina.gateway.errors import ScopeError
from trentina.gateway.loader import (
    load_profiles,
    register_active_config,
)
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.scope import (
    current_scope,
    require_caller,
    require_operator,
    resolve_backend,
)

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
    backends:
      wiki:
        url: http://wiki:1/mcp
"""


def _profile(name: str, role: str = "agent", **kwargs: object) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TEST"),
        role=role,  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture
def live_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A registered ActiveConfig — i.e. a running, multi-tenant gateway."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    register_active_config(path, load_profiles(path), {})


class TestStandalone:
    """No gateway means one tenant, and nothing to insulate it from."""

    def test_unbound_caller_gets_full_scope(self) -> None:
        scope = current_scope()

        assert scope.is_operator
        assert scope.name == "standalone"
        assert scope.label == "standalone"
        assert scope.backends == {}

    def test_require_caller_does_not_raise(self) -> None:
        assert require_caller("t").is_operator


class TestLiveGateway:
    def test_unbound_caller_is_refused(self, live_gateway: None) -> None:
        """The refusal that keeps a future ingress from becoming a hole."""
        with pytest.raises(ScopeError, match="no calling profile bound"):
            current_scope()

        with pytest.raises(ScopeError, match="no calling profile bound"):
            require_caller("quarantine_stats")

    def test_bound_agent_is_not_an_operator(self, live_gateway: None) -> None:
        with profile_context(_profile("beta")):
            scope = require_caller("t")

        assert scope.name == "beta"
        assert not scope.is_operator

    def test_bound_operator_holds_the_role(self, live_gateway: None) -> None:
        with profile_context(_profile("alpha", role="operator")):
            scope = require_caller("t")

        assert scope.is_operator
        require_operator(scope, "anything")

    def test_require_operator_refuses_an_agent(self, live_gateway: None) -> None:
        with profile_context(_profile("beta")):
            scope = require_caller("t")

        with pytest.raises(ScopeError, match="requires the operator role"):
            require_operator(scope, "flushing the gateway")


class TestResolveBackend:
    def test_exact_name_in_the_callers_profile(self) -> None:
        profile = _profile("beta", backends={"gw-work": Backend(url="http://w:1/mcp")})
        with profile_context(profile):
            url, cfg = resolve_backend(require_caller("t"), "gw-work")

        assert url == "http://w:1/mcp"
        assert cfg.url == url

    def test_a_prefix_is_not_a_match(self) -> None:
        """The bug this replaces: 'gw' used to reach gw-work and gw-personal."""
        profile = _profile(
            "beta",
            backends={
                "gw-work": Backend(url="http://work:1/mcp"),
                "gw-personal": Backend(url="http://personal:1/mcp"),
            },
        )
        with profile_context(profile), pytest.raises(ScopeError):
            resolve_backend(require_caller("t"), "gw")

    def test_a_backend_in_another_profile_is_simply_absent(self) -> None:
        """The refusal must not distinguish 'no such backend' from 'not yours'."""
        profile = _profile("beta", backends={"wiki": Backend(url="http://w:1/mcp")})
        with profile_context(profile):
            scope = require_caller("t")
            with pytest.raises(ScopeError) as mine:
                resolve_backend(scope, "jira")
            with pytest.raises(ScopeError) as nonexistent:
                resolve_backend(scope, "nope")

        assert str(mine.value).replace("jira", "X") == str(nonexistent.value).replace("nope", "X")
