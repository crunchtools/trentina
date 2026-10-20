"""Tests for gateway/profile.py and gateway/loader.py."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    LlmKeyOverride,
    OAuthConfig,
    ParameterConstraint,
    Profile,
)


class TestOAuthConfig:
    """OAuthConfig: opt-in Google-backed access with an email allowlist."""

    def test_disabled_default(self) -> None:
        cfg = OAuthConfig()
        assert cfg.enabled is False
        assert cfg.allowed_emails == []

    def test_enabled_with_allowlist_valid(self) -> None:
        cfg = OAuthConfig(enabled=True, allowed_emails=["alice@example.com"])
        assert cfg.enabled is True
        assert cfg.allowed_emails == ["alice@example.com"]

    def test_emails_lowercased(self) -> None:
        cfg = OAuthConfig(enabled=True, allowed_emails=["  Alice@Example.COM "])
        assert cfg.allowed_emails == ["alice@example.com"]

    def test_enabled_without_allowlist_rejected(self) -> None:
        with pytest.raises(ValidationError, match="allowed_emails is empty"):
            OAuthConfig(enabled=True)

    def test_enabled_with_empty_allowlist_rejected(self) -> None:
        with pytest.raises(ValidationError, match="allowed_emails is empty"):
            OAuthConfig(enabled=True, allowed_emails=[])

    def test_disabled_without_allowlist_ok(self) -> None:
        # A block present but off is fine — nothing to authorize.
        cfg = OAuthConfig(enabled=False)
        assert cfg.allowed_emails == []

    @pytest.mark.parametrize(
        "bad",
        ["notanemail", "@example.com", "alice@", "alice@localhost", ""],
    )
    def test_malformed_email_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not an email"):
            OAuthConfig(enabled=True, allowed_emails=[bad])

    def test_extra_key_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            OAuthConfig(enabled=True, allowed_emails=["a@b.co"], sneaky=1)

    def test_subjects_default_empty(self) -> None:
        cfg = OAuthConfig(enabled=True, allowed_emails=["a@b.co"])
        assert cfg.allowed_subjects == []

    def test_an_unquoted_yaml_sub_is_taken_exactly(self) -> None:
        """#458: a 21-digit sub reaches us from YAML as an int, and must not round."""
        parsed = yaml.safe_load("allowed_subjects: [108123456789012345678, ' 42 ']")
        cfg = OAuthConfig(enabled=True, allowed_emails=["a@b.co"], **parsed)
        assert cfg.allowed_subjects == ["108123456789012345678", "42"]

    @pytest.mark.parametrize("bad", ["", "  ", "1 2", True, 1.5, None])
    def test_malformed_subject_rejected(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="not a Google account ID"):
            OAuthConfig(enabled=True, allowed_emails=["a@b.co"], allowed_subjects=[bad])

    def test_profile_oauth_optional_and_default_none(self) -> None:
        p = Profile(name="x", auth=AuthConfig(bearer_token_env="X"))
        assert p.oauth is None

    def test_profile_with_oauth_block(self) -> None:
        p = Profile(
            name="gemini-app",
            auth=AuthConfig(bearer_token_env="X"),
            oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
        )
        assert p.oauth is not None
        assert p.oauth.enabled is True


class TestProfileModel:
    """Pydantic-level unit tests for Profile / Backend / DefenseConfig."""

    def test_minimal_profile_valid(self) -> None:
        p = Profile(
            name="agent2",
            auth=AuthConfig(bearer_token_env="TRENTINA_PROFILE_AGENT2_TOKEN"),
        )
        assert p.name == "agent2"
        assert p.auth.bearer_token_env == "TRENTINA_PROFILE_AGENT2_TOKEN"
        assert p.backends == {}
        assert p.defense.enforcement == "flag"
        assert p.defense.audit is True

    def test_profile_with_backends(self) -> None:
        p = Profile(
            name="agent1",
            auth=AuthConfig(bearer_token_env="TRENTINA_PROFILE_AGENT1_TOKEN"),
            backends={
                "mcp-slack": Backend(url="http://mcp-slack:8000/mcp"),
                "mcp-atlassian": Backend(
                    url="http://mcp-atlassian:8000/mcp",
                    tools_deny=["jira_delete_issue"],
                ),
            },
        )
        assert len(p.backends) == 2
        assert p.backends["mcp-atlassian"].tools_deny == ["jira_delete_issue"]

    def test_bad_profile_name(self) -> None:
        with pytest.raises(ValidationError):
            Profile(
                name="Has_Underscore",
                auth=AuthConfig(bearer_token_env="X"),
            )

    def test_bad_backend_name(self) -> None:
        with pytest.raises(ValidationError):
            Profile(
                name="ok",
                auth=AuthConfig(bearer_token_env="X"),
                backends={"BAD_NAME": Backend(url="http://example/mcp")},
            )

    def test_bad_url_scheme(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="ftp://example/mcp")

    def test_internal_url_scheme_accepted(self) -> None:
        b = Backend(url="internal://web")
        assert b.is_internal is True

    def test_http_backend_is_not_internal(self) -> None:
        assert Backend(url="http://x/mcp").is_internal is False

    def test_internal_url_requires_slug_label(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="internal://")
        with pytest.raises(ValidationError):
            Backend(url="internal://Bad_Label")

    def test_bad_env_name(self) -> None:
        with pytest.raises(ValidationError):
            AuthConfig(bearer_token_env="lowercase_not_allowed")

    def test_extra_keys_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            Profile.model_validate(
                {
                    "name": "x",
                    "auth": {"bearer_token_env": "T"},
                    "extra_unexpected_key": True,
                }
            )

    def test_bad_glob_pattern_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_allow=["bad/pattern"])
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_allow=["-leading-hyphen"])
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_deny=["has space"])

    def test_glob_pattern_allowed(self) -> None:
        b = Backend(
            url="http://x/mcp",
            tools_allow=["*", "delete_*", "get_*_thing", "*_suffix"],
        )
        assert "*" in b.tools_allow

    def test_backend_with_parameter_guards(self) -> None:
        b = Backend(
            url="http://x/mcp",
            parameter_guards={
                "send_gmail_message": {
                    "to": ParameterConstraint(allow=["alice@example.com"]),
                    "cc": ParameterConstraint(allow=["alice@example.com"], deny=["banned@x.com"]),
                }
            },
        )
        assert "send_gmail_message" in b.parameter_guards
        assert b.parameter_guards["send_gmail_message"]["to"].allow == ["alice@example.com"]
        assert b.parameter_guards["send_gmail_message"]["cc"].deny == ["banned@x.com"]

    def test_parameter_guard_invalid_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ParameterConstraint(allow=["has;semicolon"])

    def test_parameter_guard_extra_keys_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ParameterConstraint.model_validate({"allow": ["*"], "unknown_field": True})

    def test_parameter_guard_valid_patterns(self) -> None:
        c = ParameterConstraint(allow=["*@corp.example.com", "you@example.com", "*"])
        assert len(c.allow) == 3

    def test_list_timeout_defaults(self) -> None:
        b = Backend(url="http://x/mcp")
        assert b.list_timeout_seconds == 30.0
        assert b.timeout_seconds == 30.0

    def test_list_timeout_custom(self) -> None:
        b = Backend(url="http://x/mcp", list_timeout_seconds=5.0)
        assert b.list_timeout_seconds == 5.0

    def test_list_timeout_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", list_timeout_seconds=0)
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", list_timeout_seconds=61.0)

    def test_defense_defaults(self) -> None:
        d = DefenseConfig()
        assert d.enforcement == "flag"
        assert d.audit is True
        assert d.audit is True
        assert d.l2_threshold is None  # the model's own threshold (#350)

    def test_defense_threshold_bounds(self) -> None:
        with pytest.raises(ValidationError):
            DefenseConfig(l2_threshold=1.5)
        with pytest.raises(ValidationError):
            DefenseConfig(quarantine_threshold=-0.1)

    def test_defense_provider_defaults_to_none(self) -> None:
        d = DefenseConfig()
        assert d.provider is None

    def test_defense_provider_valid_values(self) -> None:
        for name in ("gemini", "openai", "anthropic", "ollama"):
            d = DefenseConfig(provider=name)
            assert d.provider == name

    def test_defense_provider_invalid_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Unknown provider"):
            DefenseConfig(provider="unsupported-llm")

    def test_defense_provider_in_profile_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent2:
    auth:
      bearer_token_env: TEST_TOK
    defense:
      provider: anthropic
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        gateway_cfg = load_profiles(cfg)
        assert gateway_cfg.profiles["agent2"].defense.provider == "anthropic"

    def test_defense_provider_omitted_in_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent3:
    auth:
      bearer_token_env: TEST_TOK
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        gateway_cfg = load_profiles(cfg)
        assert gateway_cfg.profiles["agent3"].defense.provider is None


class TestLlmKeys:
    """Per-profile LLM proxy key overrides."""

    def test_llm_key_override_valid(self) -> None:
        override = LlmKeyOverride(api_key_env="AGENT1_GEMINI_API_KEY")
        assert override.api_key_env == "AGENT1_GEMINI_API_KEY"
        assert override.api_key.get_secret_value() == ""

    def test_llm_key_override_bad_env_name(self) -> None:
        with pytest.raises(ValidationError, match="UPPERCASE"):
            LlmKeyOverride(api_key_env="lowercase-key")

    def test_llm_key_override_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            LlmKeyOverride(api_key_env="KEY", surprise="nope")

    def test_profile_with_llm_keys(self) -> None:
        p = Profile(
            name="agent1",
            auth=AuthConfig(bearer_token_env="TRENTINA_PROFILE_AGENT1_TOKEN"),
            llm_keys={"gemini": LlmKeyOverride(api_key_env="AGENT1_GEMINI_API_KEY")},
        )
        assert p.llm_keys["gemini"].api_key_env == "AGENT1_GEMINI_API_KEY"

    def test_profile_llm_keys_default_empty(self) -> None:
        p = Profile(name="t", auth=AuthConfig(bearer_token_env="TEST"))
        assert p.llm_keys == {}

    def test_bad_provider_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Provider name"):
            Profile(
                name="t",
                auth=AuthConfig(bearer_token_env="TEST"),
                llm_keys={"Bad_Name": LlmKeyOverride(api_key_env="KEY")},
            )

    def test_llm_key_env_resolved_by_loader(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent1:
    auth:
      bearer_token_env: AGENT1_TOK
    llm_keys:
      gemini:
        api_key_env: AGENT1_GEMINI_API_KEY
"""
        )
        monkeypatch.setenv("AGENT1_TOK", "tok")
        monkeypatch.setenv("AGENT1_GEMINI_API_KEY", "gm-secret")
        gateway_cfg = load_profiles(cfg)
        key = gateway_cfg.profiles["agent1"].llm_keys["gemini"].api_key
        assert key.get_secret_value() == "gm-secret"

    def test_llm_key_env_missing_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent1:
    auth:
      bearer_token_env: AGENT1_TOK
    llm_keys:
      gemini:
        api_key_env: AGENT1_GEMINI_API_KEY
"""
        )
        monkeypatch.setenv("AGENT1_TOK", "tok")
        monkeypatch.delenv("AGENT1_GEMINI_API_KEY", raising=False)
        with pytest.raises(ProfileConfigError, match="AGENT1_GEMINI_API_KEY"):
            load_profiles(cfg)


class TestLoader:
    """End-to-end tests for the YAML profile loader."""

    def test_load_happy_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent2:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT2_TOKEN
    backends:
      mcp-slack:
        url: http://mcp-slack:8000/mcp
        tools_allow: ["*"]
        tools_deny: ["slack_destructive_*"]
"""
        )
        monkeypatch.setenv("TRENTINA_PROFILE_AGENT2_TOKEN", "tok-agent2")
        gateway_cfg = load_profiles(cfg)
        assert set(gateway_cfg.profiles) == {"agent2"}
        token = gateway_cfg.profiles["agent2"].auth.bearer_token
        assert token is not None
        assert token.get_secret_value() == "tok-agent2"

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ProfileConfigError, match="not found"):
            load_profiles(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("not: valid: yaml: [")
        with pytest.raises(ProfileConfigError, match="Invalid YAML"):
            load_profiles(cfg)

    def test_top_level_not_a_mapping(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("- a\n- b\n")
        with pytest.raises(ProfileConfigError, match="top-level mapping"):
            load_profiles(cfg)

    def test_missing_profiles_key(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("other_key: value\n")
        with pytest.raises(ProfileConfigError, match="non-empty 'profiles'"):
            load_profiles(cfg)

    def test_header_env_ref_expanded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
"""
        )
        monkeypatch.setenv("TRENTINA_PROFILE_AGENT1_TOKEN", "tok")
        monkeypatch.setenv("MCP_MEMORY_API_KEY", "memsecret")
        gateway_cfg = load_profiles(cfg)
        assert (
            gateway_cfg.profiles["agent1"].backends["memory"].headers["Authorization"]
            == "Bearer memsecret"
        )

    def test_header_env_ref_missing_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
"""
        )
        monkeypatch.setenv("TRENTINA_PROFILE_AGENT1_TOKEN", "tok")
        monkeypatch.delenv("MCP_MEMORY_API_KEY", raising=False)
        with pytest.raises(ProfileConfigError, match="MCP_MEMORY_API_KEY"):
            load_profiles(cfg)

    def test_missing_token_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  alice:
    auth:
      bearer_token_env: NEVER_SET_IN_ENV_FOR_TEST_123
"""
        )
        monkeypatch.delenv("NEVER_SET_IN_ENV_FOR_TEST_123", raising=False)
        with pytest.raises(ProfileConfigError, match="not set or empty"):
            load_profiles(cfg)

    def test_extra_key_in_yaml_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  alice:
    auth:
      bearer_token_env: TEST_TOK
    unknown_field: oops
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        with pytest.raises(ProfileConfigError):
            load_profiles(cfg)


class TestDelegatedOAuthConfig:
    """Delegated mode config rules (RT #1502).

    The audience is the security boundary, not a formality: a Google access
    token verifies for ANY OAuth client unless its `aud` is pinned.
    """

    ISSUER = "https://accounts.google.com"

    def test_issuer_and_audience_env_together_are_accepted(self) -> None:
        cfg = OAuthConfig(
            enabled=True,
            allowed_emails=["alice@example.com"],
            issuer=self.ISSUER,
            audience_env="TRENTINA_GEMINI_GOOGLE_CLIENT_ID",
        )
        assert cfg.issuer == self.ISSUER
        assert cfg.audience is None  # resolved by the loader, not the model

    def test_issuer_without_audience_env_is_refused(self) -> None:
        """An unpinned audience accepts tokens minted for any other app."""
        with pytest.raises(ValidationError, match=r"requires oauth\.audience_env"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                issuer=self.ISSUER,
            )

    def test_audience_env_without_issuer_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="never be consulted"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                audience_env="TRENTINA_GEMINI_GOOGLE_CLIENT_ID",
            )

    def test_issuer_requires_oauth_enabled(self) -> None:
        with pytest.raises(ValidationError, match=r"requires oauth\.enabled"):
            OAuthConfig(
                enabled=False,
                issuer=self.ISSUER,
                audience_env="TRENTINA_GEMINI_GOOGLE_CLIENT_ID",
            )

    def test_delegated_and_provisioned_are_mutually_exclusive(self) -> None:
        """Combined, the provisioned client_id would be registered into the
        gateway-wide proxy as a live client for the OTHER profiles' AS."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                issuer=self.ISSUER,
                audience_env="TRENTINA_GEMINI_GOOGLE_CLIENT_ID",
                client_id="375f3fdb-c322-41bc-8dc6-c2010a095f04",
                client_secret_env="TRENTINA_GEMINI_APP_CLIENT_SECRET",
                client_redirect_uris=["https://example.com/cb"],
            )

    def test_issuer_is_stored_byte_for_byte(self) -> None:
        """No trailing slash is added. Google publishes the bare origin, and a
        client compares it byte-for-byte (RFC 8414 3.3) — normalizing here is
        how 0.8.1 broke, in mirror image."""
        cfg = OAuthConfig(
            enabled=True,
            allowed_emails=["alice@example.com"],
            issuer=self.ISSUER,
            audience_env="A_CLIENT_ID",
        )
        assert cfg.issuer == "https://accounts.google.com"
        assert not cfg.issuer.endswith("/")

    def test_surrounding_whitespace_is_stripped(self) -> None:
        cfg = OAuthConfig(
            enabled=True,
            allowed_emails=["alice@example.com"],
            issuer=f"  {self.ISSUER}  ",
            audience_env="A_CLIENT_ID",
        )
        assert cfg.issuer == self.ISSUER

    def test_unknown_issuer_is_refused_at_load(self) -> None:
        """The issuer selects a verifier; there is no generic fallback, so one
        we cannot verify must fail here rather than at request time."""
        with pytest.raises(ValidationError, match="no verifier in this build"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                issuer="https://login.microsoftonline.com/common/v2.0",
                audience_env="A_CLIENT_ID",
            )

    def test_http_issuer_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must be an https"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                issuer="http://accounts.google.com",
                audience_env="A_CLIENT_ID",
            )

    def test_lowercase_audience_env_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="UPPERCASE"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["alice@example.com"],
                issuer=self.ISSUER,
                audience_env="trentina_gemini_google_client_id",
            )


class TestProfileNeedsAnAuthenticationMethod:
    """A profile must have at least one way to authenticate (0.15.0).

    `auth` was required until now, so every profile carried a static bearer and
    this property held by accident. The cost was that adding OAuth to a seat
    forced a permanent anonymous credential alongside it — and because the
    bearer is checked first, that credential bypassed the OAuth entirely.
    """

    OAUTH = OAuthConfig(enabled=True, allowed_emails=["alice@example.com"])

    def test_oauth_only_profile_is_valid(self) -> None:
        """The shape that was impossible to express before."""
        profile = Profile(name="claude-web", oauth=self.OAUTH)
        assert profile.auth is None
        assert profile.oauth is not None and profile.oauth.enabled

    def test_bearer_only_profile_is_valid(self) -> None:
        profile = Profile(name="agent1", auth=AuthConfig(bearer_token_env="TOK"))
        assert profile.oauth is None

    def test_both_together_is_valid(self) -> None:
        """gemini-web deliberately keeps both while the connector is in beta."""
        profile = Profile(
            name="gemini-web",
            auth=AuthConfig(bearer_token_env="TOK"),
            oauth=self.OAUTH,
        )
        assert profile.auth is not None and profile.oauth is not None

    def test_neither_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="has no authentication"):
            Profile(name="wide-open")

    def test_disabled_oauth_does_not_count(self) -> None:
        """`enabled: false` authenticates nobody, so it cannot stand in for auth."""
        with pytest.raises(ValidationError, match="has no authentication"):
            Profile(name="wide-open", oauth=OAuthConfig(enabled=False))

    def test_the_refusal_names_both_remedies(self) -> None:
        with pytest.raises(ValidationError) as exc:
            Profile(name="wide-open")
        message = str(exc.value)
        assert "bearer_token_env" in message
        assert "oauth.enabled" in message


class TestBearerPathWithNoStaticToken:
    """gateway/auth.py must tolerate a profile that has no `auth` block."""

    OAUTH_ONLY = Profile(
        name="claude-web",
        oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
    )

    def test_verify_bearer_refuses_and_says_why(self) -> None:
        from trentina.gateway.auth import AuthError, verify_bearer

        with pytest.raises(AuthError, match="no static bearer token"):
            verify_bearer("Bearer anything", self.OAUTH_ONLY)

    def test_token_lookup_skips_it_rather_than_crashing(self) -> None:
        """resolve_profile_by_token walks every profile in the registry."""
        from trentina.gateway.auth import resolve_profile_by_token

        registry = {"claude-web": self.OAUTH_ONLY}
        assert resolve_profile_by_token("Bearer whatever", registry) is None

    def test_loader_does_not_demand_an_env_var(self) -> None:
        from trentina.gateway.loader import _resolve_bearer_token

        profile = Profile(
            name="claude-web",
            oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
        )
        _resolve_bearer_token("claude-web", profile)  # must not raise
        assert profile.auth is None


class TestEnforcementModeNames:
    """`annotate`/`extract` became `warn`/`clean` in 0.25.0, and those became
    `flag`/`redact` in 0.35.0 (see TestPre035SpellingsAreGone in test_mode_param.py).

    The old names described the MECHANISM — a note gets attached, an
    extraction is run. The new ones describe what the reading agent is being
    told, which is the thing a profile author is actually choosing between.

    Every profile model is `extra="forbid"` and a profile that fails to load
    is FATAL, so a deployed config carrying the old spelling would take the
    gateway down on upgrade rather than warn. These tests are the alias
    window; they get deleted with it in 0.27.0.
    """

    def test_the_default_is_flag(self) -> None:
        from trentina.gateway.profile import DefenseConfig

        assert DefenseConfig().enforcement == "flag"

    @pytest.mark.parametrize("old", ["annotate", "extract"])
    def test_the_pre_0_25_spellings_are_gone(self, old: str) -> None:
        """Accepted with a warning from 0.25.0, removed in 0.29.0 as promised.

        The warning named the release for four minors; this is the release.
        A profile still carrying one now fails to load, which is loud and
        recoverable — the alternative was migrating it forever.
        """
        import pydantic

        from trentina.gateway.profile import DefenseConfig

        with pytest.raises(pydantic.ValidationError):
            DefenseConfig(enforcement=old)

    def test_redact_is_refused_at_load_and_says_why(self) -> None:
        """`enforcement` is the DEFAULT mode, and redact cannot be a default.

        A call that omits the mode carries no extraction prompt either. The
        message has to say where redact belongs — `modes` — or pydantic's own
        "input should be 'flag' or 'block'" sends an operator hunting for a
        typo.
        """
        from pydantic import ValidationError

        from trentina.gateway.profile import DefenseConfig

        with pytest.raises(ValidationError, match="cannot be a default"):
            DefenseConfig(enforcement="redact")

    def test_the_alert_ingress_refuses_redact_too(self) -> None:
        """Both push and pull paths, or the gap just moves."""
        from pydantic import ValidationError

        from trentina.gateway.profile import AlertIngressConfig

        with pytest.raises(ValidationError, match="cannot be a default"):
            AlertIngressConfig(token_env="T", forward_url="http://x:1/h", enforcement="redact")

    def test_a_bogus_mode_is_still_refused(self) -> None:
        from pydantic import ValidationError

        from trentina.gateway.profile import DefenseConfig

        with pytest.raises(ValidationError):
            DefenseConfig(enforcement="ignore")


class TestPushPathEnforcement:
    """Who picks the mode, on the paths where no agent exists to ask.

    On the PULL path a primary agent picks per call. On a PUSH path nobody
    is waiting, so before 0.25.0 the choice was hardcoded — and
    `defense.enforcement` was read ONLY on the tool path, which meant the
    one path with an agent to ask was the only path that was configurable.
    """

    def test_the_alert_ingress_defaults_to_flag(self) -> None:
        """Nagios pages forward with the warning attached.

        Silently dropping a real incident on a classifier false positive is
        worse than forwarding a flagged one, and the warning lands ahead of
        the payload so the receiving agent reads the caution first.
        """
        from trentina.gateway.profile import AlertIngressConfig

        assert AlertIngressConfig.model_fields["enforcement"].default == "flag"

    def test_the_matrix_ingress_has_no_mode_on_purpose(self) -> None:
        """Refusing a Matrix response does not drop a message — it breaks the
        client's /sync loop, which is the proxy eating the agent's traffic
        rather than filtering it. A mode here would have to be per-EVENT."""
        from trentina.gateway.profile import MatrixIngressConfig

        assert "enforcement" not in MatrixIngressConfig.model_fields


class TestL3Briefing:
    """#204: `Backend.l3_briefing` says what a backend is, in a bounded space."""

    def test_the_limit_is_accepted_and_one_past_it_is_not(self) -> None:
        from pydantic import ValidationError

        from trentina.gateway.profile import MAX_L3_BRIEFING_CHARS, Backend

        at_limit = Backend(url="http://ops:8000/mcp", l3_briefing="x" * MAX_L3_BRIEFING_CHARS)
        assert at_limit.l3_briefing is not None
        with pytest.raises(ValidationError):
            Backend(url="http://ops:8000/mcp", l3_briefing="x" * (MAX_L3_BRIEFING_CHARS + 1))

    def test_unset_is_none(self) -> None:
        from trentina.gateway.profile import Backend

        assert Backend(url="http://ops:8000/mcp").l3_briefing is None


class TestBackendAuth:
    """#479: a backend authenticated by a per-profile OAuth grant."""

    def test_self_authorize_is_off_by_default(self) -> None:
        backend = Backend(url="https://era.example/mcp", auth={"type": "oauth"})
        assert backend.auth is not None
        assert backend.auth.self_authorize is False

    @pytest.mark.parametrize("header", ["Authorization", "proxy-authorization", "Cookie"])
    def test_a_credential_header_beside_auth_is_refused(self, header: str) -> None:
        with pytest.raises(ValidationError, match="cannot be combined"):
            Backend(url="https://era.example/mcp", headers={header: "x"}, auth={"type": "oauth"})

    def test_an_ordinary_header_beside_auth_is_fine(self) -> None:
        backend = Backend(
            url="https://era.example/mcp", headers={"X-Org": "1"}, auth={"type": "oauth"}
        )
        assert backend.headers == {"X-Org": "1"}

    def test_a_url_credential_beside_auth_is_refused(self) -> None:
        with pytest.raises(ValidationError, match=r"\$\{VAR\}"):
            Backend(url="https://era.example/mcp?key=${ERA_KEY}", auth={"type": "oauth"})

    def test_internal_and_decoy_backends_refuse_auth(self) -> None:
        with pytest.raises(ValidationError, match="internal"):
            Backend(url="internal://tools", auth={"type": "oauth"})
        with pytest.raises(ValidationError, match="auth does not apply to a decoy"):
            Backend(
                url="decoy://bait",
                decoys={"t": {"description": "d", "result": "r"}},
                auth={"type": "oauth"},
            )

    def test_a_client_secret_needs_a_client_id(self) -> None:
        with pytest.raises(ValidationError, match="requires client_id"):
            Backend(
                url="https://era.example/mcp",
                auth={"type": "oauth", "client_secret_env": "ERA_SECRET"},
            )

    @pytest.mark.parametrize("scopes", [[], ["read write"], ['a"b']])
    def test_scopes_are_scope_tokens(self, scopes: list[str]) -> None:
        with pytest.raises(ValidationError):
            Backend(url="https://era.example/mcp", auth={"type": "oauth", "scopes": scopes})

    def test_the_client_secret_resolves_and_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {
                    "profiles": {
                        "josui": {
                            "auth": {"bearer_token_env": "JOSUI_BEARER"},
                            "backends": {
                                "era": {
                                    "url": "https://era.example/mcp",
                                    "auth": {
                                        "type": "oauth",
                                        "client_id": "c1",
                                        "client_secret_env": "ERA_CLIENT_SECRET",
                                    },
                                }
                            },
                        }
                    }
                }
            )
        )
        monkeypatch.setenv("JOSUI_BEARER", "b" * 32)
        monkeypatch.delenv("ERA_CLIENT_SECRET", raising=False)
        with pytest.raises(ProfileConfigError, match="ERA_CLIENT_SECRET"):
            load_profiles(cfg)
        monkeypatch.setenv("ERA_CLIENT_SECRET", "s" * 32)
        auth = load_profiles(cfg).profiles["josui"].backends["era"].auth
        assert auth is not None
        assert auth.client_secret is not None
        assert auth.client_secret.get_secret_value() == "s" * 32
