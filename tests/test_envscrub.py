"""Startup-only secrets leave ``os.environ`` once held; the signing key takes ``_FILE`` (#268)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from trentina import config as config_mod
from trentina.gateway import loader

# Imported before conftest's autouse fixture swaps the module attribute for a
# no-op, so this is the real function.
from trentina.gateway.envscrub import STARTUP_ONLY_SECRETS, scrub_startup_secrets


@pytest.fixture(autouse=True)
def _fresh_profile_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "_profile_env_names", set())
    # Registered with monkeypatch so a scrub here cannot strip the developer's
    # own keys from the environment for the rest of the session.
    for name in STARTUP_ONLY_SECRETS:
        if name in os.environ:
            monkeypatch.setenv(name, os.environ[name])


class TestScrub:
    def test_startup_only_secrets_are_popped_after_config_holds_them(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", "jwt-key")
        config_mod._config = None

        removed = scrub_startup_secrets()

        assert "OPENROUTER_API_KEY" in removed
        assert "TRENTINA_OAUTH_JWT_SIGNING_KEY" in removed
        assert "OPENROUTER_API_KEY" not in os.environ
        # The singleton was built before the pop, so L3 still has its key.
        assert config_mod.get_config().openrouter_api_key.get_secret_value() == "or-key"

    def test_a_name_a_profile_resolved_is_kept_for_reload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """reload_profiles re-reads every profile secret; popping one breaks it."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "shared")
        monkeypatch.setenv("ALICE_TOKEN", "alice")
        assert loader.read_secret_env("OPENROUTER_API_KEY") == "shared"
        assert loader.read_secret_env("ALICE_TOKEN") == "alice"

        removed = scrub_startup_secrets(["ALICE_TOKEN"])

        assert removed == []
        assert os.environ["OPENROUTER_API_KEY"] == "shared"
        assert os.environ["ALICE_TOKEN"] == "alice"

    def test_llm_provider_keys_are_popped_when_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROXY_ANTHROPIC_KEY", "sk")
        assert scrub_startup_secrets(["PROXY_ANTHROPIC_KEY"]) == ["PROXY_ANTHROPIC_KEY"]
        assert "PROXY_ANTHROPIC_KEY" not in os.environ

    def test_an_unrecorded_read_does_not_protect_a_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", "k")
        loader.read_secret_env("TRENTINA_OAUTH_JWT_SIGNING_KEY", record=False)
        assert "TRENTINA_OAUTH_JWT_SIGNING_KEY" in scrub_startup_secrets()

    def test_the_log_names_names_never_values(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "CANARY-VALUE")
        with caplog.at_level(logging.INFO):
            scrub_startup_secrets()
        assert "GEMINI_API_KEY" in caplog.text
        assert "CANARY-VALUE" not in caplog.text

    def test_the_list(self) -> None:
        assert set(STARTUP_ONLY_SECRETS) == {
            "TRENTINA_OAUTH_JWT_SIGNING_KEY",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET",
            "TRENTINA_BACKEND_TOKEN_KEY",
            "GEMINI_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENROUTER_API_KEY",
        }


@pytest.mark.skipif(not Path("/proc/self/environ").exists(), reason="Linux /proc only")
def test_proc_self_environ_still_holds_a_popped_secret() -> None:
    """The limit of the pop, pinned so no one mistakes it for a fix.

    ``/proc/<pid>/environ`` is the process's initial environment block, which
    ``unsetenv`` never rewrites. Only the ``_FILE`` form keeps a secret out.
    """
    code = (
        "import os\n"
        "os.environ.pop('TRENTINA_SCRUB_CANARY')\n"
        "assert 'TRENTINA_SCRUB_CANARY' not in os.environ\n"
        "print(b'TRENTINA_SCRUB_CANARY=hunter2' in open('/proc/self/environ','rb').read())\n"
    )
    env = {**os.environ, "TRENTINA_SCRUB_CANARY": "hunter2"}
    out = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "True"


class TestSigningKeyFile:
    def _signing_key(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        from trentina import _build_oauth_context
        from trentina.gateway.loader import GatewayConfig
        from trentina.gateway.profile import AuthConfig, OAuthConfig, Profile

        profile = Profile(
            name="gem",
            auth=AuthConfig(bearer_token_env="A"),
            oauth=OAuthConfig(enabled=True, allowed_emails=["a@example.com"]),
        )
        monkeypatch.setenv("TRENTINA_OAUTH_GOOGLE_CLIENT_ID", "cid")
        seen: dict[str, Any] = {}

        def build(*_args: Any, **kwargs: Any) -> Any:
            seen["signing_key"] = kwargs["signing_key"]
            return object(), "https://issuer/", ()

        with patch("trentina._build_proxy_provider", side_effect=build):
            _build_oauth_context(GatewayConfig(profiles={"gem": profile}))
        return seen["signing_key"]

    def test_file_form_is_read_and_stripped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        key_file = tmp_path / "jwt"
        key_file.write_text("from-the-file\n", encoding="utf-8")
        key_file.chmod(0o600)
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE", str(key_file))
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", "from-the-env")

        assert self._signing_key(monkeypatch) == "from-the-file"
        # Startup-only: not recorded, so the scrub may remove the env form.
        assert "TRENTINA_OAUTH_JWT_SIGNING_KEY" not in loader.profile_env_names()

    def test_env_form_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE", raising=False)
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", " from-the-env ")
        assert self._signing_key(monkeypatch) == "from-the-env"

    def test_unset_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE", raising=False)
        monkeypatch.delenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", raising=False)
        assert self._signing_key(monkeypatch) is None

    def test_a_missing_file_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from trentina.gateway.errors import ProfileConfigError

        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE", str(tmp_path / "absent"))
        with pytest.raises(ProfileConfigError, match="TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE"):
            self._signing_key(monkeypatch)
