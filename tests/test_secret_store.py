"""The secret store (#736): a profile needing credentials, added to a running gateway.

``token_store`` closed this for the bearer alone. Every other profile secret is
named as an env var, and a variable the process never had, or one ``envscrub``
popped, made the candidate fail validation, so ``config_tool`` refused the
write outright. The store is the third source for the same name, read on every
load. The acceptance test at the bottom is the issue's "done when", run
through the operator tool rather than through the loader.
"""

from __future__ import annotations

import io
import os
import pathlib
import stat
from collections.abc import Iterator
from typing import Any

import pytest

from trentina import config as config_mod
from trentina import logsafe
from trentina.gateway import secret_store
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.llm_proxy import load_llm_providers
from trentina.gateway.loader import (
    _expand_env_refs,
    _require_env,
    _reset_protected_secret_envs,
    get_active_config,
    load_profiles,
    read_profile_secret,
    register_active_config,
)
from trentina.tools.config import manage_config
from trentina.tools.confine import confine

pytestmark = pytest.mark.anyio


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    yield tmp_path / "state"
    config_mod._config = None


class TestStore:
    def test_a_value_round_trips_stripped(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "the-value\n")
        assert secret_store.read_secret("STORE_X") == "the-value"

    def test_absent_is_empty_not_an_error(self, data_dir: pathlib.Path) -> None:
        assert secret_store.read_secret("STORE_NOT_THERE") == ""

    def test_a_name_is_written_once(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "first-value")
        with pytest.raises(FileExistsError):
            secret_store.put("STORE_X", "second-value")
        assert secret_store.read_secret("STORE_X") == "first-value"

    def test_replace_rotates(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "first-value")
        secret_store.put("STORE_X", "second-value", replace=True)
        assert secret_store.read_secret("STORE_X") == "second-value"

    def test_an_empty_value_is_refused(self, data_dir: pathlib.Path) -> None:
        with pytest.raises(ProfileConfigError, match="empty"):
            secret_store.put("STORE_X", " \n")

    @pytest.mark.parametrize("name", ["../etc", "lower", "A/B", "A.B", "", "1ABC", "A" * 129])
    def test_a_name_that_is_not_an_env_var_is_refused(
        self, data_dir: pathlib.Path, name: str
    ) -> None:
        with pytest.raises(ProfileConfigError, match="not an env var name"):
            secret_store.put(name, "value-value")
        with pytest.raises(ProfileConfigError, match="not an env var name"):
            secret_store.read_secret(name)

    def test_the_file_and_directory_are_private(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "the-value")
        directory = secret_store.secrets_dir()
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE((directory / "STORE_X").stat().st_mode) == 0o600

    def test_a_planted_symlink_is_refused(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "the-value")
        (secret_store.secrets_dir() / "STORE_LINK").symlink_to(
            secret_store.secrets_dir() / "STORE_X"
        )
        with pytest.raises(ProfileConfigError, match="cannot read STORE_LINK"):
            secret_store.read_secret("STORE_LINK")

    def test_no_file_tool_can_read_the_store(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", "the-value")
        with pytest.raises(Exception, match=r"not_found_or_denied|denied|outside"):
            confine(str(secret_store.secrets_dir() / "STORE_X"))

    def test_names_lists_names_only(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_B", "value-b-value")
        secret_store.put("STORE_A", "value-a-value")
        assert secret_store.names() == ["STORE_A", "STORE_B"]

    def test_the_cli_reads_the_value_from_stdin(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin-value\n"))
        assert secret_store.main(["put", "STORE_CLI"]) == 0
        assert secret_store.read_secret("STORE_CLI") == "from-stdin-value"
        monkeypatch.setattr("sys.stdin", io.StringIO("again-value"))
        assert secret_store.main(["put", "STORE_CLI"]) == 1


class TestPrecedence:
    """The store is LAST, so a deployment setting ``FOO`` or ``FOO_FILE``
    resolves exactly what it did before."""

    def test_env_wins_over_the_store(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_store.put("PREC_X", "from-store-value")
        monkeypatch.setenv("PREC_X", "from-env-value")
        assert read_profile_secret("PREC_X") == "from-env-value"

    def test_file_wins_over_the_store(
        self, data_dir: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_store.put("PREC_X", "from-store-value")
        secret = tmp_path / "prec"
        secret.write_text("from-file-value")
        monkeypatch.delenv("PREC_X", raising=False)
        monkeypatch.setenv("PREC_X_FILE", str(secret))
        assert read_profile_secret("PREC_X") == "from-file-value"

    def test_the_store_answers_when_neither_is_set(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PREC_X", raising=False)
        monkeypatch.delenv("PREC_X_FILE", raising=False)
        secret_store.put("PREC_X", "from-store-value")
        assert _require_env("p", "PREC_X", "t").get_secret_value() == "from-store-value"
        assert _expand_env_refs("Bearer ${PREC_X}", context="t") == "Bearer from-store-value"

    def test_the_refusal_names_the_store(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PREC_MISSING", raising=False)
        with pytest.raises(ProfileConfigError, match="secret store"):
            _require_env("p", "PREC_MISSING", "t")

    def test_a_stored_value_is_held_out_of_logs(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PREC_HELD", raising=False)
        secret_store.put("PREC_HELD", "stored-canary-9f3e2a")
        read_profile_secret("PREC_HELD")
        assert "stored-canary-9f3e2a" not in logsafe.scrub("leaking stored-canary-9f3e2a")


class TestProtectionStillHolds:
    def test_a_header_naming_a_declared_credential_is_refused_from_the_store(
        self, data_dir: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One namespace is the point: the rule that keeps a header from naming
        another credential applies to a stored value exactly as to an env one."""
        _reset_protected_secret_envs()
        monkeypatch.delenv("PROT_GIT", raising=False)
        monkeypatch.setenv("PROT_BEARER", "b" * 20)
        secret_store.put("PROT_GIT", "git-token-value")
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            "git_remotes:\n  forge:\n    upstream: https://git.example.com\n"
            "profiles:\n  agent1:\n    auth:\n      bearer_token_env: PROT_BEARER\n"
            "    git:\n      forge:\n        token_env: PROT_GIT\n        fetch: [acme/*]\n"
            "    backends:\n      out:\n        url: https://outside.example/mcp\n"
            "        headers:\n          Authorization: Bearer ${PROT_GIT}\n",
            encoding="utf-8",
        )
        try:
            with pytest.raises(ProfileConfigError, match="holds a secret"):
                load_profiles(cfg)
        finally:
            _reset_protected_secret_envs()


#: A running gateway: one operator, and the provider and git remote the new
#: agent will use, both of which bind at startup.
LIVE = """\
llm_providers:
  gemini:
    enabled: true
    upstream: https://generativelanguage.googleapis.com
    auth_header: x-goog-api-key
    api_key_env: LIVE_PROVIDER_KEY
git_remotes:
  forge:
    upstream: https://git.example.com
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: LIVE_OP_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - config_tool
"""

#: The developer profile #736 could not write: a git token, an LLM key and a
#: backend header credential, none of them in the environment.
NEW_AGENT: dict[str, Any] = {
    "auth": {"bearer_token_env": "LIVE_DEV_BEARER"},
    "git": {"forge": {"token_env": "LIVE_DEV_GIT", "fetch": ["acme/*"]}},
    "llm_keys": {"gemini": {"api_key_env": "LIVE_DEV_GEMINI"}},
    "backends": {
        "tickets": {
            "url": "https://tickets.example/mcp",
            "headers": {"Authorization": "Bearer ${LIVE_DEV_TICKETS}"},
        }
    },
}

_STORED = {
    "LIVE_DEV_BEARER": "dev-bearer-value-0001",
    "LIVE_DEV_GIT": "dev-git-value-0002",
    "LIVE_DEV_GEMINI": "dev-gemini-value-0003",
    "LIVE_DEV_TICKETS": "dev-tickets-value-0004",
}


@pytest.fixture
def gateway(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.setenv("LIVE_OP_TOKEN", "o" * 20)
    monkeypatch.setenv("LIVE_PROVIDER_KEY", "p" * 20)
    for name in _STORED:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    config_mod._config = None
    _reset_protected_secret_envs()
    path = tmp_path / "config" / "profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(LIVE, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, load_llm_providers(config.llm_providers))
    set_profiles(config.profiles)
    yield path
    config_mod._config = None
    _reset_protected_secret_envs()


async def _op(*args: Any) -> dict[str, Any]:
    operator = (get_active_config() or pytest.fail("no gateway")).config.profiles["op"]
    with profile_context(operator):
        return await manage_config(*args)


class TestAcceptance:
    async def test_a_credentialed_profile_is_written_and_applied_without_a_restart(
        self, gateway: pathlib.Path
    ) -> None:
        before = await _op("get")
        refused = await _op("set", "profiles.dev", NEW_AGENT, before["hash"])
        assert refused.get("applied") is not True
        assert "secret store" in str(refused)

        for name, value in _STORED.items():
            secret_store.put(name, value)

        read = await _op("get")
        result = await _op("set", "profiles.dev", NEW_AGENT, read["hash"])
        assert result.get("applied") is True, result

        active = get_active_config()
        assert active is not None
        dev = active.config.profiles["dev"]
        assert dev.auth.bearer_token is not None
        assert dev.auth.bearer_token.get_secret_value() == _STORED["LIVE_DEV_BEARER"]
        grant = dev.git["forge"]
        assert grant.token is not None
        assert grant.token.get_secret_value() == _STORED["LIVE_DEV_GIT"]
        assert dev.llm_keys["gemini"].api_key.get_secret_value() == (_STORED["LIVE_DEV_GEMINI"])
        assert dev.backends["tickets"].headers == {
            "Authorization": f"Bearer {_STORED['LIVE_DEV_TICKETS']}"
        }
        # The file names variables, never values.
        written = gateway.read_text(encoding="utf-8")
        assert not any(value in written for value in _STORED.values())
        assert os.environ.get("LIVE_DEV_GIT") is None
