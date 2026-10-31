"""profile_token and tokens by name (#635): a profile added without a restart.

Two halves, like the keygen it mirrors. Minting: the token comes back ONCE,
which nothing else in Trentina does, and it is written where no file tool can
reach it. Referring: a profile names a minted token instead of an environment
variable, which is what lets a whole new agent profile be added to a running
gateway — before this, a profile naming an unset variable did not merely need
a restart, it failed validation, so the write was refused and the file
restored.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator

import pytest
from pydantic import ValidationError

from trentina import config as config_mod
from trentina.gateway import token_store
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.key_store import KEY_DIR_MODE, KEY_FILE_MODE
from trentina.gateway.loader import GatewayConfig, load_profiles, register_active_config
from trentina.gateway.profile import AuthConfig, Profile
from trentina.gateway.token_store import MINTED_PREFIX, token_path
from trentina.tools.confine import confine
from trentina.tools.reload import reload_profiles
from trentina.tools.token import profile_token

pytestmark = pytest.mark.anyio

PROFILE_YAML = """\
profiles:
  newagent:
    auth:
      {field}: {value}
    backends:
      web:
        url: "internal://web"
        tools_allow: [fetch_tool]
"""


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    """A private data directory, so tokens land under this test's own tree."""
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    yield tmp_path / "state"
    config_mod._config = None


class TestMinting:
    """No ActiveConfig is registered, so the caller is the standalone operator."""

    async def test_it_returns_the_token_and_its_name(self, data_dir: pathlib.Path) -> None:
        result = await profile_token("newagent")
        assert result["token_name"] == "newagent"
        assert result["token"].startswith(MINTED_PREFIX)

    async def test_the_token_is_what_was_stored(self, data_dir: pathlib.Path) -> None:
        result = await profile_token("newagent")
        assert token_store.read_token("newagent") == result["token"]

    async def test_it_carries_a_recognisable_shape(self, data_dir: pathlib.Path) -> None:
        """An opaque random string has no shape a scrubber could catch. The
        lead-in is what lets credential_shapes hold it out of a log record even
        somewhere nobody held it by hand."""
        from trentina.credential_shapes import CredentialKind, kinds

        token = (await profile_token("newagent"))["token"]
        assert CredentialKind.TRENTINA_PROFILE_TOKEN in kinds(f"auth {token}")

    async def test_the_file_and_directory_are_private(self, data_dir: pathlib.Path) -> None:
        await profile_token("newagent")
        path = token_path("newagent")
        assert os.stat(path).st_mode & 0o777 == KEY_FILE_MODE
        assert os.stat(path.parent).st_mode & 0o777 == KEY_DIR_MODE

    async def test_a_name_is_written_once(self, data_dir: pathlib.Path) -> None:
        """O_EXCL: a token in use is never replaced underneath a live profile."""
        first = await profile_token("newagent")
        stored = token_store.read_token("newagent")
        second = await profile_token("newagent")
        assert "already exists" in second["error"]
        assert token_store.read_token("newagent") == stored == first["token"]

    async def test_no_file_tool_can_read_the_store(self, data_dir: pathlib.Path) -> None:
        await profile_token("newagent")
        with pytest.raises(Exception, match=r"not_found_or_denied|denied|outside"):
            confine(str(token_path("newagent")))

    @pytest.mark.parametrize(
        "bad", ["Newagent", "9agent", "new_agent", "new/../escape", "agent.txt", ""]
    )
    async def test_a_name_that_is_not_a_filename_is_refused(
        self, data_dir: pathlib.Path, bad: str
    ) -> None:
        result = await profile_token(bad)
        assert "lowercase letters" in result["error"]
        # The rejected name is caller-chosen text and becomes a filename, so it
        # is never echoed back (#262).
        assert bad not in result["error"] or bad == ""

    async def test_an_agent_caller_is_refused(self, data_dir: pathlib.Path) -> None:
        """It hands back a usable credential, so an agent reaching it would get
        a token rather than merely a refusal."""
        agent = Profile(name="ag", auth=AuthConfig(bearer_token_env="AG_TOKEN"))
        register_active_config(
            data_dir / "profiles.yaml", GatewayConfig(profiles={"ag": agent}), {}
        )
        try:
            with profile_context(agent):
                result = await profile_token("newagent")
        finally:
            config_mod._config = None
        assert "operator" in result["error"]


class TestTokenByName:
    async def test_a_named_token_resolves_to_what_was_minted(
        self, data_dir: pathlib.Path
    ) -> None:
        minted = (await profile_token("newagent"))["token"]
        path = data_dir.parent / "profiles.yaml"
        path.write_text(
            PROFILE_YAML.format(field="bearer_token_name", value="newagent"), encoding="utf-8"
        )
        loaded = load_profiles(path)
        auth = loaded.profiles["newagent"].auth
        assert auth is not None and auth.bearer_token is not None
        assert auth.bearer_token.get_secret_value() == minted

    async def test_a_name_with_no_token_fails_closed(self, data_dir: pathlib.Path) -> None:
        path = data_dir.parent / "profiles.yaml"
        path.write_text(
            PROFILE_YAML.format(field="bearer_token_name", value="never-minted"), encoding="utf-8"
        )
        with pytest.raises(ProfileConfigError, match="profile_token"):
            load_profiles(path)

    async def test_an_empty_token_file_fails_closed(self, data_dir: pathlib.Path) -> None:
        await profile_token("newagent")
        token_path("newagent").write_text("", encoding="utf-8")
        path = data_dir.parent / "profiles.yaml"
        path.write_text(
            PROFILE_YAML.format(field="bearer_token_name", value="newagent"), encoding="utf-8"
        )
        with pytest.raises(ProfileConfigError, match="empty"):
            load_profiles(path)

    async def test_reload_picks_up_a_token_minted_after_startup(
        self, data_dir: pathlib.Path
    ) -> None:
        """The whole point: the token is read on every load, and a reload is a
        load, so a profile added now authenticates without a restart."""
        path = data_dir.parent / "profiles.yaml"
        path.write_text(
            PROFILE_YAML.format(field="bearer_token_env", value="START_TOKEN"), encoding="utf-8"
        )
        os.environ["START_TOKEN"] = "s" * 20
        try:
            config = load_profiles(path)
            register_active_config(path, config, {})
            set_profiles(config.profiles)

            operator = config.profiles["newagent"]
            operator.role = "operator"
            # A live gateway refuses an unbound caller, so both calls are made
            # as the operator — which is how an operator agent would make them.
            with profile_context(operator):
                minted = (await profile_token("later"))["token"]
                path.write_text(
                    PROFILE_YAML.format(field="bearer_token_name", value="later"),
                    encoding="utf-8",
                )
                applied = await reload_profiles()
            assert applied["reloaded"] is True

            from trentina.gateway.loader import get_active_config

            active = get_active_config()
            assert active is not None
            auth = active.config.profiles["newagent"].auth
            assert auth is not None and auth.bearer_token is not None
            assert auth.bearer_token.get_secret_value() == minted
        finally:
            os.environ.pop("START_TOKEN", None)
            config_mod._config = None


class TestOneSource:
    def test_both_sources_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="use one"):
            AuthConfig(bearer_token_env="T", bearer_token_name="t")

    def test_neither_source_is_refused(self) -> None:
        """An auth block naming no token would read as a profile that
        authenticates and then matches nothing."""
        with pytest.raises(ValidationError, match="bearer_token_env or bearer_token_name"):
            AuthConfig()

    def test_a_token_name_must_be_a_filename(self) -> None:
        with pytest.raises(ValidationError):
            AuthConfig(bearer_token_name="../escape")

    def test_an_env_name_must_still_be_uppercase(self) -> None:
        with pytest.raises(ValidationError, match="UPPERCASE"):
            AuthConfig(bearer_token_env="lowercase")
