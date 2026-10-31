"""federation_keygen (#633): the operator mints an edge keypair without a shell.

What matters here is the asymmetry. The PUBLIC half must come back, because the
peer gateway has to pin it and a public key is not a secret. The PRIVATE half
must not: not in the result, not in a log, and not anywhere a file tool can
read. These tests hold both halves of that.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator

import pytest

from trentina import config as config_mod
from trentina.errors import FileReadError
from trentina.gateway.context import profile_context
from trentina.gateway.edge_key import load_private_key, load_public_key, sign, verify
from trentina.gateway.profile import Profile
from trentina.tools.confine import confine
from trentina.tools.keygen import KEY_DIR_MODE, KEY_FILE_MODE, federation_keygen, key_path

pytestmark = pytest.mark.anyio

PRIVATE_MARKER = "-----BEGIN PRIVATE KEY-----"


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    """A private data directory, so the keys land under this test's own tree."""
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    yield tmp_path / "state"
    config_mod._config = None


class TestMinting:
    """No ActiveConfig is registered, so the caller is the standalone operator."""

    async def test_it_returns_a_loadable_public_key(self, data_dir: pathlib.Path) -> None:
        result = await federation_keygen("edge-to-lotor")
        assert result["key"] == "edge-to-lotor"
        load_public_key(result["public_key"])  # raises EdgeKeyError if it is not one

    async def test_the_public_key_belongs_to_the_private_key(self, data_dir: pathlib.Path) -> None:
        """The returned half must actually verify what the stored half signs —
        otherwise the peer pins a key that can never authenticate this edge."""
        result = await federation_keygen("edge-to-lotor")
        private = load_private_key(key_path("edge-to-lotor").read_text(encoding="utf-8"))
        payload = b"a federated request"
        assert verify(load_public_key(result["public_key"]), sign(private, payload), payload)

    async def test_the_private_half_never_comes_back(self, data_dir: pathlib.Path) -> None:
        result = await federation_keygen("edge-to-lotor")
        assert PRIVATE_MARKER not in str(result)
        assert set(result) == {"key", "public_key"}

    async def test_the_key_and_its_directory_are_private(self, data_dir: pathlib.Path) -> None:
        await federation_keygen("edge-to-lotor")
        path = key_path("edge-to-lotor")
        assert path.read_text(encoding="utf-8").startswith(PRIVATE_MARKER)
        assert os.stat(path).st_mode & 0o777 == KEY_FILE_MODE
        assert os.stat(path.parent).st_mode & 0o777 == KEY_DIR_MODE

    async def test_an_existing_directory_is_tightened(self, data_dir: pathlib.Path) -> None:
        """``mkdir(mode=)`` does nothing to a directory that already exists, so
        the explicit chmod is what decides the mode."""
        loose = data_dir / "keys"
        previous = os.umask(0)
        try:
            loose.mkdir(parents=True)  # 0o777, with nothing masked off
        finally:
            os.umask(previous)

        await federation_keygen("edge-to-lotor")

        assert os.stat(loose).st_mode & 0o777 == KEY_DIR_MODE

    async def test_no_file_tool_can_read_the_key(self, data_dir: pathlib.Path) -> None:
        """The keys sit under the gateway's own data directory, which
        ``confine`` refuses to read_tool and dir_tool alike."""
        await federation_keygen("edge-to-lotor")
        with pytest.raises(FileReadError):
            confine(str(key_path("edge-to-lotor")))


class TestWrittenOnce:
    async def test_a_second_mint_of_one_name_is_refused(self, data_dir: pathlib.Path) -> None:
        first = await federation_keygen("edge-to-lotor")
        stored = key_path("edge-to-lotor").read_text(encoding="utf-8")

        second = await federation_keygen("edge-to-lotor")

        assert "already exists" in second["error"]
        assert "public_key" not in second
        # The live key is untouched: rotating under a running edge would break it.
        assert key_path("edge-to-lotor").read_text(encoding="utf-8") == stored
        assert load_public_key(first["public_key"])


class TestNames:
    @pytest.mark.parametrize(
        "name",
        [
            "Edge",  # uppercase
            "9edge",  # leading digit
            "edge_to_lotor",  # underscore: a backend name has none either
            "edge/../escape",  # traversal
            "edge.pem",  # a dot would make the suffix ambiguous
            "",
            "e" * 64,  # one past the limit
        ],
    )
    async def test_a_name_that_is_not_a_name_is_refused(
        self, data_dir: pathlib.Path, name: str
    ) -> None:
        result = await federation_keygen(name)
        assert "error" in result
        assert "public_key" not in result
        # Nothing was created, under any spelling.
        keys = data_dir / "keys"
        assert not keys.exists() or not list(keys.glob("*"))

    async def test_the_refusal_does_not_echo_the_name(self, data_dir: pathlib.Path) -> None:
        """The name is caller-chosen text, so the refusal describes the shape
        instead of quoting it (#262)."""
        result = await federation_keygen("../../etc/shadow")
        assert "shadow" not in result["error"]


class TestScope:
    async def test_an_agent_cannot_mint_a_key(self, data_dir: pathlib.Path) -> None:
        agent = Profile.model_validate(
            {"name": "ag", "auth": {"bearer_token_env": "A"}, "backends": {}}
        )
        with profile_context(agent):
            result = await federation_keygen("edge-to-lotor")
        assert "operator" in result["error"].lower()
        assert not (data_dir / "keys").exists()
