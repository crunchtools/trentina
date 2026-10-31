"""federation_keygen and keys by name (#633): an edge set up without a shell.

Two halves. Minting: the PUBLIC key must come back, because the peer gateway
has to pin it and a public key is not a secret; the PRIVATE key must not — not
in the result, not in a log, not anywhere a file tool can reach. Referring:
a profile names a minted key instead of an environment variable, which is what
removes the restart, because the key is re-read on every load and a reload is
a load.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from trentina import config as config_mod
from trentina.errors import FileReadError
from trentina.gateway import key_store
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.edge_key import load_private_key, load_public_key, sign, verify
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.key_store import KEY_DIR_MODE, KEY_FILE_MODE, key_path
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import Profile
from trentina.tools.confine import confine
from trentina.tools.keygen import federation_keygen
from trentina.tools.reload import reload_profiles

pytestmark = pytest.mark.anyio

PRIVATE_MARKER = "-----BEGIN PRIVATE KEY-----"

UPSTREAM = "https://lotor.example/gateway/fed-breetai/mcp"

#: A peer's public half, which the model validates as a real Ed25519 PEM.
PEER_PUBLIC_KEY = (
    Ed25519PrivateKey.generate()
    .public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode()
)

FED_YAML = """\
profiles:
  edge:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: EDGE_TOKEN
    backends:
      lotor:
        url: "{url}"
        tools_allow: ["*"]
        federated:
          {key_field}: {key_value}
"""


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


class TestKeyByName:
    """A profile names a key the gateway minted, instead of an env var."""

    @pytest.fixture
    def fed_config(
        self, data_dir: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> pathlib.Path:
        monkeypatch.setenv("EDGE_TOKEN", "t" * 20)
        path = tmp_path / "profiles.yaml"
        path.write_text(
            FED_YAML.format(url=UPSTREAM, key_field="edge_key_name", key_value="edge-to-lotor"),
            encoding="utf-8",
        )
        return path

    def test_a_named_key_resolves_to_its_pem(self, fed_config: pathlib.Path) -> None:
        key_store.mint("edge-to-lotor")

        config = load_profiles(fed_config)

        edge = config.profiles["edge"].backends["lotor"].federated
        assert edge is not None and edge.edge_key is not None
        load_private_key(edge.edge_key.get_secret_value())

    def test_a_key_minted_after_the_first_load_needs_no_restart(
        self, fed_config: pathlib.Path
    ) -> None:
        """The whole point of the name form. A reload re-runs load_profiles,
        which re-reads the key, so minting then reloading is enough."""
        with pytest.raises(ProfileConfigError, match="has not minted"):
            load_profiles(fed_config)

        key_store.mint("edge-to-lotor")

        edge = load_profiles(fed_config).profiles["edge"].backends["lotor"].federated
        assert edge is not None and edge.edge_key is not None

    async def test_reload_profiles_picks_up_a_newly_minted_key(
        self, fed_config: pathlib.Path
    ) -> None:
        """End to end through the operator tool an agent would actually call."""
        key_store.mint("edge-to-lotor")
        config = load_profiles(fed_config)
        register_active_config(fed_config, config, {})
        set_profiles(config.profiles)
        operator = config.profiles["edge"]

        key_store.mint("edge-rotated")
        fed_config.write_text(
            FED_YAML.format(url=UPSTREAM, key_field="edge_key_name", key_value="edge-rotated"),
            encoding="utf-8",
        )
        with profile_context(operator):
            result = await reload_profiles()

        assert result["reloaded"] is True
        rotated = config.profiles["edge"].backends["lotor"].federated
        assert rotated is not None and rotated.edge_key_name == "edge-rotated"
        load_private_key(rotated.edge_key.get_secret_value())

    def test_a_name_with_no_minted_key_fails_closed(self, fed_config: pathlib.Path) -> None:
        with pytest.raises(ProfileConfigError, match="federation_keygen"):
            load_profiles(fed_config)

    def test_an_edge_key_by_name_still_needs_a_gateway_url(
        self, data_dir: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The audience comes from the URL, so the rule cannot depend on which
        source the key came from — a check naming only `edge_key_env` is the gap
        this item closed."""
        monkeypatch.setenv("EDGE_TOKEN", "t" * 20)
        key_store.mint("edge-to-lotor")
        path = tmp_path / "profiles.yaml"
        path.write_text(
            FED_YAML.format(
                url="https://lotor.example/mcp",
                key_field="edge_key_name",
                key_value="edge-to-lotor",
            ),
            encoding="utf-8",
        )
        with pytest.raises(ProfileConfigError, match="gateway MCP"):
            load_profiles(path)


class TestOneKeySource:
    def test_both_sources_for_one_key_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="both set"):
            Profile.model_validate(
                {
                    "name": "edge",
                    "auth": {"bearer_token_env": "A"},
                    "backends": {
                        "lotor": {
                            "url": UPSTREAM,
                            "federated": {
                                "edge_key_env": "EDGE_KEY",
                                "edge_key_name": "edge-to-lotor",
                            },
                        }
                    },
                }
            )

    def test_both_signing_key_sources_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="both set"):
            Profile.model_validate(
                {
                    "name": "up",
                    "auth": {"bearer_token_env": "A"},
                    "backends": {},
                    "federation": {
                        "peers": {"breetai": {"public_key": PEER_PUBLIC_KEY}},
                        "signing_key_env": "SIGN",
                        "signing_key_name": "ingress-signing",
                    },
                }
            )

    @pytest.mark.parametrize("name", ["Edge", "9edge", "edge_to_lotor", "../escape", "edge.pem"])
    def test_a_name_that_is_not_a_key_name_is_refused(self, name: str) -> None:
        with pytest.raises(ValidationError, match="edge_key_name"):
            Profile.model_validate(
                {
                    "name": "edge",
                    "auth": {"bearer_token_env": "A"},
                    "backends": {"lotor": {"url": UPSTREAM, "federated": {"edge_key_name": name}}},
                }
            )
