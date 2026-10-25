"""The matrix_bridge block (#162, spec 015).

What these tests pin down is the part of the design that holds regardless of
the code behind it: the gateway's half of the config carries nothing for the
public homeserver, both endpoints it does carry are on private networks, and
an enabled bridge cannot load without every token it needs.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from trentina.channels import Channel, Kind
from trentina.gateway.drivers import CHANNEL_KIND, build_transforms
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles, matrix_other_agents
from trentina.gateway.profile import (
    MatrixBridgeConfig,
    MatrixBridgeLocalConfig,
    ProcessorChainConfig,
)


def _bridge(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "public_user_id": "@agent1:matrix.org",
        "bridge_url": "http://127.0.0.1:8471",
        "bridge_token_env": "AGENT1_BRIDGE_TOKEN",
        "ingress_token_env": "AGENT1_BRIDGE_INGRESS",
        "local": {
            "homeserver": "http://127.0.0.1:6167",
            "server_name": "agent1.local",
            "as_token_env": "AGENT1_AS_TOKEN",
            "hs_token_env": "AGENT1_HS_TOKEN",
            "agent_localpart": "agent1",
        },
    }
    body.update(overrides)
    return body


class TestModel:
    def test_defaults_are_off_and_block(self) -> None:
        cfg = MatrixBridgeConfig.model_validate(_bridge())
        assert cfg.enabled is False
        assert cfg.enforcement == "block"
        assert cfg.preprocess.processors == []
        assert cfg.local.user_prefix == "remote_"

    def test_no_field_holds_a_public_credential(self) -> None:
        """The bridge process owns the matrix.org login. A field for it here
        would put that credential in the gateway's environment, and the
        gateway would then be able to speak upstream without the bridge."""
        fields = set(MatrixBridgeConfig.model_fields) | set(MatrixBridgeLocalConfig.model_fields)
        assert not {f for f in fields if "password" in f or "recovery" in f or "access" in f}

    @pytest.mark.parametrize(
        "url",
        [
            "http://matrix.org:8471",
            "http://8.8.8.8:8471",
            "http://169.254.169.254",
            "http://0.0.0.0:8471",
            "http://[fe80::1]:8471",
            "http://192.0.2.1",
            "http://bridge.example.com:8471",
            "unix:///run/bridge.sock",
            "ftp://127.0.0.1",
        ],
    )
    def test_bridge_url_must_be_private(self, url: str) -> None:
        with pytest.raises(ValidationError, match="private host"):
            MatrixBridgeConfig.model_validate(_bridge(bridge_url=url))

    def test_local_homeserver_must_be_private(self) -> None:
        body = _bridge()
        body["local"]["homeserver"] = "https://conduit.example.com"
        with pytest.raises(ValidationError, match="private host"):
            MatrixBridgeConfig.model_validate(body)

    @pytest.mark.parametrize(
        "host",
        [
            "http://localhost:6167/",
            "http://[::1]:6167",
            "http://10.0.10.3:6167",
            "http://conduit-agent1:6167",
            "http://192.168.1.4",
        ],
    )
    def test_private_spellings_are_accepted(self, host: str) -> None:
        body = _bridge()
        body["local"]["homeserver"] = host
        cfg = MatrixBridgeConfig.model_validate(body)
        assert not cfg.local.homeserver.endswith("/")

    @pytest.mark.parametrize(
        "user_id",
        [
            "agent1:matrix.org",
            "@Agent1:matrix.org",
            "@k",
            "@a:matrix.org:99999",
            "@a:[::::]",
            "@:matrix.org",
        ],
    )
    def test_public_user_id_is_a_matrix_id(self, user_id: str) -> None:
        with pytest.raises(ValidationError, match="Matrix user ID"):
            MatrixBridgeConfig.model_validate(_bridge(public_user_id=user_id))

    def test_env_names_are_checked(self) -> None:
        with pytest.raises(ValidationError, match="env var name"):
            MatrixBridgeConfig.model_validate(_bridge(bridge_token_env="lower-case"))

    def test_redact_is_not_a_default(self) -> None:
        with pytest.raises(ValidationError):
            MatrixBridgeConfig.model_validate(_bridge(enforcement="redact"))

    def test_types_are_strict(self) -> None:
        with pytest.raises(ValidationError):
            MatrixBridgeConfig.model_validate(_bridge(enabled="yes"))

    def test_unknown_keys_are_refused(self) -> None:
        with pytest.raises(ValidationError):
            MatrixBridgeConfig.model_validate(_bridge(password_env="X"))


class TestLocal:
    @pytest.mark.parametrize(
        "url", ["http://127.0.0.1:abc", "http://127.0.0.1:99999", "http://127.0.0.1:0"]
    )
    def test_a_bad_port_is_a_load_error(self, url: str) -> None:
        with pytest.raises(ValidationError, match="invalid port"):
            MatrixBridgeConfig.model_validate(_bridge(bridge_url=url))

    @pytest.mark.parametrize(
        "name",
        [
            "agent1.local",
            "a",
            "matrix.example.com",
            "agent1.local:8448",
            "[::1]",
            "[::1]:6167",
            "10.0.10.3",
            "agent1.local:1",
            "agent1.local:65535",
        ],
    )
    def test_server_names_accepted(self, name: str) -> None:
        body = _bridge()
        body["local"]["server_name"] = name
        assert MatrixBridgeConfig.model_validate(body).local.server_name == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "Agent1.local",
            "-agent",
            "a b",
            "x" * 254,
            "agent1..local",
            "agent1-.local",
            ".local",
            "[::::]",
            "[::1",
            "[::1]junk",
            "[::1]:0",
            "agent1.local:",
            "agent1.local:0",
            "agent1.local:65536",
            "agent1.local:99999",
            "a:b:c",
        ],
    )
    def test_server_names_refused(self, name: str) -> None:
        body = _bridge()
        body["local"]["server_name"] = name
        with pytest.raises(ValidationError, match="server_name"):
            MatrixBridgeConfig.model_validate(body)

    @pytest.mark.parametrize("field", ["sender_localpart", "user_prefix"])
    @pytest.mark.parametrize(
        ("value", "ok"), [("x" * 64, True), ("x" * 65, False), ("Bad", False), ("", False)]
    )
    def test_localparts(self, field: str, value: str, ok: bool) -> None:
        body = _bridge()
        body["local"][field] = value
        if ok:
            assert getattr(MatrixBridgeConfig.model_validate(body).local, field) == value
        else:
            with pytest.raises(ValidationError, match="localpart"):
                MatrixBridgeConfig.model_validate(body)

    @pytest.mark.parametrize("field", ["as_token_env", "hs_token_env"])
    def test_local_env_names_are_checked(self, field: str) -> None:
        body = _bridge()
        body["local"][field] = "as-token"
        with pytest.raises(ValidationError, match="env var name"):
            MatrixBridgeConfig.model_validate(body)


class TestChannel:
    def test_bridge_channel_carries_text(self) -> None:
        """The bridge already decrypted, so what is scanned is what is
        delivered: a string, not a document to select from."""
        assert CHANNEL_KIND[Channel.MATRIX_BRIDGE] is Kind.TEXT

    def test_empty_chain_builds(self) -> None:
        assert build_transforms(ProcessorChainConfig(), channel=Channel.MATRIX_BRIDGE) == []

    @pytest.mark.parametrize("name", ["detect", "matrix"])
    def test_no_processor_is_locked_to_it_yet(self, name: Any) -> None:
        with pytest.raises(ProfileConfigError, match="not valid on the matrix_bridge channel"):
            build_transforms(ProcessorChainConfig(processors=[name]), channel=Channel.MATRIX_BRIDGE)


def _write(tmp_path: Path, bridge_yaml: str, prefix: str = "") -> Path:
    path = tmp_path / "profiles.yaml"
    path.write_text(
        prefix + "profiles:\n"
        "  agent1:\n"
        "    auth:\n"
        "      bearer_token_env: TEST_BEARER\n"
        "    backends: {}\n"
        "    matrix_bridge:\n" + bridge_yaml,
        encoding="utf-8",
    )
    return path


_BRIDGE_YAML = (
    "      public_user_id: '@agent1:matrix.org'\n"
    "      bridge_url: http://127.0.0.1:8471\n"
    "      bridge_token_env: AGENT1_BRIDGE_TOKEN\n"
    "      ingress_token_env: AGENT1_BRIDGE_INGRESS\n"
    "      local:\n"
    "        homeserver: http://127.0.0.1:6167\n"
    "        server_name: agent1.local\n"
    "        as_token_env: AGENT1_AS_TOKEN\n"
    "        hs_token_env: AGENT1_HS_TOKEN\n"
    "        agent_localpart: agent1\n"
)


class TestLoader:
    @pytest.fixture(autouse=True)
    def _bearer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_BEARER", "b" * 32)

    def test_a_disabled_bridge_loads_without_its_secrets(self, tmp_path: Path) -> None:
        """Nothing reads the tokens until a bridge runs, so an inert block
        must not demand them."""
        cfg = load_profiles(_write(tmp_path, _BRIDGE_YAML))
        bridge = cfg.profiles["agent1"].matrix_bridge
        assert bridge is not None
        assert bridge.enabled is False

    def test_an_enabled_bridge_needs_every_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path, "      enabled: true\n" + _BRIDGE_YAML)
        tokens = {
            "AGENT1_BRIDGE_TOKEN": "tok-bridge-7f3a",
            "AGENT1_BRIDGE_INGRESS": "tok-ingress-7f3a",
            "AGENT1_AS_TOKEN": "tok-as-7f3a",
            "AGENT1_HS_TOKEN": "tok-hs-7f3a",
        }
        for missing in tokens:
            for name, value in tokens.items():
                monkeypatch.setenv(name, value)
            monkeypatch.delenv(missing)
            with pytest.raises(ProfileConfigError, match=missing):
                load_profiles(path)

        for name, value in tokens.items():
            monkeypatch.setenv(name, value)
        bridge = load_profiles(path).profiles["agent1"].matrix_bridge
        assert bridge is not None
        assert bridge.local.as_token is not None
        assert bridge.local.as_token.get_secret_value() == "tok-as-7f3a"
        assert "7f3a" not in bridge.model_dump_json(), "a resolved token must never serialize"

    def test_other_agents_are_read_and_validated_at_load(self, tmp_path: Path) -> None:
        ashigaru = "@ashigaru-crunchtools-bot:matrix.org"
        good = f'matrix:\n  other_agent_user_ids: ["{ashigaru}"]\n'
        cfg = load_profiles(_write(tmp_path, _BRIDGE_YAML, prefix=good))
        assert matrix_other_agents(cfg.matrix) == {ashigaru}
        bad = 'matrix:\n  other_agent_user_ids: ["ashigaru-no-at"]\n'
        with pytest.raises(ProfileConfigError, match="1 entries") as err:
            load_profiles(_write(tmp_path, _BRIDGE_YAML, prefix=bad))
        assert "ashigaru-no-at" not in str(err.value)

    @pytest.mark.parametrize("value", ["@a:matrix.org", {"a": 1}, [1]])
    def test_other_agents_must_be_a_list_of_ids(self, value: Any) -> None:
        with pytest.raises(ProfileConfigError, match="other_agent_user_ids"):
            matrix_other_agents({"other_agent_user_ids": value})

    def test_other_agents_default_to_none(self) -> None:
        assert matrix_other_agents({}) == frozenset()

    def test_the_channel_lock_fires_at_load(self, tmp_path: Path) -> None:
        body = _BRIDGE_YAML + "      preprocess:\n        processors: [detect]\n"
        with pytest.raises(ProfileConfigError, match="matrix_bridge channel"):
            load_profiles(_write(tmp_path, body))


class TestDependencyGuard:
    def test_nio_crypto_is_installed_in_ci(self) -> None:
        """Copied from test_matrix_keybackup: the bridge suite that lands in
        phase 1 must not go green by skipping on a CI leg without the extra."""
        if os.environ.get("CI"):
            assert importlib.util.find_spec("nio.crypto") is not None, (
                "matrix-nio[e2e] missing in CI — install the bridge extra"
            )
