"""The inbound OAuth store refuses plaintext records (#495)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.server.auth.providers.google import GoogleProvider

from trentina import _build_oauth_context
from trentina.gateway.loader import GatewayConfig
from trentina.gateway.oauth_binding import TokenBinding
from trentina.gateway.oauth_storage import (
    StrictFernetEncryptionWrapper,
    harden_client_storage,
    harden_provider_storage,
)
from trentina.gateway.oauth_store import resolve_cullable
from trentina.gateway.profile import AuthConfig, OAuthConfig, Profile

KEY = "k" * 48
COLLECTION = "trentina-token-bindings"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import fastmcp

    monkeypatch.setattr(fastmcp.settings, "home", tmp_path)
    return tmp_path


def _fastmcp_storage() -> Any:
    """The store FastMCP builds for a provider with a signing key."""
    return GoogleProvider(
        client_id="id",
        client_secret="secret",
        base_url="https://gw.example",
        jwt_signing_key=KEY,
    )._client_storage


def build_client_storage() -> StrictFernetEncryptionWrapper:
    """The store the gateway serves from: FastMCP's own, made strict."""
    return harden_client_storage(_fastmcp_storage())


async def _plant(storage: StrictFernetEncryptionWrapper, collection: str, key: str) -> None:
    """Write a plaintext record straight into the file tree, under the wrapper."""
    await storage.key_value.put(key=key, value={"profile": "operator"}, collection=collection)


class TestStrictStore:
    async def test_encrypted_round_trip(self, home: Path) -> None:
        storage = build_client_storage()
        await storage.put(key="k1", value={"a": 1}, collection="c")
        assert await storage.get(key="k1", collection="c") == {"a": 1}

    @pytest.mark.parametrize(
        "collection", [COLLECTION, "mcp-upstream-tokens", "mcp-oauth-proxy-clients"]
    )
    async def test_plaintext_record_is_a_miss(self, home: Path, collection: str) -> None:
        storage = build_client_storage()
        await _plant(storage, collection, "token:up1")
        assert await storage.get(key="token:up1", collection=collection) is None

    async def test_plaintext_binding_is_not_read(self, home: Path) -> None:
        from key_value.aio.adapters.pydantic import PydanticAdapter

        storage = build_client_storage()
        await _plant(storage, COLLECTION, "token:up1")
        adapter = PydanticAdapter[TokenBinding](
            key_value=storage,
            pydantic_model=TokenBinding,
            default_collection=COLLECTION,
            raise_on_validation_error=True,
        )
        assert await adapter.get(key="token:up1") is None

    async def test_cull_sweep_still_reaches_the_file_store(self, home: Path) -> None:
        storage = build_client_storage()
        assert resolve_cullable(storage) is storage.key_value

    def test_only_a_fernet_store_is_accepted(self) -> None:
        with pytest.raises(RuntimeError):
            harden_client_storage(object())

    def test_provider_without_a_store_is_refused(self) -> None:
        with pytest.raises(RuntimeError):
            harden_provider_storage(object())

    def test_provider_with_a_foreign_store_is_refused(self) -> None:
        with pytest.raises(RuntimeError):
            harden_provider_storage(SimpleNamespace(_client_storage=object()))

    async def test_bad_ciphertext_is_a_miss(self, home: Path) -> None:
        """Key rotation: a record sealed under another key reads as a miss."""
        storage = build_client_storage()
        await storage.key_value.put(
            key="k1",
            value={"__encrypted_data__": "bm90LWZlcm5ldA==", "__encryption_version__": 1},
            collection="c",
        )
        assert await storage.get(key="k1", collection="c") is None

    def test_provider_store_is_hardened_in_place(self, home: Path) -> None:
        provider = GoogleProvider(
            client_id="id",
            client_secret="secret",
            base_url="https://gw.example",
            jwt_signing_key=KEY,
        )
        harden_provider_storage(provider)
        assert type(provider._client_storage) is StrictFernetEncryptionWrapper


class TestGatewayWiring:
    """The gateway's own provider serves from the strict store."""

    @pytest.mark.parametrize("signing_key", [None, "s" * 48])
    async def test_built_provider_refuses_plaintext(
        self, home: Path, signing_key: str | None
    ) -> None:
        env = {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": "proxy-client.apps.googleusercontent.com",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "upstream-secret",
            "TRENTINA_OAUTH_BASE_URL": "https://mcp.example.com",
        }
        if signing_key:
            env["TRENTINA_OAUTH_JWT_SIGNING_KEY"] = signing_key
        profile = Profile(
            name="agent2",
            auth=AuthConfig(bearer_token_env="A"),
            oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
        )
        with patch.dict("os.environ", env, clear=False):
            ctx = _build_oauth_context(GatewayConfig(profiles={"agent2": profile}))
        assert ctx is not None
        storage = ctx.provider._client_storage
        assert type(storage) is StrictFernetEncryptionWrapper
        await _plant(storage, COLLECTION, "token:up1")
        assert await storage.get(key="token:up1", collection=COLLECTION) is None


class TestParityWithFastMCP:
    async def test_same_directory_and_key_as_fastmcp(self, home: Path) -> None:
        """Records FastMCP's default store wrote stay readable, and the reverse."""
        theirs = _fastmcp_storage()
        ours = build_client_storage()
        await theirs.put(key="k1", value={"a": 1}, collection="c")
        assert await ours.get(key="k1", collection="c") == {"a": 1}
        await ours.put(key="k2", value={"b": 2}, collection="c")
        assert await theirs.get(key="k2", collection="c") == {"b": 2}
