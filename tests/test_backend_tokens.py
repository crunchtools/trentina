"""The per-(profile, backend) grant store for outbound OAuth (#479)."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from trentina.gateway import backend_tokens
from trentina.gateway.backend_tokens import (
    KEY_ENV,
    BackendClient,
    BackendGrant,
    BackendTokenStore,
    GrantConflictError,
    _SealedGrant,
    configure_backend_tokens,
    open_backend_token_store,
)
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.profile import AuthConfig, Backend, BackendAuth, Profile

CANARY = "zqx7canary-access-token-0123456789"
REFRESH = "zqx7canary-refresh-token-0123456789"
KEY = "k" * 48
OTHER_KEY = "o" * 48
ERA = Backend(url="https://context.era.app/mcp", auth=BackendAuth(type="oauth"))


def _grant(**changes: object) -> BackendGrant:
    fields: dict[str, object] = {
        "access_token": SecretStr(CANARY),
        "refresh_token": SecretStr(REFRESH),
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
        "scopes": ("read",),
        "issuer": "https://auth.era.app",
        "obtained_at": datetime.now(UTC),
    }
    fields.update(changes)
    return BackendGrant.model_validate(fields)


def _open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str = KEY) -> BackendTokenStore:
    monkeypatch.setenv(KEY_ENV, key)
    store = open_backend_token_store(tmp_path)
    assert store is not None
    return store


async def _put(store: BackendTokenStore, profile: str = "josui", backend: Backend = ERA) -> None:
    async with store.locked(profile, "era"):
        await store.put_grant(profile, "era", backend, _grant(), expected_generation=0)


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def _grant_files(root: Path) -> list[Path]:
    return [p for p in _files(root) if p.parent.name.startswith("S_backend_grants")]


def _record_file(root: Path) -> Path:
    (path,) = _grant_files(root)
    return path


class TestRoundTrip:
    async def test_a_grant_reads_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        got = await store.get_grant("josui", "era", ERA)
        assert got is not None
        assert got.access_token.get_secret_value() == CANARY
        assert got.refresh_token is not None
        assert got.refresh_token.get_secret_value() == REFRESH
        assert got.scopes == ("read",)
        assert got.generation == 1

    async def test_survives_a_restart(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _put(_open(tmp_path, monkeypatch))
        reopened = _open(tmp_path, monkeypatch)
        assert await reopened.get_grant("josui", "era", ERA) is not None

    async def test_delete_drops_the_grant_and_keeps_the_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        await store.put_client("josui", "era", ERA, BackendClient(client_id="c1", issuer="i"))
        assert await store.delete_grant("josui", "era")
        assert await store.get_grant("josui", "era", ERA) is None
        client = await store.get_client("josui", "era", ERA)
        assert client is not None
        assert client.client_id == "c1"


class TestIsolation:
    async def test_another_profile_does_not_get_the_grant(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store, "josui")
        assert await store.get_grant("kagetora", "era", ERA) is None

    async def test_a_copied_record_does_not_open_in_another_slot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store, "kagetora")
        kagetora_file = _record_file(tmp_path)
        await _put(store, "josui")
        (josui_file,) = [p for p in _grant_files(tmp_path) if p != kagetora_file]
        josui_file.write_bytes(kagetora_file.read_bytes())
        assert await store.get_grant("josui", "era", ERA) is None

    async def test_a_moved_backend_url_needs_auth_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        moved = Backend(url="https://elsewhere.example/mcp", auth=BackendAuth(type="oauth"))
        assert await store.get_grant("josui", "era", moved) is None
        # The path is not the host: a moved path keeps the grant.
        repathed = Backend(url="https://context.era.app/v2/mcp", auth=BackendAuth(type="oauth"))
        assert await store.get_grant("josui", "era", repathed) is not None


class TestTheDiskIsNotTrusted:
    async def test_no_token_is_written_in_plaintext(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        await store.put_client(
            "josui",
            "era",
            ERA,
            BackendClient(client_id="c", client_secret=SecretStr(CANARY), issuer="i"),
        )
        for path in _files(tmp_path):
            assert b"zqx7canary" not in path.read_bytes()

    async def test_a_planted_plaintext_record_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        path = _record_file(tmp_path)
        entry = json.loads(path.read_text())
        entry["value"] = {
            "slot": "josui:era",
            "origin": "https://context.era.app",
            "stored_until": "2099-01-01T00:00:00Z",
            "access_token": "attacker",
            "token_type": "Bearer",
            "expires_at": None,
            "scopes": [],
            "issuer": "x",
            "obtained_at": "2026-01-01T00:00:00Z",
            "generation": 1,
        }
        path.write_text(json.dumps(entry))
        assert await store.get_grant("josui", "era", ERA) is None

    async def test_another_key_reads_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _put(_open(tmp_path, monkeypatch))
        rotated = _open(tmp_path, monkeypatch, OTHER_KEY)
        assert await rotated.get_grant("josui", "era", ERA) is None

    async def test_a_tampered_ciphertext_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        path = _record_file(tmp_path)
        entry = json.loads(path.read_text())
        ct = entry["value"]["ct"]
        entry["value"]["ct"] = ct[:-6] + ("A" if ct[-6] != "A" else "B") + ct[-5:]
        path.write_text(json.dumps(entry))
        assert await store.get_grant("josui", "era", ERA) is None

    def test_the_directory_is_private_and_not_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _open(tmp_path, monkeypatch)
        (directory,) = list(tmp_path.iterdir())
        assert directory.stat().st_mode & 0o077 == 0
        assert KEY[:12] not in directory.name


class TestGenerations:
    async def test_a_stale_write_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        async with store.locked("josui", "era"):
            with pytest.raises(GrantConflictError):
                await store.put_grant("josui", "era", ERA, _grant(), expected_generation=0)
            stored = await store.put_grant("josui", "era", ERA, _grant(), expected_generation=1)
        assert stored.generation == 2

    async def test_a_write_outside_the_lock_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        with pytest.raises(RuntimeError, match="locked"):
            await store.put_grant("josui", "era", ERA, _grant(), expected_generation=0)

    async def test_one_slot_refreshes_one_at_a_time(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        inside = 0
        most = 0

        async def refresh() -> None:
            nonlocal inside, most
            async with store.locked("josui", "era"):
                inside += 1
                most = max(most, inside)
                await asyncio.sleep(0.01)
                inside -= 1

        await asyncio.gather(*(refresh() for _ in range(5)))
        assert most == 1


class TestTokensNeverPrint:
    def test_repr_str_and_dump_hold_no_token(self) -> None:
        grant = _grant()
        for text in (repr(grant), str(grant), grant.model_dump_json()):
            assert "zqx7canary" not in text

    def test_a_validation_error_holds_no_token(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _SealedGrant.model_validate({"access_token": CANARY, "slot": 7})
        assert "zqx7canary" not in str(caught.value)

    async def test_a_malformed_record_logs_no_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        store = _open(tmp_path, monkeypatch)
        await _put(store)
        path = _record_file(tmp_path)
        entry = json.loads(path.read_text())
        bad = {"slot": 7, "access_token": CANARY}
        entry["value"]["ct"] = store._fernet.encrypt(json.dumps(bad).encode()).decode()
        path.write_text(json.dumps(entry))
        with caplog.at_level(logging.DEBUG):
            assert await store.get_grant("josui", "era", ERA) is None
        assert "did not open" in caplog.text
        assert "zqx7canary" not in caplog.text


class TestOpening:
    def test_no_key_no_store(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(KEY_ENV, raising=False)
        monkeypatch.delenv(f"{KEY_ENV}_FILE", raising=False)
        assert open_backend_token_store(tmp_path) is None
        assert list(tmp_path.iterdir()) == []

    def test_a_short_key_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(KEY_ENV, "short-but-sixteen")
        with pytest.raises(ProfileConfigError, match="openssl rand"):
            open_backend_token_store(tmp_path)

    def test_unset_key_warns_when_a_backend_wants_one(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv(KEY_ENV, raising=False)
        monkeypatch.delenv(f"{KEY_ENV}_FILE", raising=False)
        monkeypatch.setattr(backend_tokens, "_store", None)
        bearer = AuthConfig(bearer_token_env="JOSUI_TOKEN")
        wants = {"josui": Profile(name="josui", auth=bearer, backends={"era": ERA})}
        plain = {
            "josui": Profile(
                name="josui", auth=bearer, backends={"x": Backend(url="https://x.example")}
            )
        }
        with caplog.at_level(logging.WARNING):
            assert configure_backend_tokens(plain) is None
            assert "needs auth" not in caplog.text
            assert configure_backend_tokens(wants) is None
        assert 'report "needs auth"' in caplog.text
