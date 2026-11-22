"""Minted bearer tokens are stored as SHA-256 digests, never as plaintext (#868)."""

from __future__ import annotations

import hashlib
import os
import pathlib
from collections.abc import Iterator

import pytest
from pydantic import SecretStr

from trentina import config as config_mod
from trentina.gateway import auth as auth_mod
from trentina.gateway import token_store
from trentina.gateway.auth import resolve_profile_by_token, verify_bearer
from trentina.gateway.errors import AuthError
from trentina.gateway.profile import AuthConfig, Profile

LEGACY = "trt_legacyplaintexttokenvalue0123456789abcdefg"


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    token_store.ensure_tokens_dir()
    yield tmp_path / "state" / "tokens"
    config_mod._config = None


def _profile_for(name: str) -> Profile:
    p = Profile(name="p", auth=AuthConfig(bearer_token_name=name))
    assert p.auth is not None
    p.auth.bearer_token_sha256 = token_store.read_digest(name)
    return p


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _plant_legacy(d: pathlib.Path, name: str = "old") -> pathlib.Path:
    path = d / name
    path.write_text(LEGACY + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_mint_writes_only_a_digest_and_the_token_authenticates(data_dir: pathlib.Path) -> None:
    token = token_store.mint("agent")
    raw = (data_dir / "agent").read_text(encoding="utf-8")
    assert token not in raw
    assert raw == f"sha256:{_digest(token).hex()}\n"
    assert os.stat(data_dir / "agent").st_mode & 0o777 == 0o600
    verify_bearer(f"Bearer {token}", _profile_for("agent"))


@pytest.mark.usefixtures("data_dir")
def test_wrong_token_is_refused() -> None:
    token_store.mint("agent")
    with pytest.raises(AuthError, match="invalid token"):
        verify_bearer("Bearer trt_nope", _profile_for("agent"))


def test_legacy_file_migrates_on_first_load(data_dir: pathlib.Path) -> None:
    path = _plant_legacy(data_dir)
    profile = _profile_for("old")
    assert path.read_text(encoding="utf-8") == f"sha256:{_digest(LEGACY).hex()}\n"
    assert not (data_dir / "old.bak").exists()
    assert not (data_dir / "old.migrating").exists()
    assert os.stat(path).st_mode & 0o777 == 0o600
    verify_bearer(f"Bearer {LEGACY}", profile)


def test_migration_is_idempotent(data_dir: pathlib.Path) -> None:
    path = _plant_legacy(data_dir)
    first = token_store.read_digest("old")
    before = path.read_bytes()
    inode = os.stat(path).st_ino
    assert token_store.read_digest("old") == first
    assert path.read_bytes() == before
    assert os.stat(path).st_ino == inode


def test_crash_before_rename_leaves_the_original_then_completes(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _plant_legacy(data_dir)
    real_replace = os.replace

    def crash(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if str(src).endswith(".migrating"):
            raise OSError("simulated crash")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError, match="simulated"):
        token_store.read_digest("old")
    monkeypatch.undo()

    assert path.read_text(encoding="utf-8") == LEGACY + "\n"
    assert (data_dir / "old.bak").read_text(encoding="utf-8") == LEGACY + "\n"

    assert token_store.read_digest("old") == _digest(LEGACY)
    assert path.read_text(encoding="utf-8") == f"sha256:{_digest(LEGACY).hex()}\n"
    assert not (data_dir / "old.bak").exists()


def test_crash_after_rename_leaves_a_bak_the_next_load_removes(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _plant_legacy(data_dir)
    real_unlink = pathlib.Path.unlink

    def crash(self: pathlib.Path, missing_ok: bool = False) -> None:
        if self.name == "old.bak":
            raise OSError("simulated crash")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(pathlib.Path, "unlink", crash)
    with pytest.raises(OSError, match="simulated"):
        token_store.read_digest("old")
    monkeypatch.undo()

    assert path.read_text(encoding="utf-8") == f"sha256:{_digest(LEGACY).hex()}\n"
    assert (data_dir / "old.bak").exists()
    (data_dir / "old.migrating").write_text("stale")

    assert token_store.read_digest("old") == _digest(LEGACY)
    assert not (data_dir / "old.bak").exists()
    assert not (data_dir / "old.migrating").exists()


def test_empty_file_is_refused(data_dir: pathlib.Path) -> None:
    (data_dir / "blank").write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        token_store.read_digest("blank")


@pytest.mark.usefixtures("data_dir")
def test_compare_is_on_32_byte_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    token = token_store.mint("agent")
    seen: list[tuple[object, object]] = []
    real = auth_mod.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(auth_mod.hmac, "compare_digest", spy)
    profile = _profile_for("agent")
    verify_bearer(f"Bearer {token}", profile)
    assert resolve_profile_by_token(f"Bearer {token}", {"p": profile}) is profile
    assert len(seen) == 2
    for a, b in seen:
        assert isinstance(a, bytes) and isinstance(b, bytes)
        assert len(a) == len(b) == 32


def test_env_profile_still_authenticates() -> None:
    p = Profile(name="e", auth=AuthConfig(bearer_token_env="E_TOKEN"))
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("plain-env-token")
    verify_bearer("Bearer plain-env-token", p)
    assert resolve_profile_by_token("Bearer plain-env-token", {"e": p}) is p
    with pytest.raises(AuthError, match="invalid token"):
        verify_bearer("Bearer other", p)


def test_unresolved_token_is_refused() -> None:
    p = Profile(name="u", auth=AuthConfig(bearer_token_env="U_TOKEN"))
    with pytest.raises(AuthError, match="not resolved"):
        verify_bearer("Bearer x", p)
