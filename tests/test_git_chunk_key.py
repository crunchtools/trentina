"""The git chunk key is sealed at rest like every other secret (a1706).

It was 0600 plaintext beside the perimeter store, out of reach of
``at_rest.seal_all`` and a KEK rotation. These hold the move into the sealed
store (and a crash part way through it), rotation, a wrong KEK never answered
with a new key, and the log line a new key always gets.
"""

from __future__ import annotations

import logging
import os
import pathlib
from collections.abc import Iterator

import pytest

from trentina import config as config_mod
from trentina.gateway import at_rest, git_fetch
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.git_chunks import KEY_BYTES, gateway_chunk_key

OLD = "o" * 48
NEW = "n" * 48
LEGACY_KEY = bytes(range(KEY_BYTES))


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.delenv("TRENTINA_PERIMETER_DB", raising=False)
    monkeypatch.delenv(at_rest.KEK_ENV, raising=False)
    monkeypatch.delenv(f"{at_rest.KEK_ENV}_FILE", raising=False)
    monkeypatch.delenv("TRENTINA_REQUIRE_HARDENED", raising=False)
    monkeypatch.setattr(git_fetch, "_chunk_secret", None)
    config_mod._config = None
    at_rest.reset()
    (tmp_path / "state").mkdir()
    yield tmp_path / "state"
    config_mod._config = None
    at_rest.reset()


def _kek(monkeypatch: pytest.MonkeyPatch, *lines: str) -> None:
    monkeypatch.setenv(at_rest.KEK_ENV, "\n".join(lines))
    at_rest.reset()


def _stored(data: pathlib.Path) -> pathlib.Path:
    return data / "git" / "chunk-key"


def _legacy(data: pathlib.Path) -> pathlib.Path:
    path = data / "git-chunk.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(LEGACY_KEY)
    return path


def _opens_with(monkeypatch: pytest.MonkeyPatch, path: pathlib.Path, line: str) -> bytes:
    _kek(monkeypatch, line)
    kek = at_rest._current()
    assert kek is not None
    plaintext, stale = at_rest._open(kek, path, path.read_bytes())
    assert not stale
    return plaintext


def test_a_new_key_is_sealed_made_once_and_said_so(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _kek(monkeypatch, NEW)
    with caplog.at_level(logging.WARNING, logger="trentina.gateway.git_chunks"):
        key = gateway_chunk_key()
        assert gateway_chunk_key() == key
    assert len(key) == KEY_BYTES
    raw = _stored(data_dir).read_bytes()
    assert raw.startswith(at_rest.SEALED_MAGIC)
    assert key not in raw
    assert _stored(data_dir).stat().st_mode & 0o777 == 0o600
    assert (data_dir / "git").stat().st_mode & 0o777 == 0o700
    news = [r for r in caplog.records if "a new one was made" in r.getMessage()]
    assert len(news) == 1
    assert "cached chunk verdicts" in news[0].getMessage().lower()


def test_a_plaintext_key_is_moved_in_sealed_at_startup(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    legacy = _legacy(data_dir)
    _kek(monkeypatch, NEW)
    at_rest.configure()
    with caplog.at_level(logging.INFO, logger="trentina.gateway.git_chunks"):
        git_fetch.migrate_chunk_key()
    assert not legacy.exists()
    raw = _stored(data_dir).read_bytes()
    assert raw.startswith(at_rest.SEALED_MAGIC)
    assert LEGACY_KEY not in raw
    assert git_fetch.chunk_secret() == LEGACY_KEY
    assert not any("a new one was made" in r.getMessage() for r in caplog.records)
    assert any("moved into git/chunk-key" in r.getMessage() for r in caplog.records)
    # A cached verdict is keyed by its chunk's text, and the cuts are unchanged.
    monkeypatch.setattr(git_fetch, "_chunk_secret", None)
    assert git_fetch.chunk_secret() == LEGACY_KEY


def test_startup_makes_no_key_when_there_was_none(data_dir: pathlib.Path) -> None:
    git_fetch.migrate_chunk_key()
    assert not _stored(data_dir).exists()


def test_a_crash_after_the_move_leaves_the_plaintext_for_the_next_start(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _kek(monkeypatch, NEW)
    sealed = gateway_chunk_key()
    legacy = _legacy(data_dir)
    assert gateway_chunk_key(legacy=legacy) == sealed
    assert not legacy.exists()


def test_without_a_kek_the_key_waits_in_the_store_and_seal_all_seals_it(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = _legacy(data_dir)
    assert gateway_chunk_key(legacy=legacy) == LEGACY_KEY
    assert not legacy.exists()
    assert _stored(data_dir).read_bytes() == LEGACY_KEY
    _kek(monkeypatch, NEW)
    at_rest.configure()
    assert _stored(data_dir).read_bytes().startswith(at_rest.SEALED_MAGIC)
    assert gateway_chunk_key() == LEGACY_KEY


def test_rotation_reseals_the_key_under_the_new_first_line(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _kek(monkeypatch, OLD)
    key = gateway_chunk_key(legacy=_legacy(data_dir))
    _kek(monkeypatch, NEW, OLD)
    at_rest.configure()
    assert _opens_with(monkeypatch, _stored(data_dir), NEW) == key == LEGACY_KEY
    # Once resealed, the old line can go.
    _kek(monkeypatch, NEW)
    at_rest.configure()
    assert gateway_chunk_key() == key


def test_a_wrong_kek_is_refused_never_answered_with_a_new_key(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _kek(monkeypatch, OLD)
    gateway_chunk_key()
    before = _stored(data_dir).read_bytes()
    _kek(monkeypatch, NEW)
    kek = at_rest._current()
    assert kek is not None
    assert at_rest.seal_all(kek) == ["git/chunk-key"]
    with pytest.raises(ProfileConfigError):
        gateway_chunk_key()
    assert _stored(data_dir).read_bytes() == before


def test_a_kek_that_cannot_seal_uses_the_plaintext_key_where_it_is(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = _legacy(data_dir)
    _kek(monkeypatch, NEW)
    kek = at_rest._current()
    assert kek is not None
    kek.writable = False
    assert gateway_chunk_key(legacy=legacy) == LEGACY_KEY
    assert legacy.read_bytes() == LEGACY_KEY
    assert not _stored(data_dir).exists()


def test_an_empty_key_file_is_a_create_cut_short(
    data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _kek(monkeypatch, NEW)
    (data_dir / "git").mkdir(mode=0o700)
    _stored(data_dir).touch(mode=0o600)
    with caplog.at_level(logging.WARNING, logger="trentina.gateway.git_chunks"):
        key = gateway_chunk_key()
    assert len(key) == KEY_BYTES
    assert any("a new one was made" in r.getMessage() for r in caplog.records)


def test_a_short_plaintext_key_is_refused(data_dir: pathlib.Path) -> None:
    legacy = data_dir / "git-chunk.key"
    legacy.write_bytes(b"short")
    with pytest.raises(OSError, match="shorter"):
        gateway_chunk_key(legacy=legacy)
    assert legacy.exists()
    assert not _stored(data_dir).exists()


def test_a_symlink_in_place_of_the_key_is_refused(
    data_dir: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    (data_dir / "git").mkdir(mode=0o700)
    target = tmp_path / "elsewhere"
    target.write_bytes(LEGACY_KEY)
    _stored(data_dir).symlink_to(target)
    with pytest.raises(OSError, match="symbolic links"):
        gateway_chunk_key()
