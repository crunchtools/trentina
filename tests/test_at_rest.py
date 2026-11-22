"""Sealing the data volume's secrets under one KEK (#868).

Federation keys and ``<data>/secrets`` were 0600 plaintext, so a copy of the
volume was every credential in it. These hold the four things the design
decision named: migration (idempotent, and safe across a crash at either
point), rotation by a new first line, a hardened start refusing without a
usable KEK, and no key or value in a log line.
"""

from __future__ import annotations

import io
import logging
import os
import pathlib
from collections.abc import Iterator

import pytest

from trentina import config as config_mod
from trentina.errors import ConfigError
from trentina.gateway import at_rest, key_store, secret_file, secret_store
from trentina.gateway.errors import ProfileConfigError

OLD = "o" * 48
NEW = "n" * 48
VALUE = "outside-credential-value-0123456789"


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.delenv(at_rest.KEK_ENV, raising=False)
    monkeypatch.delenv(f"{at_rest.KEK_ENV}_FILE", raising=False)
    monkeypatch.delenv("TRENTINA_REQUIRE_HARDENED", raising=False)
    config_mod._config = None
    at_rest.reset()
    yield tmp_path / "state"
    config_mod._config = None
    at_rest.reset()


def _kek(monkeypatch: pytest.MonkeyPatch, *lines: str) -> None:
    monkeypatch.setenv(at_rest.KEK_ENV, "\n".join(lines))
    at_rest.reset()


def _raw(path: pathlib.Path) -> bytes:
    return path.read_bytes()


def _plaintext_secret(name: str) -> pathlib.Path:
    """A value written the way the store did before #868."""
    secret_file.private_dir("secrets")
    path = secret_store.secrets_dir() / name
    secret_file.write_once(path, VALUE.encode())
    return path


class TestSealing:
    def test_a_new_value_is_sealed_and_reads_back(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, NEW)
        secret_store.put("STORE_X", VALUE)
        raw = _raw(secret_store.secrets_dir() / "STORE_X")
        assert raw.startswith(at_rest.SEALED_MAGIC)
        assert VALUE.encode() not in raw
        assert secret_store.read_secret("STORE_X") == VALUE

    def test_a_minted_key_is_sealed_and_loads(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, NEW)
        key_store.mint("fed-a")
        raw = _raw(key_store.key_path("fed-a"))
        assert raw.startswith(at_rest.SEALED_MAGIC)
        assert b"PRIVATE KEY" not in raw
        assert key_store.read_key("fed-a").startswith("-----BEGIN PRIVATE KEY-----")

    def test_without_a_kek_nothing_changes(self, data_dir: pathlib.Path) -> None:
        secret_store.put("STORE_X", VALUE)
        assert _raw(secret_store.secrets_dir() / "STORE_X") == VALUE.encode()
        assert secret_store.read_secret("STORE_X") == VALUE

    def test_a_sealed_file_without_the_kek_refuses_by_name(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, NEW)
        secret_store.put("STORE_X", VALUE)
        monkeypatch.delenv(at_rest.KEK_ENV)
        at_rest.reset()
        with pytest.raises(ProfileConfigError, match=at_rest.KEK_ENV):
            secret_store.read_secret("STORE_X")

    def test_a_wrong_kek_refuses(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, OLD)
        secret_store.put("STORE_X", VALUE)
        _kek(monkeypatch, NEW)
        with pytest.raises(ProfileConfigError, match="no key"):
            secret_store.read_secret("STORE_X")


class TestMigration:
    def test_a_plaintext_file_is_sealed_on_first_read(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _plaintext_secret("LEGACY")
        _kek(monkeypatch, NEW)
        assert secret_store.read_secret("LEGACY") == VALUE
        assert _raw(path).startswith(at_rest.SEALED_MAGIC)
        assert not path.with_name("LEGACY.bak").exists()
        assert not path.with_name("LEGACY.staged").exists()
        assert oct(path.stat().st_mode & 0o777) == oct(secret_file.FILE_MODE)

    def test_migration_is_idempotent(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _plaintext_secret("LEGACY")
        _kek(monkeypatch, NEW)
        secret_store.read_secret("LEGACY")
        sealed = _raw(path)
        assert secret_store.read_secret("LEGACY") == VALUE
        assert _raw(path) == sealed  # read again, not resealed

    def test_a_crash_before_the_rename_leaves_the_original(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _plaintext_secret("LEGACY")
        _kek(monkeypatch, NEW)
        real_replace = os.replace

        def crash(src: str, dst: str) -> None:
            if pathlib.Path(dst) == path:
                raise OSError(5, "simulated crash")
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", crash)
        with pytest.raises(ProfileConfigError):
            secret_store.read_secret("LEGACY")
        assert _raw(path) == VALUE.encode()
        assert path.with_name("LEGACY.bak").exists()
        monkeypatch.setattr(os, "replace", real_replace)

        assert secret_store.read_secret("LEGACY") == VALUE
        assert _raw(path).startswith(at_rest.SEALED_MAGIC)
        assert not path.with_name("LEGACY.bak").exists()

    def test_a_crash_after_the_rename_is_finished_by_the_next_read(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _plaintext_secret("LEGACY")
        _kek(monkeypatch, NEW)
        backup = path.with_name("LEGACY.bak")
        real_unlink = pathlib.Path.unlink

        def crash(self: pathlib.Path, missing_ok: bool = False) -> None:
            if self == backup:
                raise OSError(5, "simulated crash")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(pathlib.Path, "unlink", crash)
        with pytest.raises(ProfileConfigError, match="simulated crash"):
            secret_store.read_secret("LEGACY")
        assert _raw(path).startswith(at_rest.SEALED_MAGIC)
        assert backup.exists()
        monkeypatch.setattr(pathlib.Path, "unlink", real_unlink)

        assert secret_store.read_secret("LEGACY") == VALUE
        assert not backup.exists()

    def test_startup_seals_every_file_and_skips_backups(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_path = _plaintext_secret("UNREFERENCED")
        key_store.mint("fed-a")  # no KEK yet: plaintext PEM
        key_path = key_store.key_path("fed-a")
        assert b"PRIVATE KEY" in _raw(key_path)
        _kek(monkeypatch, NEW)
        assert at_rest.configure() is True
        assert _raw(secret_path).startswith(at_rest.SEALED_MAGIC)
        assert _raw(key_path).startswith(at_rest.SEALED_MAGIC)
        assert secret_store.names() == ["UNREFERENCED"]


class TestRotation:
    def test_a_new_first_line_reseals_on_read(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, OLD)
        secret_store.put("STORE_X", VALUE)
        under_old = _raw(secret_store.secrets_dir() / "STORE_X")

        _kek(monkeypatch, NEW, OLD)
        assert secret_store.read_secret("STORE_X") == VALUE
        resealed = _raw(secret_store.secrets_dir() / "STORE_X")
        assert resealed != under_old

        _kek(monkeypatch, NEW)  # the old line can go now
        assert secret_store.read_secret("STORE_X") == VALUE

    def test_startup_reseals_a_key_nobody_reads(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, OLD)
        key_store.mint("fed-a")
        _kek(monkeypatch, NEW, OLD)
        at_rest.configure()
        _kek(monkeypatch, NEW)
        assert key_store.read_key("fed-a").startswith("-----BEGIN PRIVATE KEY-----")


class TestStartup:
    def test_hardened_without_a_kek_refuses_naming_both_forms(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        with pytest.raises(ConfigError) as refused:
            at_rest.configure()
        assert at_rest.KEK_ENV in str(refused.value)
        assert f"{at_rest.KEK_ENV}_FILE" in str(refused.value)

    def test_hardened_with_a_missing_kek_file_refuses(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        monkeypatch.setenv(f"{at_rest.KEK_ENV}_FILE", str(data_dir / "nope"))
        with pytest.raises(ConfigError, match=f"{at_rest.KEK_ENV}_FILE"):
            at_rest.configure()

    def test_hardened_with_a_kek_that_opens_nothing_refuses(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, OLD)
        secret_store.put("STORE_X", VALUE)
        _kek(monkeypatch, NEW)
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        with pytest.raises(ConfigError, match="secrets/STORE_X"):
            at_rest.configure()

    def test_a_short_kek_line_refuses_hardened_or_not(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _kek(monkeypatch, NEW, "short")
        with pytest.raises(ConfigError, match="line 2"):
            at_rest.configure()

    def test_hardened_with_a_kek_starts(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        _kek(monkeypatch, NEW)
        assert at_rest.configure() is True

    def test_unhardened_without_a_kek_warns_and_starts(
        self, data_dir: pathlib.Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert at_rest.configure() is False
        assert "UNSEALED" in caplog.text
        assert at_rest.KEK_ENV in caplog.text

    def test_no_key_or_value_reaches_a_log_line(
        self,
        data_dir: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _plaintext_secret("LEGACY")
        _kek(monkeypatch, NEW, OLD)
        with caplog.at_level(logging.DEBUG):
            at_rest.configure()
            secret_store.read_secret("LEGACY")
        assert VALUE not in caplog.text
        assert NEW not in caplog.text
        assert OLD not in caplog.text

    def test_the_cli_refuses_to_write_unsealed_when_hardened(
        self, data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        monkeypatch.setattr("sys.stdin", io.StringIO(VALUE))
        assert secret_store.main(["put", "STORE_X"]) == 1
        assert not (secret_store.secrets_dir() / "STORE_X").exists()
