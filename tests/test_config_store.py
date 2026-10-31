"""config_store (#633): replace profiles.yaml without ever leaving it broken.

Two properties. A reader never sees a partial file — it sees the old bytes or
the new ones, never half of either. And the bytes that were there are still
recoverable afterwards, which is the "backed up" half of Scott's requirement
that config changes be logged, backed up and version controlled.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator

import pytest

from trentina import config as config_mod
from trentina.gateway import config_store

ORIGINAL = "profiles:\n  a: 1\n"
REPLACEMENT = "profiles:\n  a: 2\n"


@pytest.fixture
def data_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    yield tmp_path / "state"
    config_mod._config = None


@pytest.fixture
def live(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "config" / "profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(ORIGINAL, encoding="utf-8")
    return path


class TestHash:
    def test_it_changes_when_a_comment_changes(self) -> None:
        """The hash is of the text, not the parsed config: a hand edit that only
        touched a comment still has to invalidate a pending write."""
        assert config_store.config_hash("a: 1\n") != config_store.config_hash("# note\na: 1\n")

    def test_it_is_stable(self) -> None:
        assert config_store.config_hash(ORIGINAL) == config_store.config_hash(ORIGINAL)


class TestReplace:
    def test_it_writes_the_new_text(self, live: pathlib.Path) -> None:
        config_store.replace_config(live, REPLACEMENT)
        assert live.read_text(encoding="utf-8") == REPLACEMENT

    def test_it_leaves_no_staging_file(self, live: pathlib.Path) -> None:
        config_store.replace_config(live, REPLACEMENT)
        assert sorted(p.name for p in live.parent.iterdir()) == ["profiles.yaml"]

    def test_it_keeps_the_mode_the_file_already_had(self, live: pathlib.Path) -> None:
        """os.replace swaps the inode, so a mode of our own choosing would
        silently re-permission a file the operator mounted deliberately.

        The mode compared is whatever the ambient umask gave the file, rather
        than one this test sets: asserting equality catches the regression
        wherever that is not already ``BACKUP_FILE_MODE``, and the test never
        has to create a group-readable file to make its point.
        """
        before = os.stat(live).st_mode & 0o777

        config_store.replace_config(live, REPLACEMENT)

        assert os.stat(live).st_mode & 0o777 == before

    def test_a_failed_write_leaves_the_original_and_no_litter(
        self, live: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_: object, **__: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(config_store.os, "fsync", boom)
        with pytest.raises(OSError, match="disk full"):
            config_store.replace_config(live, REPLACEMENT)

        assert live.read_text(encoding="utf-8") == ORIGINAL
        assert sorted(p.name for p in live.parent.iterdir()) == ["profiles.yaml"]

    def test_a_leftover_staging_file_does_not_wedge_later_writes(self, live: pathlib.Path) -> None:
        """A crash mid-write leaves one identifiable file; the next write must
        not be blocked by it."""
        live.with_name(f".{live.name}.staged").write_text("junk", encoding="utf-8")
        config_store.replace_config(live, REPLACEMENT)
        assert live.read_text(encoding="utf-8") == REPLACEMENT


class TestBackups:
    def test_it_keeps_the_previous_text(self, data_dir: pathlib.Path) -> None:
        kept = config_store.back_up(ORIGINAL, after_hash="a" * 64, now=1_000_000)
        assert kept.read_text(encoding="utf-8") == ORIGINAL

    def test_backups_are_private(self, data_dir: pathlib.Path) -> None:
        kept = config_store.back_up(ORIGINAL, after_hash="a" * 64, now=1_000_000)
        assert os.stat(kept).st_mode & 0o777 == config_store.BACKUP_FILE_MODE
        assert os.stat(kept.parent).st_mode & 0o777 == config_store.BACKUP_DIR_MODE

    def test_they_do_not_land_beside_the_live_file(
        self, data_dir: pathlib.Path, live: pathlib.Path
    ) -> None:
        """On lotor the config directory is a git repo with a drift check on it,
        so a backup written there would trip the check on every write."""
        kept = config_store.back_up(ORIGINAL, after_hash="a" * 64, now=1_000_000)
        assert live.parent not in kept.parents

    def test_two_writes_in_one_second_do_not_collide(self, data_dir: pathlib.Path) -> None:
        first = config_store.back_up(ORIGINAL, after_hash="a" * 64, now=1_000_000)
        second = config_store.back_up(REPLACEMENT, after_hash="b" * 64, now=1_000_000)
        assert first != second
        assert first.read_text(encoding="utf-8") == ORIGINAL
        assert second.read_text(encoding="utf-8") == REPLACEMENT

    def test_it_prunes_to_the_limit_oldest_first(self, data_dir: pathlib.Path) -> None:
        for tick in range(config_store.KEEP_BACKUPS + 5):
            config_store.back_up(f"version: {tick}\n", after_hash="c" * 64, now=1_000_000 + tick)

        kept = sorted(config_store.backups_dir().glob("profiles-*.yaml"))
        assert len(kept) == config_store.KEEP_BACKUPS
        # The survivors are the newest, and the very latest is still readable.
        assert kept[-1].read_text(encoding="utf-8") == (
            f"version: {config_store.KEEP_BACKUPS + 4}\n"
        )
        assert "version: 0\n" not in [p.read_text(encoding="utf-8") for p in kept]
