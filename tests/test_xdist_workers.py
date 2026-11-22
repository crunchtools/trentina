"""How `-n auto --worker-mb` sizes the in-image suites (a1000).

The cgroup tree and /proc/meminfo are fake directories here: the point is the
arithmetic and the leaf-to-root walk, not this machine's memory.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from tests import conftest

if TYPE_CHECKING:
    import pytest

GIB = 1024 * conftest.MIB


def _level(path: pathlib.Path, limit: str, current: int, inactive_file: int = 0) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "memory.max").write_text(f"{limit}\n", encoding="utf-8")
    (path / "memory.current").write_text(f"{current}\n", encoding="utf-8")
    (path / "memory.stat").write_text(
        f"anon 1\ninactive_file {inactive_file}\nactive_file 7\n", encoding="utf-8"
    )


def _membership(tmp_path: pathlib.Path, rel: str) -> pathlib.Path:
    path = tmp_path / "cgroup"
    path.write_text(f"0::{rel}\n", encoding="utf-8")
    return path


class TestCgroupHeadroom:
    def test_a_parent_limit_binds_a_child_that_shows_max(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "fs"
        _level(root / "seat", str(4 * GIB), 1 * GIB)
        _level(root / "seat" / "gate", "max", 0)
        got = conftest._cgroup_headroom_mb(root, _membership(tmp_path, "/seat/gate"))
        assert got == 3 * 1024

    def test_the_tightest_level_wins(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "fs"
        _level(root / "seat", str(4 * GIB), 3 * GIB)
        _level(root / "seat" / "gate", str(8 * GIB), 0)
        got = conftest._cgroup_headroom_mb(root, _membership(tmp_path, "/seat/gate"))
        assert got == 1024

    def test_inactive_page_cache_counts_as_free(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "fs"
        _level(root / "seat", str(4 * GIB), 4 * GIB, inactive_file=2 * GIB)
        assert conftest._cgroup_headroom_mb(root, _membership(tmp_path, "/seat")) == 2 * 1024

    def test_no_limit_anywhere_is_none(self, tmp_path: pathlib.Path) -> None:
        root = tmp_path / "fs"
        root.mkdir()
        assert conftest._cgroup_headroom_mb(root, _membership(tmp_path, "/")) is None


def test_mem_available_is_read_in_mb(tmp_path: pathlib.Path) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal:       30385628 kB\nMemAvailable:    4194304 kB\n", encoding="utf-8"
    )
    assert conftest._mem_available_mb(meminfo) == 4096


def _workers(
    monkeypatch: pytest.MonkeyPatch,
    worker_mb: int,
    cgroup_mb: int | None,
    available_mb: int,
    cpus: int,
) -> int | None:
    monkeypatch.setattr(conftest, "_cgroup_headroom_mb", lambda: cgroup_mb)
    monkeypatch.setattr(conftest, "_mem_available_mb", lambda: available_mb)
    monkeypatch.setattr(conftest.os, "process_cpu_count", lambda: cpus)
    config = SimpleNamespace(getoption=lambda name: {"worker_mb": worker_mb}[name])
    return conftest.pytest_xdist_auto_num_workers(cast("pytest.Config", config))


class TestAutoWorkers:
    def test_without_worker_mb_xdist_decides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _workers(monkeypatch, 0, 8192, 8192, 4) is None

    def test_a_4gb_seat_runs_in_process(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _workers(monkeypatch, 1800, 3239, 11515, 24) == 0

    def test_an_8gb_runner_keeps_four(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _workers(monkeypatch, 1800, 8000, 14000, 4) == 4

    def test_cpus_cap_what_memory_allows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _workers(monkeypatch, 1800, 64000, 64000, 3) == 3

    def test_mem_available_caps_a_loose_cgroup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _workers(monkeypatch, 1800, 64000, 5400, 24) == 3

    def test_no_cgroup_limit_falls_back_to_mem_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert _workers(monkeypatch, 1800, None, 7200, 24) == 4

    def test_a_cgroup_over_its_limit_is_zero_not_negative(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert _workers(monkeypatch, 1800, -500, 9000, 24) == 0
