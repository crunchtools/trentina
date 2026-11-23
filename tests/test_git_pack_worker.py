"""The pack reader as a child process, and the feeder that drives it (spec 027 phase 1).

The child is run for real on real packs from the system ``git``; the feeder is
driven with a fake judge that records what reached it.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING, cast

import pytest

from trentina.gateway import git_fetch, git_judge, git_wire
from trentina.gateway.git_fetch import _Feeder, _header, _Reading
from trentina.unpack import child
from trentina.unpack.git_pack import REASONS, PackObject

from .test_git_pack import (
    FORMATS,
    blob_pack,
    copy_all_then,
    expected_objects,
    fmt_of,
    make_repo,
    object_id,
    repack_bytes,
)

if TYPE_CHECKING:
    from pathlib import Path

ARRIVED, INFLATED, CPU = 256 << 20, 2 << 30, 60


@pytest.fixture(scope="module", params=FORMATS)
def repo(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_repo(tmp_path_factory.mktemp("worker"), request.param)


def _run(pack: bytes, fmt: str, spool: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "trentina.unpack.git_pack_worker",
            fmt,
            str(ARRIVED),
            str(INFLATED),
            str(CPU),
            str(spool),
        ],
        input=pack,
        capture_output=True,
        env=child.environment(),
        check=False,
        timeout=120,
    )


def _frames(out: bytes) -> tuple[dict[str, tuple[str, bytes]], bytes]:
    """The objects in a child's stdout, and its closing line."""
    objects: dict[str, tuple[str, bytes]] = {}
    i = 0
    while True:
        eol = out.index(b"\n", i)
        line = out[i : eol + 1]
        words = line.split()
        if words[0] in (b"end", b"refused"):
            assert eol + 1 == len(out), "nothing follows the closing line"
            return objects, line
        kind, oid, _offset, length = words
        start = eol + 1
        objects[oid.decode()] = (kind.decode(), out[start : start + int(length)])
        i = start + int(length)


def test_real_pack_equals_git(repo: Path, tmp_path: Path) -> None:
    proc = _run(repack_bytes(repo), fmt_of(repo), tmp_path)
    assert proc.returncode == 0
    objects, last = _frames(proc.stdout)
    assert last == b"end\n"
    assert objects == expected_objects(repo)


def test_a_truncated_pack_is_refused(repo: Path, tmp_path: Path) -> None:
    pack = repack_bytes(repo)
    for cut in (pack[:-3], pack[: len(pack) // 2]):
        proc = _run(cut, fmt_of(repo), tmp_path)
        assert proc.returncode == 0
        _objects, last = _frames(proc.stdout)
        assert last.startswith(b"refused ")
        assert last.split()[1].decode() in REASONS


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_thin_pack_is_refused(fmt: str, tmp_path: Path) -> None:
    builder = blob_pack(fmt)
    builder.ref(object_id("blob", b"elsewhere", fmt), copy_all_then(9, b"!"))
    _objects, last = _frames(_run(builder.build(), fmt, tmp_path).stdout)
    assert last == b"refused thin_pack\n"


def test_the_wrong_argument_count_exits_2(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "trentina.unpack.git_pack_worker", "sha1", str(tmp_path)],
        input=b"",
        capture_output=True,
        env=child.environment(),
        check=False,
        timeout=60,
    )
    assert proc.returncode == 2
    assert proc.stdout == b""


def test_the_child_environment_carries_no_credential() -> None:
    env = child.environment()
    assert env
    assert not [k for k in env if k.upper().endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD"))]


# --- the feeder --------------------------------------------------------------------


class FakeJudge:
    def __init__(self) -> None:
        self.submitted: list[PackObject] = []
        self.finished = 0
        self.closed = 0

    def submit(self, obj: PackObject) -> None:
        self.submitted.append(obj)

    def finish_pack(self) -> None:
        self.finished += 1

    def close(self) -> None:
        self.closed += 1


def _feeder(spool: Path, fmt: str, deadline: int = 60) -> tuple[_Feeder, FakeJudge]:
    judge = FakeJudge()
    reading = _Reading(fmt, ARRIVED, INFLATED, deadline, str(spool))
    return _Feeder(reading, cast("git_judge.GitJudge", judge)), judge


async def _feed_in_pieces(feeder: _Feeder, pack: bytes, size: int = 7000) -> None:
    for i in range(0, len(pack), size):
        await feeder.feed(pack[i : i + size])


async def test_the_feeder_hands_every_object_to_the_judge(repo: Path, tmp_path: Path) -> None:
    feeder, judge = _feeder(tmp_path, fmt_of(repo))
    await _feed_in_pieces(feeder, repack_bytes(repo))
    await feeder.finish()
    assert feeder.refused is None
    assert feeder.done()
    assert {o.oid: (o.kind, o.content) for o in judge.submitted} == expected_objects(repo)
    assert judge.finished == 1 and judge.closed == 1


async def test_a_truncated_pack_through_the_feeder(repo: Path, tmp_path: Path) -> None:
    feeder, judge = _feeder(tmp_path, fmt_of(repo))
    await _feed_in_pieces(feeder, repack_bytes(repo)[:-3])
    await feeder.finish()
    assert feeder.refused in REASONS
    assert judge.finished == 0 and judge.closed == 1


async def test_a_child_past_the_deadline_is_killed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sleeper = [sys.executable, "-c", "import time; time.sleep(60)"]
    monkeypatch.setattr(_Reading, "argv", lambda self: sleeper)
    feeder, judge = _feeder(tmp_path, "sha1", deadline=1)
    await feeder.feed(b"PACK")
    await feeder.finish()
    assert feeder.refused == "deadline"
    assert feeder._proc is not None and feeder._proc.returncode is not None
    assert judge.finished == 0 and judge.closed == 1


async def test_a_malformed_header_is_a_failed_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    liar = [sys.executable, "-c", "print('blob zz 0 5')"]
    monkeypatch.setattr(_Reading, "argv", lambda self: liar)
    feeder, judge = _feeder(tmp_path, "sha1")
    await feeder.finish()
    assert feeder.refused == "failed"
    assert judge.submitted == [] and judge.closed == 1


async def test_a_child_that_ends_silent_is_a_failed_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mute = [sys.executable, "-c", "pass"]
    monkeypatch.setattr(_Reading, "argv", lambda self: mute)
    feeder, _judge = _feeder(tmp_path, "sha1")
    await feeder.finish()
    assert feeder.refused == "failed"


# --- _header -----------------------------------------------------------------------

SHA1, SHA256 = "a" * 40, "b" * 64


def test_header_accepts_both_object_formats() -> None:
    assert _header(["blob", SHA1, "12", "5"], 100) == ("blob", SHA1, 12, 5)
    assert _header(["commit", SHA256, "0", "100"], 100) == ("commit", SHA256, 0, 100)


@pytest.mark.parametrize(
    "words",
    [
        ["bogus", SHA1, "0", "5"],
        ["blob", "g" * 40, "0", "5"],
        ["blob", "A" * 40, "0", "5"],
        ["blob", "a" * 39, "0", "5"],
        ["blob", "a" * 41, "0", "5"],
        ["blob", SHA1, "0", "-1"],
        ["blob", SHA1, "0", "x"],
        ["blob", SHA1, "-3", "5"],
        ["blob", SHA1, "0", "101"],
        ["blob", SHA1, "0"],
        ["blob", SHA1, "0", "5", "extra"],
    ],
)
def test_header_rejects(words: list[str]) -> None:
    with pytest.raises(ValueError, match="not a"):
        _header(words, 100)


async def test_a_pack_over_the_grants_cap_is_named_unjudged(repo: Path, tmp_path: Path) -> None:
    """``max_judged_pack_bytes``: past it the reader stops and the rest of the
    pack is delivered unjudged, which the side band says in one line."""
    pack = repack_bytes(repo)
    judge = FakeJudge()
    reading = _Reading(fmt_of(repo), len(pack) // 2, INFLATED, 60, str(tmp_path))
    feeder = _Feeder(reading, cast("git_judge.GitJudge", judge))
    await _feed_in_pieces(feeder, pack)
    await feeder.finish()
    assert feeder.refused == "too_large"
    assert judge.finished == 0 and judge.closed == 1
    named = git_fetch._named(cast("git_judge.GitJudge", _NoOutcome()), feeder.refused, 0)
    assert named == [git_wire.progress("Trentina: unjudged pack (too_large)")]


class _NoOutcome:
    """A judge that found nothing, for the side-band wording alone."""

    def outcome(self) -> git_judge.Outcome:
        return git_judge.Outcome(flagged=[], unjudged=[], pending=0, judged=0, total=0)
