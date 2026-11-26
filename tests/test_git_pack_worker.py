"""The pack reader as a child process, and the feeder that drives it (spec 027 phase 1).

The child is run for real on real packs from the system ``git``; the feeder is
driven with a fake judge that records what reached it.
"""

from __future__ import annotations

import asyncio
import random
import subprocess
import sys
from typing import TYPE_CHECKING, cast

import pytest

from trentina.gateway import git_fetch, git_judge, git_wire
from trentina.gateway.git_fetch import _Feeder, _header, _Reading
from trentina.unpack import child, git_pack_worker
from trentina.unpack.git_pack import REASONS, PackObject

from .test_git_pack import (
    FORMATS,
    blob_pack,
    copy_all_then,
    expected_objects,
    fmt_of,
    git,
    make_repo,
    object_id,
    repack_bytes,
    stream_bytes,
)

if TYPE_CHECKING:
    from pathlib import Path

ARRIVED, INFLATED, CPU = 256 << 20, 2 << 30, 60


@pytest.fixture(scope="module", params=FORMATS)
def repo(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_repo(tmp_path_factory.mktemp("worker"), request.param)


def _run(
    pack: bytes, fmt: str, spool: Path, max_object: int = INFLATED
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "trentina.unpack.git_pack_worker",
            fmt,
            str(ARRIVED),
            str(INFLATED),
            str(max_object),
            str(CPU),
            str(spool),
        ],
        input=pack,
        capture_output=True,
        env=child.environment(),
        check=False,
        timeout=120,
    )


def _frames(out: bytes) -> tuple[dict[str, tuple[str, bytes | None]], bytes]:
    """The objects in a child's stdout, and its closing line; an object sent
    over the limit has no content."""
    objects: dict[str, tuple[str, bytes | None]] = {}
    i = 0
    while True:
        eol = out.index(b"\n", i)
        line = out[i : eol + 1]
        words = line.split()
        if words[0] in (b"end", b"refused"):
            assert eol + 1 == len(out), "nothing follows the closing line"
            return objects, line
        if words[4:] == [b"over"]:
            objects[words[1].decode()] = (words[0].decode(), None)
            i = eol + 1
            continue
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


def test_an_object_over_the_limit_is_sent_without_its_content(repo: Path, tmp_path: Path) -> None:
    expected = expected_objects(repo)
    limit = sorted(len(content) for _kind, content in expected.values())[len(expected) // 2]
    objects, last = _frames(_run(repack_bytes(repo), fmt_of(repo), tmp_path, limit).stdout)
    assert last == b"end\n"
    assert objects == {
        oid: (kind, None if len(content) > limit else content)
        for oid, (kind, content) in expected.items()
    }
    assert any(content is None for _kind, content in objects.values())


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


def test_running_out_of_memory_is_refused_as_too_large(tmp_path: Path) -> None:
    probe = (
        "import sys\n"
        "from trentina.unpack import git_pack_worker as w\n"
        "def starve(self, piece):\n"
        "    raise MemoryError\n"
        "w.PackReader.feed = starve\n"
        f"sys.exit(w.main(['w', 'sha1', '1', '1', '1', '7', {str(tmp_path)!r}]))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        input=b"PACK",
        capture_output=True,
        env=child.environment(),
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == b"refused too_large\n"


def test_the_child_sets_its_own_cpu_and_memory_limits(tmp_path: Path) -> None:
    """Read back from inside a child run as the gateway runs it: the limits
    are the child's own, set before the first byte of the pack is read."""
    probe = (
        "import os, resource, sys\n"
        "from trentina.unpack import git_pack_worker as w\n"
        "os.read = lambda fd, n: b''\n"
        f"w.main(['w', 'sha1', '1', '1', '1', '7', {str(tmp_path)!r}])\n"
        "print(resource.getrlimit(resource.RLIMIT_CPU),"
        " resource.getrlimit(resource.RLIMIT_AS), file=sys.stderr)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        input=b"",
        capture_output=True,
        env=child.environment(),
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    memory = git_pack_worker.MEMORY_BYTES
    assert proc.stderr.decode().split("\n")[-2] == f"(7, 7) ({memory}, {memory})"


def test_the_child_environment_carries_no_credential() -> None:
    env = child.environment()
    assert env
    assert not [k for k in env if k.upper().endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD"))]


# --- the feeder --------------------------------------------------------------------


class FakeJudge:
    def __init__(self) -> None:
        self.submitted: list[PackObject] = []
        self.unread: dict[str, str] = {}
        self.finished = 0
        self.closed = 0
        self.expires_at: float | None = None

    async def add(self, obj: PackObject) -> None:
        self.submitted.append(obj)

    def submit_unread(self, oid: str, _kind: str, gap: str) -> None:
        self.unread[oid] = gap

    def full(self) -> bool:
        return False

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


async def test_the_feeder_names_an_object_over_the_limit_unjudged(
    repo: Path, tmp_path: Path
) -> None:
    expected = expected_objects(repo)
    limit = sorted(len(content) for _kind, content in expected.values())[len(expected) // 2]
    judge = FakeJudge()
    reading = _Reading(fmt_of(repo), ARRIVED, INFLATED, 60, str(tmp_path), max_object=limit)
    feeder = _Feeder(reading, cast("git_judge.GitJudge", judge))
    await _feed_in_pieces(feeder, repack_bytes(repo))
    await feeder.finish()
    assert feeder.refused is None
    over = {oid for oid, (_kind, content) in expected.items() if len(content) > limit}
    assert over and judge.unread == dict.fromkeys(over, "too_large")
    assert {o.oid for o in judge.submitted} == expected.keys() - over


async def test_content_over_the_limit_without_saying_so_is_a_failed_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    liar = [sys.executable, "-c", f"print('blob {SHA1} 0 9'); print('012345678')"]
    monkeypatch.setattr(_Reading, "argv", lambda self: liar)
    judge = FakeJudge()
    reading = _Reading("sha1", ARRIVED, INFLATED, 60, str(tmp_path), max_object=8)
    feeder = _Feeder(reading, cast("git_judge.GitJudge", judge))
    await feeder.finish()
    assert feeder.refused == "failed"
    assert judge.submitted == []


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
    assert _header(["blob", SHA1, "12", "5"], 100) == ("blob", SHA1, 12, 5, False)
    assert _header(["commit", SHA256, "0", "100"], 100) == ("commit", SHA256, 0, 100, False)
    assert _header(["blob", SHA1, "12", "50", "over"], 100) == ("blob", SHA1, 12, 50, True)


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
        ["blob", SHA1, "0", "5", "over", "over"],
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
    named = git_fetch._named(cast("git_judge.GitJudge", _NoOutcome()), feeder.refused, 0, 0)
    assert named == [git_wire.progress("Trentina: unjudged pack (too_large)")]


class _NoOutcome:
    """A judge that found nothing, for the side-band wording alone."""

    def outcome(self) -> git_judge.Outcome:
        return git_judge.Outcome(flagged=[], unjudged=[], pending=0, judged=0, total=0)


async def test_objects_reach_the_judge_while_the_pack_still_arrives(tmp_path: Path) -> None:
    """A pack over ``FEED_BYTES`` is written to the child as it comes, so its
    first objects are judged before the forge has sent the last byte."""
    repo = tmp_path / "big"
    repo.mkdir()
    git("init", "-q", cwd=repo)
    rng = random.Random(7)
    for n in range(6):
        (repo / f"f{n}.bin").write_bytes(rng.randbytes(512 * 1024))
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "big", cwd=repo)
    pack = stream_bytes(repo)
    assert len(pack) > 2 * git_fetch.FEED_BYTES
    feeder, judge = _feeder(tmp_path / "spool", "sha1")
    (tmp_path / "spool").mkdir()
    await _feed_in_pieces(feeder, pack[: len(pack) - 4096], size=64 * 1024)
    for _ in range(200):
        if judge.submitted:
            break
        await asyncio.sleep(0.02)
    assert judge.submitted, "objects were read before the pack ended"
    await feeder.feed(pack[len(pack) - 4096 :])
    await feeder.finish()
    assert feeder.refused is None and judge.finished == 1
    assert len({o.oid for o in judge.submitted}) == 6 + 2  # six blobs, a tree, a commit
