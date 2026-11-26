"""Keyed chunking of git text blobs (spec 027)."""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from trentina.gateway.git_chunks import (
    LEAD_BYTES,
    MAX_CHUNK,
    Chunk,
    chunk_blob,
    estimate_tokens,
)

KEY = b"k" * 32
OTHER = b"o" * 32


def _text_of(data: bytes, key: bytes = KEY) -> list[bytes]:
    return [c.text.encode() for c in chunk_blob(data, key)]


def _corpus() -> list[bytes]:
    root = Path(__file__).resolve().parent.parent / "src"
    return [p.read_bytes() for p in sorted(root.rglob("*.py"))]


def _lines(n: int, width: int = 40) -> bytes:
    return b"".join(b"line %06d " % i + b"x" * (width - 12) + b"\n" for i in range(n))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a" * 50_000,
        b"a" * 50_000 + b"\n",
        b"\n" * 20_000,
        b"ab\n" * 10_000,
        b"no trailing newline " * 400,
        ("é" * 30_000).encode(),
        ("日本語\n" * 5_000).encode(),
    ],
)
def test_bounded_and_reassembles(data: bytes) -> None:
    chunks = chunk_blob(data, KEY)
    assert all(len(c.text.encode()) <= MAX_CHUNK for c in chunks)
    assert b"".join(_text_of(data)) == data
    assert [c.start for c in chunks] == [
        sum(len(t) for t in _text_of(data)[:i]) for i in range(len(chunks))
    ]
    assert (not chunks) == (not data)


def test_never_splits_a_character() -> None:
    for data in (("é" * 30_000).encode(), ("日" * 20_000).encode(), ("a" + "😀" * 9000).encode()):
        for chunk in chunk_blob(data, KEY):
            assert "�" not in chunk.text
            assert "�" not in chunk.lead_in


def test_first_chunk_has_no_lead_in_and_later_ones_do() -> None:
    chunks = chunk_blob(_lines(500), KEY)
    assert chunks[0].lead_in == ""
    for before, after in itertools.pairwise(chunks):
        assert after.lead_in
        assert before.text.endswith(after.lead_in)
        assert len(after.lead_in.encode()) <= LEAD_BYTES + 32


def test_chunks_cut_at_line_ends() -> None:
    data = _lines(500)
    for chunk in chunk_blob(data, KEY)[:-1]:
        assert chunk.text.endswith("\n")


def test_min_chunk_respected() -> None:
    chunks = chunk_blob(_lines(2000), KEY)
    assert all(len(c.text) >= 1024 for c in chunks[:-1])


def test_average_size_on_repo_sources() -> None:
    sizes = [len(c.text.encode()) for data in _corpus() for c in chunk_blob(data, KEY)]
    average = sum(sizes) / len(sizes)
    assert 1500 <= average <= 3000, average


def test_cut_points_depend_on_the_key() -> None:
    data = b"".join(_corpus()[:20])
    mine = [c.start for c in chunk_blob(data, KEY)]
    theirs = [c.start for c in chunk_blob(data, OTHER)]
    assert mine != theirs
    assert chunk_blob(data, KEY) == chunk_blob(data, KEY)


def test_edit_changes_only_its_chunk_and_the_next() -> None:
    lines = _lines(1000).split(b"\n")[:-1]
    base = chunk_blob(b"\n".join(lines) + b"\n", KEY)
    old_keys = {c.key() for c in base}
    tested = 0
    for index in range(400, 600, 7):
        edited = list(lines)
        edited[index] = edited[index].replace(b"x", b"y")  # same length
        new = chunk_blob(b"\n".join(edited) + b"\n", KEY)
        if [c.start for c in new] != [c.start for c in base]:
            continue  # the edit moved a keyed cut; resync is the next test
        tested += 1
        assert len(old_keys - {c.key() for c in new}) <= 2
        assert len({c.key() for c in new} - old_keys) <= 2
    assert tested >= 5


def test_cuts_resync_after_a_length_changing_edit() -> None:
    lines = _lines(1000).split(b"\n")[:-1]
    base = chunk_blob(b"\n".join(lines) + b"\n", KEY)
    lines[500] = lines[500] + b" inserted text"
    new = chunk_blob(b"\n".join(lines) + b"\n", KEY)
    assert [c.key() for c in new[-4:]] == [c.key() for c in base[-4:]]
    assert len(new) in (len(base), len(base) + 1, len(base) - 1)


def test_chunk_key_covers_lead_in() -> None:
    assert Chunk("ab", "c", 0).key() != Chunk("ab", "d", 0).key()
    assert Chunk("ab", "", 0).key() != Chunk("a", "b", 0).key()
    assert Chunk("x", "y", 5).key() == Chunk("x", "y", 9).key()


def test_estimate_tokens() -> None:
    assert estimate_tokens("") == 0
    assert estimate_tokens("abc") == 1
    assert estimate_tokens("abcd") == 2
    assert estimate_tokens("é" * 3) == 2
