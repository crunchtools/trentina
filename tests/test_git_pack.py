"""The pack reader (spec 027): real packs, a differential fuzz against git, hostile packs.

Real packs come from the system ``git``; the fuzz mutates them and asks
``git index-pack`` the same question the reader answers. The rule it holds:

- git refuses structurally (``index-pack`` without ``--strict`` refuses) =>
  the reader refuses;
- git accepts => the reader accepts and the object sets are equal;
- ``--strict`` alone refusing is an fsck or connectivity verdict on what the
  objects say (a tree naming a missing blob, a mangled commit header). The
  reader reads a pack, not a repository's well-formedness, and may accept it.
  That is the one place the reader is more lenient than git, and it is by design.

The reader may be stricter than git in the cases ``STRICTER`` lists, and in
no others.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import subprocess
import time
import tracemalloc
import zlib
from typing import TYPE_CHECKING, Any

import pytest

from trentina.unpack.git_pack import (
    REASONS,
    Limits,
    PackObject,
    PackReader,
    PackRefusedError,
    commit_tree,
    is_binary,
    render_text,
    tag_target,
    tree_entries,
)

if TYPE_CHECKING:
    from pathlib import Path

GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin"),
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "A U Thor",
    "GIT_AUTHOR_EMAIL": "a@example.invalid",
    "GIT_COMMITTER_NAME": "C O Mitter",
    "GIT_COMMITTER_EMAIL": "c@example.invalid",
    "GIT_AUTHOR_DATE": "1700000000 +0000",
    "GIT_COMMITTER_DATE": "1700000000 +0000",
}
FORMATS = ("sha1", "sha256")
HASH_LEN = {"sha1": 20, "sha256": 32}

STRICTER = ("a pack naming one object twice: plain `git index-pack` accepts, `--strict` refuses",)
"""The cases where the reader refuses a pack that plain git accepts. The
differential compares against ``--strict``, which agrees with the reader here;
each entry is also asserted by a test below."""


GIT = shutil.which("git") or "git"


def git(
    *args: str, cwd: Path, data: bytes | None = None, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        [GIT, *args],
        cwd=cwd,
        input=data,
        env=GIT_ENV,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode:
        raise AssertionError(f"git {args}: {proc.stderr.decode(errors='replace')}")
    return proc


# ------------------------------------------------------------------ builders


def object_id(kind: str, data: bytes, fmt: str = "sha1") -> bytes:
    h = hashlib.new(fmt)
    h.update(f"{kind} {len(data)}\0".encode())
    h.update(data)
    return h.digest()


def entry_head(code: int, size: int) -> bytes:
    byte = (code << 4) | (size & 15)
    size >>= 4
    out = bytearray()
    while size:
        out.append(byte | 0x80)
        byte = size & 0x7F
        size >>= 7
    out.append(byte)
    return bytes(out)


def ofs_encode(distance: int) -> bytes:
    out = [distance & 0x7F]
    distance >>= 7
    while distance:
        distance -= 1
        out.insert(0, 0x80 | (distance & 0x7F))
        distance >>= 7
    return bytes(out)


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def delta(src: int, dst: int, ops: bytes) -> bytes:
    return varint(src) + varint(dst) + ops


def copy_all_then(src_len: int, tail: bytes) -> bytes:
    """A delta body copying the whole base (< 64 KiB) and appending ``tail``."""
    copy = bytes([0x80 | 0x10 | (0x20 if src_len > 255 else 0), src_len & 255])
    if src_len > 255:
        copy += bytes([src_len >> 8])
    return delta(src_len, src_len + len(tail), copy + bytes([len(tail)]) + tail)


class PackBuilder:
    """Hand-assembled packs, so a hostile one can say exactly what it lies about."""

    def __init__(self, fmt: str = "sha1") -> None:
        self.fmt = fmt
        self.entries: list[bytes] = []
        self.offsets: list[int] = []
        self.pos = 12

    def _add(self, raw: bytes) -> int:
        self.offsets.append(self.pos)
        self.entries.append(raw)
        self.pos += len(raw)
        return len(self.entries) - 1

    def full(self, code: int, data: bytes) -> int:
        return self._add(entry_head(code, len(data)) + zlib.compress(data))

    def ofs(self, base: int, body: bytes) -> int:
        dist = self.pos - self.offsets[base]
        return self._add(entry_head(6, len(body)) + ofs_encode(dist) + zlib.compress(body))

    def ref(self, base_oid: bytes, body: bytes) -> int:
        return self._add(entry_head(7, len(body)) + base_oid + zlib.compress(body))

    def raw(self, raw: bytes) -> int:
        return self._add(raw)

    def build(self, *, count: int | None = None, version: int = 2) -> bytes:
        n = len(self.entries) if count is None else count
        body = b"PACK" + version.to_bytes(4, "big") + n.to_bytes(4, "big") + b"".join(self.entries)
        return seal(body, self.fmt)


def seal(body: bytes, fmt: str) -> bytes:
    return body + hashlib.new(fmt, body).digest()


def run_reader(
    pack: bytes,
    *,
    fmt: str = "sha1",
    seed: int = 0,
    maxpiece: int = 4096,
    limits: Limits | None = None,
    spool_dir: str | None = None,
) -> list[PackObject]:
    reader = PackReader(object_format=fmt, limits=limits or Limits(), spool_dir=spool_dir)
    rng = random.Random(seed)
    out: list[PackObject] = []
    i = 0
    while i < len(pack):
        n = rng.randint(1, maxpiece)
        out += reader.feed(pack[i : i + n])
        i += n
    out += reader.finish()
    return out


def refusal(pack: bytes, **kw: Any) -> str:
    with pytest.raises(PackRefusedError) as info:
        run_reader(pack, **kw)
    assert info.value.reason in REASONS
    return info.value.reason


# ------------------------------------------------------------------ real repos


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def make_repo(root: Path, fmt: str) -> Path:
    repo = root / f"repo-{fmt}"
    repo.mkdir()
    git("init", "-q", f"--object-format={fmt}", "-b", "main", cwd=repo)
    rng = random.Random(7)
    lines = [f"line {i} of the file, with some words to compress {i * 31}" for i in range(400)]
    binary = bytearray(rng.randbytes(3000))
    for n in range(9):
        lines[n * 40] = f"edited in commit {n}"
        lines.append(f"appended {n}")
        for _ in range(20):
            binary[rng.randrange(len(binary))] = rng.randrange(256)
        _write(repo / "a.txt", ("\n".join(lines) + "\n").encode())
        _write(repo / "bin.dat", bytes(binary))
        _write(repo / "sub" / "dir" / f"c{n % 3}.txt", f"small file {n}\n".encode() * (n + 1))
        _write(repo / "empty", b"")
        git("add", "-A", cwd=repo)
        git("commit", "-q", "-m", f"commit {n}\n\nbody line {n}\n", cwd=repo)
        if n == 4:
            git("tag", "-a", "-m", "release four", "v1", cwd=repo)
    git("repack", "-adf", "--depth=50", "--window=50", cwd=repo)
    return repo


@pytest.fixture(scope="module", params=FORMATS)
def repo(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_repo(tmp_path_factory.mktemp("real"), request.param)


def fmt_of(repo: Path) -> str:
    return repo.name.split("-")[1]


def repack_bytes(repo: Path) -> bytes:
    packs = list((repo / ".git" / "objects" / "pack").glob("*.pack"))
    assert len(packs) == 1
    return packs[0].read_bytes()


def stream_bytes(repo: Path, *flags: str) -> bytes:
    revs = git("rev-list", "--objects", "--all", cwd=repo).stdout
    return git(
        "pack-objects", "--stdout", "--window=50", "--depth=50", *flags, cwd=repo, data=revs
    ).stdout


def expected_objects(repo: Path) -> dict[str, tuple[str, bytes]]:
    """Every object in the repository, by ``git cat-file``."""
    batch = git("cat-file", "--batch-all-objects", "--batch", cwd=repo).stdout
    out: dict[str, tuple[str, bytes]] = {}
    i = 0
    while i < len(batch):
        eol = batch.index(b"\n", i)
        oid, kind, size = batch[i:eol].decode().split()
        start = eol + 1
        out[oid] = (kind, batch[start : start + int(size)])
        i = start + int(size) + 1
    return out


def test_repo_is_rich_enough(repo: Path) -> None:
    objects = expected_objects(repo)
    assert {k for k, _ in objects.values()} == {"commit", "tree", "blob", "tag"}
    verify = git(
        "verify-pack", "-v", *map(str, (repo / ".git/objects/pack").glob("*.idx")), cwd=repo
    )
    assert b"chain length" in verify.stdout


@pytest.mark.parametrize("variant", ["repack", "ofs", "ref"])
@pytest.mark.parametrize("spool", [False, True])
def test_real_packs_match_git(
    repo: Path, variant: str, spool: bool, tmp_path_factory: pytest.TempPathFactory
) -> None:
    pack = {
        "repack": lambda: repack_bytes(repo),
        "ofs": lambda: stream_bytes(repo, "--delta-base-offset"),
        "ref": lambda: stream_bytes(repo),
    }[variant]()
    spool_dir = str(tmp_path_factory.mktemp("spool")) if spool else None
    expected = expected_objects(repo)
    for seed, maxpiece in ((1, 1 << 20), (2, 9), (3, 700)):
        got = run_reader(pack, fmt=fmt_of(repo), seed=seed, maxpiece=maxpiece, spool_dir=spool_dir)
        assert {o.oid for o in got} == set(expected)
        assert len(got) == len(expected)
        for obj in got:
            assert (obj.kind, obj.content) == expected[obj.oid]


def test_oids_equal_show_index(repo: Path) -> None:
    idx = next((repo / ".git/objects/pack").glob("*.idx"))
    shown = git("show-index", f"--object-format={fmt_of(repo)}", cwd=repo, data=idx.read_bytes())
    ids = {line.split()[1].decode() for line in shown.stdout.splitlines()}
    offsets = {int(line.split()[0]): line.split()[1].decode() for line in shown.stdout.splitlines()}
    got = run_reader(repack_bytes(repo), fmt=fmt_of(repo))
    assert {o.oid for o in got} == ids
    assert {o.offset: o.oid for o in got} == offsets


def test_byte_at_a_time(repo: Path) -> None:
    pack = repack_bytes(repo)
    reader = PackReader(object_format=fmt_of(repo))
    seen = 0
    for i in range(len(pack)):
        seen += len(reader.feed(pack[i : i + 1]))
        assert reader.arrived == i + 1
    reader.finish()
    assert seen == reader.declared == reader.read


def test_reader_state_after_header(repo: Path) -> None:
    pack = repack_bytes(repo)
    reader = PackReader(object_format=fmt_of(repo))
    assert (reader.declared, reader.read, reader.arrived) == (0, 0, 0)
    reader.feed(pack[:12])
    assert reader.declared == len(expected_objects(repo))


def test_render_and_links_on_real_objects(repo: Path) -> None:
    fmt = fmt_of(repo)
    oid_len = HASH_LEN[fmt]
    objects = expected_objects(repo)
    commits = {o: d for o, (k, d) in objects.items() if k == "commit"}
    trees = {o: d for o, (k, d) in objects.items() if k == "tree"}
    for data in commits.values():
        text, flag = render_text(data)
        assert flag is None
        assert text.startswith("tree ")
        assert "\n\ncommit " in text
        assert commit_tree(data) in trees
    for data in trees.values():
        for mode, name, oid in tree_entries(data, oid_len=oid_len):
            assert oid in objects
            assert objects[oid][0] == ("tree" if mode == "40000" else "blob")
            assert name
    tag = next(d for o, (k, d) in objects.items() if k == "tag")
    target = tag_target(tag)
    assert target is not None
    assert target[0] in commits
    assert target[1] == "commit"
    assert "release four" in render_text(tag)[0]


# ------------------------------------------------------------------ differential


@pytest.fixture(scope="module", params=FORMATS)
def scratch(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("scratch")
    git("init", "-q", "--bare", f"--object-format={request.param}", cwd=path)
    return path


@pytest.fixture
def real_scratch(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("rscratch")
    git("init", "-q", "--bare", f"--object-format={fmt_of(repo)}", cwd=path)
    return path


def git_accepts(scratch: Path, fmt: str, pack: bytes, *, strict: bool) -> set[str] | None:
    """The object ids ``git index-pack --stdin`` indexes, or None when it refuses."""
    packdir = scratch / "objects" / "pack"
    shutil.rmtree(packdir, ignore_errors=True)
    packdir.mkdir()
    args = ["index-pack", "--stdin"]  # the scratch repo carries the object format
    if strict:
        args.append("--strict")
    proc = git(*args, cwd=scratch, data=pack, check=False)
    idxs = list(packdir.glob("*.idx"))
    if proc.returncode or len(idxs) != 1:
        return None
    shown = git("show-index", f"--object-format={fmt}", cwd=scratch, data=idxs[0].read_bytes())
    return {line.split()[1].decode() for line in shown.stdout.splitlines()}


def ours(pack: bytes, fmt: str, seed: int) -> set[str] | None:
    try:
        return {o.oid for o in run_reader(pack, fmt=fmt, seed=seed, maxpiece=300)}
    except PackRefusedError:
        return None


def agree(scratch: Path, fmt: str, pack: bytes, seed: int = 0) -> str:
    """Hold the differential rule on one pack; returns which way it went."""
    ids = git_accepts(scratch, fmt, pack, strict=True)
    mine = ours(pack, fmt, seed)
    if ids is not None:
        assert mine == ids, f"git accepted {len(ids)} objects, reader said {mine and len(mine)}"
        return "both accept"
    if mine is None:
        return "both refuse"
    # git --strict refused and the reader accepted. Only fsck and connectivity may account for it:
    # plain index-pack must have accepted the pack, and to the same set of objects.
    plain = git_accepts(scratch, fmt, pack, strict=False)
    assert plain is not None, "git refuses the pack's structure and the reader accepted it"
    assert plain == mine
    return "fsck only"


def mutate(rng: random.Random, pack: bytes, fmt: str, offsets: list[int]) -> bytes:
    hl = HASH_LEN[fmt]
    original_trailer = pack[-hl:]
    body = bytearray(pack[:-hl])
    kind = rng.choice(["flip", "flip", "truncate", "header", "insert", "delete", "count", "varint"])
    match kind:
        case "flip":
            for _ in range(rng.randint(1, 3)):
                body[rng.randrange(12, len(body))] ^= rng.randrange(1, 256)
        case "truncate":
            del body[rng.randrange(1, len(body)) :]
        case "header":
            body[rng.choice(offsets)] = rng.randrange(256)
        case "insert":
            body.insert(rng.randrange(12, len(body)), rng.randrange(256))
        case "delete":
            del body[rng.randrange(12, len(body))]
        case "count":
            n = int.from_bytes(body[8:12], "big") + rng.choice([-2, -1, 1, 2, 1000, 1 << 31])
            body[8:12] = (n % (1 << 32)).to_bytes(4, "big")
        case _:  # a size varint: set or clear the continuation bit, or change a nibble
            at = rng.choice(offsets)
            body[at] = (body[at] ^ rng.choice([0x80, 0x0F, 0x01])) & 0xFF
    if rng.random() < 0.75:
        return seal(bytes(body), fmt)
    return bytes(body) + original_trailer


def test_differential_fuzz_real_packs(repo: Path, real_scratch: Path) -> None:
    scratch = real_scratch
    fmt = fmt_of(repo)
    assert git_accepts(scratch, fmt, repack_bytes(repo), strict=True) is not None
    idx = next((repo / ".git/objects/pack").glob("*.idx"))
    shown = git("show-index", f"--object-format={fmt}", cwd=repo, data=idx.read_bytes())
    offsets = sorted(int(line.split()[0]) for line in shown.stdout.splitlines())
    bases = [repack_bytes(repo), stream_bytes(repo, "--delta-base-offset"), stream_bytes(repo)]
    rng = random.Random(1062 if fmt == "sha1" else 2062)
    started = time.monotonic()
    tally: dict[str, int] = {}
    for n in range(400):
        pack = bases[n % len(bases)]
        # Entry offsets differ per base; the repack's are used for the first, and any in-range
        # byte is a legitimate mutation target for the others.
        spots = [o for o in offsets if o < len(pack) - HASH_LEN[fmt]] or [12]
        verdict = agree(scratch, fmt, mutate(rng, pack, fmt, spots), seed=n)
        tally[verdict] = tally.get(verdict, 0) + 1
        assert time.monotonic() - started < 20
    assert tally.get("both refuse", 0) > 10


def split_entries(pack: bytes, fmt: str) -> list[dict[str, object]]:
    """A valid pack as editable entries: type, inflated payload and what a delta is based on."""
    hl = HASH_LEN[fmt]
    offsets = [o.offset for o in run_reader(pack, fmt=fmt)]
    offsets.sort()
    index = {off: n for n, off in enumerate(offsets)}
    entries: list[dict[str, object]] = []
    for off, end in zip(offsets, [*offsets[1:], len(pack) - hl], strict=True):
        raw = pack[off:end]
        code, i = (raw[0] >> 4) & 7, 1
        while raw[i - 1] & 0x80:
            i += 1
        base: int | None = None
        oid = b""
        if code == 6:
            byte = raw[i]
            i += 1
            dist = byte & 0x7F
            while byte & 0x80:
                byte = raw[i]
                i += 1
                dist = ((dist + 1) << 7) | (byte & 0x7F)
            base = index[off - dist]
        elif code == 7:
            oid, i = raw[i : i + hl], i + hl
        entries.append(
            {"code": code, "payload": zlib.decompress(raw[i:]), "base": base, "oid": oid}
        )
    return entries


def join_entries(entries: list[dict[str, object]], fmt: str) -> bytes:
    """Re-emit entries, recomputing every OFS_DELTA distance, with a correct trailer."""
    out = bytearray()
    first: dict[object, int] = {}
    for n, e in enumerate(entries):
        pos = 12 + len(out)
        first.setdefault(e.get("orig", n), pos)
        payload = e["payload"]
        assert isinstance(payload, bytes)
        code = e["code"]
        assert isinstance(code, int)
        out += entry_head(code, len(payload))
        if code == 6:
            dist = pos - first.get(e["base"], 0)
            out += ofs_encode(dist if dist > 0 else 1)
        elif code == 7:
            oid = e["oid"]
            assert isinstance(oid, bytes)
            out += oid
        out += zlib.compress(payload)
    body = b"PACK" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big") + bytes(out)
    return seal(body, fmt)


def zero_a_copy_size(rng: random.Random, body: bytes) -> bytes:
    """Rewrite one copy op of a delta so its size field is absent (meaning 0x10000)."""
    src, pos = 0, 0
    for _ in range(2):  # skip the two size varints
        while body[pos] & 0x80:
            pos += 1
        pos += 1
    ops_at = pos
    spans: list[tuple[int, int]] = []
    while pos < len(body):
        op = body[pos]
        n = 1 + (bin(op & 0x7F).count("1") if op & 0x80 else op)
        spans.append((pos, pos + n))
        pos += n
    copies = [sp for sp in spans if body[sp[0]] & 0x80 and body[sp[0]] & 0x70]
    if not copies or pos != len(body):
        return body
    a, b = rng.choice(copies)
    op = body[a] & 0x8F
    keep = bytes(body[a + 1 : a + 1 + bin(op & 0x0F).count("1")])
    del src, ops_at
    return body[:a] + bytes([op]) + keep + body[b:]


def edit_entries(rng: random.Random, entries: list[dict[str, object]]) -> None:
    for n, e in enumerate(entries):
        e.setdefault("orig", n)
    pick = rng.randrange(len(entries))
    e = entries[pick]
    payload = e["payload"]
    assert isinstance(payload, bytes)
    kind = rng.choice(["payload", "payload", "retype", "dup", "drop", "zerocopy", "rebase"])
    code = e["code"]
    match kind:
        case "payload" if payload:
            i = rng.randrange(len(payload))
            flipped = bytes([payload[i] ^ rng.randrange(1, 256)])
            e["payload"] = payload[:i] + flipped + payload[i + 1 :]
        case "retype" if code in {1, 2, 3, 4}:
            e["code"] = rng.choice([1, 2, 3, 4])
        case "dup":
            entries.insert(pick + 1, dict(e))
        case "drop":
            del entries[pick]
        case "zerocopy" if code in {6, 7}:
            e["payload"] = zero_a_copy_size(rng, payload)
        case "rebase" if code == 6:
            e["base"] = rng.randrange(max(pick, 1))
        case "rebase" if code == 7:
            oid = e["oid"]
            assert isinstance(oid, bytes)
            e["oid"] = bytes(rng.randrange(256) for _ in oid)


def test_differential_fuzz_structured(repo: Path, real_scratch: Path) -> None:
    """Mutations that keep every zlib stream valid, so delta and link logic is what is tested."""
    fmt, scratch = fmt_of(repo), real_scratch
    rng = random.Random(27 if fmt == "sha1" else 28)
    bases = [repack_bytes(repo), stream_bytes(repo, "--delta-base-offset"), stream_bytes(repo)]
    tally: dict[str, int] = {}
    started = time.monotonic()
    for n in range(300):
        entries = split_entries(bases[n % 3], fmt)
        assert join_entries(entries, fmt) is not None
        for _ in range(rng.randint(1, 2)):
            edit_entries(rng, entries)
        if not entries:
            continue
        verdict = agree(scratch, fmt, join_entries(entries, fmt), seed=n)
        tally[verdict] = tally.get(verdict, 0) + 1
        assert time.monotonic() - started < 20
    assert tally.get("both refuse", 0) > 20
    assert tally.get("both accept", 0) + tally.get("fsck only", 0) > 20


def test_rejoin_is_lossless(repo: Path) -> None:
    for pack in (repack_bytes(repo), stream_bytes(repo, "--delta-base-offset")):
        rebuilt = join_entries(split_entries(pack, fmt_of(repo)), fmt_of(repo))
        assert {o.oid for o in run_reader(rebuilt, fmt=fmt_of(repo))} == {
            o.oid for o in run_reader(pack, fmt=fmt_of(repo))
        }


# ------------------------------------------------------------------ hand-built, against git too


def blob_pack(fmt: str = "sha1") -> PackBuilder:
    b = PackBuilder(fmt)
    b.full(3, b"hello\n")
    return b


def chain(n: int, fmt: str = "sha1", *, ref: bool = False) -> bytes:
    """A blob and ``n`` deltas, each on the one before, each one byte longer."""
    b = blob_pack(fmt)
    content = b"hello\n"
    prev_oid = object_id("blob", content, fmt)
    for i in range(n):
        body = copy_all_then(len(content), b"x")
        if ref:
            b.ref(prev_oid, body)
        else:
            b.ofs(i, body)
        content += b"x"
        prev_oid = object_id("blob", content, fmt)
    return b.build()


@pytest.mark.parametrize("ref", [False, True])
def test_chain_depth_boundary(ref: bool, scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    ok = chain(50, fmt, ref=ref)
    assert len(run_reader(ok, fmt=fmt)) == 51
    assert refusal(chain(51, fmt, ref=ref), fmt=fmt) == "too_deep"
    assert agree(scratch, fmt, ok) == "both accept"


def scratch_fmt(scratch: Path) -> str:
    return "sha256" if (scratch / "config").read_text().count("sha256") else "sha1"


def test_thin_pack(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    b = blob_pack(fmt)
    b.ref(object_id("blob", b"elsewhere", fmt), copy_all_then(9, b"!"))
    assert refusal(b.build(), fmt=fmt) == "thin_pack"
    assert agree(scratch, fmt, b.build()) == "both refuse"


def test_ref_delta_base_later_in_pack(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    b = PackBuilder(fmt)
    b.ref(object_id("blob", b"hello\n", fmt), copy_all_then(6, b"!"))
    b.full(3, b"hello\n")
    pack = b.build()
    got = run_reader(pack, fmt=fmt, maxpiece=5)
    assert {bytes(o.content) for o in got} == {b"hello\n", b"hello\n!"}
    assert agree(scratch, fmt, pack) in {"both accept", "both refuse"}


def test_ref_delta_names_its_own_result(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    b = blob_pack(fmt)
    b.ref(object_id("blob", b"hello\n!", fmt), copy_all_then(6, b"!"))
    assert refusal(b.build(), fmt=fmt) == "thin_pack"
    assert agree(scratch, fmt, b.build()) == "both refuse"


def test_ref_delta_cycle_never_hangs() -> None:
    b = PackBuilder()
    a, c = b"aaa", b"aaab"
    b.ref(object_id("blob", c), copy_all_then(3, b"b"))
    b.ref(object_id("blob", a), delta(4, 3, bytes([0x90, 3])))
    assert refusal(b.build()) == "thin_pack"


def test_header_count_lies(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    b = blob_pack(fmt)
    b.full(3, b"world\n")
    assert refusal(b.build(count=1), fmt=fmt) == "count"
    assert refusal(b.build(count=3), fmt=fmt) in {"count", "malformed"}
    assert refusal(b.build(count=0), fmt=fmt) in {"count", "malformed"}
    for count in (1, 3):
        assert agree(scratch, fmt, b.build(count=count)) == "both refuse"


def test_bad_trailer(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    pack = blob_pack(fmt).build()
    bad = pack[:-1] + bytes([pack[-1] ^ 1])
    assert refusal(bad, fmt=fmt) == "trailer"
    assert refusal(pack[:-3], fmt=fmt) == "trailer"
    assert refusal(pack + b"x", fmt=fmt) == "malformed"
    assert agree(scratch, fmt, bad) == "both refuse"


def test_bad_header_and_truncation() -> None:
    pack = blob_pack().build()
    assert refusal(b"NACK" + pack[4:]) == "malformed"
    assert refusal(pack[:4] + (4).to_bytes(4, "big") + pack[8:]) == "malformed"
    assert refusal(pack[:20]) == "count"
    assert refusal(pack[:30]) == "trailer"
    reader = PackReader()
    reader.feed(pack[:5])
    with pytest.raises(PackRefusedError) as info:
        reader.finish()
    assert info.value.reason == "malformed"


def test_refusal_is_final() -> None:
    reader = PackReader()
    with pytest.raises(PackRefusedError):
        reader.feed(b"NOPE" * 8)
    with pytest.raises(PackRefusedError):
        reader.feed(b"x")
    with pytest.raises(PackRefusedError):
        reader.finish()


def test_inflation_bomb() -> None:
    bomb = zlib.compress(bytes(200 * 1024 * 1024), 9)
    assert len(bomb) < 200 * 1024
    # Declared small, inflates huge: refused at the declared size, never expanded.
    small = PackBuilder()
    small.raw(entry_head(3, 10) + bomb)
    started = time.monotonic()
    assert refusal(small.build()) == "malformed"
    assert time.monotonic() - started < 5
    # Declared as large as it is: the cumulative limit refuses it.
    big = PackBuilder()
    big.raw(entry_head(3, 200 * 1024 * 1024) + bomb)
    assert refusal(big.build(), limits=Limits(max_inflated=1024 * 1024)) == "too_large"


def test_an_object_is_not_held_twice_while_it_inflates() -> None:
    mib = 1024 * 1024
    size = 32 * mib
    blob = PackBuilder()
    blob.full(3, bytes(size))
    pack = blob.build()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        objects = run_reader(pack, maxpiece=64)
        peak = tracemalloc.get_traced_memory()[1] - base
    finally:
        tracemalloc.stop()
    assert len(objects) == 1
    assert len(objects[0].content) == size
    assert peak < 1.5 * size


def _fan_out(kind: str, count: int = 40) -> tuple[bytes, int]:
    """One base and ``count`` deltas on it, and what the targets alone cost."""
    base = bytes(range(256)) * 4
    pack = PackBuilder()
    oid = object_id("blob", base)
    if kind == "ref_before":
        bodies = [copy_all_then(len(base), bytes([i])) for i in range(count)]
        for body in bodies:
            pack.ref(oid, body)
        pack.full(3, base)
    else:
        index = pack.full(3, base)
        bodies = [copy_all_then(len(base), bytes([i])) for i in range(count)]
        for body in bodies:
            if kind == "ofs":
                pack.ofs(index, body)
            else:
                pack.ref(oid, body)
    targets = sum(len(body) + len(base) + 1 for body in bodies)
    return pack.build(), len(base) + targets


@pytest.mark.parametrize("kind", ["ofs", "ref_after", "ref_before"])
def test_delta_fan_out_pays_for_every_base_read(kind: str, tmp_path: Path) -> None:
    pack, targets = _fan_out(kind)
    reads = 40 * 1024
    spool = str(tmp_path)
    assert refusal(pack, limits=Limits(max_inflated=targets), spool_dir=spool) == "too_large"
    objects = run_reader(pack, limits=Limits(max_inflated=targets + reads), spool_dir=spool)
    assert len(objects) == 41
    assert refusal(pack, limits=Limits(max_inflated=targets + reads - 1)) == "too_large"


def test_delta_target_bomb() -> None:
    b = blob_pack()
    b.ofs(0, delta(6, 1 << 40, bytes([0x90, 6])))
    assert refusal(b.build(), limits=Limits(max_inflated=1 << 20)) == "too_large"


def test_arrived_and_object_limits() -> None:
    pack = chain(5)
    assert refusal(pack, limits=Limits(max_arrived=40)) == "too_large"
    assert refusal(pack, limits=Limits(max_objects=5)) == "too_many"
    assert len(run_reader(pack, limits=Limits(max_objects=6))) == 6


def test_delta_malformations() -> None:
    cases = {
        "opcode zero": delta(6, 1, bytes([0x00])),
        "source size": delta(7, 6, bytes([0x90, 6])),
        "target short": delta(6, 7, bytes([0x90, 6])),
        "target long": delta(6, 5, bytes([0x90, 6])),
        "copy past base": delta(6, 7, bytes([0x91, 1, 6])),
        "insert past end": delta(6, 9, bytes([9, 1, 2])),
        "truncated copy args": delta(6, 6, bytes([0xFF])),
        "no ops": delta(6, 0, b""),
    }
    for name, body in cases.items():
        b = blob_pack()
        b.ofs(0, body)
        if name == "no ops":  # a delta that produces the empty object is legal
            assert len(run_reader(b.build())) == 2
            continue
        assert refusal(b.build()) == "malformed", name


def test_ofs_delta_bad_base() -> None:
    b = blob_pack()
    b.raw(entry_head(6, 3) + ofs_encode(5000) + zlib.compress(b"abc"))
    assert refusal(b.build()) == "malformed"
    c = blob_pack()
    c.raw(entry_head(6, 3) + ofs_encode(3) + zlib.compress(b"abc"))  # points inside an entry
    assert refusal(c.build()) == "malformed"


def test_copy_size_zero_is_0x10000(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    base = bytes(range(256)) * 300  # 76800 bytes
    b = PackBuilder(fmt)
    b.full(3, base)
    b.ofs(0, delta(len(base), 0x10000, bytes([0x80])))  # copy, offset 0, size absent => 0x10000
    pack = b.build()
    got = run_reader(pack, fmt=fmt)
    assert got[1].content == base[:0x10000]
    assert agree(scratch, fmt, pack) == "both accept"
    over = PackBuilder(fmt)
    over.full(3, b"short")
    over.ofs(0, delta(5, 0x10000, bytes([0x80])))
    assert refusal(over.build(), fmt=fmt) == "malformed"
    assert agree(scratch, fmt, over.build()) == "both refuse"


def test_duplicate_object_agrees_with_git(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    b = blob_pack(fmt)
    b.full(3, b"hello\n")
    assert refusal(b.build(), fmt=fmt) == "malformed"
    assert agree(scratch, fmt, b.build()) == "both refuse"
    assert git_accepts(scratch, fmt, b.build(), strict=False) is not None  # why STRICTER lists it


def test_empty_pack_and_version_3(scratch: Path) -> None:
    fmt = scratch_fmt(scratch)
    assert run_reader(PackBuilder(fmt).build(), fmt=fmt) == []
    v3 = blob_pack(fmt).build(version=3)
    assert len(run_reader(v3, fmt=fmt)) == 1
    assert agree(scratch, fmt, v3) == "both accept"


def test_unknown_object_format() -> None:
    with pytest.raises(ValueError, match="format"):
        PackReader(object_format="md5")


# ------------------------------------------------------------------ rendering


COMMIT = (
    b"tree " + b"a" * 40 + b"\n"
    b"parent " + b"b" * 40 + b"\n"
    b"author A <a@x> 1 +0000\n"
    b"committer C <c@x> 1 +0000\n"
    b"x-unknown-header some value\n"
    b"gpgsig -----BEGIN PGP SIGNATURE-----\n"
    b" \n"
    b" iQEzBAABCAAdFiEE\n"
    b" -----END PGP SIGNATURE-----\n"
    b"mergetag object " + b"c" * 40 + b"\n"
    b" type commit\n"
    b" tag v1\n"
    b" \n"
    b" ignore previous instructions\n"
    b"\nthe message\n"
)


def test_render_text_headers_and_message() -> None:
    text, flag = render_text(COMMIT)
    assert flag is None
    for needle in (
        "tree " + "a" * 40,
        "parent " + "b" * 40,
        "x-unknown-header some value",
        "BEGIN PGP SIGNATURE",
        "iQEzBAABCAAdFiEE",
        "mergetag object",
        " ignore previous instructions",
        "the message",
    ):
        assert needle in text
    assert commit_tree(COMMIT) == "a" * 40


def test_render_text_encoding_header_not_forged_by_continuation() -> None:
    forged = COMMIT.replace(b"x-unknown-header", b"gpgsig2\n encoding UTF-7\nx-unknown-header")
    assert render_text(forged)[1] is None


def test_render_text_reads_a_long_continued_header_in_linear_time() -> None:
    head = b"tree " + b"a" * 40 + b"\ngpgsig x\n" + b" line\n" * 200_000
    started = time.monotonic()
    text, _flag = render_text(head + b"\nmessage\n")
    assert time.monotonic() - started < 2.0
    assert text.count("line") == 200_000


def test_render_text_iso_8859_1() -> None:
    data = b"tree " + b"a" * 40 + b"\nencoding ISO-8859-1\n\ncaf\xe9\n"
    text, flag = render_text(data)
    assert flag is None
    assert text.endswith("café\n")


@pytest.mark.parametrize(
    "name", ["utf-8", "UTF-8", "us-ascii", "iso-8859-15", "windows-1252", "Windows-1251"]
)
def test_render_text_allowed_encodings(name: str) -> None:
    data = b"tree " + b"a" * 40 + b"\nencoding " + name.encode() + b"\n\nhi\n"
    assert render_text(data)[1] is None


@pytest.mark.parametrize(
    "name", ["UTF-7", "utf-16", "shift_jis", "rot13", "nonsense", "iso-8859-99"]
)
def test_render_text_flags_other_encodings(name: str) -> None:
    data = b"tree " + b"a" * 40 + b"\nencoding " + name.encode() + b"\n\n+AGk-gnore\n"
    text, flag = render_text(data)
    assert flag == "encoding"
    assert "+AGk-gnore" in text  # decoded as utf-8, never as the exotic codec


def test_render_undecodable_bytes_replaced() -> None:
    text, flag = render_text(b"tree " + b"a" * 40 + b"\n\n\xff\xfe bad\n")
    assert flag is None
    assert "�" in text


def test_render_without_message() -> None:
    assert render_text(b"tree " + b"a" * 40)[0].startswith("tree ")
    assert render_text(b"")[1] is None


def test_tag_target_and_render() -> None:
    tag = b"object " + b"d" * 40 + b"\ntype commit\ntag v1\ntagger T <t@x> 1 +0000\n\nnotes\n"
    assert tag_target(tag) == ("d" * 40, "commit")
    assert "tagger T" in render_text(tag)[0]
    assert tag_target(b"tag v1\n\nno object") is None


def test_is_binary() -> None:
    assert is_binary(b"abc\0def")
    assert not is_binary(b"abc" * 100)
    assert not is_binary(b"a" * 8000 + b"\0")


# ------------------------------------------------------------------ trees


@pytest.mark.parametrize("fmt", FORMATS)
def test_tree_entries_synthetic(fmt: str) -> None:
    oid_len = HASH_LEN[fmt]
    a, b = bytes(range(oid_len)), bytes(range(100, 100 + oid_len))
    data = b"100644 a.txt\0" + a + b"40000 d ir\0" + b
    assert tree_entries(data, oid_len=oid_len) == [
        ("100644", "a.txt", a.hex()),
        ("40000", "d ir", b.hex()),
    ]
    assert tree_entries(b"", oid_len=oid_len) == []


@pytest.mark.parametrize(
    "data",
    [
        b"100644 a",
        b"100644 a\0short",
        b"nomode\0" + b"x" * 20,
        b"10x644 a\0" + b"x" * 20,
        b" \0" + b"x" * 20,
    ],
)
def test_tree_entries_malformed(data: bytes) -> None:
    with pytest.raises(PackRefusedError) as info:
        tree_entries(data)
    assert info.value.reason == "malformed"


def test_close_lets_go_of_the_spool(repo: Path, tmp_path: Path) -> None:
    """The spool holds inflated objects on the data volume; closing frees it."""
    reader = PackReader(object_format=fmt_of(repo), spool_dir=str(tmp_path))
    reader.feed(repack_bytes(repo))
    reader.finish()
    reader.close()
    assert reader._spool is None
    reader.close()  # twice is harmless
