"""An incremental reader of a git packfile, and of the objects inside it (spec 027).

The git transport used to deliver a pack it could not read. This module reads
one as it streams in, the way ``git index-pack`` does and with none of its
trust: every entry is inflated with zlib, ``OFS_DELTA`` and ``REF_DELTA`` are
resolved against bases in the same pack, and each resolved object is hashed
here, by ``hashlib``. A pack's own claims are checked, never believed: the
header's object count, a ``REF_DELTA``'s base id, and the trailer checksum.

Python has no ``sha1dc``, git's collision-detecting SHA-1, so an id this module
computes **names** an object and is never what a verdict is keyed on. A
verdict binds the sha256 of the object's content, which is phase 2.

Every refusal is a ``PackRefusedError`` whose ``reason`` is one of ``REASONS``.
A refusal never quotes the pack.

Reading is bounded by ``Limits`` and cannot hang or recurse: bytes arrive in
any piece size, an entry's inflater is given at most one byte more than the
size its header declared, and deltas resolve from an explicit stack no deeper
than ``Limits.max_depth``. With a ``spool_dir`` resolved bytes go to an
anonymous file there and only their place is kept in memory.

The rest of the module reads what a pack holds: ``render_text`` gives
the text the judging layers read, ``tree_entries`` and
the two target helpers give the links between objects.
"""

from __future__ import annotations

import codecs
import contextlib
import hashlib
import os
import re
import tempfile
import zlib
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterator

OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, OBJ_TAG = "commit", "tree", "blob", "tag"

REASONS = ("malformed", "thin_pack", "too_large", "too_many", "too_deep", "trailer", "count")
"""The closed set of ``PackRefusedError.reason`` values."""

_VARINT_MORE = 0x80
"""The continuation bit of a git varint: set while another byte follows."""
_VARINT_BITS = 0x7F
"""The seven payload bits of a git varint byte."""
_MAX_DELTA_SHIFT = 63
"""A delta header size past 2**63 is no size git writes."""
_TYPE_MASK = 7
"""The three type bits of an entry's first byte."""
_SIZE_LOW_MASK = 15
"""The four low size bits of an entry's first byte."""
_MAX_OBJECTS = 1_000_000
"""Default most entries one pack may declare."""
_MAX_DELTA_DEPTH = 50
"""Default longest delta chain; git's own default ``pack.depth`` is 50."""
_KINDS = {1: OBJ_COMMIT, 2: OBJ_TREE, 3: OBJ_BLOB, 4: OBJ_TAG}
_OFS_DELTA, _REF_DELTA = 6, 7
_HASH_LEN = {"sha1": 20, "sha256": 32}
_PACK_HEADER = 12
_MAX_VARINT_BYTES = 10
_COPY_ZERO = 0x10000
_HEAD, _ENTRY, _BODY, _TAIL = range(4)


class PackRefusedError(Exception):
    """A pack that cannot be read, or must not be trusted. ``reason`` is in ``REASONS``."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Limits:
    """What one pack may cost: bytes in, bytes inflated, entries, delta chain length."""

    max_arrived: int = 256 * 1024 * 1024
    max_inflated: int = 2 * 1024 * 1024 * 1024
    max_objects: int = _MAX_OBJECTS
    max_depth: int = _MAX_DELTA_DEPTH


DEFAULT_LIMITS = Limits()
"""Spec 027's bounds, for a reader given none."""


@dataclass(frozen=True)
class PackObject:
    """A resolved object: its id (hex), type, content and its entry's offset in the pack."""

    oid: str
    kind: str
    content: bytes
    offset: int


# ---------------------------------------------------------------- deltas


def _malformed(detail: str) -> PackRefusedError:
    return PackRefusedError("malformed", detail)


def _varint(payload: bytes, pos: int) -> tuple[int, int]:
    """A little-endian base-128 number, as a delta header writes its sizes."""
    result = shift = 0
    while True:
        if pos >= len(payload) or shift > _MAX_DELTA_SHIFT:
            raise _malformed("delta header")
        byte = payload[pos]
        pos += 1
        result |= (byte & _VARINT_BITS) << shift
        shift += 7
        if not byte & _VARINT_MORE:
            return result, pos


def _copy_args(delta: bytes, pos: int, op: int) -> tuple[int, int, int]:
    """Offset, size and next position of a copy op. A size of 0 means 0x10000."""
    if pos + bin(op & _VARINT_BITS).count("1") > len(delta):
        raise _malformed("delta copy")
    offset = size = 0
    for bit in range(4):
        if op & (1 << bit):
            offset |= delta[pos] << (8 * bit)
            pos += 1
    for bit in range(3):
        if op & (0x10 << bit):
            size |= delta[pos] << (8 * bit)
            pos += 1
    return offset, size or _COPY_ZERO, pos


def apply_delta(base: bytes, delta: bytes, pos: int, target: int) -> bytes:
    """Apply the ops of ``delta`` from ``pos`` (past its size header) to ``base``."""
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & _VARINT_MORE:
            offset, size, pos = _copy_args(delta, pos, op)
            if offset + size > len(base):
                raise _malformed("delta copy range")
            out += base[offset : offset + size]
        elif op:
            if pos + op > len(delta):
                raise _malformed("delta insert")
            out += delta[pos : pos + op]
            pos += op
        else:
            raise _malformed("delta opcode 0")
        if len(out) > target:
            raise _malformed("delta result size")
    if len(out) != target:
        raise _malformed("delta result size")
    return bytes(out)


# ---------------------------------------------------------------- entries


class _Head(NamedTuple):
    code: int
    size: int
    distance: int
    base_oid: bytes
    length: int


def _entry_size(buf: bytes, i: int) -> tuple[int, int, int, int] | None:
    """Type, size and the position after an entry's type/size varint, or None if short."""
    if i >= len(buf):
        return None
    byte = buf[i]
    code, size, shift, i = (byte >> 4) & _TYPE_MASK, byte & _SIZE_LOW_MASK, 4, i + 1
    while byte & _VARINT_MORE:
        if i >= len(buf):
            return None
        if shift > 4 + 7 * (_MAX_VARINT_BYTES - 1):
            raise _malformed("entry size")
        byte = buf[i]
        i += 1
        size |= (byte & _VARINT_BITS) << shift
        shift += 7
    return code, size, shift, i


def _ofs_distance(buf: bytes, i: int) -> tuple[int, int] | None:
    """The negative offset of an OFS_DELTA (git's offset-encoded varint)."""
    if i >= len(buf):
        return None
    byte = buf[i]
    i += 1
    distance = byte & _VARINT_BITS
    count = 1
    while byte & _VARINT_MORE:
        if i >= len(buf):
            return None
        if count >= _MAX_VARINT_BYTES:
            raise _malformed("delta offset")
        byte = buf[i]
        i += 1
        count += 1
        distance = ((distance + 1) << 7) | (byte & _VARINT_BITS)
    return distance, i


def _parse_head(buf: bytes, start: int, oid_len: int) -> _Head | None:
    """One entry's header at ``start``, or None while the bytes are not all here."""
    first = _entry_size(buf, start)
    if first is None:
        return None
    code, size, _shift, i = first
    if code in _KINDS:
        return _Head(code, size, 0, b"", i - start)
    if code == _OFS_DELTA:
        got = _ofs_distance(buf, i)
        return None if got is None else _Head(code, size, got[0], b"", got[1] - start)
    if code == _REF_DELTA:
        if i + oid_len > len(buf):
            return None
        return _Head(code, size, 0, buf[i : i + oid_len], i + oid_len - start)
    raise _malformed("entry type")


@dataclass
class _Entry:
    offset: int
    head: _Head
    inflater: zlib._Decompress
    out: bytearray


@dataclass
class _Pending:
    """A delta waiting for its base."""

    offset: int
    delta: bytes
    pos: int
    target: int
    source: int


@dataclass
class _Slot:
    """Where a resolved object's bytes are: in ``payload``, or in the spool file."""

    kind: str
    depth: int
    payload: bytes | None
    foff: int = 0
    length: int = 0


@dataclass
class _Resolved:
    offset: int
    oid: bytes
    kind: str
    depth: int
    payload: bytes


class PackReader:
    """Reads one pack, fed in pieces. ``feed`` each piece, then ``finish``.

    Any ``PackRefusedError`` is final: the reader refuses again on every later
    call. Not thread-safe; one reader belongs to one stream.
    """

    def __init__(
        self,
        *,
        object_format: str = "sha1",
        limits: Limits = DEFAULT_LIMITS,
        spool_dir: str | None = None,
    ) -> None:
        if object_format not in _HASH_LEN:
            raise ValueError("unknown object format")
        self._fmt = object_format
        self._hash_len = _HASH_LEN[object_format]
        self._limits = limits
        self._spool_dir = spool_dir
        self._spool: IO[bytes] | None = None
        self._spool_end = 0
        self._checksum = hashlib.new(object_format, usedforsecurity=False)
        self._buf = b""
        self._i = 0
        self._pos = 0
        self._arrived = 0
        self._state = _HEAD
        self._declared = 0
        self._read = 0
        self._inflated = 0
        self._cur: _Entry | None = None
        self._starts: set[int] = set()
        self._slots: dict[int, _Slot] = {}
        self._by_oid: dict[bytes, int] = {}
        self._wait_off: dict[int, list[_Pending]] = {}
        self._wait_oid: dict[bytes, list[_Pending]] = {}
        self._failed: PackRefusedError | None = None

    # ------------------------------------------------------------ public

    @property
    def declared(self) -> int:
        return self._declared

    @property
    def read(self) -> int:
        return self._read

    @property
    def arrived(self) -> int:
        return self._arrived

    def tail_offset(self) -> int:
        """Offset of the first unparsed byte: the start of the entry being read."""
        if self._state == _BODY and self._cur is not None:
            return self._cur.offset
        return self._pos

    @contextlib.contextmanager
    def _final(self) -> Iterator[None]:
        """Remember a refusal raised inside: it is final."""
        try:
            yield
        except PackRefusedError as exc:
            self._failed = exc
            raise

    def feed(self, payload: bytes) -> list[PackObject]:
        """Objects completed (resolved) by these bytes, in order of completion."""
        if self._failed is not None:
            raise self._failed
        out: list[PackObject] = []
        with self._final():
            self._arrived += len(payload)
            if self._arrived > self._limits.max_arrived:
                raise PackRefusedError("too_large", "pack bytes")
            self._buf = self._buf[self._i :] + payload
            self._i = 0
            more = True
            while more:
                if self._state == _HEAD:
                    more = self._read_pack_header()
                elif self._state == _ENTRY:
                    more = self._read_entry_head()
                elif self._state == _BODY:
                    more = self._read_body(out)
                else:
                    rest = self._buf[self._i :]
                    if len(rest) > self._hash_len:
                        raise self._overrun(rest)
                    more = False
        return out

    def close(self) -> None:
        """Let go of every object held, the spool file on the data volume included."""
        if self._spool is not None:
            self._spool.close()
            self._spool = None
        self._slots.clear()
        self._by_oid.clear()

    def finish(self) -> list[PackObject]:
        """End of stream. Verifies count, trailer and that no delta lacks a base."""
        if self._failed is not None:
            raise self._failed
        with self._final():
            if self._state == _HEAD:
                raise _malformed("pack header")
            if self._state != _TAIL:
                raise PackRefusedError("count", "fewer entries than declared")
            rest = self._buf[self._i :]
            if len(rest) > self._hash_len:
                raise self._overrun(rest)
            if rest != self._checksum.digest():
                raise PackRefusedError("trailer", "checksum")
            if self._wait_off or self._wait_oid:
                raise PackRefusedError("thin_pack", "delta base not in pack")
        return []

    # ------------------------------------------------------------ parsing

    def _consume(self, n: int) -> None:
        self._checksum.update(self._buf[self._i : self._i + n])
        self._i += n
        self._pos += n

    def _read_pack_header(self) -> bool:
        raw = self._buf[self._i : self._i + _PACK_HEADER]
        if len(raw) < _PACK_HEADER:
            return False
        version = int.from_bytes(raw[4:8], "big")
        if raw[:4] != b"PACK" or version not in (2, 3):
            raise _malformed("pack header")
        self._declared = int.from_bytes(raw[8:12], "big")
        if self._declared > self._limits.max_objects:
            raise PackRefusedError("too_many", "object count")
        self._consume(_PACK_HEADER)
        self._state = _ENTRY if self._declared else _TAIL
        return True

    def _charge(self, n: int) -> None:
        self._inflated += n
        if self._inflated > self._limits.max_inflated:
            raise PackRefusedError("too_large", "inflated bytes")

    def _read_entry_head(self) -> bool:
        head = _parse_head(self._buf, self._i, self._hash_len)
        if head is None:
            return False
        start = self._pos
        if head.code == _OFS_DELTA and (
            head.distance <= 0 or start - head.distance not in self._starts
        ):
            raise _malformed("delta base offset")
        self._charge(head.size)
        self._consume(head.length)
        self._starts.add(start)
        self._cur = _Entry(start, head, zlib.decompressobj(), bytearray())
        self._state = _BODY
        return True

    def _read_body(self, out: list[PackObject]) -> bool:
        entry = self._cur
        if entry is None:
            raise _malformed("no entry")
        chunk = self._buf[self._i :]
        if not chunk:
            return False
        done = self._inflate(entry, chunk)
        if done is None:
            self._consume(len(chunk))
            return False
        self._consume(len(chunk) - done)
        self._finish_entry(entry, out)
        return True

    def _inflate(self, entry: _Entry, chunk: bytes) -> int | None:
        """Feed ``chunk``; the count of its bytes left over once the stream ends, else None."""
        size = entry.head.size
        inflater, payload = entry.inflater, chunk
        while True:
            try:
                got = inflater.decompress(payload, size - len(entry.out) + 1)
            except zlib.error:
                raise _malformed("zlib stream") from None
            entry.out += got
            if len(entry.out) > size:
                raise _malformed("entry size")
            if inflater.eof:
                return len(inflater.unused_data)
            payload = inflater.unconsumed_tail
            if not payload:
                return None
            if not got and len(payload) == len(chunk):
                raise _malformed("zlib stalled")

    def _finish_entry(self, entry: _Entry, out: list[PackObject]) -> None:
        if len(entry.out) != entry.head.size:
            raise _malformed("entry size")
        self._cur = None
        self._read += 1
        self._state = _ENTRY if self._read < self._declared else _TAIL
        payload = bytes(entry.out)
        if entry.head.code in _KINDS:
            self._settle(self._resolve(entry.offset, _KINDS[entry.head.code], 0, payload), out)
        else:
            self._on_delta(entry, payload, out)

    # ------------------------------------------------------------ deltas

    def _on_delta(self, entry: _Entry, delta: bytes, out: list[PackObject]) -> None:
        source, pos = _varint(delta, 0)
        target, pos = _varint(delta, pos)
        self._charge(target)
        pending = _Pending(entry.offset, delta, pos, target, source)
        head = entry.head
        if head.code == _OFS_DELTA:
            base_off = entry.offset - head.distance
        else:
            base_off = self._by_oid.get(head.base_oid, -1)
        slot = self._slots.get(base_off)
        if slot is not None:
            self._settle(self._apply(pending, slot, self._load(slot)), out)
        elif head.code == _OFS_DELTA:
            self._wait_off.setdefault(base_off, []).append(pending)
        else:
            self._wait_oid.setdefault(head.base_oid, []).append(pending)

    def _apply(self, pending: _Pending, base: _Slot, base_data: bytes) -> _Resolved:
        depth = base.depth + 1
        if depth > self._limits.max_depth:
            raise PackRefusedError("too_deep", "delta chain")
        if pending.source != len(base_data):
            raise _malformed("delta source size")
        payload = apply_delta(base_data, pending.delta, pending.pos, pending.target)
        return self._resolve(pending.offset, base.kind, depth, payload)

    def _resolve(self, offset: int, kind: str, depth: int, payload: bytes) -> _Resolved:
        digest = hashlib.new(self._fmt, usedforsecurity=False)
        digest.update(f"{kind} {len(payload)}\0".encode("ascii"))
        digest.update(payload)
        return _Resolved(offset, digest.digest(), kind, depth, payload)

    def _settle(self, first: _Resolved, out: list[PackObject]) -> None:
        """Record ``first`` and, from an explicit stack, every delta that was waiting on it."""
        stack: list[tuple[_Slot, bytes, list[_Pending]]] = [self._record(first, out)]
        while stack:
            slot, payload, waiting = stack[-1]
            if not waiting:
                stack.pop()
                continue
            stack.append(self._record(self._apply(waiting.pop(), slot, payload), out))

    def _record(self, res: _Resolved, out: list[PackObject]) -> tuple[_Slot, bytes, list[_Pending]]:
        if res.oid in self._by_oid:
            # git accepts a repeated object unless asked to be --strict; a pack that names
            # one twice is not one git's own packers write.
            raise _malformed("duplicate object")
        slot = _Slot(res.kind, res.depth, res.payload)
        if self._spool_dir is not None:
            if self._spool is None:
                fd, name = tempfile.mkstemp(dir=self._spool_dir)
                os.unlink(name)  # anonymous from here: only this descriptor reaches it
                self._spool = os.fdopen(fd, "w+b")
            self._spool.seek(self._spool_end)
            self._spool.write(res.payload)
            slot = _Slot(res.kind, res.depth, None, self._spool_end, len(res.payload))
            self._spool_end += len(res.payload)
        self._slots[res.offset] = slot
        self._by_oid[res.oid] = res.offset
        out.append(PackObject(res.oid.hex(), res.kind, res.payload, res.offset))
        waiting = self._wait_off.pop(res.offset, []) + self._wait_oid.pop(res.oid, [])
        return slot, res.payload, waiting

    def _load(self, slot: _Slot) -> bytes:
        held = slot.payload
        if held is None and self._spool is not None:
            self._spool.seek(slot.foff)
            held = self._spool.read(slot.length)
        if held is None:
            raise _malformed("spool")
        return held

    # ------------------------------------------------------------ the end

    def _overrun(self, rest: bytes) -> PackRefusedError:
        trailer_follows = rest[: self._hash_len] == self._checksum.digest()
        return (
            _malformed("bytes after trailer")
            if trailer_follows
            else PackRefusedError("count", "more entries than declared")
        )


# ---------------------------------------------------------------- objects


def is_binary(payload: bytes) -> bool:
    """Git's rule: a NUL in the first 8000 bytes."""
    return b"\0" in payload[:8000]


_ENCODING_OK = re.compile(r"(?:utf-?8|us-ascii|iso[-_]?8859-\d{1,2}|windows-125\d)", re.IGNORECASE)
_HEX_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def _split(payload: bytes) -> tuple[list[tuple[bytes, bytes]], bytes, bytes]:
    """Headers (continuation lines joined with a newline), the raw header block, the message."""
    cut = payload.find(b"\n\n")
    head, message = (payload, b"") if cut < 0 else (payload[:cut], payload[cut + 2 :])
    headers: list[tuple[bytes, bytes]] = []
    for line in head.split(b"\n"):
        if line.startswith(b" ") and headers:
            name, value = headers[-1]
            headers[-1] = (name, value + b"\n" + line[1:])
        else:
            name, _, value = line.partition(b" ")
            headers.append((name, value))
    return headers, head, message


def _first(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    return next((value for key, value in headers if key == name), None)


def render_text(payload: bytes) -> tuple[str, str | None]:
    """A commit or an annotated tag as the text the layers read: every header, then the message.

    The message is decoded by the object's ``encoding`` header, as ``git log``
    does. The second element is None, or ``"encoding"`` when that header names
    anything but utf-8, us-ascii, iso-8859-* or windows-125x (an absent header
    means utf-8). Undecodable bytes become U+FFFD.
    """
    headers, head, message = _split(payload)
    value = _first(headers, b"encoding")
    name = "utf-8" if value is None else value.decode("ascii", "replace").strip()
    codec, allowed = "utf-8", value is None or _ENCODING_OK.fullmatch(name) is not None
    try:
        codec = codecs.lookup(name).name if allowed else codec
    except LookupError:
        allowed = False
    flag = None if allowed else "encoding"
    return head.decode(codec, "replace") + "\n\n" + message.decode(codec, "replace"), flag


@dataclass(frozen=True)
class Commit:
    """A commit's parsed headers. ``headers`` holds every one, in order."""

    tree: str | None
    parents: tuple[str, ...]
    author: str | None
    committer: str | None
    encoding: str | None
    headers: tuple[tuple[str, str], ...]
    message: bytes


def _text(value: bytes | None) -> str | None:
    return None if value is None else value.decode("utf-8", "replace")


def parse_commit(payload: bytes) -> Commit:
    """A commit's headers and raw message. Never raises: a missing header is None."""
    headers, _head, message = _split(payload)
    return Commit(
        tree=_hex_header(headers, b"tree"),
        parents=tuple(v.decode("ascii", "replace") for k, v in headers if k == b"parent"),
        author=_text(_first(headers, b"author")),
        committer=_text(_first(headers, b"committer")),
        encoding=_text(_first(headers, b"encoding")),
        headers=tuple(
            (k.decode("utf-8", "replace"), v.decode("utf-8", "replace")) for k, v in headers
        ),
        message=message,
    )


def _hex_header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    value = _first(headers, name)
    text = None if value is None else value.decode("ascii", "replace")
    return text if text is not None and _HEX_ID.fullmatch(text) else None


def commit_tree(payload: bytes) -> str | None:
    """The tree id a commit names, or None."""
    return _hex_header(_split(payload)[0], b"tree")


def tag_target(payload: bytes) -> tuple[str, str] | None:
    """The ``(id, type)`` an annotated tag points at, or None."""
    headers = _split(payload)[0]
    oid, kind = _hex_header(headers, b"object"), _text(_first(headers, b"type"))
    return None if oid is None or kind is None else (oid, kind)


_MODE = re.compile(rb"[0-7]{1,7}")


def tree_entries(payload: bytes, *, oid_len: int = 20) -> list[tuple[str, str, str]]:
    """A tree's ``(mode, name, hex id)`` entries. Raises ``PackRefusedError("malformed")``."""
    entries: list[tuple[str, str, str]] = []
    i = 0
    while i < len(payload):
        space = payload.find(b" ", i)
        nul = payload.find(b"\0", space + 1) if space >= 0 else -1
        if space < 0 or nul <= space + 1 or nul + 1 + oid_len > len(payload):
            raise _malformed("tree entry")
        mode = payload[i:space]
        if not _MODE.fullmatch(mode):
            raise _malformed("tree mode")
        name = payload[space + 1 : nul].decode("utf-8", "replace")
        entries.append((mode.decode("ascii"), name, payload[nul + 1 : nul + 1 + oid_len].hex()))
        i = nul + 1 + oid_len
    return entries
