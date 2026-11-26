"""Keyed content-defined chunking of a git text blob (spec 027).

Judging every blob whole is not viable (a full clone is a day of L2), so a
text blob is judged as chunks of about 2 KB. Three things hold:

- **A cut is an edit-local decision.** Cuts fall after a line end that a keyed
  hash of that line selects, so an edit moves the chunks around it and the
  cuts after it come back where they were. The key is a secret per gateway
  (``gateway_chunk_key``), sealed at rest: an author who cannot compute the hash cannot place
  a cut, so cannot arrange for an instruction to straddle one.
- **Chunk size is bounded.** Never a cut before ``MIN_CHUNK`` bytes since the
  last, and never a chunk over ``MAX_CHUNK``: a line that would carry a chunk
  past it is cut before it, or inside it when it is alone that long, on a
  UTF-8 character boundary.
- **A chunk is read behind its lead-in.** The previous chunk's last
  ``LEAD_TOKENS`` tokens, as ``paging.py`` reads a part behind
  ``GUARD_TOKENS`` of the one before it, so an instruction cut by a boundary
  is read whole. Its key hashes the lead-in with the text, so a chunk whose
  context changed is judged again.

Pure and CPU-bound, no I/O but ``gateway_chunk_key``; run it in a worker
thread.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import at_rest, secret_file
from .errors import ProfileConfigError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

MIN_CHUNK = 1024
MAX_CHUNK = 8192
TARGET_CHUNK = 2048
"""Bytes. No cut inside the first ``MIN_CHUNK``, a chunk never over
``MAX_CHUNK``, the average aimed at ``TARGET_CHUNK``."""

LEAD_TOKENS = 64
TOKEN_BYTES = 3
"""The spec's estimate for code: three bytes a token. L2's tokenizer is not
asked (it may be absent, and a cut must not depend on it)."""

LEAD_BYTES = LEAD_TOKENS * TOKEN_BYTES
LEAD_BACK = 32
"""How far back a lead-in may start earlier than ``LEAD_BYTES`` to begin on
whitespace, so its first token is whole."""

_UTF8_CONT_PREFIX = 0b10
"""The top two bits of a UTF-8 continuation byte."""
_MEAN_LINE = 32
_SELECT_MASK = (1 << ((TARGET_CHUNK - MIN_CHUNK) // _MEAN_LINE).bit_length() - 1) - 1
"""A line end is selected when the low bits of its keyed hash are zero. After
``MIN_CHUNK`` the wait is geometric with this mask's period in lines, about
``TARGET_CHUNK - MIN_CHUNK`` bytes of code."""

KEY_BYTES = 32
CHUNK_KEY_STORE = "git"
"""The chunk key's directory under ``<data>``, one of ``at_rest.SEALED_DIRS``."""
CHUNK_KEY_NAME = "chunk-key"


@dataclass(frozen=True)
class Chunk:
    """A chunk of a blob and the text read in front of it."""

    text: str
    lead_in: str
    start: int
    """Byte offset of ``text`` in the blob."""

    def key(self) -> str:
        """sha256 over the lead-in and the text, each length-prefixed."""
        digest = hashlib.sha256()
        for part in (self.lead_in, self.text):
            raw = part.encode("utf-8")
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
        return digest.hexdigest()


def estimate_tokens(text: str) -> int:
    """Tokens at ``TOKEN_BYTES`` bytes each, rounded up."""
    return -(-len(text.encode("utf-8")) // TOKEN_BYTES)


def gateway_chunk_key(legacy: Path | None = None) -> bytes:
    """The gateway's chunking secret: 32 random bytes in ``<data>/git/chunk-key``.

    Kept like every other secret on the volume: sealed by ``at_rest`` when
    there is a KEK, so ``at_rest.seal_all`` and a KEK rotation reach it. Held
    under the store's lock, so a second caller, in this process or another,
    reads what the first wrote.

    ``legacy`` is where the key was kept before (a1706), 0600 plaintext beside
    the perimeter store. A key found there is moved in, sealed and read back
    before the plaintext goes, so cuts stay where they were and so does every
    cached chunk verdict. A KEK that failed its startup check cannot seal, so
    the plaintext key is used where it is until that is fixed.

    A new key is made only when there is none at all, and said so: cuts follow
    the key, so see ``_NEW_KEY`` for what that costs.

    Raises:
        OSError: a key is stored and unreadable, or shorter than ``KEY_BYTES``.
        ProfileConfigError: it is sealed and no key in the KEK opens it. Never
            answered with a new key: the operator fixes the KEK instead.
    """
    directory = secret_file.private_dir(CHUNK_KEY_STORE)
    path = directory / CHUNK_KEY_NAME
    with secret_file.locked(directory):
        # Writers hold this lock, so an empty file is a crash mid-write: no key.
        stored = at_rest.read(path) if os.path.lexists(path) else b""
        if stored:
            key = _whole_key(stored, path)
            if legacy is not None:
                # A crash between the move and the unlink left the plaintext.
                legacy.unlink(missing_ok=True)
            return key
        if legacy is not None and legacy.exists():
            key = _whole_key(legacy.read_bytes(), legacy)
            try:
                sealed = at_rest.seal(key)
            except ProfileConfigError:
                logger.warning(
                    "git chunk key: the KEK cannot seal this run, so the plaintext key "
                    "beside the perimeter store is used where it is until it can"
                )
                return key
            secret_file.replace_atomically(path, sealed)
            if at_rest.read(path) != key:
                raise OSError(errno.EIO, f"{path} did not read back; the plaintext key kept")
            legacy.unlink()
            logger.info("git chunk key: moved into %s/%s", CHUNK_KEY_STORE, CHUNK_KEY_NAME)
            return key
        key = os.urandom(KEY_BYTES)
        secret_file.replace_atomically(path, at_rest.seal(key))
    logger.warning("%s", _NEW_KEY)
    return key


_NEW_KEY = (
    "git chunk key: none was stored, so a new one was made. Cuts follow the key, so every "
    "text blob is cut afresh and judged again at L2 and L3. Cached chunk verdicts stay "
    "true (a chunk's verdict key is its text, not the cut key) but the new chunks no "
    "longer match them, and they age out of git_verdicts. Expected once, on a new data "
    "volume; otherwise the key was lost"
)


def _whole_key(stored: bytes, path: Path) -> bytes:
    if len(stored) < KEY_BYTES:
        raise OSError(errno.EIO, f"chunk key file {path} is shorter than {KEY_BYTES} bytes")
    return stored[:KEY_BYTES]


def chunk_blob(blob: bytes | bytearray, key: bytes) -> list[Chunk]:
    """Cut ``blob`` into chunks, each with its lead-in. An empty blob has none."""
    mac_key = key if len(key) <= 64 else hashlib.sha256(key).digest()
    cuts = _cuts(blob, mac_key)
    chunks: list[Chunk] = []
    begin = 0
    for end in cuts:
        chunks.append(
            Chunk(
                text=blob[begin:end].decode("utf-8", errors="replace"),
                lead_in=_lead_in(blob, chunks[-1].start, begin) if chunks else "",
                start=begin,
            )
        )
        begin = end
    return chunks


def _cuts(blob: bytes | bytearray, mac_key: bytes) -> list[int]:
    """End offsets of the chunks, the last being ``len(blob)``."""
    cuts: list[int] = []
    begin = 0
    previous_end = 0  # the last line end seen after ``begin``
    position = 0
    size = len(blob)
    while position < size:
        newline = blob.find(b"\n", position)
        line_end = size if newline < 0 else newline + 1
        if line_end - begin > MAX_CHUNK:
            if previous_end - begin >= MIN_CHUNK:
                cuts.append(previous_end)
                begin = previous_end
            while line_end - begin > MAX_CHUNK:
                cut = _boundary(blob, begin, begin + MAX_CHUNK)
                cuts.append(cut)
                begin = cut
        previous_end = line_end
        if (
            line_end - begin >= MIN_CHUNK
            and line_end < size
            and _selected(blob[position:line_end], mac_key)
        ):
            cuts.append(line_end)
            begin = line_end
        position = line_end
    if size and (not cuts or cuts[-1] != size):
        cuts.append(size)
    return cuts


def _selected(line: bytes | bytearray, mac_key: bytes) -> bool:
    digest = hashlib.blake2b(line, key=mac_key, digest_size=4).digest()
    return int.from_bytes(digest, "big") & _SELECT_MASK == 0


def _boundary(blob: bytes | bytearray, begin: int, cut: int) -> int:
    """``cut`` moved back off a UTF-8 continuation byte, never to ``begin``."""
    point = cut
    while point > begin + 1 and point < len(blob) and blob[point] >> 6 == _UTF8_CONT_PREFIX:
        point -= 1
    return point if point > begin else cut


def _lead_in(blob: bytes | bytearray, prev_start: int, prev_end: int) -> str:
    """The last ``LEAD_TOKENS`` tokens of the chunk ``[prev_start, prev_end)``.

    ``LEAD_BYTES`` back, then earlier if whitespace is within ``LEAD_BACK``
    bytes so the lead-in starts on a whole token, else forward to a character
    boundary.
    """
    begin = max(prev_start, prev_end - LEAD_BYTES)
    if begin > prev_start:
        floor = max(prev_start, begin - LEAD_BACK)
        for index in range(begin - 1, floor - 1, -1):
            if blob[index] in b" \t\r\n":
                begin = index + 1
                break
        else:
            while begin < prev_end and blob[begin] >> 6 == _UTF8_CONT_PREFIX:
                begin += 1
    return blob[begin:prev_end].decode("utf-8", errors="replace")
