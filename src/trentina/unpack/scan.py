"""Decode what decodes to text, label what does not (#367).

A first pass over the text, then a bounded second pass for Ascii85 and base85
(``_ascii85_pass``); both linear in the text's length. A token qualifies only
when decoding it is exact: strict base64, base32, Ascii85 or base85 whose
re-encoding reproduces it, or hex. Anything a lenient decoder would read
differently (URL-safe characters, missing padding, junk after ``=``) is left
as it arrived, so the layers and the agent's own tools can never disagree
about what it says.

Three more of garak's encodings are decoded by their shape rather than a
re-encode, because they are lossy (#546): uuencode by its ``b2a_uu`` line
framing (still re-encode-checked per line), and Braille and Morse by their
own alphabets (the U+2800 block; ``.-/`` groups), each gated by ``_as_text``.
Their tables live in ``alphabets.py``, in-tree, because runtime code cannot
import ``corpora``.

What becomes of a token:

* **It decodes to text:** the layers read the text in its place, unmarked,
  and it is unpacked again, to ``MAX_DEPTH`` levels. There is no length
  floor, because ``cm0gLXJmIH4=`` is ``rm -rf ~``, and hex is decoded at any
  length too. English words that happen to be valid base64 (``findings``,
  ``annotate``) decode to bytes that fail ``_as_text``, and are left alone.
* **It decodes to binary of ``LABEL_FLOOR`` characters or more:** the
  layers read a label in its place, ``(image/png, 1.1 KB, not read)``. An
  image, PDF or archive is always labelled, and that label is the
  ``binary_unread`` refusal. Anything else is labelled only when its own
  characters read as noise (``_reads_as_noise``): otherwise an instruction
  written without spaces could hide behind a label. Measured with the default L2
  (``benchmarks/l2_blob_length.py``), blobs from 64 characters up are where
  L2 starts reacting: a 64-character integrity hash scored 0.92, an SSH
  public key 0.99. A 44-character key in a config scored 0.47.
* **It decodes to an archive or an office file** (#368): the layers read
  what is inside. ``archive.py`` opens zip, tar, gzip, bzip2 and xz within
  limits; each file is then read by these same rules, an office part as its
  text (``office.py``). One that does not open, or breaks a limit, falls to
  the next case and is labelled unread.
* **Anything else stays verbatim:** short binary, hex digests up to SHA-512's
  128 characters, numbers (decimal digits up to ``DECIMAL_MAX``), and runs
  that decode to binary but read like words, such as a URL path or a run
  of ``x``.

Why decoded text carries no marker: any bracketed note in front of it, such
as ``[base64 → text]``, made L2 flag 4 to 8 of the 14 benign corpus texts,
against 1 without one (docs/benchmark.md). L3 learns what was decoded from
its briefing, which names the counts. Labels for binary measured at L2's
baseline in parentheses.

A data URI is labelled whole, so the layers read its type rather than its
payload, and ``data:image/...`` stops looking like an exfiltration URL to L1.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import secrets
import string
from collections import Counter
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING

from . import office
from .alphabets import decode_braille, decode_morse
from .archive import OPENABLE, ZIP, Budget, Entry, open_archive
from .ocr import MAX_IMAGE_BYTES, MAX_IMAGES, ImageText, read_images
from .pdf import SECTIONS, PdfReading, read_pdf
from .signatures import OPAQUE, Kind, from_media_type, identify
from .stats import UnpackStats

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

LABEL_FLOOR = 64
"""Base64 characters from which binary is labelled. Measured; see the module docstring."""

MIN_TOKEN = 8
"""Shorter tokens are never decoded: ``rm -rf`` needs eight characters."""

MAX_DEPTH = 2
"""Levels of decoding: base64 of base64 is read, a third layer is left."""

MAX_NESTING = 2
"""Archives opened inside one another: a zip in a tar.gz is read, a third
level stays unread."""

MAX_MEDIA_TOKEN = 8_000_000
"""Characters of a token that opens as an image, a PDF or an archive and is
decoded whole to be read inside (#370): a screenshot or a paper is megabytes
of base64. Anything else stops at ``MAX_TOKEN``."""

MAX_TOKEN = 140_000
"""Characters past which a token is left encoded. L1's decode cap
(``l1/encoded.py``), and above what admission lets through anyway."""

HEX_DIGEST_MAX = 128
"""Hex runs up to SHA-512's length that do not decode to text are digests,
identifiers read as they are. Hex that decodes to text is decoded at any
length."""

DECIMAL_MAX = 20
"""A run of decimal digits up to this long is a number, read as it is: twenty
digits is the largest unsigned 64-bit integer. Without it an even-length byte
count is hex that happens to decode to text, and ``"Size":7764637970`` reached
the layers as ``"Size":wdcyp`` (#431). Hex text written in digits alone can
spell at most ten characters under this, from an alphabet without ``j`` to
``o`` or ``z``."""

TINY_IMAGE_PIXELS = 4
"""An image whose header says it is at most this many pixels a side cannot
draw a letter or a QR code (21 modules a side at the least), so it counts as
read: tracking pixels and spacers. Byte size is no guide; a QR code PNG is a
couple of hundred bytes."""

_TOKEN = re.compile(
    r"(?P<uri>data:(?P<type>[a-z0-9.+-]{1,127}/[a-z0-9.+-]{1,127})"
    r"(?:;[a-z0-9=.+-]{1,64}){0,4};base64,(?P<payload>[A-Za-z0-9+/]*={0,2}))"
    # Braille cells (U+2800 block), with spaces, tabs and newlines between them.
    r"|(?P<braille>[⠁-⣿][⠀-⣿ \t\n\r]*)"
    # Morse: two or more code groups, separated by spaces or word slashes. Each
    # atom is BOUNDED (a Morse letter is at most six symbols), so a long run
    # that is not Morse costs O(1) per start position, never O(n) (ReDoS).
    r"|(?P<morse>[.-]{1,6}(?:[ /]{1,6}[.-]{1,6})+)"
    # uuencode: one or more b2a_uu lines (data is 0x20-0x60, no lower case, so a
    # lower-case base64 token on its own line is never mistaken for one). The
    # ranges are case-sensitive despite the flag below, or they catch lower case.
    # The line body is BOUNDED (b2a_uu emits at most 60 data chars), so a long
    # newline-free run cannot make each start position rescan the suffix (ReDoS).
    r"|(?P<uu>(?-i:(?:[\x21-\x60][\x20-\x60]{0,60}\n)+))"
    # base32 (A-Z2-7), its own group so the full 0-6 padding is captured: the
    # run below stops at two '='. Tried as base32 then base64 (all-upper tokens).
    # Case-sensitive, else the flag below lets it fragment a base64 token.
    r"|(?P<b32>(?-i:[A-Z2-7]{8,}={0,6}))"
    # base64 or hex, the original run: anything a lenient decoder would read
    # differently is left verbatim, so '=' stays a delimiter (SECRET=<b64>).
    r"|(?P<run>[A-Za-z0-9+/_-]+={0,2})",
    re.IGNORECASE,
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_BASE32 = re.compile(r"[A-Z2-7]+={0,6}")
_HEX = re.compile(r"[0-9a-fA-F]+")

# Ascii85 and base85 are a second pass (``_ascii85_pass``): their alphabets are
# a superset of base64's, so a shared tokenizer would fragment a bare blob or
# swallow a base64 '=' delimiter. Pass one leaves a blob it cannot read
# untouched, so pass two sees it whole and tokenises it on the wider alphabet.
_WIDE = re.compile(r"[\x21-\x7e]{16,}")
A85_MIN = 16
"""Shortest Ascii85 or base85 token decoded. Short blobs decode to a few bytes
that re-encode canonically by chance; a real encoded attack is far longer, so
the floor (the ``_WIDE`` minimum) keeps the benign false-positive surface down."""
A85_MAX = 20_000
"""Longest Ascii85/base85 blob the second pass decodes. a85/b85 decode is pure
Python, so an unbounded run would be super-linear; an encoded attack is far
shorter than this. A longer blob is left (a narrow part of gap 21)."""
_PLAIN = frozenset(string.printable) - frozenset("\r\x0b\x0c")
SHORT_TEXT = 32
"""Decodings shorter than this must read as plain text, not merely as UTF-8."""


HEAD = 4096
"""Characters of an oversized token decoded to find its signature."""


@dataclass(frozen=True)
class Unpacked:
    """What the layers read, and what they could not.

    Attributes:
        text: The delivery with every packed part unpacked. The same object
            as the input when nothing qualified.
        stats: Counts for L3's briefing.
        unread: Kinds of binary an agent's tools could open and no layer
            read, sorted and distinct. Non-empty is the ``binary_unread`` gap.
        hidden: Lines of an office file that its application would not show
            (``office.py``). The layers read them; this is the count L1
            reports with its other hidden-content findings.
    """

    text: str
    stats: UnpackStats
    unread: tuple[str, ...]
    hidden: int = 0


@dataclass
class _Exposure:
    """One image set aside: what it is, its bytes, and where its text will go."""

    kind: str
    image: bytes
    mark: str


@dataclass
class _Darkroom:
    """The images of one payload, read together.

    OCR starts a process and loads three models, about a second before the
    first image is read. So an image met while unpacking is not read on the
    spot: it is set aside here and a mark is left in the text. When the pass
    is over every image is read in one request, and each mark is replaced by
    what its image says. The mark carries a random token, so no payload can
    write one.
    """

    token: str = field(default_factory=lambda: secrets.token_hex(8))
    exposures: list[_Exposure] = field(default_factory=list)
    read: dict[str, ImageText | None] | None = None

    def expose(self, kind: str, decoded: bytes) -> _Exposure | None:
        """Set an image aside, or None if there is no room for it."""
        if len(self.exposures) >= MAX_IMAGES or len(decoded) > MAX_IMAGE_BYTES:
            return None
        exposure = _Exposure(kind, decoded, f"\x00{self.token}:{len(self.exposures)}\x00")
        self.exposures.append(exposure)
        return exposure

    def develop(self) -> dict[str, ImageText | None]:
        """What each image says, by its mark; read once however many passes ask."""
        if self.read is None:
            said = read_images([e.image for e in self.exposures]) if self.exposures else []
            self.read = {e.mark: text for e, text in zip(self.exposures, said, strict=True)}
        return self.read


@dataclass
class _Pass:
    stats: UnpackStats = field(default_factory=UnpackStats)
    unread: set[str] = field(default_factory=set)
    hidden: int = 0
    nesting: int = 0
    budget: Budget = field(default_factory=Budget)
    darkroom: _Darkroom = field(default_factory=_Darkroom)
    exposed: list[_Exposure] = field(default_factory=list)

    def expose(self, kind: str, decoded: bytes) -> str | None:
        """Set an image aside for this pass and return its mark, or None."""
        exposure = self.darkroom.expose(kind, decoded)
        if exposure is None:
            return None
        self.exposed.append(exposure)
        return exposure.mark

    def result(self, text: str) -> Unpacked:
        """The finished view: every image's mark replaced by what the image says.

        An image OCR read is its text under a line naming it, with the text
        too faint to see set apart and counted as hidden. One it could not
        read is labelled unread, like any other binary no layer opened.
        """
        read = self.darkroom.develop() if self.exposed else {}
        for exposure in self.exposed:
            kind, said = exposure.kind, read[exposure.mark]
            size = _size(len(exposure.image))
            self.stats.binary_labelled += 1
            if said is None:
                self.stats.binary_unread += 1
                self.unread.add(kind)
                printed = [f"({kind}, {size}, not read)"]
            elif not said.text and not said.faint:
                printed = [f"({kind}, {size}, no text found in it)"]
            else:
                printed = [f"({kind}, {size}, text read from it below)", *said.text]
                if said.faint:
                    printed.extend(["(text in it too faint to see:)", *said.faint])
            if said is not None:
                self.stats.images_read += 1
                self.hidden += len(said.faint)
            text = text.replace(exposure.mark, "\n".join(printed))
        return Unpacked(text, self.stats, tuple(sorted(self.unread)), self.hidden)


def unpack(text: str) -> Unpacked:
    """Build what the layers read from ``text``. Pure; never raises on content."""
    # TRUST: decoding a payload's encodings before any layer has judged it
    #   untrusted: all of `text`, chosen by whoever wrote the payload
    #   judged-by: L1, L2 and L3 read what this returns; the delivery is never replaced
    #   on-failure: fail-closed (binary no layer reads is the binary_unread gap); a
    #     token that does not decode strictly is read as it arrived
    #   owner: unpack.scan.unpack
    #   evidence: T1 strict decode + re-encode equality (b64/b32/a85/b85/uu),
    #     Braille/Morse by alphabet; T4 test_unpack.py linearity; T3 layer contract
    state = _Pass()
    unpacked = _unpack(text, 0, state)
    return state.result(_ascii85_pass(unpacked, state))


def _ascii85_pass(text: str, state: _Pass, depth: int = 0) -> str:
    """Decode Ascii85 and base85 blobs the first pass left whole (#546).

    Only text decodes are taken, each strict (the decode must re-encode to the
    blob), so a base64 token the first pass already judged is never touched: it
    does not re-encode as canonical Ascii85 or base85. A decoded blob is read by
    ``_unpack``, then by this pass again (to ``MAX_DEPTH`` levels, so Ascii85 of
    Ascii85 is read), like any other decoded text.
    """
    if depth >= MAX_DEPTH:
        return text
    pieces: list[str] = []
    last = 0
    changed = False
    for match in _WIDE.finditer(text):
        if match.end() - match.start() > A85_MAX:
            continue  # skip without copying a long run that cannot qualify
        plain = _decode_a85(match.group())
        if plain is None:
            continue
        state.stats.text_decoded += 1
        pieces.append(text[last : match.start()])
        pieces.append(_ascii85_pass(_unpack(plain, MAX_DEPTH - 1, state), state, depth + 1))
        last = match.end()
        changed = True
    if not changed:
        return text
    pieces.append(text[last:])
    return "".join(pieces)


def _unpack(text: str, depth: int, state: _Pass) -> str:
    changed = False
    pieces: list[str] = []
    last = 0
    for match in _TOKEN.finditer(text):
        if match["uri"] is not None:
            replacement = _data_uri(match, depth, state)
        else:
            for group, decode in _CIPHERS:
                if match[group] is not None:
                    replacement = decode(match[group], depth, state)
                    break
            else:
                replacement = _run(match["run"], depth, state)
        if replacement is not None:
            pieces.append(text[last : match.start()])
            pieces.append(replacement)
            last = match.end()
            changed = True
    if not changed:
        return text
    pieces.append(text[last:])
    return "".join(pieces)


def _run(token: str, depth: int, state: _Pass) -> str | None:
    """The replacement for one run of base64 or hex characters, or None."""
    if len(token) > MAX_TOKEN:
        return _long(token, OPAQUE, state)
    number = len(token) <= DECIMAL_MAX and token.isascii() and token.isdigit()
    if len(token) < MIN_TOKEN or number:
        return None  # too short to decode, or a plain number
    if _HEX.fullmatch(token) and not len(token) % 2:
        unhexed = bytes.fromhex(token)
        if _as_text(unhexed) is None and len(token) <= HEX_DIGEST_MAX:
            return None  # a digest: an identifier, read as it is
        return _decoded(unhexed, token, depth, state)
    decoded = None if len(token) % 4 else _strict_base64(token)
    return None if decoded is None else _decoded(decoded, token, depth, state)


def _base32_token(token: str, depth: int, state: _Pass) -> str | None:
    """A base32 run (its own group, for the full 0-6 padding), read as base32
    text first (#546): a padless base32 token is valid base64 too, so trying
    base64 first would read the wrong bytes. An all-upper token that is not
    base32 text falls through to base64, which it can also be."""
    if len(token) > MAX_TOKEN:
        return _run(token, depth, state)  # _run's _long path, no large base32 decode
    decoded = _strict_base32(token)
    if decoded is not None:
        text = _as_text(decoded)
        if text is not None:
            return _text(text, depth, state)
    return _run(token, depth, state)


def _long(token: str, declared: Kind, state: _Pass) -> str | None:
    """A token past ``MAX_TOKEN``, identified from its head.

    One that opens as an image, a PDF or an archive is decoded whole, up to
    ``MAX_MEDIA_TOKEN``, and read inside. Past that, or when it does not
    decode or open, it is labelled unread: flag reads an over-cap payload's
    head, so an openable format must still be counted. Anything else is left
    as it arrived, for admission to refuse on length.
    """
    head = _strict_base64(token[:HEAD]) or b""
    kind = identify(head)
    kind = kind if kind is not OPAQUE else declared
    if not kind.extractable:
        return None
    if len(token) <= MAX_MEDIA_TOKEN:
        whole = _strict_base64(token)
        opened = None if whole is None else _opened(kind, whole, state)
        if opened is not None:
            return opened
    return _label(kind, head, state, size=len(token) * 3 // 4)


def _data_uri(match: re.Match[str], depth: int, state: _Pass) -> str | None:
    """A data URI, labelled or decoded whole, or None to leave it as it is."""
    declared = from_media_type(match["type"].lower())
    payload = match["payload"]
    if len(payload) > MAX_TOKEN:
        return _long(payload, declared, state)
    decoded = _strict_base64(payload) if payload else None
    if decoded is None:
        return None
    # Text is text whatever the URI declares: application/javascript or
    # octet-stream can carry an instruction as well as text/plain can.
    text = _as_text(decoded)
    kind = identify(decoded)
    return (
        _text(text, depth, state)
        if text is not None
        else _read_or_labelled(kind if kind is not OPAQUE else declared, decoded, state)
    )


def _read_or_labelled(kind: Kind, decoded: bytes, state: _Pass) -> str:
    """Binary an agent could open: what is inside it, or its label, unread."""
    return _opened(kind, decoded, state) or _label(kind, decoded, state)


def _decoded(decoded: bytes, token: str, depth: int, state: _Pass) -> str | None:
    text = _as_text(decoded)
    if text is not None:
        return _text(text, depth, state)
    kind = identify(decoded, short=len(token) < LABEL_FLOOR)
    if kind.extractable:  # an openable format at any size
        return _read_or_labelled(kind, decoded, state)
    if len(token) < LABEL_FLOOR or not _reads_as_noise(token):
        return None
    return _labelled_with_strings(kind, decoded, state)


def _labelled_with_strings(kind: Kind, decoded: bytes, state: _Pass) -> str:
    """A label, then the readable strings inside the bytes.

    Those strings are what a ``strings`` tool would show an agent, so the
    layers read them too, bare after the label.
    """
    inside = " ".join(run.decode("ascii") for run in _SENTENCE.findall(decoded) if b" " in run)
    label = _label(kind, decoded, state)
    return f"{label} {inside}" if inside else label


_ARCHIVE_NAMES = {ZIP: "zip archive"}
"""What an opened archive is called once it is known not to be an office file."""

ENCRYPTED_ENTRY = "encrypted or unsupported archive entry"
"""The ``unread`` kind for a file inside an archive that could not be read."""


def _opened(kind: Kind, decoded: bytes, state: _Pass) -> str | None:
    """What the layers read for an archive or office file, or None if it stays unread.

    A header naming the kind and its file count, then every file under a
    ``=== name ===`` line: an office part as its text, a text file unpacked
    like any other text, an archive inside opened in turn, other binary
    labelled. File names are the archive author's text and are read with the
    rest. None leaves the caller to label the whole archive unread: a kind
    not opened here, a corrupt file, a broken limit, or nesting past
    ``MAX_NESTING``.
    """
    if state.nesting >= MAX_NESTING:
        return None
    if kind.name.startswith(IMAGE):
        return _image(kind, decoded, state)
    if kind.name == PDF:
        return _opened_pdf(decoded, state)
    if kind.name not in OPENABLE:
        return None
    entries = open_archive(decoded, kind.name, state.budget)
    if entries is None:
        return None
    state.stats.archives_opened += 1
    office_kind = office.kind_of(e.name for e in entries) if kind.name == ZIP else None
    reading = office.read(entries, office_kind) if office_kind else None
    if reading is not None:
        state.hidden += reading.hidden
    name = reading.kind if reading is not None else _ARCHIVE_NAMES.get(kind.name, kind.name)
    files = "1 file" if len(entries) == 1 else f"{len(entries)} files"
    parts = [f"({name}, {_size(len(decoded))}, {files})"]
    state.nesting += 1
    try:
        for entry in entries:
            body = _entry(entry, reading, state)
            if body:
                parts.append(f"=== {entry.name} ===\n{body}")
    finally:
        state.nesting -= 1
    return "\n".join(parts)


IMAGE = "image"
"""How the name of every kind OCR can read begins: ``image/png``, or plain
``image`` for one known only by a data URI's declared type."""


def _image(kind: Kind, decoded: bytes, state: _Pass) -> str | None:
    """A mark where an image's text will go, or None to leave it labelled.

    None for an image too small to draw a letter (its label already says it
    is read), and for one there is no room to read: past ``ocr.MAX_IMAGES``
    in the payload or ``ocr.MAX_IMAGE_BYTES`` in size. Those stay unread.
    """
    return None if _too_small_to_draw(decoded) else state.expose(kind.name, decoded)


PDF = "application/pdf"
SCANNED_PAGE = "scanned PDF page"
"""The ``unread`` kind for a PDF page that is a picture of a page (#370)."""


def _opened_pdf(decoded: bytes, state: _Pass) -> str | None:
    """What the layers read for a PDF, or None when it could not be read.

    Each page's text, with what a reader would not see under its own
    heading; then every text entry the file carries outside its pages, by
    kind; then each embedded file, read like a file in an archive. A page
    that is a picture, with or without a text layer over it, has its image
    read by OCR with the payload's other images (#370): what the picture
    says is read beside what its layer claims. A picture OCR did not read
    leaves its page unread. The rest is still read.
    """
    reading: PdfReading | None = read_pdf(decoded)
    if reading is None:
        return None
    state.stats.archives_opened += 1
    state.hidden += reading.hidden
    count = len(reading.pages)
    parts = [f"({PDF}, {_size(len(decoded))}, {count} page{'' if count == 1 else 's'})"]
    parts.extend(_pdf_text(reading))
    sent = 0
    for number, picture in reading.pictures:
        mark = state.expose(SCANNED_PAGE, picture)
        if mark is not None:
            parts.append(f"=== page {number}, read from its image ===\n{mark}")
            sent += 1
    # A page that is a picture is read when OCR reads its image. One whose
    # image did not come back, or that there was no room to send, is unread.
    unsent = reading.scanned + reading.text_layers - sent
    if unsent > 0:
        state.stats.binary_labelled += unsent
        state.stats.binary_unread += unsent
        state.unread.add(SCANNED_PAGE)
    state.nesting += 1
    try:
        for entry in reading.attachments:
            body = _entry(entry, None, state)
            if body:
                parts.append(f"=== attached: {entry.name} ===\n{body}")
    finally:
        state.nesting -= 1
    return "\n".join(parts)


def _pdf_text(reading: PdfReading) -> Iterator[str]:
    """A PDF's own text, section by section, and a line for pages that are pictures."""
    for number, (visible, unseen) in enumerate(reading.pages, start=1):
        if visible:
            yield f"=== page {number} ===\n{visible}"
        if unseen:
            yield f"=== page {number}, text not shown ===\n{unseen}"
    for section in SECTIONS:
        if reading.fields.get(section):
            yield f"=== {section} ===\n" + "\n".join(reading.fields[section])
    if reading.scanned:
        yield f"({reading.scanned} page(s) are images with no text)"
    if reading.text_layers:
        yield (
            f"({reading.text_layers} page(s) are images under a text layer; "
            "the text above is the layer)"
        )


def _entry(entry: Entry, reading: office.Reading | None, state: _Pass) -> str:
    """What the layers read for one file of an archive. Empty for an empty file."""
    if entry.content is None:
        state.stats.binary_labelled += 1
        state.stats.binary_unread += 1
        state.unread.add(ENCRYPTED_ENTRY)
        return f"({entry.unread}, not read)"
    if reading is not None and entry.name in reading.parts:
        return reading.parts[entry.name].all()
    if not entry.content:
        return ""
    text = _file_text(entry.content)
    if text is not None:
        # One more level: a base64 token in a file inside an archive is decoded.
        return _unpack(text, MAX_DEPTH - 1, state)
    kind = identify(entry.content)
    if kind.extractable:
        return _read_or_labelled(kind, entry.content, state)
    return _labelled_with_strings(kind, entry.content, state)


_BOMS = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)
TEXT_SHARE = 0.95
"""Share of a file's characters that must be printable for it to be text."""


def _file_text(raw: bytes) -> str | None:
    """A file's bytes as text when a text editor would show them as text.

    UTF-8 first; then a byte-order mark's encoding; then Latin-1, which
    decodes anything, accepted only when nearly all of it is printable. A
    file is not held to ``_as_text``'s short-token rules: it was found as a
    file, not guessed at from a run of base64 characters.
    """
    for bom, encoding in _BOMS:
        if raw.startswith(bom):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    printable = sum(c.isprintable() or c in "\n\r\t" for c in text)
    return text if printable >= TEXT_SHARE * len(text) else None


def _text(text: str, depth: int, state: _Pass) -> str:
    state.stats.text_decoded += 1
    return _unpack(text, depth + 1, state) if depth + 1 < MAX_DEPTH else text


def _label(kind: Kind, decoded: bytes, state: _Pass, *, size: int | None = None) -> str:
    state.stats.binary_labelled += 1
    unread = kind.extractable and not _too_small_to_draw(decoded)
    if unread:
        state.stats.binary_unread += 1
        state.unread.add(kind.name)
    tail = ", not read" if unread else ""
    return f"({kind.name}, {_size(len(decoded) if size is None else size)}{tail})"


def _too_small_to_draw(decoded: bytes) -> bool:
    """A PNG or GIF whose header gives both sides as ``TINY_IMAGE_PIXELS`` or less."""
    if decoded.startswith(b"\x89PNG\r\n\x1a\n") and decoded[12:16] == b"IHDR":
        width, height = int.from_bytes(decoded[16:20]), int.from_bytes(decoded[20:24])
    elif decoded[:6] in (b"GIF87a", b"GIF89a"):
        width = int.from_bytes(decoded[6:8], "little")
        height = int.from_bytes(decoded[8:10], "little")
    else:
        return False
    return 0 < width <= TINY_IMAGE_PIXELS and 0 < height <= TINY_IMAGE_PIXELS


def image_too_small_to_draw(encoded: str) -> bool:
    """An MCP image block whose header states 4 by 4 pixels or less (see ``_label``)."""
    decoded = _strict_base64(encoded) if len(encoded) <= MAX_TOKEN else None
    return decoded is not None and _too_small_to_draw(decoded)


def read_blob(blob: str) -> Unpacked | None:
    """What the layers read for an MCP resource blob, or None if they cannot.

    A blob is one base64 token, so it unpacks like one: to its text, to what
    is inside it, to a label, or, when short, to itself. None for a blob that
    is not canonical base64 or is too long to decode: it cannot be
    identified, so the caller counts it as unread, never as harmless.
    """
    return read_blobs([blob])[0]


def read_blobs(blobs: list[str]) -> list[Unpacked | None]:
    """``read_blob`` for every blob of one response, their images read together.

    One OCR request serves all of them: a response with three screenshots
    starts the models once. Each blob still gets its own view and counts.
    """
    darkroom = _Darkroom()
    passes: list[tuple[_Pass, str] | None] = []
    for blob in blobs:
        decoded = _strict_base64(blob) if len(blob) <= MAX_MEDIA_TOKEN else None
        if decoded is None:
            passes.append(None)
            continue
        state = _Pass(darkroom=darkroom)
        text = _decoded(decoded, blob, 0, state)
        passes.append((state, blob if text is None else text))
    return [None if entry is None else entry[0].result(entry[1]) for entry in passes]


UNDECODABLE = Kind("undecodable blob", extractable=True)
"""A blob ``read_blob`` could not decode. Counted as unread."""

IMAGE_BLOCK = Kind("image", extractable=True)
"""An MCP image content block. Its declared ``mimeType`` is the backend's
text, so the label does not echo it."""


WINDOW = 64
"""Characters per window of the surface test, the label floor."""

MIN_ENTROPY = 4.8
"""Bits per character a window needs to read as random. Random base64
measured 4.91 at the least over 64 characters; spaceless English 4.72 at
the most (corpus payloads, camel-cased)."""

MAX_WORD_SHARE = 0.5
"""Share of a window in word-shaped letter runs past which it reads as
language. Random base64 measured 0.58 at the most, 0.36 at the 99th
percentile; spaceless English built from short words 0.58 at the least."""

_LETTER_RUN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_SENTENCE = re.compile(rb"[\x20-\x7e]{12,}")
"""Printable ASCII runs in binary long enough to say something. Kept only
with a space in them: twelve random bytes are all printable about once in
150,000 tries, and nearly never hold a space as well."""
_VOWELS = frozenset("aeiouAEIOU")


def _reads_as_noise(token: str) -> bool:
    """Whether every window of the token's own characters reads as random.

    Asked before binary that an agent cannot open is labelled, since a label
    means no layer reads the token's characters. Decoding says nothing about
    the surface: ``MIIB`` followed by an instruction written without spaces
    decodes to a DER signature. An agent reads that surface, so it is
    labelled only when no window of it reads as language: each must have the
    entropy of random base64 and few word-shaped runs. Windows overlap by
    half, so a sentence hidden inside a random blob lands whole in one.
    """
    last = max(len(token) - WINDOW, 0)
    starts = [*range(0, last, WINDOW // 2), last]  # the last window ends at the end
    return all(_noise(token[i : i + WINDOW]) for i in starts)


def _noise(window: str) -> bool:
    counts = Counter(window).values()
    entropy = -sum(n / len(window) * math.log2(n / len(window)) for n in counts)
    worded = sum(len(run) for run in _LETTER_RUN.findall(window) if _word_shaped(run))
    return entropy >= MIN_ENTROPY and worded < MAX_WORD_SHARE * len(window)


def _word_shaped(run: str) -> bool:
    """Three letters or more, a vowel, and no four consonants together."""
    if len(run) < 3 or not _VOWELS.intersection(run):
        return False
    consonants = 0
    for letter in run:
        consonants = 0 if letter in _VOWELS else consonants + 1
        if consonants >= 4:
            return False
    return True


def _strict_base64(token: str) -> bytes | None:
    """Decode only canonical base64: what decodes must re-encode to ``token``."""
    if not _BASE64.fullmatch(token):
        return None
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b64encode(decoded).decode("ascii") == token else None


def _strict_base32(token: str) -> bytes | None:
    """Decode only canonical base32 (A-Z2-7), re-encoding to ``token`` (#546)."""
    if not _BASE32.fullmatch(token) or len(token) % 8:
        return None
    try:
        decoded = base64.b32decode(token)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b32encode(decoded).decode("ascii") == token else None


_A85_CODECS = (
    (base64.a85decode, base64.a85encode),
    (base64.b85decode, base64.b85encode),
)


def _decode_a85(token: str) -> str | None:
    """Ascii85 or base85 as text, or None (#546). Both alphabets overlap, so
    each is tried and the one that yields text wins; a decode that is not
    canonical (does not re-encode to the token) or not text is declined. The
    caller bounds the length (``A85_MAX``) before paying to copy the token."""
    for decode, encode in _A85_CODECS:
        try:
            blob = decode(token)
        except (binascii.Error, ValueError):
            continue
        if encode(blob).decode("ascii") != token:
            continue
        plain = _as_text(blob)
        if plain is not None:
            return plain
    return None


def _strict_uu(token: str) -> bytes | None:
    """Decode garak's uuencode, re-encoding line for line to ``token`` (#546)."""
    try:
        chunks = [binascii.a2b_uu(line.encode("ascii")) for line in token.splitlines() if line]
    except (binascii.Error, ValueError):
        return None
    decoded = b"".join(chunks)
    try:
        reencoded = "".join(
            binascii.b2a_uu(decoded[i : i + 45]).decode("ascii") for i in range(0, len(decoded), 45)
        )
    except (binascii.Error, ValueError):
        return None
    return decoded if reencoded == token else None


def _uu_decoded(token: str, depth: int, state: _Pass) -> str | None:
    """The replacement for a uuencoded block, or None to leave it as it arrived."""
    if len(token) > MAX_TOKEN:
        return None
    decoded = _strict_uu(token)
    return None if decoded is None else _decoded(decoded, token, depth, state)


def _cipher(
    token: str, depth: int, state: _Pass, *, decode: Callable[[str], str | None]
) -> str | None:
    """A Braille or Morse run, decoded and read as text, or None to leave it.

    ``decode`` returns the plain text, which must still read as text: a run of
    cells or code groups that spells nothing is left as it arrived.
    """
    if len(token) > MAX_TOKEN:
        return None
    plain = decode(token)
    if not plain:
        return None
    text = _as_text(plain.encode("utf-8"))
    return None if text is None else _text(text, depth, state)


_CIPHERS: tuple[tuple[str, Callable[..., str | None]], ...] = (
    ("braille", partial(_cipher, decode=decode_braille)),
    ("morse", partial(_cipher, decode=decode_morse)),
    ("uu", _uu_decoded),
    ("b32", _base32_token),
)
"""Token group -> decoder, tried in order after the data-URI group (#546).
base32 is last so the common base64/hex ``run`` is reached quickly."""


def _as_text(decoded: bytes) -> str | None:
    """``decoded`` as text when it reads as text, else None.

    Long decodings need 95% printable UTF-8. Short ones, where chance matters,
    must be plain printable ASCII, at least half letters, digits and spaces:
    without that, ordinary words that happen to be valid base64 ("findings",
    "annotate") decoded to garbage. Measured over every token in this
    repository's docs and source, the rule decodes only real base64, and
    accepts 37 in 20,000 random six-byte tokens.
    """
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not any(c.isalpha() for c in text):
        return None
    if len(text) < SHORT_TEXT:
        plain = all(c in _PLAIN for c in text)
        wordy = sum(c.isalnum() or c == " " for c in text) * 2 >= len(text)
        return text if plain and wordy else None
    printable = sum(c.isprintable() or c in "\n\r\t" for c in text)
    return text if printable >= 0.95 * len(text) else None


_UNITS = ((1024 * 1024, "MB"), (1024, "KB"))


def _size(n: int) -> str:
    return next((f"{n / scale:.1f} {unit}" for scale, unit in _UNITS if n >= scale), f"{n} B")
