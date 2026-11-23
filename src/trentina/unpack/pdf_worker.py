"""Read one PDF from stdin and print what it says as JSON (#369).

Run as a child process by ``pdf.read_pdf`` and by nothing else:

    python -m trentina.unpack.pdf_worker < file.pdf

A PDF is the most complicated thing this gateway opens, in a pure-Python
parser with a history of inputs that loop or allocate without end. A thread
cannot be stopped; a process can. So the parse happens here, under a CPU
limit and an address-space limit this process sets on itself, with no
credential in its environment, and the parent kills it at a wall-clock
deadline. Any exception is left to end the process: a PDF that cannot be
read to the end is not half read.

The output is everything a tool handed the file could show an agent:

* the text of each page, split by whether a reader would see it;
* every text-valued entry worth reading in every object of the file
  (annotation contents, form values, link targets, JavaScript, document
  information, alternate text), reached by walking the cross-reference
  table and not the page tree, so an object nothing points to is read too;
* the XMP metadata packet, and each embedded file's bytes up to
  ``MAX_ATTACHED`` in all: a file past that is named with no content, and
  the parent counts it unread. Outline entries are dictionaries with a
  ``/Title``, so the walk above reads them with everything else.

Invisible means drawn so by a named operator: text render mode 3 or 7, a
size under a point once the matrices are applied or a position outside the
page (both judged for text drawn on the page itself, not inside a form), or
a white fill on a page that has painted nothing else. Two things
that look the same are not counted, because they are how ordinary files are
written: white text after a fill, a shading or an image (a dark slide), and
a page that is an image with all of its text invisible (a scan with its OCR
text layer). That text is read as the page's text and the page is reported
as ``text_layers``: nothing here checks that the layer says what the
picture shows, so the parent still counts the picture unread. Text in a hidden optional-content
layer, behind an image or clipped away is read as visible (Known gaps).
"""

from __future__ import annotations

import base64
import io
import json
import math
import resource
import sys
from dataclasses import dataclass, field
from typing import Any

from pypdf import PdfReader, overwrite_configuration
from pypdf.errors import PyPdfError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject

from .ocr import MAX_IMAGE_BYTES, MAX_IMAGES

CPU_SECONDS = 20
MEMORY_BYTES = 1024 * 1024 * 1024
MAX_STREAM_BYTES = 32 * 1024 * 1024
"""What one compressed stream may inflate to. pypdf's own default is 75 MB."""

MAX_PAGES = 500
MAX_OBJECTS = 100_000
MAX_TEXT = 1_000_000
"""Characters of text collected before the file is given up as too large.
Admission refuses long before this; the cap bounds the work."""

MAX_ATTACHED = 1024 * 1024
"""Bytes of embedded files returned, the archive stage's own budget."""

INVISIBLE_MODES = frozenset({3, 7})
"""Text render modes that paint nothing: invisible, and clip-only."""

MIN_POINT_SIZE = 1.0
MARGIN = 2.0
"""Points outside the page box a text origin may sit before it is off the page."""

_SHOW = frozenset({b"Tj", b"TJ", b"'", b'"'})
_GRAY = frozenset({b"g"})
_RGB = frozenset({b"rg", b"sc", b"scn"})
_CMYK = frozenset({b"k"})
_INLINE_IMAGE = b"INLINE IMAGE"
_FILLS = frozenset({b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*"})
_PAINTS = frozenset({b"sh", b"Do", _INLINE_IMAGE})
"""Operators that put something other than text on the page: a shading, an
image or a form. After one, white text may be sitting on something dark."""

FIELDS = {
    "/Contents": "note",
    "/RC": "note",
    "/T": "field",
    "/TU": "field",
    "/V": "field",
    "/DV": "field",
    "/URI": "link",
    "/JS": "javascript",
    "/Title": "title",
    "/Author": "information",
    "/Subject": "information",
    "/Keywords": "information",
    "/Alt": "alternate text",
    "/ActualText": "alternate text",
    "/E": "alternate text",
    "/Desc": "file",
    "/UF": "file",
}
"""Dictionary entries whose text a reader or an extraction tool shows, and
the fixed word each is reported under. The key is the PDF's; the word is
ours, so nothing from the file names a section."""


STREAM_KEYS = frozenset({"/JS", "/RC"})
"""Entries that may hold their text in a stream."""


class TooLargeError(Exception):
    """A cap was reached. The file is refused, not truncated."""


@dataclass
class _Painter:
    """The parts of the graphics state that decide whether text is seen."""

    box: tuple[float, float, float, float]
    mode: int = 0
    white: bool = False
    painted: bool = False
    stack: list[tuple[int, bool]] = field(default_factory=list)
    shown_hidden: bool = False
    shown_visible: bool = False
    images: int = 0
    visible: list[str] = field(default_factory=list)
    hidden: list[str] = field(default_factory=list)
    hidden_chunks: int = 0
    misplaced_chunks: int = 0
    forms: int = 0

    def after(self, operator: Any, *_: Any) -> None:
        """pypdf's ``visitor_operand_after``: a form's content has all been read."""
        if operator == b"Do":
            self.forms -= 1

    def operand(self, operator: Any, operands: Any, *_: Any) -> None:
        """pypdf's ``visitor_operand_before``: track what decides visibility."""
        if operator == b"Do":
            self.forms += 1
        white = _white_fill(operator, operands)
        if white is not None:
            self.white = white
            return
        match operator:
            case b"Tr" if operands:
                self.mode = int(operands[0])
            case b"q":
                self.stack.append((self.mode, self.white))
            case b"Q" if self.stack:
                self.mode, self.white = self.stack.pop()
            case _ if operator in _PAINTS or (operator in _FILLS and not self.white):
                self.images += operator == _INLINE_IMAGE
                self.painted = True
            case _ if operator in _SHOW:
                # White text is unseen only on a page that has painted nothing:
                # on a dark slide or over a figure it is the ordinary way to write.
                unseen = self.mode in INVISIBLE_MODES or (self.white and not self.painted)
                self.shown_hidden = self.shown_hidden or unseen
                self.shown_visible = self.shown_visible or not unseen

    def text(self, chunk: str, cm: Any, tm: Any, *font: Any) -> None:
        """pypdf's ``visitor_text``: one run of text, with the matrices in force
        and ``font`` its dictionary and size.

        A run can hold several show operators. It is hidden when none of
        them painted visibly, or when the whole run is too small or off the
        page; it is COUNTED as hidden when any of them was, so text mixed
        into a visible line is still reported.
        """
        if not chunk.strip():
            (self.hidden if self.hidden and not self.visible else self.visible).append(chunk)
            return
        # Inside a form the matrices are the form's own, not the page's, so
        # size and position are judged only for text drawn on the page itself.
        misplaced = self.forms == 0 and (_tiny(cm, tm, font[1]) or self._off_page(cm, tm))
        unseen = misplaced or (self.shown_hidden and not self.shown_visible)
        if misplaced or self.shown_hidden:
            self.hidden_chunks += 1
            self.misplaced_chunks += misplaced
        (self.hidden if unseen else self.visible).append(chunk)
        self.shown_hidden = self.shown_visible = False

    def is_text_layer(self, pictured: bool) -> bool:
        """Whether this page is a scan with its recognized text laid over it.

        That is how every OCR tool writes a searchable PDF: the page is an
        image and all of its text is invisible. The text is the page's
        content, not something hidden in it, so it is read as the page and
        not counted. It is taken at its word: nothing here checks that the
        layer says what the picture shows (Known gaps, #370).
        """
        only_unseen = bool(self.hidden) and not "".join(self.visible).strip()
        return pictured and only_unseen and not self.misplaced_chunks

    def _off_page(self, cm: Any, tm: Any) -> bool:
        x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
        y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
        left, bottom, right, top = self.box
        return not (left - MARGIN <= x <= right + MARGIN and bottom - MARGIN <= y <= top + MARGIN)


def _white_fill(operator: Any, operands: Any) -> bool | None:
    """Whether a fill-colour operator sets white, or None for any other operator."""
    if operator in _GRAY:
        return _all(operands, 1)
    if operator in _RGB:
        return len(operands) >= 3 and _all(operands, 1)
    if operator in _CMYK:
        return _all(operands, 0)
    return None


def _all(operands: Any, value: float) -> bool:
    try:
        return bool(operands) and all(abs(float(o) - value) < 1e-3 for o in operands)
    except (TypeError, ValueError):
        return False


def _tiny(cm: Any, tm: Any, size: float) -> bool:
    scale = math.sqrt(abs(tm[0] * tm[3] - tm[1] * tm[2]) * abs(cm[0] * cm[3] - cm[1] * cm[2]))
    return abs(float(size)) * scale < MIN_POINT_SIZE


def _has_image(resources: Any, depth: int = 0) -> bool:
    """Whether a page's resources draw an image, directly or inside a form."""
    xobjects = resources.get("/XObject") if isinstance(resources, DictionaryObject) else None
    if not isinstance(xobjects, DictionaryObject) or depth > 4:
        return False
    for ref in xobjects.values():
        xobject = ref.get_object()
        if not isinstance(xobject, DictionaryObject):
            continue
        if xobject.get("/Subtype") == "/Image":
            return True
        if xobject.get("/Subtype") == "/Form" and _has_image(xobject.get("/Resources"), depth + 1):
            return True
    return False


def _text_of(value: Any, *, stream: bool = False) -> str:
    """A dictionary entry as text, or empty when it is not text.

    A stream counts only where the key can hold one (``STREAM_KEYS``):
    ``/Contents`` on a page is its drawing operators, not a note.
    """
    value = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(value, StreamObject):
        return value.get_data().decode("utf-8", "replace") if stream else ""
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return value if isinstance(value, str) and not str(value).startswith("/") else ""


@dataclass
class _Reading:
    reader: PdfReader
    size: int = 0
    out: dict[str, Any] = field(default_factory=dict)

    def spend(self, text: str) -> str:
        self.size += len(text)
        if self.size > MAX_TEXT:
            raise TooLargeError
        return text

    def pages(self) -> None:
        pages: list[list[str]] = []
        hidden = scanned = layers = 0
        if len(self.reader.pages) > MAX_PAGES:
            raise TooLargeError
        for page in self.reader.pages:
            box = tuple(float(v) for v in page.mediabox)
            painter = _Painter((box[0], box[1], box[2], box[3]))
            page.extract_text(
                visitor_operand_before=painter.operand,
                visitor_operand_after=painter.after,
                visitor_text=painter.text,
            )
            pictured = painter.images > 0 or _has_image(page.get("/Resources"))
            layered = painter.is_text_layer(pictured)
            shown, unshown = (painter.hidden, []) if layered else (painter.visible, painter.hidden)
            visible = self.spend("".join(shown).strip())
            unseen = self.spend("".join(unshown).strip())
            hidden += 0 if layered else painter.hidden_chunks
            layers += layered
            if pictured and (layered or not (visible or unseen)):
                # A page that is a picture: its image goes back for OCR (#370).
                scanned += not layered
                self.picture(len(pages) + 1, page)
            pages.append([visible, unseen])
        self.out.update(pages=pages, hidden=hidden, scanned=scanned, text_layers=layers)

    def picture(self, number: int, page: Any) -> None:
        """Hand back the largest image of a page that is a picture, for OCR.

        Up to ``ocr.MAX_IMAGES`` pages and ``ocr.MAX_IMAGE_BYTES`` each: what
        one OCR request reads. A page
        past either, or whose image this cannot decode (JBIG2 needs a decoder
        the image does not carry), sends nothing and stays unread.
        """
        pictures = self.out.setdefault("pictures", [])
        if len(pictures) >= MAX_IMAGES:
            return
        try:
            largest = max((image.data for image in page.images), key=len, default=b"")
        except (PyPdfError, OSError, ValueError, KeyError, NotImplementedError, TypeError):
            return
        if 0 < len(largest) <= MAX_IMAGE_BYTES:
            pictures.append([number, base64.b64encode(largest).decode("ascii")])

    def fields(self) -> None:
        """Every text entry in ``FIELDS``, from every object the file has."""
        # The objects the cross-reference table defines, each with its
        # generation, in a table or an object stream. Asking for one it does
        # not define sends the parser searching the whole file for it.
        defined = {(n, generation) for generation, table in self.reader.xref.items() for n in table}
        defined.update((n, 0) for n in self.reader.xref_objStm)
        if len(defined) > MAX_OBJECTS:
            raise TooLargeError
        found: dict[str, dict[str, None]] = {}
        for number, generation in sorted(defined):
            target = self.reader.get_object(IndirectObject(number, generation, self.reader))
            for entry in _dictionaries(target):
                for key, section in FIELDS.items():  # in declared order: the output is stable
                    text = (
                        _text_of(entry.get(key), stream=key in STREAM_KEYS) if key in entry else ""
                    )
                    if text.strip() and text not in found.setdefault(section, {}):
                        found[section][self.spend(text)] = None
        packet = self.reader.root_object.get("/Metadata")
        if packet is not None:
            found.setdefault("metadata", {})[self.spend(_text_of(packet, stream=True))] = None
        self.out["fields"] = {section: list(texts) for section, texts in found.items()}

    def attachments(self) -> None:
        """Embedded files, base64. One past the byte cap is named with no
        content: the parent counts it unread and still reads the rest."""
        attached: list[list[str | None]] = []
        total = 0
        for name, contents in self.reader.attachments.items():
            for content in contents:
                total += len(content)
                fits = total <= MAX_ATTACHED
                attached.append(
                    [str(name), base64.b64encode(content).decode("ascii") if fits else None]
                )
        self.out["attachments"] = attached


def _dictionaries(target: Any) -> list[DictionaryObject]:
    """``target`` and the dictionaries directly inside it, one level down."""
    if isinstance(target, DictionaryObject):
        inner = [v for v in target.values() if isinstance(v, DictionaryObject)]
        return [target, *inner]
    if isinstance(target, ArrayObject):
        return [v for v in target if isinstance(v, DictionaryObject)]
    return []


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    overwrite_configuration(
        zlib_maximum_output_length=MAX_STREAM_BYTES,
        lzw_maximum_output_length=MAX_STREAM_BYTES,
    )
    reader = PdfReader(io.BytesIO(sys.stdin.buffer.read()))
    if reader.is_encrypted and not reader.decrypt(""):
        json.dump({"encrypted": True}, sys.stdout)
        return 0
    reading = _Reading(reader)
    reading.out["pictures"] = []
    reading.pages()
    reading.fields()
    reading.attachments()
    json.dump(reading.out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
