"""Small PDF files built in memory with pypdf, for the unpack tests.

A page is its content stream: the operators are written out by the test, so
what is invisible is invisible because of a named operator (``3 Tr``,
``1 1 1 rg``) and not because of a tool's choices.
"""

from __future__ import annotations

import io

from pypdf import PdfWriter
from pypdf.actions import JavaScript
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

LETTER = (612, 792)
FORM_BOX = (0, 0, 6000, 6000)
"""A form's own coordinate space: far larger than the page it is drawn on."""
NOTE_BOX = (72, 600, 172, 620)
"""Where an annotation sits on the page: left, bottom, right, top."""


def show(text: str, x: float = 72, y: float = 700, size: float = 12, before: str = "") -> str:
    """One line of text at ``(x, y)``. ``before`` is operators inside ``BT``."""
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return f"BT /F1 {size} Tf {before} 1 0 0 1 {x} {y} Tm ({safe}) Tj ET\n"


def _stream(data: bytes, **entries: object) -> DecodedStreamObject:
    stream = DecodedStreamObject()
    stream.set_data(data)
    stream.update({NameObject(f"/{key}"): value for key, value in entries.items()})
    return stream


def _resources(writer: PdfWriter, font_ref: object, *, image: bool, form: str) -> DictionaryObject:
    fonts = DictionaryObject({NameObject("/F1"): font_ref})
    resources = DictionaryObject({NameObject("/Font"): fonts})
    xobjects = DictionaryObject()
    if image:
        pixel = _stream(
            b"\x00",
            Type=NameObject("/XObject"),
            Subtype=NameObject("/Image"),
            Width=NumberObject(1),
            Height=NumberObject(1),
            ColorSpace=NameObject("/DeviceGray"),
            BitsPerComponent=NumberObject(8),
        )
        xobjects[NameObject("/Im1")] = writer._add_object(pixel)
    if form:
        xform = _stream(
            form.encode("latin-1"),
            Type=NameObject("/XObject"),
            Subtype=NameObject("/Form"),
            BBox=ArrayObject([FloatObject(v) for v in FORM_BOX]),
            Resources=DictionaryObject({NameObject("/Font"): fonts}),
        )
        xobjects[NameObject("/Fm1")] = writer._add_object(xform)
    if xobjects:
        resources[NameObject("/XObject")] = xobjects
    return resources


def _annotation(fields: dict[str, str]) -> DictionaryObject:
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link" if "URI" in fields else "/Text"),
            NameObject("/Rect"): ArrayObject([FloatObject(v) for v in NOTE_BOX]),
        }
    )
    for key, value in fields.items():
        if key == "URI":
            action = {
                NameObject("/S"): NameObject("/URI"),
                NameObject("/URI"): TextStringObject(value),
            }
            annotation[NameObject("/A")] = DictionaryObject(action)
        else:
            annotation[NameObject(f"/{key}")] = TextStringObject(value)
    return annotation


def pdf(
    *pages: str,
    info: dict[str, str] | None = None,
    annotations: list[dict[str, str]] | None = None,
    attachments: dict[str, bytes] | None = None,
    javascript: str = "",
    image: bool = False,
    form: str = "",
) -> bytes:
    """A PDF with one page per content stream in ``pages``.

    ``annotations`` go on the first page, each a dict of text entries
    (``Contents``, ``T``, ``URI``). ``image`` adds a 1 by 1 image XObject to
    every page's resources and draws it. ``form`` is the content stream of a
    form XObject, drawn on every page shrunk to a tenth of its size.
    """
    writer = PdfWriter()
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    font_ref = writer._add_object(font)
    drawn_image = "q 200 0 0 200 72 300 cm /Im1 Do Q\n" if image else ""
    drawn_form = "q 0.1 0 0 0.1 72 400 cm /Fm1 Do Q\n" if form else ""
    for content in pages:
        page = writer.add_blank_page(*LETTER)
        page[NameObject("/Resources")] = _resources(writer, font_ref, image=image, form=form)
        drawing = (content + drawn_image + drawn_form).encode("latin-1")
        page[NameObject("/Contents")] = writer._add_object(_stream(drawing))
    if annotations:
        refs = ArrayObject(writer._add_object(_annotation(fields)) for fields in annotations)
        writer.pages[0][NameObject("/Annots")] = refs
    if info:
        writer.add_metadata({f"/{key}": value for key, value in info.items()})
    for name, content in (attachments or {}).items():
        writer.add_attachment(name, content)
    if javascript:
        writer.add_open_action(JavaScript(javascript))
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()
