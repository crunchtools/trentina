"""PDF — FREE conversion of a PDF to the text a reader sees (#369).

A PDF is a reducer format, as HTML is: an agent that fetched a paper wants
its text, and the file itself is megabytes of base64 it cannot use. This
processor turns a PDF into Markdown and drops what the page does not show,
counting it for L1 as ``html.py`` counts hidden elements.

The payload is the PDF as canonical base64: ``client.fetch_url`` hands a
fetched PDF over that way, and a PDF inside a JSON string arrives that way
(``structured.py`` calls ``reduce_base64`` per field). Parsing happens in a
child process (``unpack/pdf.py``); a PDF it cannot read is declined, and
goes on as it arrived for the unpack stage to count as unread.

What is delivered:

* each page's visible text, pages separated by a blank line;
* the links its annotations point to;
* a line for what was left out and why: pages that are images with no
  text, and embedded files. Neither is silently missing.

``trentina_preprocess: false`` delivers the file, and the unpack stage then
reads all of it, invisible text and embedded files included.
"""

from __future__ import annotations

import base64
import binascii

from ..channels import Channel, Kind
from ..unpack.child import run_unpacking
from ..unpack.pdf import PdfReading, read_pdf
from .base import Cost, TransformContext, TransformResult

PDF_BASE64_PREFIX = "JVBERi0"
"""How canonical base64 of ``%PDF-`` always starts."""

PDF_TYPE = "application/pdf"

MAX_PDF_CHARS = 7_000_000
"""Base64 characters of a PDF this will open: the fetch cap of 5 MB, encoded."""


def is_pdf_type(content_type: str | None) -> bool:
    """The declared type, never a sniff of the bytes."""
    return (content_type or "").split(";", 1)[0].strip().lower() == PDF_TYPE


def markdown_of(reading: PdfReading) -> str:
    """What stage 1 delivers for a PDF that was read."""
    parts = [reading.markdown()]
    links = reading.fields.get("link")
    if links:
        parts.append("Links:\n" + "\n".join(f"- {link}" for link in links))
    if reading.scanned:
        parts.append(
            f"[{reading.scanned} page(s) of this PDF are images with no text and were not read.]"
        )
    if reading.attachments:
        parts.append(f"[{len(reading.attachments)} file(s) embedded in this PDF are not included.]")
    return "\n\n".join(part for part in parts if part)


def reduce_base64(token: str) -> tuple[str, int] | None:
    """A base64 PDF as ``(Markdown, hidden runs dropped)``, or None to decline.

    Declines anything that is not canonical base64 of a PDF, is over the
    size cap, could not be read, or has nothing to deliver.
    """
    if not token.startswith(PDF_BASE64_PREFIX) or len(token) > MAX_PDF_CHARS or len(token) % 4:
        return None
    try:
        packed = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    reading = read_pdf(packed)
    if reading is None:
        return None
    markdown = markdown_of(reading)
    return (markdown, reading.hidden) if markdown else None


class PdfProcessor:
    """FREE. Converts a base64 PDF to the text its pages show."""

    name = "pdf"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, _ctx: TransformContext) -> TransformResult:
        # Driven by the payload's shape, like html.py: it reads no job context.
        token = payload.strip()
        if not token.startswith(PDF_BASE64_PREFIX):
            return TransformResult.declined(self.name, self.cost, payload, reason="not_pdf")
        reduced = await run_unpacking(reduce_base64, token)
        if reduced is None:
            return TransformResult.declined(self.name, self.cost, payload, reason="unreadable_pdf")
        markdown, hidden = reduced
        return TransformResult(
            name=self.name,
            cost=self.cost,
            content=markdown,
            applied=True,
            bytes_in=len(payload.encode("utf-8")),
            bytes_out=len(markdown.encode("utf-8")),
            details={"pdf_converted": 1, "pdf_hidden": hidden},
        )
