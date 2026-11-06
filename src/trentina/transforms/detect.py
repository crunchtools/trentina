"""Detect — look at the payload, then run the minifiers that fit it (0.38.0).

The default transform. Before 0.38.0 a profile listed a chain and every
processor in it tried every payload, each declining what was not its shape.
That works for the reducers, whose declines are cheap and exact. It does not
work for ``html``: its gate is "is there any markup at all", and on text that
merely contains angle brackets it is destructive. Measured before this module
existed, it deleted ``<alice@example.com>`` from a mail header, turned
``Vec<String>`` into ``Vec``, stripped wikitext ``<ref>`` and corrupted JSON
by writing newlines into string values. A converter that is always in the
chain has to be told when to run.

So detection happens once, here, and it is strict in the direction that
deletes nothing:

* **HTML** only when the server SAID so (``TransformContext.content_type``)
  or the text is unmistakably a document: a leading doctype or ``<html>``, or
  at least ``_MIN_TAGS`` real tags, one of them structural, and NOT ONE tag
  name that HTML does not define. ``<alice``, ``<String``, ``<ref`` are
  unknown names, so one of them is enough to leave the payload alone. Missing
  a real page costs tokens; mistaking text for a page costs the agent content.
* **JSON** when it is bracketed at both ends. ``structured`` collapses
  repeated elements and re-serializes compactly; it is the one parse, and
  when it says ``not_json`` the payload takes the text path instead.
* **Everything else** goes through ``email`` then ``petit``. Both already
  decline what is not their shape (``email._looks_like_mail``, petit's record
  framing and its own format detection), so asking petit to name the format
  first would parse the payload twice to learn nothing.

HTML is followed by ``petit`` too: a converted page is text, and a listing
page is exactly the repetition petit collapses.

The chain's results are merged into ONE result named ``detect``. ``format``
says which path ran and ``chain`` which processors applied, so a reader of
the sidecar can tell "detected JSON, nothing to collapse" from "detected
text". A processor that FAILED (``base.Failed``) makes the whole result
``Failed`` with its reason, so a profile that pins ``detect`` as ``required``
refuses rather than delivers half a transformation.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

from ..channels import Channel, Kind
from .base import (
    Applied,
    Cost,
    Declined,
    Failed,
    Transform,
    TransformContext,
    TransformRecord,
    TransformResult,
)
from .email import EmailProcessor
from .html import HtmlProcessor
from .pdf import PDF_BASE64_PREFIX, PdfProcessor, is_pdf_type
from .petit import PetitProcessor
from .structured import StructuredProcessor

if TYPE_CHECKING:
    from collections.abc import Sequence

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})

# How much of the payload the HTML sniff reads. A page declares itself early;
# a hostile payload must not buy a scan of megabytes.
_SNIFF_CHARS = 65_536

_PDF_SNIFF = 64
_MIN_TAGS = 3

# A tag name right after `<` or `</`, and the character after it. Linear: one
# bounded character class. A name counts as HTML only when that character
# ends a tag name, so `<p.x>` and a 40-letter `<a...` are not markup.
_TAG = re.compile(r"</?([A-Za-z][A-Za-z0-9-]{0,31})(.?)", re.S)
_NAME_END = frozenset(" \t\r\n/>")

# fmt: off
_STRUCTURAL = frozenset((
    "a", "article", "body", "div", "h1", "h2", "h3", "h4", "h5", "h6", "head",
    "li", "main", "nav", "ol", "p", "section", "span", "table", "td", "th",
    "tr", "ul",
))
# Every element name in the HTML Living Standard, a few retired ones pages
# still use, and the SVG/MathML roots. A name outside this set means the
# angle brackets are not markup.
_HTML_TAGS = _STRUCTURAL | frozenset((
    "abbr", "address", "area", "aside", "audio", "b", "base", "bdi", "bdo",
    "big", "blockquote", "br", "button", "canvas", "caption", "center", "cite",
    "code", "col", "colgroup", "data", "datalist", "dd", "del", "details",
    "dfn", "dialog", "dl", "dt", "em", "embed", "fieldset", "figcaption",
    "figure", "font", "footer", "form", "header", "hgroup", "hr", "html", "i",
    "iframe", "img", "input", "ins", "kbd", "label", "legend", "link", "map",
    "mark", "math", "menu", "meta", "meter", "noscript", "object", "optgroup",
    "option", "output", "param", "picture", "pre", "progress", "q", "rp", "rt",
    "ruby", "s", "samp", "script", "search", "select", "slot", "small",
    "source", "strike", "strong", "style", "sub", "summary", "sup", "svg",
    "tbody", "template", "textarea", "tfoot", "thead", "time", "title",
    "track", "tt", "u", "var", "video", "wbr",
))
# fmt: on


class Format(str, Enum):
    """What the payload was taken to be."""

    HTML = "html"
    JSON = "json"
    PDF = "pdf"
    TEXT = "text"


def is_html_type(content_type: str | None) -> bool:
    """The declared type, never a sniff of the bytes."""
    return (content_type or "").split(";", 1)[0].strip().lower() in _HTML_TYPES


def _starts_as_document(head: str) -> bool:
    """A leading doctype or ``<html>``, after any comments. Linear: find, not a regex."""
    pos = 0
    while True:
        while pos < len(head) and head[pos].isspace():
            pos += 1
        if not head.startswith("<!--", pos):
            break
        end = head.find("-->", pos + 4)
        if end < 0:
            return False
        pos = end + 3
    start = head[pos : pos + 15].lower()
    return start.startswith("<!doctype html") or bool(re.match(r"<html[\s>]", start))


def _looks_like_html(text: str) -> bool:
    head = text[:_SNIFF_CHARS]
    if _starts_as_document(head):
        return True
    tags = _TAG.findall(head)
    names = {name.lower() for name, _ in tags}
    if any(end not in _NAME_END for _, end in tags):
        return False
    if not names or not names <= _HTML_TAGS or not names & _STRUCTURAL:
        return False
    return len(tags) >= _MIN_TAGS


def _is_one_pdf(text: str) -> bool:
    """One base64 token that opens as a PDF: a tool that returned the file itself."""
    head = text[:_PDF_SNIFF].lstrip()
    return head.startswith(PDF_BASE64_PREFIX) and not any(c.isspace() for c in text.strip())


def _is_json(text: str) -> bool:
    """Bracketed at both ends. ``structured`` parses it once and says if it was wrong."""
    stripped = text.strip()
    return bool(stripped) and (stripped[0], stripped[-1]) in {("{", "}"), ("[", "]")}


def detect(text: str, content_type: str | None = None) -> Format:
    """Which path a payload takes. Declared HTML wins; the sniff is strict."""
    if is_html_type(content_type):
        return Format.HTML
    if is_pdf_type(content_type) or _is_one_pdf(text):
        return Format.PDF
    if _is_json(text):
        return Format.JSON
    if _looks_like_html(text):
        return Format.HTML
    return Format.TEXT


_CHAINS: dict[Format, tuple[Transform, ...]] = {
    Format.HTML: (HtmlProcessor(), PetitProcessor()),
    Format.JSON: (StructuredProcessor(),),
    Format.PDF: (PdfProcessor(),),
    Format.TEXT: (EmailProcessor(), PetitProcessor()),
}


async def _run_chain(fmt: Format, payload: str, ctx: TransformContext) -> list[TransformRecord]:
    """The format's processors, each fed the last applied output. Every result
    is kept, paired with the processor that produced it."""
    records: list[TransformRecord] = []
    current = payload
    for processor in _CHAINS[fmt]:
        result = await processor.run(current, ctx)
        records.append(TransformRecord.of(processor.name, processor.cost, current, result))
        if isinstance(result, Applied):
            current = result.content
    return records


class DetectProcessor(Transform):
    """FREE. Picks the minifiers for the payload's format and runs them."""

    name = "detect"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, ctx: TransformContext) -> TransformResult:
        fmt = detect(payload, ctx.content_type)
        records = await _run_chain(fmt, payload, ctx)
        first = records[0].result
        if fmt is Format.JSON and isinstance(first, Declined) and first.reason == "not_json":
            fmt = Format.TEXT
            records = await _run_chain(fmt, payload, ctx)
        for record in records:
            # A sub-processor that FAILED makes the whole detection fail with
            # its reason, so a profile that pins ``detect`` as required refuses
            # rather than delivering half a transformation.
            if isinstance(record.result, Failed):
                return Failed(record.result.reason, {"format": fmt.value, "failed": record.name})
        content: str | None = None
        details: dict[str, int | float | str] = {}
        chain: list[str] = []
        for record in records:
            if isinstance(record.result, Applied):
                content = record.result.content
                details.update(record.result.details)
                chain.append(record.name)
        if content is None:
            return Declined("nothing_to_minify", {"format": fmt.value})
        details["format"] = fmt.value
        details["chain"] = ",".join(chain)
        return Applied(content, details)


_HIDING_DETAILS = (
    "hidden_elements",
    "off_screen_elements",
    "same_color_text",
    "template_tags",
    "office_hidden",
    "pdf_hidden",
)
_CONVERTED_DETAILS = ("office_converted", "pdf_converted")


def _converted(result: TransformRecord) -> bool:
    """Whether a result deleted markup or converted an office file or a PDF
    (#368, #369), directly or inside ``detect``."""
    if not result.applied:
        return False
    if any(int(result.details.get(key, 0)) for key in _CONVERTED_DETAILS):
        return True
    return result.name == "html" or "html" in str(result.details.get("chain", "")).split(",")


def hiding_removed(results: Sequence[TransformRecord]) -> int | None:
    """Elements hidden from a human reader that conversion deleted.

    None when nothing was converted, which is different from zero: the
    caller recounts the ORIGINAL's hiding for L1 only when conversion ran.
    """
    converted = [r for r in results if _converted(r)]
    if not converted:
        return None
    return sum(int(r.details.get(k, 0)) for r in converted for k in _HIDING_DETAILS)


def document_hidden(results: Sequence[TransformRecord]) -> int:
    """Hidden text that converting an office file or a PDF dropped (#368, #369).

    ``detect_hidden_markup`` cannot recount these from the original, which is
    a base64 token, so the count stage 1 took is what L1 is handed.
    """
    return sum(
        int(r.details.get(key, 0))
        for r in results
        if r.applied
        for key in ("office_hidden", "pdf_hidden")
    )


def hiding_briefing(removed: int) -> str | None:
    """What L3 is told when conversion deleted hidden elements, or None."""
    if not removed:
        return None
    return (
        f"This content was converted from HTML, an office file or a PDF to Markdown before "
        f"judging, and "
        f"the conversion removed {removed} element(s) hidden from a human "
        f"reader, so you are not reading all of the original. Hiding text is "
        f"a common way to address an agent without the reader noticing."
    )
