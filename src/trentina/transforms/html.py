"""HTML — conversion to Markdown, which ELIMINATES an attack class.

Tier 1 of the two-tier answer in ``l1/hidden.py``. This processor is not a
detector that happens to shrink things; it removes the vocabulary that can
express hidden content. Markdown has no ``style`` attribute, no
``display:none``, no ``position:absolute``, no foreground/background pair.
After conversion the category is ABSENT, not mitigated, and there is nothing
left for a detector to find.

That is the whole argument for keeping it in the default chain rather than
treating it as an optional nicety, and the reason a profile that considers
HTML hostile enough can pin it as required rather than agent-selectable.

Lived in ``l1/html.py`` behind a ``looks_like_html`` sniffer until 0.28.0.
The sniffer was the bug: it matched a leading ``<!DOCTYPE`` or ``<html>``, so
an HTML fragment took the text path and was neither converted nor checked.
There is no sniffer here. This processor tries to parse, and DECLINES when
there is nothing to convert — the same shape ``structured.py`` uses with its
bracket gate and ``not_json`` decline. It can therefore sit in the default
chain permanently and no-op on everything that is not markup, which is what
replaces the dispatch rather than relocating it.

COMPOSITION. This is the first processor here that TRANSFORMS without
existing to shrink, the case ``compose.py`` documents as deliberate: it
survives under ``chain`` and under ``auto`` (it is FREE), and loses under
``best_of`` to anything that shrank more. Conversion nearly always does
shrink, since tags outweigh their text, but that is incidental and this
module does not self-decline on size the way the reducers do. Configure it
with ``chain``.

WHAT IT DELETES it deletes, which is invariant 1's permitted direction: a
hidden element's bytes are removed and reach nobody. The counts go to the
sidecar as telemetry and are deliberately NOT load-bearing — if this
processor never runs, ``l1/hidden.py`` still counts the fingerprints on the
raw bytes, which is what keeps the risk score honest without a wire from
outside the perimeter into ``PipelineStats``.

Hostile input is bounded by ``_MAX_PARSE_BYTES``, and the parse runs on a
worker thread: BeautifulSoup is synchronous and a large document must not
stall the gateway's event loop.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field

from bs4 import BeautifulSoup, Comment, Tag
from markdownify import markdownify

from ..channels import Channel, Kind
from ..l1.hidden import ClassRules, class_declarations, class_style, classify_style
from .base import Applied, Cost, Declined, Failed, TransformContext, TransformResult

# Past this, do not even parse. Matches structured.py: the converter refuses
# to be the expensive step.
_MAX_PARSE_BYTES = 4_000_000

_STRIP_TAGS = ("script", "style", "noscript", "meta", "link")


@dataclass
class ConversionStats:
    """What the conversion removed on its way to Markdown.

    The first three are the hiding fingerprints, kept here for the sidecar so
    an operator can see that conversion did its job. ``l1/hidden.py`` owns the
    same three for RISK purposes and counts them independently, so these are
    reporting rather than enforcement.

    The rest is tag hygiene — expected on any web page, never suspicious, and
    never part of the risk score even when it lived in ``HtmlStats``.

    ``template_tags`` counts the `<template>` elements removed, nested ones
    included. A browser never renders one, so its text is hidden content and
    its `<style>` blocks apply to nothing (#179).
    """

    hidden_elements: int = field(default=0)
    off_screen_elements: int = field(default=0)
    same_color_text: int = field(default=0)
    script_tags: int = field(default=0)
    style_tags: int = field(default=0)
    noscript_tags: int = field(default=0)
    meta_tags: int = field(default=0)
    html_comments: int = field(default=0)
    template_tags: int = field(default=0)


# The concepts `l1.hidden.classify_style` reports, mapped to this module's
# more descriptive field names. One precedence table, two audiences.
_CONCEPT_FIELD = {
    "hidden": "hidden_elements",
    "off_screen": "off_screen_elements",
    "same_color": "same_color_text",
}


def _classify_and_remove(
    soup: BeautifulSoup,
    declarations: ClassRules,
    stats: ConversionStats,
) -> None:
    """Remove elements hidden from a human reader, counting what went.

    The predicates come from ``l1/hidden.py`` so that what is STRIPPED here
    and what is COUNTED there are one rule with one precedence order. An
    element's style is its inline style and its classes' `<style>`-block
    declarations together, so hiding by class is caught like hiding
    inline (#179). Both are read, neither overrides: see
    ``class_declarations`` for why this errs toward hidden.
    """
    for tag in list(soup.find_all(True)):
        if not isinstance(tag, Tag) or tag.attrs is None:
            continue

        inline = tag.get("style", "")
        style = "; ".join(
            part
            for part in (
                inline.lower() if isinstance(inline, str) else "",
                class_style(tag.get("class") or [], declarations),
            )
            if part
        )
        concept = classify_style(style) if style else None
        field_name = _CONCEPT_FIELD[concept] if concept else None
        if field_name is None and tag.get("hidden") is not None:
            field_name = "hidden_elements"

        if field_name is not None:
            setattr(stats, field_name, getattr(stats, field_name) + 1)
            tag.decompose()


def _strip_dangerous_tags(soup: BeautifulSoup, stats: ConversionStats) -> None:
    """Remove script, style, noscript, meta and link tags."""
    for tag_name in _STRIP_TAGS:
        found = soup.find_all(tag_name)
        match tag_name:
            case "script":
                stats.script_tags = len(found)
            case "style":
                stats.style_tags = len(found)
            case "noscript":
                stats.noscript_tags = len(found)
            case "meta" | "link":
                stats.meta_tags += len(found)
        for tag in found:
            tag.decompose()


def to_markdown(html_content: str) -> tuple[str, ConversionStats]:
    """Parse HTML, strip what a human never sees, convert to Markdown."""
    stats = ConversionStats()
    soup = BeautifulSoup(html_content, "html.parser")

    # A `<template>` is never rendered, text or styles, so it goes first. The
    # class rules then come from the parsed `<style>` nodes that remain, not
    # the raw text, so a block inside an HTML comment stays inert too. Read
    # before `_strip_dangerous_tags` deletes them.
    templates = soup.find_all("template")
    stats.template_tags = len(templates)
    for template in templates:
        template.decompose()
    styles = "".join(str(tag) for tag in soup.find_all("style"))
    _classify_and_remove(soup, class_declarations(styles), stats)
    _strip_dangerous_tags(soup, stats)

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    stats.html_comments = len(comments)
    for comment in comments:
        comment.extract()

    markdown: str = markdownify(str(soup), heading_style="ATX", strip=["img"])
    return markdown, stats


def _convert(payload: str) -> tuple[str, ConversionStats] | None:
    """Convert, or None when there is no markup to convert.

    No try/except around the parse. A parse that raises is an operational
    FAILURE, not a shape decline: ``compose.py`` catches it into ``Failed``
    (logged, named) and the internal floor raises ``TransformFailedError``, so
    a required converter fails closed. This function's only non-raising outcome
    besides success is "there was nothing to convert", which is a shape decline
    — so it returns None here and the caller spells that ``Declined`` itself,
    never a reclassifiable reason string.
    """
    soup = BeautifulSoup(payload, "html.parser")

    # The gate that replaces the sniffer. No decision about whether this "is
    # HTML" — only whether there is any markup to convert. Text that merely
    # mentions `<` in prose yields no tags and is handed back untouched.
    if not soup.find(True):
        return None

    return to_markdown(payload)


class HtmlProcessor:
    """FREE. Converts markup to Markdown, deleting what a human never sees."""

    name = "html"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, _ctx: TransformContext) -> TransformResult:
        # Conversion is driven by the payload's shape; it reads no job context.
        if len(payload.encode("utf-8")) > _MAX_PARSE_BYTES:
            # A required converter cannot excuse itself on size: padding a
            # payload past the parse cap must not be a way around it. Failed,
            # so a floor refuses rather than delivers the unconverted markup.
            return Failed("too_large")

        # Cheap gate before spending a parse: markup contains a tag open.
        if "<" not in payload:
            return Declined("not_markup")

        converted = await asyncio.to_thread(_convert, payload)
        if converted is None:
            return Declined("not_markup")

        text, stats = converted
        return Applied(text, asdict(stats))
