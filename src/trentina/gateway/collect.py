"""Pulling judgeable text out of an MCP tool result.

The perimeter judges one document; these helpers build it from a tool result's
content blocks and ``structuredContent``. Text blocks and resource text join
directly; image blocks and resource blobs are set aside and read together
(``unpack.scan.read_blobs``), so the images of one response share one OCR
request. Keys are walked as well as values, because a model reads
``{"IGNORE ALL PREVIOUS INSTRUCTIONS": true}`` exactly like a value and keys
used to be a scan-free channel. The walk is iterative: a few KB of ``[[[[…``
nesting is an attacker-supplied ``RecursionError``.

``_unread_warning`` records the ``binary_unread`` gap for blocks no layer could
read; the proxied-response edge and the tool-list edge import what they need
from here.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from ..l1.hidden import HiddenStats
from ..unpack.child import run_unpacking
from ..unpack.scan import IMAGE_BLOCK, UNDECODABLE, image_too_small_to_draw, read_blobs


def _collect_strings(value: Any, out: list[str]) -> None:
    """Iterative walk over keys AND values.

    Iterative because a few KB of "[[[[..." nesting is an attacker-supplied
    RecursionError; keys because a model reads {"IGNORE ALL PREVIOUS
    INSTRUCTIONS": true} exactly like a value, and keys used to be a
    scan-free channel.
    """
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if node:
                out.append(node)
        elif isinstance(node, dict):
            for k, v in reversed(list(node.items())):
                stack.append(v)
                stack.append(k)
        elif isinstance(node, list):
            stack.extend(reversed(node))


@dataclass
class _Collected:
    """What one MCP tool result holds, as the layers will read it.

    ``texts`` is in block order. An image block or a resource blob leaves a
    None there and joins ``pending``; once every block has been walked they
    are read together (``unpack.scan.read_blobs``), so the images of one
    response share one OCR request.
    """

    texts: list[str | None] = dataclass_field(default_factory=list)
    pending: list[tuple[int, str, str]] = dataclass_field(
        default_factory=list
    )  # (slot, blob, unread kind)
    unscannable: dict[str, int] = dataclass_field(default_factory=lambda: {"images": 0, "blobs": 0})
    unread: set[str] = dataclass_field(default_factory=set)
    hidden: int = 0

    def later(self, blob: object, kind: str) -> None:
        """Queue a base64 payload to be read with the others; ``kind`` is
        what it is counted as if it turns out not to be base64 at all."""
        if isinstance(blob, str):
            self.pending.append((len(self.texts), blob, kind))
            self.texts.append(None)
        else:
            self.unread.add(kind)

    def read_pending(self) -> None:
        views = read_blobs([blob for _, blob, _ in self.pending])
        for (slot, _, kind), view in zip(self.pending, views, strict=True):
            if view is None:
                self.unread.add(kind)
                continue
            self.texts[slot] = view.text
            self.unread.update(view.unread)
            self.hidden += view.hidden


def _collect_response_texts(
    content_blocks: list[Any] | None,
    structured_content: Any,
) -> tuple[list[str], dict[str, int], set[str], int]:
    """Pull every judgeable string out of an MCP tool result.

    Returns the texts; a count of the blocks that are not text (image blocks
    and resource blobs); the kinds among those an agent's tools could open
    and no layer read (#367), which are the ``binary_unread`` gap; and how
    much text inside them was hidden from a reader (#368 to #370). An image
    is read by OCR, a blob like one token of the unpack stage: to its text,
    to what is inside it, or to its label.
    """
    found = _Collected()
    for block in content_blocks or []:
        if isinstance(block, dict):
            _collect_block(block, found)
    found.read_pending()
    texts = [text for text in found.texts if text]
    if structured_content is not None:
        _collect_strings(structured_content, texts)
    return texts, found.unscannable, found.unread, found.hidden


def _collect_block(block: dict[str, Any], found: _Collected) -> None:
    btype = block.get("type")
    if btype == "text":
        text = block.get("text")
        if isinstance(text, str) and text:
            found.texts.append(text)
    elif btype == "image":
        found.unscannable["images"] += 1
        image = block.get("data")
        if isinstance(image, str) and image_too_small_to_draw(image):
            found.texts.append(f"({IMAGE_BLOCK.name}, too small to draw text)")
        else:
            found.later(image, IMAGE_BLOCK.name)
    elif btype == "resource" and isinstance(block.get("resource"), dict):
        resource = block["resource"]
        rtext = resource.get("text")
        if isinstance(rtext, str) and rtext:
            found.texts.append(rtext)
        if resource.get("blob") is not None:  # a resource may carry both, and each is read
            found.unscannable["blobs"] += 1
            found.later(resource["blob"], UNDECODABLE.name)


async def _read_response(
    content_blocks: list[Any] | None, structured_content: Any, hidden: HiddenStats | None
) -> tuple[list[str], dict[str, int], set[str], HiddenStats | None]:
    """The response's texts, what in it is not text or not read, and its hiding.

    Text hidden inside an image, an office file or a PDF that arrived as a
    block is added to the hiding stage 1 found, for L1 to report.
    """
    # Decoding blobs is linear in their size; off the loop, like L1 (#295).
    texts, unscannable, unread, inside = await run_unpacking(
        _collect_response_texts, content_blocks, structured_content
    )
    if inside:
        hidden = (hidden or HiddenStats()) + HiddenStats(elements=inside)
    return texts, unscannable, unread, hidden


def _unread_warning(warning: dict[str, Any] | None, unread: set[str]) -> dict[str, Any]:
    """``warning`` with the ``binary_unread`` gap for blocks no layer read."""
    kinds = sorted(unread | set((warning or {}).get("unread_kinds", ())))
    return {**(warning or {}), "binary_unread": True, "unread_kinds": kinds}
