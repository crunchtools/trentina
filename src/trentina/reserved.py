"""Keys only the gateway may write, and the one place they are stripped (#265).

A marker the gateway attaches — ``_trentina_warning``, ``_trentina_refusal``,
``scan`` — means something only if nothing else can write it. Until #265 a
backend's ``structuredContent`` or an alert's JSON could carry
``_trentina_warning: {"risk_level": "low"}`` and reach the agent looking like
the gateway's verdict, and the router merged into whatever warning was already
there instead of replacing it. A marker that is not authenticated tells the
consumer nothing.

The rule, in two parts, so adding a marker adds it to the strip list:

* any key beginning ``_trentina_``, at ANY depth. New markers take the prefix,
  and are then stripped without anyone remembering to list them.
* ``RESERVED_ROOT_KEYS`` — the gateway's verdict vocabulary without the prefix
  (``scan``, ``l1``), at the ROOT of a document only. That is the only place
  the gateway writes them, and nested ``scan`` is ordinary vocabulary in
  backend data (code-scanning and image-scanning results), so stripping it at
  depth would damage content without closing anything.

Keys are compared after NFKC, dropping format characters (zero-width and
friends) and casefolding, so ``_Trentina_Warning``, or ``_trentina_warning``
with a zero-width space inside it, is the same key to this rule as it is to a
model reading it.

Callers strip BEFORE the defense scan and BEFORE adding their own markers, and
report how many keys they removed as ``reserved_stripped`` in the gateway's
own warning. They log the count, never the key: a key is the sender's string
(#262).

Iterative, like ``jsonwalk``: a depth bomb must not become a RecursionError
mid-strip.
"""

from __future__ import annotations

import copy
import json
import unicodedata
from typing import Any

RESERVED_PREFIX = "_trentina_"
RESERVED_ROOT_KEYS: tuple[str, ...] = ("scan", "l1")

WARNING_KEY = RESERVED_PREFIX + "warning"
REFUSAL_KEY = RESERVED_PREFIX + "refusal"
# A federated peer's pin state, carried in a tools/list ``_meta`` (#592, E1c):
# ``{"held": N}``, the count of tools the peer is withholding in this caller's
# slice. Prefix-reserved, so a backend's own result can never forge it.
PINS_KEY = RESERVED_PREFIX + "pins"

# What the gateway's own warning calls the count.
STRIPPED_FIELD = "reserved_stripped"

WITHHELD_TEXT = "[trentina] withheld: a gateway-reserved key could not be removed"


def is_reserved(key: Any, *, root: bool = False) -> bool:
    """Whether ``key`` is the gateway's to write: anywhere, or also at the root."""
    if not isinstance(key, str):
        return False
    folded = unicodedata.normalize("NFKC", key)
    canonical = "".join(c for c in folded if unicodedata.category(c) != "Cf").casefold().strip()
    return canonical.startswith(RESERVED_PREFIX) or (root and canonical in RESERVED_ROOT_KEYS)


def reserved_sites(payload: Any, *, root_keys: bool = True) -> list[tuple[dict[str, Any], str]]:
    """Every (object, key) pair the rule reserves, without touching ``payload``.

    Root keys are checked only on the top-level object, and not at all when
    ``root_keys`` is false (an MCP content block is a wrapper, not a
    document). A reserved key's value is not searched: it goes whole. A
    caller that does not own ``payload`` asks this first and copies only
    when the answer is not empty.
    """
    sites: list[tuple[dict[str, Any], str]] = []
    stack: list[Any] = [payload]
    root = root_keys
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if is_reserved(key, root=root):
                    sites.append((node, key))
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))
        root = False
    return sites


def strip_reserved(payload: Any, *, root_keys: bool = True) -> int:
    """Remove every reserved key from ``payload`` IN PLACE; return how many."""
    sites = reserved_sites(payload, root_keys=root_keys)
    for node, key in sites:
        del node[key]
    return len(sites)


def strip_reserved_text(text: str) -> tuple[str, int]:
    """The same rule over JSON carried as text; the text unchanged when nothing went.

    Only text that parses as a JSON object or array is touched, and it is
    re-serialized only when a key was removed, so clean text stays
    byte-identical. A document that cannot be written back is withheld
    rather than delivered with the forged key still in it.
    """
    if not text.lstrip().startswith(("{", "[")):
        return text, 0
    try:
        parsed = json.loads(text)
    except RecursionError:
        # JSON too deep for us to walk may not be too deep for the agent's
        # parser, so a key in it cannot be ruled out: withheld, not passed.
        return WITHHELD_TEXT, 1
    except ValueError:
        return text, 0
    count = strip_reserved(parsed)
    if not count:
        return text, 0
    try:
        return json.dumps(parsed, ensure_ascii=False), count
    except (ValueError, RecursionError):
        return WITHHELD_TEXT, count


def strip_content_blocks(blocks: list[Any] | None) -> tuple[list[Any], int]:
    """Strip MCP content blocks: each block's keys, and JSON inside ``text``.

    A block is itself a JSON object, so the prefix rule applies to its keys
    and to everything nested in it (a resource, ``_meta``, annotations). A
    text block's or a text resource's ``text`` is parsed when it is JSON.
    """
    if not blocks:
        return list(blocks or []), 0
    count = 0
    out: list[Any] = []
    for block in blocks:
        if not isinstance(block, dict):
            out.append(block)
            continue
        texts = {}
        for name, holder in (("block", block), ("resource", block.get("resource"))):
            if isinstance(holder, dict) and isinstance(holder.get("text"), str):
                text, n = strip_reserved_text(holder["text"])
                if n:
                    texts[name] = text
                    count += n
        if not texts and not reserved_sites(block, root_keys=False):
            # Copy-on-write: a clean block is passed on as it came.
            out.append(block)
            continue
        copied = copy.deepcopy(block)
        count += strip_reserved(copied, root_keys=False)
        if "block" in texts:
            copied["text"] = texts["block"]
        if "resource" in texts:
            copied["resource"]["text"] = texts["resource"]
        out.append(copied)
    return out, count


def with_stripped(warning: dict[str, Any] | None, count: int) -> dict[str, Any] | None:
    """The gateway's warning, with the count added when anything was stripped."""
    if not count:
        return warning
    return {**(warning or {}), STRIPPED_FIELD: count}
