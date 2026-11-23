"""A completion's provider-ciphertext fields, verified and kept from the layers (a1013).

A provider's encrypted reasoning and signatures are ciphertext only the
provider can read. Asked to excuse those fields and also to read them as
content when they are not ciphertext, gemini-2.5-flash-lite did neither
well: it flagged one benign completion in eight and still excused decoded
attacks planted in ``signature``. Whether a value is ciphertext is not a
judgement, so it is decided here, and a field that is ciphertext is not sent
to the layers at all: it costs L3 tokens on every completion and there is
nothing in it to judge.

A provider's ciphertext is one base64 token, dotted parts allowed, that
decodes to nothing a layer can read. Such a value is replaced by a
placeholder before L1, L2 or L3 read the body. An excused field holding
anything else (words, a ROT13 or other cipher L3 would have to read, base64
or gzip that the unpack stage turns into text, an archive or an image) is
not ciphertext: it stays in the body for the layers and the completion is
flagged.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from ..unpack.child import run_unpacking
from ..unpack.scan import unpack

if TYPE_CHECKING:
    from collections.abc import Callable

CIPHERTEXT_TYPES = frozenset({"reasoning.encrypted", "redacted_thinking"})
"""Entry types whose ``data`` is the provider's ciphertext: OpenRouter's and
OpenAI's encrypted reasoning, and Anthropic's redacted thinking."""

SIGNATURE = "signature"
DATA = "data"

_TOKEN = re.compile(r"[A-Za-z0-9+/=_.-]+")
"""One base64 or base64url token, or several joined by dots as OpenAI's
encrypted reasoning is (``gAAAAAB…``, its parts each padded): what
every provider's ciphertext is. No space, quote or other punctuation."""


def placeholder(field: str, value: str) -> str:
    """What the layers read in place of a verified ciphertext ``value``."""
    return f"[provider ciphertext: {field}, {len(value.encode())} bytes, verified]"


def _documents(body: str) -> list[tuple[int, Any]]:
    """Each JSON document in ``body``, with the index of the line it is on
    (``-1`` for a body that is one JSON document).

    ``body`` is a JSON response, or an event stream whose ``data:`` lines are
    JSON; anything else (a stream's ``[DONE]``, a cut-off body) has no
    envelope and yields nothing.
    """
    if body.lstrip().startswith(("{", "[")):
        texts = [(-1, body)]
    else:
        texts = [
            (i, line.removeprefix("data:"))
            for i, line in enumerate(body.splitlines())
            if line.startswith("data:")
        ]
    documents: list[tuple[int, Any]] = []
    for index, text in texts:
        try:
            documents.append((index, json.loads(text)))
        except ValueError:
            continue
    return documents


def _excused(document: Any, visit: Callable[[str, str], str | None]) -> None:
    """Call ``visit(field, value)`` on every excused envelope field in
    ``document``, setting the field to what it returns unless that is None.

    A ``signature`` is excused wherever it is (Anthropic's thinking blocks
    and their ``signature_delta``, OpenRouter's reasoning details); ``data``
    only in an entry of a ``CIPHERTEXT_TYPES`` type.
    """
    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                excused = key == SIGNATURE or (key == DATA and node.get("type") in CIPHERTEXT_TYPES)
                if excused and isinstance(value, str):
                    replacement = visit(key, value)
                    if replacement is not None:
                        node[key] = replacement
                else:
                    pending.append(value)


def excused_values(body: str) -> list[tuple[str, str]]:
    """``(field, value)`` for every excused envelope field in ``body``."""
    found: list[tuple[str, str]] = []
    for _, document in _documents(body):
        _excused(document, lambda key, value: found.append((key, value)))
    return found


async def non_ciphertext_fields(body: str) -> list[str]:
    """The excused fields in ``body`` whose value is not ciphertext, sorted.

    Empty means every excused value is one token no layer can read, which is
    what ``strip_ciphertext`` keeps from the layers. The field names are ours, a closed
    set, so they may be logged.

    The token test is a regex. What passes it is unpacked once per field
    name, every value of that name a line of one text, so a stream with a
    signature on every thinking block costs at most two unpacking passes,
    not one a value. A line is one token with no space, so no value is read
    together with its neighbour.
    """
    failed: set[str] = set()
    tokens: dict[str, list[str]] = {}
    for name, value in excused_values(body):
        if not value:
            continue
        if _TOKEN.fullmatch(value):
            tokens.setdefault(name, []).append(value)
        else:
            failed.add(name)
    for name, values in tokens.items():
        if name in failed:
            continue
        stats = (await run_unpacking(unpack, "\n".join(values))).stats
        if stats.text_decoded or stats.archives_opened or stats.images_read:
            failed.add(name)
    return sorted(failed)


async def strip_ciphertext(body: str) -> tuple[str, list[str]]:
    """``body`` as the layers read it, and the excused fields that are not
    ciphertext (``non_ciphertext_fields``).

    Every value of a field name that passed is replaced by its
    ``placeholder``; a name that failed keeps all its values, so the layers
    read what was planted there. Only a JSON document that held a replaced
    value is re-serialised: everything else in ``body``, its answer,
    readable reasoning and tool arguments included, reaches the layers as it
    arrived, non-ASCII unescaped.
    """
    failed = await non_ciphertext_fields(body)
    lines = body.splitlines(keepends=True)
    bare = body.splitlines()
    stripped = body
    for index, document in _documents(body):
        replaced = False

        def verified(key: str, value: str) -> str | None:
            nonlocal replaced
            if not value or key in failed:
                return None
            replaced = True
            return placeholder(key, value)

        _excused(document, verified)
        if not replaced:
            continue
        if index < 0:
            stripped = json.dumps(document, ensure_ascii=False)
            break
        ending = lines[index][len(bare[index]) :]
        lines[index] = "data: " + json.dumps(document, ensure_ascii=False) + ending
        stripped = "".join(lines)
    return stripped, failed
