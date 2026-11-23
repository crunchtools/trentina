"""The envelope fields L3 excuses in a completion, checked to be ciphertext (a1013).

``prompts.COMPLETION_BRIEFING`` tells L3 that a provider's encrypted
reasoning and signatures are ciphertext and not a finding by themselves.
Asked to excuse those fields and also to read them as content when they are
not ciphertext, gemini-2.5-flash-lite did neither well: it flagged one benign
completion in eight and still excused decoded attacks planted in
``signature``. Whether a value is ciphertext is not a judgement, so it is
decided here.

A provider's ciphertext is one base64 token, dotted parts allowed, that
decodes to nothing a layer can read. An excused field holding anything else (words, a ROT13 or other
cipher L3 would have to read, base64 or gzip that the unpack stage turns into
text, an archive or an image) is not what the briefing excuses, and the
completion is flagged.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..unpack.child import run_unpacking
from ..unpack.scan import unpack

CIPHERTEXT_TYPES = frozenset({"reasoning.encrypted", "redacted_thinking"})
"""Entry types whose ``data`` is the provider's ciphertext: OpenRouter's and
OpenAI's encrypted reasoning, and Anthropic's redacted thinking."""

SIGNATURE = "signature"
DATA = "data"

_TOKEN = re.compile(r"[A-Za-z0-9+/=_.-]+")
"""One base64 or base64url token, or several joined by dots as OpenAI's
encrypted reasoning is (``gAAAAAB…``, its parts each padded): what
every provider's ciphertext is. No space, quote or other punctuation."""


def excused_values(body: str) -> list[tuple[str, str]]:
    """``(field, value)`` for every excused envelope field in ``body``.

    ``body`` is a JSON response, or an event stream whose ``data:`` lines are
    JSON; anything else (a stream's ``[DONE]``, a cut-off body) has no
    envelope to excuse and yields nothing. A ``signature`` is excused
    wherever it is (Anthropic's thinking blocks and their ``signature_delta``,
    OpenRouter's reasoning details); ``data`` only in an entry of a
    ``CIPHERTEXT_TYPES`` type.
    """
    events = [line.removeprefix("data:") for line in body.splitlines() if line.startswith("data:")]
    pending: list[Any] = []
    for text in [body] if body.lstrip().startswith(("{", "[")) else events:
        try:
            pending.append(json.loads(text))
        except ValueError:
            continue
    found: list[tuple[str, str]] = []
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                excused = key == SIGNATURE or (key == DATA and node.get("type") in CIPHERTEXT_TYPES)
                if excused and isinstance(value, str):
                    found.append((key, value))
                else:
                    pending.append(value)
    return found


async def not_ciphertext(body: str) -> list[str]:
    """The excused fields in ``body`` whose value is not ciphertext, sorted.

    Empty means every excused value is one token no layer can read, which is
    what the briefing tells L3 to excuse. The field names are ours, a closed
    set, so they may be logged.
    """
    failed = set()
    for name, value in excused_values(body):
        if not value:
            continue
        if not _TOKEN.fullmatch(value):
            failed.add(name)
            continue
        stats = (await run_unpacking(unpack, value)).stats
        if stats.text_decoded or stats.archives_opened or stats.images_read:
            failed.add(name)
    return sorted(failed)
