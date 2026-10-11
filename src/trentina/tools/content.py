"""Content tools — block_content, flag_content and redact_content."""

from __future__ import annotations

import hashlib
from typing import Any

from ..defense import admission
from ..errors import ContentSizeError
from ..modes import Mode
from .judged import check_blocklist, judge_and_deliver, pageable
from .preprocess import prepare


def _content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for blocklist keying."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


async def judge_content(
    content: str,
    mode: Mode,
    prompt: str | None = None,
    *,
    content_type: str = "text/plain",
    preprocess: Any = None,
) -> dict[str, Any]:
    """Judge text the agent handed in. It is never allowlisted.

    Inline content has no provenance to appeal to: fetch asks the domain,
    read asks the path, and this has neither. The blocklist is keyed by the
    content's hash — of what was handed in, before any pre-processing.

    ``content_type`` is the hint it was kept for (#183): declared HTML is
    converted, the way fetch converts a page its server calls HTML. Minified
    by default; ``preprocess=False`` judges and returns the text as given.
    """
    # Before the blocklist and pre-processing: the agent's own text, so it is
    # told to split it rather than handed a refusal or flag's partial scan.
    # Behind the gateway, text too large to judge in one call is judged and
    # handed back in parts (#446), up to the most parts a response is cut into.
    tokens, cap = await admission(content)
    if tokens > cap and not pageable(tokens):
        raise ContentSizeError(tokens, cap)

    chash = _content_hash(content)
    blocked = check_blocklist(chash, mode)

    page = await prepare(
        content, requested=preprocess, tool="content_tool", source=chash, content_type=content_type
    )
    return await judge_and_deliver(
        page.content,
        mode=mode,
        family="content",
        source=chash,
        source_type="content",
        kind="content",
        ref=chash,
        prompt=prompt,
        blocklisted=blocked,
        provenance=page.provenance,
        precomputed_l1=page.pipeline,
        l3_context=page.briefing,
        extras=page.extras,
        redact_extras=page.extras,
    )


async def block_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Refuse flagged or incompletely judged content; otherwise what was judged.

    That is the text as given, or its Markdown when ``content_type`` is HTML.
    """
    return await judge_content(content, Mode.BLOCK, content_type=content_type)


async def flag_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """What was judged — the text as given, or its Markdown when declared
    HTML — with the verdict attached when there is one."""
    return await judge_content(content, Mode.FLAG, content_type=content_type)


async def redact_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """A verified L3 extraction of the content."""
    return await judge_content(content, Mode.REDACT, prompt, content_type=content_type)
