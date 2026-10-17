"""Matrix message content as the plain text a phone shows.

RCS renders no markdown and no HTML, so the agent's ``body`` (which is
markdown source for every agent we run) loses the markup that would show as
noise and keeps everything that carries meaning: words, code, link targets.
Deterministic and lossy only in punctuation; nothing here decides anything.
"""

from __future__ import annotations

import re

_LINK_RE = re.compile(r"\[([^\]\n]+)\]\((\S+?)\)")
_HEADING_RE = re.compile(r"^#{1,6}[ \t]+", re.MULTILINE)
_EMPHASIS_RE = re.compile(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1")
_FENCE_RE = re.compile(r"^```[^\n]*\n?", re.MULTILINE)
_BLANK_RUN_RE = re.compile(r"\n{3,}")
# What an emote reads as, since a phone has no /me.
_EMOTE = "* "


def flatten(msgtype: str, body: str) -> str:
    """The text of one message, markup removed."""
    text = _FENCE_RE.sub("", body)
    text = _LINK_RE.sub(lambda m: m[1] if m[1] == m[2] else f"{m[1]} ({m[2]})", text)
    text = _HEADING_RE.sub("", text)
    text = _EMPHASIS_RE.sub(r"\2", text)
    text = _BLANK_RUN_RE.sub("\n\n", text).strip()
    return f"{_EMOTE}{text}" if msgtype == "m.emote" else text


def chunks(text: str, limit: int) -> list[str]:
    """``text`` in pieces of at most ``limit`` characters, split at a
    paragraph, then a line, then a space, and only mid-word as a last resort.
    Empty text is no message at all."""
    out: list[str] = []
    rest = text.strip()
    while len(rest) > limit:
        window = rest[: limit + 1]
        cut = -1
        for sep in ("\n\n", "\n", " "):
            cut = window.rfind(sep, 0, limit + 1)
            if cut > limit // 2:
                break
        if cut <= 0:
            cut = limit
        out.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip()
    if rest:
        out.append(rest)
    return out
