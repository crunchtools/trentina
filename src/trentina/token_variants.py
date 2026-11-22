"""Find a secret token in text however it was dressed: encoded, reversed or cut (#864).

A honeytoken (``gateway/decoy.py``) and the L3 canary (``quarantine/agent.py``)
are tripwires on one string. Matching that string only as written missed the
cheapest exfiltration there is: encode it, reverse it, or send part of it.
``TokenMatcher`` precomputes the forms a token takes and finds any of them in
a haystack:

- the token itself, and reversed;
- hex of its UTF-8 bytes, lower and upper case;
- base64, standard and URL-safe, unpadded, at all three byte alignments. The
  token inside a larger blob is preceded by 0, 1 or 2 bytes of something else,
  which changes the characters around its edges; only the core that does not
  depend on its neighbours is kept;
- percent-encoding of every byte, lower and upper case;
- fragments: any ``FRAGMENT_MIN`` consecutive characters of the token, but
  only for a token of at least twice that length. A shorter token is matched
  whole, because a window of half of it would be too common to mean anything.

Percent and ``\\uXXXX`` escapes in the haystack are decoded first, as
``gateway.outbound.reveal`` does. That function is not imported: the gateway
package imports the quarantine one on its way in, and this module has to be
importable from both.

Read time is linear in the haystack: one substring search per form (a handful
per token) and one ``find`` per block of a token's eight characters. What this
does not see: a token paraphrased, split across calls, or in an encoding not
listed (ROT13, gzip, a custom cipher).
"""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote

if TYPE_CHECKING:
    from collections.abc import Iterable

FRAGMENT_MIN = 16
"""The shortest piece of a token that counts as the token. A token has fragments
only from twice this length up."""

_BLOCK = FRAGMENT_MIN // 2

_JSON_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")

# Leading base64 characters that a preceding 0, 1 or 2 bytes change: those bytes
# fill 0, 8 and 16 bits, and the character they end in mixes in the token's.
_LEAD_DROP = (0, 2, 3)

_B64_URLSAFE = str.maketrans("+/", "-_")


def _reveal(text: str) -> str:
    """``text`` with percent-escapes and JSON ``\\uXXXX`` escapes decoded."""
    return _JSON_UESC.sub(lambda m: chr(int(m.group(1), 16)), unquote(text))


def _base64_cores(raw: bytes) -> set[str]:
    """The base64 of ``raw`` that survives whatever precedes or follows it."""
    cores: set[str] = set()
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + raw).decode("ascii")
        # Only whole 3-byte groups are fixed: the last partial group is
        # completed by the bytes after the token, and the padding with it.
        core = encoded[_LEAD_DROP[offset] : 4 * ((offset + len(raw)) // 3)]
        if core:
            cores.add(core)
            cores.add(core.translate(_B64_URLSAFE))
    return cores


class TokenMatcher:
    """Finds which of a set of secret tokens appear in a text, in any form.

    Built once per token set: the forms and the fragment windows are computed
    here, not per search.
    """

    def __init__(self, tokens: Iterable[str]) -> None:
        self._forms: dict[str, set[str]] = {}
        # Every FRAGMENT_MIN piece of a token holds one of its blocks at a
        # multiple of _BLOCK, so a fragment is found by searching for the
        # blocks and checking the windows around a hit: C-speed ``find``,
        # never a slice at every offset of the haystack.
        self._blocks: dict[str, list[tuple[str, int]]] = {}
        for token in tokens:
            if not token:
                continue
            raw = token.encode("utf-8")
            percent = "".join(f"%{byte:02x}" for byte in raw)
            encoded = {
                raw.hex(),
                raw.hex().upper(),
                percent,
                percent.upper(),
                *_base64_cores(raw),
            }
            # An encoded form shorter than a fragment is too common to mean the
            # token: a short token's base64 core can be one character.
            self._forms[token] = {
                token,
                token[::-1],
                *(form for form in encoded if len(form) >= FRAGMENT_MIN),
            }
            if len(token) >= 2 * FRAGMENT_MIN:
                self._blocks[token] = [
                    (token[at : at + _BLOCK], at)
                    for at in range(0, len(token) - _BLOCK + 1, _BLOCK)
                ]

    def found(self, text: str) -> list[str]:
        """The tokens with a form or a fragment in ``text``, sorted."""
        haystacks = [text]
        if "%" in text or "\\u" in text:
            revealed = _reveal(text)
            if revealed != text:
                haystacks.append(revealed)
        hits = {
            token
            for token, forms in self._forms.items()
            if any(form in hay for hay in haystacks for form in forms)
        }
        for token, blocks in self._blocks.items():
            if token not in hits and any(
                _has_fragment(hay, token, block, at) for hay in haystacks for block, at in blocks
            ):
                hits.add(token)
        return sorted(hits)


def _has_fragment(hay: str, token: str, block: str, at: int) -> bool:
    """Whether ``hay`` holds a FRAGMENT_MIN piece of ``token`` that covers the
    block found at token offset ``at``."""
    pos = hay.find(block)
    while pos != -1:
        # The piece starts at most one block before this one and stays inside the token.
        for start in range(max(0, at - _BLOCK), min(at, len(token) - FRAGMENT_MIN) + 1):
            lead = pos - (at - start)
            if lead >= 0 and hay.startswith(token[start : start + FRAGMENT_MIN], lead):
                return True
        pos = hay.find(block, pos + 1)
    return False


_MATCHERS: dict[frozenset[str], TokenMatcher] = {}
_MATCHERS_MAX = 64


def matcher_for(tokens: frozenset[str]) -> TokenMatcher:
    """The matcher for a token set, built once. For tokens that outlive a call
    (a profile's honeytokens); a per-call token builds its own."""
    matcher = _MATCHERS.get(tokens)
    if matcher is None:
        if len(_MATCHERS) >= _MATCHERS_MAX:
            _MATCHERS.pop(next(iter(_MATCHERS)))
        matcher = _MATCHERS[tokens] = TokenMatcher(tokens)
    return matcher
