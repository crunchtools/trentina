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
- fragments: any ``FRAGMENT_MIN`` consecutive characters of the token's
  SECRET BODY, but only for a token of at least twice that length. A shorter
  token is matched whole, because a window of half of it would be too common
  to mean anything. What every token of its kind shares is not the body, so a
  window must not touch a vendor prefix (``_PREFIXES``), a JWT's header
  or payload, PEM armour, the fixed head of a key body (an OpenSSH key's public
  half, key type and framing; a DER key's header) or fall under
  ``ENTROPY_FLOOR``. A fake JWT or key that merely shares those with a real
  one is not a hit;

Base64 is also searched in a copy of the haystack with whitespace and the
literal escapes ``\\n`` and ``\\r`` removed, so a token inside base64 wrapped at
76 columns, or in a JSON string with its line breaks escaped, is still seen.

Percent and ``\\uXXXX`` escapes in the haystack are decoded first, as
``gateway.outbound.reveal`` does. That function is not imported: the gateway
package imports the quarantine one on its way in, and this module has to be
importable from both.

Read time is linear in the haystack: one substring search per form (a handful
per token) and one ``find`` per block of a token's eight characters that some
admissible window covers, plus one ``re.sub`` when the haystack has line
breaks. What this does not see: a token paraphrased, split across calls, or in
an encoding not listed (ROT13, gzip, a custom cipher); ``\\x41``-style escaped
hex; and a fragment of an ENCODED form (a piece of the token's base64 or hex),
which is matched only whole.
"""

from __future__ import annotations

import base64
import math
import re
from itertools import accumulate
from typing import TYPE_CHECKING
from urllib.parse import unquote

if TYPE_CHECKING:
    from collections.abc import Iterable

FRAGMENT_MIN = 16
"""The shortest piece of a token that counts as the token. A token has fragments
only from twice this length up."""

ENTROPY_FLOOR = 2.5
"""Shannon entropy, in bits per character, under which a FRAGMENT_MIN window is
not a fragment: ``AAAAAAAAAAAAAAAA`` is 0 and ``0000111100001111`` is 1. 16
random alphanumerics score about 3.9 and 16 random hex digits 3.4 (0.2% fall
under 2.5; at 3.0 it would be 14%, and a real fragment would go unseen)."""

_BLOCK = FRAGMENT_MIN // 2

# Fixed lead-ins of vendor credentials: every token of the kind starts with one,
# so a window over it matches somebody else's. Longest match wins. The shapes
# ``credential_shapes`` knows (``ghp_`` family, ``github_pat_``, ``sk-``,
# ``AIza``, ``ya29.``, ``syt_``, ``trt_``, ``xox?-``, AWS id prefixes) plus the
# common longer forms of ``sk-``, GitLab and Slack.
_PREFIXES = tuple(
    sorted(
        (
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "github_pat_",
            "sk-",
            "sk-proj-",
            "sk-ant-",
            "sk-ant-api03-",
            "sk-ant-admin01-",
            "sk-or-v1-",
            "xoxa-",
            "xoxb-",
            "xoxp-",
            "xoxr-",
            "xoxs-",
            "AKIA",
            "ASIA",
            "AGPA",
            "AIDA",
            "AROA",
            "ANPA",
            "ANVA",
            "AIza",
            "ya29.",
            "glpat-",
            "trt_",
            "syt_",
        ),
        key=len,
        reverse=True,
    )
)

# A JWT: three base64url segments, the first a JSON header (``{"`` is ``eyJ``).
# The header (``eyJhbGciOiJIUzI1NiIs...``) is shared by most JWTs.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

_OPENSSH_MAGIC = b"openssh-key-v1\0"
_OPENSSH_B64 = "b3BlbnNzaC1rZXktdjE"  # base64 of the magic's first 14 bytes
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
# DER private keys (PKCS#1 ``MIIE...``, PKCS#8 ``MIIEvQIBADANBgkqhkiG9w0BAQEF...``)
# open with a tag, length, version and algorithm OID in their first ~50
# characters, and an RSA modulus (public) follows. Dropped as a block.
_DER_HEAD = 64
# Where whatever parser cannot read an OpenSSH body: the same, a little wider.
_OPENSSH_FALLBACK_HEAD = 96

# Line breaks in a haystack that cut a base64 run: whitespace and the literal
# two-character escapes a JSON string holds.
_WRAP = re.compile(r"\\[nr]|\s+")

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


def _entropy(counts: dict[str, int]) -> float:
    """Shannon entropy of a FRAGMENT_MIN window, in bits per character."""
    return -sum(c / FRAGMENT_MIN * math.log2(c / FRAGMENT_MIN) for c in counts.values() if c)


def _field(raw: bytes, at: int) -> tuple[int, int]:
    """The (start, end) of the SSH string at ``at``; ValueError past the end."""
    if at + 4 > len(raw):
        raise ValueError
    end = at + 4 + int.from_bytes(raw[at : at + 4], "big")
    if end > len(raw):
        raise ValueError
    return at + 4, end


def _openssh_secret(raw: bytes) -> bytearray:
    """Which bytes of a decoded ``openssh-key-v1`` body are secret (1) or not (0).

    Layout (PROTOCOL.key): the magic, then strings cipher name, kdf name, kdf
    options, a count of keys, one public blob per key, then the private
    section. Every key of a type shares the framing and key type string, and
    the public half is public. Unencrypted, the private section is two equal
    random check words, then the key type, then the key's fields (RSA n e d
    iqmp p q, ed25519 pub and seed+pub, ECDSA curve Q d), then the comment and
    1, 2, 3.. padding. Only the check words and the fields that are not in a
    public blob are secret; ed25519's trailing 32 bytes are its public key
    again. Encrypted, the whole section is ciphertext and all of it is secret.
    """
    secret = bytearray(len(raw))
    strings = [_field(raw, len(_OPENSSH_MAGIC))]  # the cipher name
    for _ in range(2):  # then kdf name and kdf options
        strings.append(_field(raw, strings[-1][1]))
    count = int.from_bytes(raw[strings[-1][1] : strings[-1][1] + 4], "big")
    at = strings[-1][1] + 4
    publics = b""
    for _ in range(min(count, 16)):
        start, end = _field(raw, at)
        publics += raw[start:end]
        at = end
    start, end = _field(raw, at)
    if raw[strings[0][0] : strings[0][1]] != b"none":
        secret[start:end] = b"\1" * (end - start)
        return secret
    secret[start : start + 8] = b"\1" * 8
    fields = _private_fields(raw, start + 8, end)
    keytype = raw[fields[0][0] : fields[0][1]] if fields else b""
    # fields[0] is the key type and fields[-1] the comment: neither is secret.
    for first, last in fields[1:-1]:
        stop = first + 32 if keytype == b"ssh-ed25519" and last - first == 64 else last
        if raw[first:last] not in publics:
            secret[first:stop] = b"\1" * (stop - first)
    return secret


def _private_fields(raw: bytes, at: int, end: int) -> list[tuple[int, int]]:
    """The SSH strings of a private section from ``at``, up to its padding."""
    fields: list[tuple[int, int]] = []
    while at + 4 <= end:
        try:
            field = _field(raw, at)
        except ValueError:
            break  # padding reads as a huge length
        if field[1] > end:
            break
        fields.append(field)
        at = field[1]
    return fields


def _openssh_flags(body: str) -> list[bool]:
    """Per base64 character of an OpenSSH key body: carries only secret bytes."""
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        secret = _openssh_secret(raw)
    except ValueError:  # binascii.Error is a ValueError
        return [at >= _OPENSSH_FALLBACK_HEAD for at in range(len(body))]
    # Character i holds bits 6i..6i+5: the bytes those bits fall in.
    return [
        (6 * at + 5) // 8 < len(raw) and secret[6 * at // 8] == 1 and secret[(6 * at + 5) // 8] == 1
        for at in range(len(body))
    ]


def _body_positions(token: str) -> list[int]:
    """Offsets in ``token`` of its base64 characters outside any ``-----`` line."""
    lines = token.splitlines(keepends=True)
    starts = [0, *accumulate(map(len, lines[:-1]))]
    return [
        start + i
        for start, line in zip(starts, lines, strict=True)
        if not line.startswith("-----")
        for i, char in enumerate(line)
        if char in _B64_CHARS
    ]


def _pem_mask(token: str) -> list[bool]:
    """Secret-body mask of a PEM or bare OpenSSH key: armour lines, whitespace
    and the fixed head of the body are not secret."""
    positions = _body_positions(token)
    body = "".join(token[i] for i in positions)
    flags = (
        _openssh_flags(body)
        if body.startswith(_OPENSSH_B64)
        else [i >= _DER_HEAD for i in range(len(body))]
    )
    secret = dict(zip(positions, flags, strict=True))
    return [secret.get(at, False) for at in range(len(token))]


def _secret_mask(token: str) -> list[bool]:
    """Per character: whether it is in the token's secret body, the part that
    differs from one token of its kind to the next."""
    if "-----BEGIN" in token or token.startswith(_OPENSSH_B64):
        return _pem_mask(token)
    jwt = _JWT.fullmatch(token)
    if jwt:
        # Only the signature is secret: the header is shared by most JWTs, and
        # a payload is JSON whose base64 opens alike (``eyJzdWIi`` is ``{"sub"``).
        head = token.rindex(".") + 1
        return [at >= head for at in range(len(token))]
    head = next((len(prefix) for prefix in _PREFIXES if token.startswith(prefix)), 0)
    return [at >= head for at in range(len(token))]


def _fragment_starts(token: str) -> frozenset[int]:
    """Offsets of the FRAGMENT_MIN windows of ``token`` that may count: all of
    it in the secret body and at or over ``ENTROPY_FLOOR``."""
    mask = _secret_mask(token)
    counts: dict[str, int] = {}
    starts: set[int] = set()
    run = 0
    for at, char in enumerate(token):
        counts[char] = counts.get(char, 0) + 1
        if at >= FRAGMENT_MIN:
            gone = token[at - FRAGMENT_MIN]
            counts[gone] -= 1
        run = run + 1 if mask[at] else 0
        if at >= FRAGMENT_MIN - 1 and run >= FRAGMENT_MIN and _entropy(counts) >= ENTROPY_FLOOR:
            starts.add(at - FRAGMENT_MIN + 1)
    return frozenset(starts)


def _unwrapped(hay: str) -> str | None:
    """``hay`` with line breaks and whitespace removed, or None with no break."""
    if "\n" in hay or "\r" in hay or "\\n" in hay or "\\r" in hay:
        return _WRAP.sub("", hay)
    return None


class TokenMatcher:
    """Finds which of a set of secret tokens appear in a text, in any form.

    Built once per token set: the forms and the fragment windows are computed
    here, not per search.

    Which forms a token gets, by its length in bytes ``n`` (ASCII; every byte
    is one character):

    - always: the token and its reverse, whole;
    - an encoded form only when it is at least ``FRAGMENT_MIN`` (16)
      characters, since a shorter one is too common to mean anything. Hex is
      ``2n`` characters, so from ``n`` = 8; percent is ``3n``, so from 6;
      base64 core is ``4*(n//3)`` characters at alignment 0 (``n`` = 12),
      ``4*((n+1)//3) - 2`` at 1 (``n`` = 14) and ``4*((n+2)//3) - 3`` at 2
      (``n`` = 13), so the first base64 form is at ``n`` = 12 and all three
      alignments from 14;
    - fragments only from ``2 * FRAGMENT_MIN`` (32) characters up. Below that
      a token is matched in exactly the forms above and never in part, and an
      encoded form is matched whole, never a piece of it.
    """

    def __init__(self, tokens: Iterable[str]) -> None:
        self._forms: dict[str, set[str]] = {}
        # The base64 subset of the above, the only forms searched in a
        # haystack whose line breaks were removed.
        self._b64: dict[str, set[str]] = {}
        # Every FRAGMENT_MIN piece of a token holds one of its blocks at a
        # multiple of _BLOCK, so a fragment is found by searching for the
        # blocks and checking the windows around a hit: C-speed ``find``,
        # never a slice at every offset of the haystack. A block no
        # admissible window covers is not kept.
        self._blocks: dict[str, list[tuple[str, int]]] = {}
        self._starts: dict[str, frozenset[int]] = {}
        for token in tokens:
            if not token:
                continue
            raw = token.encode("utf-8")
            percent = "".join(f"%{byte:02x}" for byte in raw)
            cores = {form for form in _base64_cores(raw) if len(form) >= FRAGMENT_MIN}
            encoded = {
                raw.hex(),
                raw.hex().upper(),
                percent,
                percent.upper(),
            }
            # An encoded form shorter than a fragment is too common to mean the
            # token: a short token's base64 core can be one character.
            self._forms[token] = {
                token,
                token[::-1],
                *(form for form in encoded if len(form) >= FRAGMENT_MIN),
                *cores,
            }
            if cores:
                self._b64[token] = cores
            if len(token) >= 2 * FRAGMENT_MIN:
                starts = _fragment_starts(token)
                blocks = [
                    (token[at : at + _BLOCK], at)
                    for at in range(0, len(token) - _BLOCK + 1, _BLOCK)
                    if any(start in starts for start in range(max(0, at - _BLOCK), at + 1))
                ]
                if blocks:
                    self._blocks[token] = blocks
                    self._starts[token] = starts

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
        # Base64 broken by line breaks (76-column MIME, CRLF, JSON-escaped).
        unwrapped = [hay for hay in map(_unwrapped, haystacks) if hay is not None]
        if unwrapped:
            hits.update(
                token
                for token, forms in self._b64.items()
                if token not in hits and any(form in hay for hay in unwrapped for form in forms)
            )
        for token, blocks in self._blocks.items():
            if token not in hits and any(
                _has_fragment(hay, token, self._starts[token], block, at)
                for hay in haystacks
                for block, at in blocks
            ):
                hits.add(token)
        return sorted(hits)


def _has_fragment(hay: str, token: str, starts: frozenset[int], block: str, at: int) -> bool:
    """Whether ``hay`` holds an admissible FRAGMENT_MIN piece of ``token`` that
    covers the block found at token offset ``at``."""
    pos = hay.find(block)
    while pos != -1:
        # The piece starts at most one block before this one and stays inside the token.
        for start in range(max(0, at - _BLOCK), min(at, len(token) - FRAGMENT_MIN) + 1):
            lead = pos - (at - start)
            if (
                start in starts
                and lead >= 0
                and hay.startswith(token[start : start + FRAGMENT_MIN], lead)
            ):
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
