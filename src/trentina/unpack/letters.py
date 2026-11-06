"""Letter ciphers: Caesar shifts and Atbash, read back when the reading is English (#720).

Every text is valid ROT13 and valid Atbash, so neither can be decoded the way
base64 is, by a strict decode that re-encodes to the token. What tells
ciphertext from text is what each reading says: English under ROT13 is not
English, and ROT13 of ROT13 is. A segment is read back only when one cipher
turns it from mostly not English into mostly English, so ordinary text, in
English or any other language, is never read twice.

The unit is a segment: a line, cut again at double quotes so a ciphered JSON
string is judged by its own words and not its keys'. Words are runs of two or
more ASCII letters with no letter or digit either side, looked up in
:data:`COMMON_WORDS`; the letters of a hex digest are not words.

Leetspeak (``4`` for a, ``3`` for e, ...) is read the same way, a token at a
time: a token of letters and those digits becomes its reading when that is a
common word, in a segment where at least :data:`MIN_WORDS` tokens do.

Known gap 22 was this: the shipped L2 model lost most attacks written in
ROT13 or Atbash and flagged ciphered or leet benign text, and no layer read
through them.
"""

from __future__ import annotations

import operator
import re
import string
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase


_TABLES = {
    name: str.maketrans(_LOWER + _UPPER, back + back.upper())
    for name, back in (
        ("Atbash", _LOWER[::-1]),
        *((f"ROT{n}", _LOWER[n:] + _LOWER[:n]) for n in range(1, 26)),
    )
}

CIPHERS: dict[str, Callable[[str], str]] = {
    name: operator.methodcaller("translate", table) for name, table in _TABLES.items()
}
"""Atbash and every Caesar shift, each a table from the cipher back to the
text: Atbash is its own inverse, and ROT<n> undoes a shift of 26 - n. garak
uses ROT13 only; the other shifts cost nothing to read and are the obvious
next step for someone ROT13 no longer gets past."""

MIN_WORDS = 5
"""Common words a reading must hold, whatever its share: fewer is chance
(Atbash makes ``in`` of ``rm``). At 5, with every shift tried, no segment of
the docs, the source, the tests or the corpora is read back (425,581
segments); at 3 there were 14, all code."""

ENGLISH = 0.3
"""Share of a reading's words in :data:`COMMON_WORDS` for it to be English."""

MARGIN = 0.2
"""How much more English the reading must be than the segment as it arrived."""

COMMON_WORDS = frozenset(
    (Path(__file__).parent / "common_words.txt").read_text(encoding="utf-8").split()
)
"""The 2,000 commonest words of two letters or more in the benign rows of the
L2 training sources (``scripts/l2_train_data.py``, its plain replay), one a
line. None of the sets Trentina measures on is among them."""

_NAMES = tuple(CIPHERS)


_READINGS: dict[str, int] = {}
"""Every spelling of a common word under some cipher, to the ciphers (a bit
per index of :data:`CIPHERS`) under which it reads as that word. About
50,000 spellings, built at import so no request pays for it. A
segment is split into words once and each word is looked up once, so every
reading is scored in one pass: trying the 26 ciphers one after another ran
non-English text at 0.5 MB/s (CTO ruling on #720; Aho-Corasick answers
substring search, not this word lookup)."""
for _bit, _back in enumerate(_TABLES.values()):
    _forward = {plain: cipher for cipher, plain in _back.items()}
    for _common in COMMON_WORDS:
        _spelling = _common.translate(_forward)
        _READINGS[_spelling] = _READINGS.get(_spelling, 0) | 1 << _bit


_LEET = str.maketrans("431057", "aeiost")
"""garak's leetspeak, read back: the digits it writes for a, e, i, o, s and t."""

_LEET_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*[431057])"
    r"[A-Za-z431057]{3,}(?![A-Za-z0-9])"
)
"""Three or more letters and leet digits, at least one of each, no other
digit: ``L3`` and ``v1`` are identifiers, ``sha256`` and ``k8s`` are not leet."""

_LEET_SEAM = re.compile(r"[A-Za-z][431057]|[431057][A-Za-z]")

_WORD = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2,}(?![A-Za-z0-9])")
_SEGMENT = re.compile(r'[^"\n]+')


def read_back(segment: str) -> str | None:
    """``segment`` deciphered, when one cipher makes English of it; else None.

    The segment decides the cipher; each word decides whether it is read
    back. A common word whose reading is not common is a plain word and stays
    as it arrived, even inside ciphertext: reading the whole segment back would
    let plain text padded with ciphered filler be ciphered away from the
    layers. Every other word is read back, a rare one included.
    """
    words = [w.lower() for w in _WORD.findall(segment)]
    if not words:
        return None
    share = sum(w in COMMON_WORDS for w in words) / len(words)
    if share >= ENGLISH:
        return None  # already reads as English
    counts = [0] * len(_NAMES)
    for lowered in words:
        ciphers = _READINGS.get(lowered, 0)
        while ciphers:
            low = ciphers & -ciphers
            counts[low.bit_length() - 1] += 1
            ciphers ^= low
    floor = max(ENGLISH, share + MARGIN)
    best: tuple[float, int] | None = None
    for index, common in enumerate(counts):  # in CIPHERS order: a tie keeps the first
        reading = common / len(words)
        if common >= MIN_WORDS and reading >= floor and (best is None or reading > best[0]):
            best = (reading, index)
    if best is None:
        return None
    decipher = CIPHERS[_NAMES[best[1]]]

    def word(match: re.Match[str]) -> str:
        arrived = match.group()
        plain = decipher(arrived)
        if arrived.lower() not in COMMON_WORDS or plain.lower() in COMMON_WORDS:
            return plain
        return arrived

    return _WORD.sub(word, segment)


def read_leet(segment: str) -> str | None:
    """``segment`` with its leet tokens read back, when enough read as words."""
    if not _LEET_SEAM.search(segment):
        return None  # no letter touches a leet digit: most text, at one scan
    tokens = _LEET_TOKEN.findall(segment)
    readable = sum(t.translate(_LEET).lower() in COMMON_WORDS for t in tokens)
    if readable < MIN_WORDS or readable * 2 < len(tokens):
        return None

    def token(match: re.Match[str]) -> str:
        plain = match.group().translate(_LEET)
        return plain if plain.lower() in COMMON_WORDS else match.group()

    return _LEET_TOKEN.sub(token, segment)


def read_through(text: str) -> tuple[str, int]:
    """``text`` with every ciphered or leet segment read back, and how many were."""
    count = 0

    def one(match: re.Match[str]) -> str:
        nonlocal count
        plain = read_back(match.group()) or read_leet(match.group())
        if plain is None:
            return match.group()
        count += 1
        return plain

    return _SEGMENT.sub(one, text), count
