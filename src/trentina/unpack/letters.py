"""Letter ciphers: Caesar shifts, Atbash and backwards text, read back when the
reading is English (#720) or an exact L1 directive (#744).

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

Backwards text is one more cipher: its words are looked up spelled back to
front in the same pass, and its reading is the segment reversed.

A short line is not judged as English: five common words is the floor that
keeps chance readings out. It is read back instead when one cipher makes an
exact L1 directive of it and the line as it arrived is not one
(:func:`read_attack`). That is the test L1 made itself, on ROT13 and
backwards text, until #744 moved it here so that L2 and L3 read the attack
too; it decodes nothing L1 would not already have counted.

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

from ..l1.directives import GATE_LITERALS, LITERALS, SOFT_BREAK, matches_exact
from ..l1.evasion import KEYWORDS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase


_TABLES = {
    name: str.maketrans(_LOWER + _UPPER, back + back.upper())
    for name, back in (
        ("Atbash", _LOWER[::-1]),
        *((f"ROT{n}", _LOWER[n:] + _LOWER[:n]) for n in range(1, 26)),
    )
}

REVERSED = "reversed"

CIPHERS: dict[str, Callable[[str], str]] = {
    **{name: operator.methodcaller("translate", table) for name, table in _TABLES.items()},
    REVERSED: operator.itemgetter(slice(None, None, -1)),
}
"""Atbash and every Caesar shift, each a table from the cipher back to the
text, then backwards text. Atbash is its own inverse, and ROT<n> undoes a
shift of 26 - n. garak uses ROT13 only; the other shifts cost nothing to read
and are the obvious next step for someone ROT13 no longer gets past.
Backwards is last, so a tie keeps a letter cipher."""

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


def _spellings(word: str) -> dict[str, int]:
    """``word``'s spelling under each cipher, to the bit for that cipher."""
    found: dict[str, int] = {}
    for bit, name in enumerate(_NAMES):
        if name == REVERSED:
            spelling = word[::-1]
        else:
            spelling = word.translate({plain: cipher for cipher, plain in _TABLES[name].items()})
        found[spelling] = found.get(spelling, 0) | 1 << bit
    return found


_READINGS: dict[str, int] = {}
"""Every spelling of a common word under some cipher, to the ciphers (a bit
per index of :data:`CIPHERS`) under which it reads as that word. About
50,000 spellings, built at import so no request pays for it. A
segment is split into words once and each word is looked up once, so every
reading is scored in one pass: trying the 26 ciphers one after another ran
non-English text at 0.5 MB/s (CTO ruling on #720; Aho-Corasick answers
substring search, not this word lookup)."""
ATTACK_VOCABULARY = KEYWORDS | {
    word for needs in LITERALS.values() for word in needs if word.isalpha() and len(word) > 3
}
"""The words injection phrases are built from: the keywords ``l1/evasion.py``
corrects toward, and every whole word an exact directive needs."""

_ATTACK_READINGS: dict[str, int] = {}
"""The same as ``_READINGS`` for :data:`ATTACK_VOCABULARY`, which the common
words mostly are not. It says which ciphers are worth asking
:func:`read_attack` about beyond the two it always asks."""
for _table, _words in ((_READINGS, COMMON_WORDS), (_ATTACK_READINGS, ATTACK_VOCABULARY)):
    for _word in _words:
        for _spelling, _bits in _spellings(_word).items():
            _table[_spelling] = _table.get(_spelling, 0) | _bits


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
    counts = _tally(words, _READINGS)
    floor = max(ENGLISH, share + MARGIN)
    best: tuple[float, int] | None = None
    for index, common in enumerate(counts):  # in CIPHERS order: a tie keeps the first
        reading = common / len(words)
        if common >= MIN_WORDS and reading >= floor and (best is None or reading > best[0]):
            best = (reading, index)
    if best is None:
        return None
    return _read_words(segment, _NAMES[best[1]])


def _tally(words: list[str], table: dict[str, int]) -> list[int]:
    """For each cipher, how many of ``words`` ``table`` reads under it."""
    counts = [0] * len(_NAMES)
    for lowered in words:
        ciphers = table.get(lowered, 0)
        while ciphers:
            low = ciphers & -ciphers
            counts[low.bit_length() - 1] += 1
            ciphers ^= low
    return counts


MIN_ATTACK = 12
"""The shortest line :func:`read_attack` reads: no exact directive is shorter."""

ATTACK_WORDS = 2
"""Words that must read as :data:`ATTACK_VOCABULARY` under a cipher other than ROT13
or backwards before :func:`read_attack` asks the patterns about it. The two
it always asks are the two L1 asked about itself until #744."""

_ALWAYS = ("ROT13", REVERSED)

# Each word ``matches_exact`` needs (#709), spelled as an ASCII line would
# carry it under each of those two: both are their own inverse, so the
# reading spells it. A line holding none reads as no directive under that
# cipher, reversed whole or a word at a time in place (a literal is one word,
# or one word and a colon after a literal that is that word), so the line is
# not read back just to be asked. A line that is not ASCII is always asked:
# `re.IGNORECASE` folds a few other letters to ASCII ones.
_SPELLED = {
    name: re.compile("|".join(sorted({re.escape(CIPHERS[name](w)) for w in GATE_LITERALS})))
    for name in _ALWAYS
}


def read_attack(line: str) -> str | None:
    """``line`` read back when one cipher makes an exact L1 directive of it.

    Only when the line as it arrived is not one already: a line quoting an
    attack in plain words is L1's to count as it stands, and reading the rest
    of it back would garble what is around the quote. The reading takes the
    line's segments (cut at double quotes, as :func:`read_back` cuts them)
    whose reading is more English than they are, so a JSON key around a
    ciphered value stays as it arrived; when that loses the match, the line
    word by word, then the whole line. Backwards text is tried reversed
    whole, then a word at a time in place.
    """
    if len(line) < MIN_ATTACK:
        return None
    lowered = line.lower()
    counts = _tally(_WORD.findall(lowered), _ATTACK_READINGS)
    others = [n for n, c in zip(_NAMES, counts, strict=True) if c >= ATTACK_WORDS]
    for name in dict.fromkeys([*_ALWAYS, *others]):
        if name in _SPELLED and line.isascii() and not _SPELLED[name].search(lowered):
            continue
        whole = CIPHERS[name](line)
        if matches_exact(whole):
            if matches_exact(line):
                return None
            for read in (_read_segments(line, name), _read_words(line, name)):
                if matches_exact(read):
                    return read
            return whole
        # Each word backwards where it stands: the line reversed, then its
        # words put back in order, which is cheap enough to ask of every line.
        if name == REVERSED and matches_exact("".join(_BLANKS.split(whole)[::-1])):
            read = _read_segments(line, name, in_place=True)
            if matches_exact(read) and not matches_exact(line):
                return read
    return None


_BLANKS = re.compile(r"(\s+)")


def _read_segments(line: str, name: str, *, in_place: bool = False) -> str:
    """``line`` with each segment read back that reads as more English for it."""

    def one(match: re.Match[str]) -> str:
        segment = match.group()
        read = _read_words(segment, name, in_place=in_place)
        return read if _english(read) > _english(segment) else segment

    return _SEGMENT.sub(one, line)


def _english(text: str) -> float:
    """The share of ``text``'s words that are common English words."""
    words = _WORD.findall(text)
    return sum(w.lower() in COMMON_WORDS for w in words) / len(words) if words else 0.0


def _read_words(segment: str, name: str, *, in_place: bool = False) -> str:
    """``segment`` read back under cipher ``name``, a word at a time.

    A common word whose reading is not common is a plain word and stays as it
    arrived. Backwards text is reversed whole, so its words come back in
    order; ``in_place`` reverses each word where it stands instead, for text
    written with every word backwards and the words in order.
    """
    if name != REVERSED:
        decipher = CIPHERS[name]
        return _WORD.sub(lambda m: _kept(m.group(), decipher(m.group())), segment)
    if in_place:
        return _WORD.sub(lambda m: _kept(m.group(), m.group()[::-1]), segment)
    return _WORD.sub(lambda m: _kept(m.group()[::-1], m.group()), segment[::-1])


def _kept(arrived: str, plain: str) -> str:
    """``plain``, unless ``arrived`` is a common word and ``plain`` is not."""
    if arrived.lower() in COMMON_WORDS and plain.lower() not in COMMON_WORDS:
        return arrived
    return plain


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


def _lines(text: str) -> Iterator[tuple[int, int, str]]:
    """Each line of ``text`` as L1 reads it, with where it starts and ends:
    split at a newline that is not part of a soft break, and joined across
    the soft breaks inside it."""
    soft = {m.end() - 1 for m in SOFT_BREAK.finditer(text) if m.group().endswith("\n")}
    start = position = 0
    while True:
        end = text.find("\n", position)
        if end in soft:
            position = end + 1
            continue
        end = len(text) if end == -1 else end
        line = text[start:end]
        # `<br>` breaks a line without a newline; anything else needs one.
        yield start, end, SOFT_BREAK.sub(" ", line) if position > start or "<" in line else line
        if end == len(text):
            return
        start = position = end + 1


def read_through(text: str) -> tuple[str, int]:
    """``text`` with every ciphered or leet segment read back, and how many were.

    Lines first, by :func:`read_attack`, each joined across a soft break the
    way L1 joins it, so a directive wrapped by a Markdown hard break is read
    as the one line L1 will see. Only a line read back changes; the rest of
    the text, soft breaks included, stays byte for byte. Then segments, by
    :func:`read_back` and :func:`read_leet`.
    """
    parts: list[str] = []
    last = count = 0
    for start, end, line in _lines(text):
        read = read_attack(line)
        if read is not None:
            parts += [text[last:start], read]
            last = end
            count += 1
    if count:
        text = "".join([*parts, text[last:]])

    def one(match: re.Match[str]) -> str:
        nonlocal count
        plain = read_back(match.group()) or read_leet(match.group())
        if plain is None:
            return match.group()
        count += 1
        return plain

    return _SEGMENT.sub(one, text), count
