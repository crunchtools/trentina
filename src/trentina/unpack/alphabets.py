"""Braille and Morse decode tables, defined in-tree (#546).

Runtime code cannot import ``corpora`` (the garak encoders live there, for the
benchmark and the tests only), so the inverse of garak's Braille and Morse
encoders is written here. ``tests/test_unpack.py`` asserts these round-trip
``corpora.garak_encodings`` exactly, so the two cannot drift.

Both encoders are lossy, so a decode is NOT gated by re-encode equality the way
base64 is (``scan._strict_base64``). Braille shares one cell between a letter
and a digit (told apart by a number-sign prefix) and between some punctuation;
Morse upper-cases and drops anything it has no code for. The gate instead is
the alphabet: a run of Braille cells, or of Morse code groups, is not ordinary
text, and whatever it decodes to must still read as text (``scan._as_text``).
A cell or a code this table does not know makes the whole run decline, so a run
that is not really Braille or Morse is left as it arrived.
"""

from __future__ import annotations

# Letter cells (garak's forward map, inverted). The digit cells below reuse the
# a-j cells, which is why a number sign disambiguates them on the way out.
_LETTER = {
    "⠁": "a", "⠃": "b", "⠉": "c", "⠙": "d", "⠑": "e",
    "⠋": "f", "⠛": "g", "⠓": "h", "⠊": "i", "⠚": "j",
    "⠅": "k", "⠇": "l", "⠍": "m", "⠝": "n", "⠕": "o",
    "⠏": "p", "⠟": "q", "⠗": "r", "⠎": "s", "⠞": "t",
    "⠥": "u", "⠧": "v", "⠺": "w", "⠭": "x", "⠽": "y",
    "⠵": "z",
}  # fmt: skip

_DIGIT = {
    "⠁": "1", "⠃": "2", "⠉": "3", "⠙": "4", "⠑": "5",
    "⠋": "6", "⠛": "7", "⠓": "8", "⠊": "9", "⠚": "0",
}  # fmt: skip

# Two of garak's punctuation cells collide ('.'/'$' on U+2832, '('/')' on
# U+2836). The first key wins; the decode stays readable, which is all L2 needs.
_PUNCT = {
    "⠲": ".", "⠄": "'", "⠂": ",", "⠤": "-", "⠌": "/",
    "⠖": "!", "⠦": "?", "⠒": ":", "⠰": ";", "⠶": "(",
}  # fmt: skip

_NUMBER_SIGN = "⠼"
_CAPITAL_SIGN = "⠠"
_BRAILLE_SPACE = " \n\r\t"


def decode_braille(text: str) -> str | None:
    """garak's Braille, back to text, or None if a cell is unknown."""
    out: list[str] = []
    number = capital = False
    for cell in text:
        if cell in _BRAILLE_SPACE:
            out.append(cell)
            number = capital = False
            continue
        if cell == _NUMBER_SIGN:
            number = True
            continue
        if cell == _CAPITAL_SIGN:
            capital = True
            continue
        char = _DIGIT.get(cell) if number else _LETTER.get(cell) or _PUNCT.get(cell)
        if char is None:
            return None
        out.append(char.upper() if capital else char)
        number = capital = False
    return "".join(out)


# Morse: letters and digits only; a word space is "/", which garak also emits
# for a newline or tab. Unknown codes make the run decline.
_MORSE_CODES = (
    ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - "
    "..- ...- .-- -..- -.-- --.. .---- ..--- ...-- ....- ..... -.... --... ---.. ----. -----"
)
_MORSE = dict(zip(_MORSE_CODES.split(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", strict=True))


def decode_morse(text: str) -> str | None:
    """garak's Morse, back to upper-case text, or None if a code is unknown."""
    out: list[str] = []
    for code in text.split(" "):
        if not code:
            continue
        if code == "/":
            out.append(" ")
            continue
        char = _MORSE.get(code)
        if char is None:
            return None
        out.append(char)
    return "".join(out)
