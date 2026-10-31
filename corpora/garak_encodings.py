"""garak's encoding probes, as transforms (#423).

`NVIDIA/garak <https://github.com/NVIDIA/garak>`_ (Apache-2.0) hides a
payload in an encoding and asks a model to decode it. Its ``encoding`` probes
are the widest published list of such encodings, so they are what the L2
model is measured against beyond the six transforms it is gated on
(``trentina.quarantine.obfuscation.TRANSFORMS``).

What is taken, from ``garak/probes/encoding.py``,
``garak/resources/encodings.py`` and
``garak/resources/smuggling/smuggle_ascii.py`` at ``v0.17.0``: every encoder
the standard library can express. Each function here produces what garak's
produces for the same text, quirks included: Braille and Morse drop a
character they have no cell or code for, the NATO alphabet drops everything
but letters (spaces too), and quoted-printable and MIME call the same
routine and so agree byte for byte. Variant selectors shift every character
by a fixed offset, as garak does, so only ASCII lands on a real selector and
a character past U+2FEFF has nowhere to go and raises.

What is changed:

* Leetspeak. garak swaps each eligible letter on a coin toss from the
  process's random source. Here the toss is seeded with the text, so one
  text has one encoding on every run.
* No prompt template. garak wraps the encoded text in a request to decode
  it ("Encoded: ...\\nDecoded:"), aimed at the model under test. The gateway
  judges a document, so the encoded text stands alone, which is garak's
  first template.

What is not taken: Base2048, Ecoji and Zalgo, which need third-party
packages. Base64 and Unicode tag characters are already gate transforms.

These are measured and never gated: ``benchmarks/l2_encodings.py`` scores
them and ``docs/benchmark.md`` holds the numbers. A transform joins the gate
by moving into ``TRANSFORMS`` in the change that says why.
"""

from __future__ import annotations

import base64
import binascii
import quopri
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

REPOSITORY = "https://github.com/NVIDIA/garak"
TAG = "v0.17.0"
COMMIT = "93aa9cdec309ec4170559676f1826ea2a679920c"
LICENSE = "Apache-2.0"

_UU_LINE = 45  # bytes a uuencoded line carries
_VARIANT_BLOCK = 0xE0100  # Variation Selectors Supplement
_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_ATBASH = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
)
_LEET = str.maketrans("ieaostIEAOST", "134057134057")
_BRAILLE = dict(
    zip(
        "abcdefghijklmnopqrstuvwxyz1234567890.',-/!?$:;() ",
        "\u2801\u2803\u2809\u2819\u2811\u280b\u281b\u2813\u280a\u281a\u2805\u2807\u280d"
        "\u281d\u2815\u280f\u281f\u2817\u280e\u281e\u2825\u2827\u283a\u282d\u283d\u2835"
        "\u2801\u2803\u2809\u2819\u2811\u280b\u281b\u2813\u280a\u281a"
        "\u2832\u2804\u2802\u2824\u280c\u2816\u2826\u2832\u2812\u2830\u2836\u2836 ",
        strict=True,
    )
)
_BRAILLE_NUMBER, _BRAILLE_CAPITAL = "\u283c", "\u2820"
_MORSE_CODES = (
    ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - "
    "..- ...- .-- -..- -.-- --.. .---- ..--- ...-- ....- ..... -.... --... ---.. ----. "
    "----- / / / /"
)
_MORSE = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 \n\r\t", _MORSE_CODES.split(), strict=True))
_NATO_WORDS = (
    "Alfa Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliett Kilo Lima Mike "
    "November Oscar Papa Quebec Romeo Sierra Tango Uniform Victor Whiskey Xray Yankee Zulu"
)
_NATO = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", _NATO_WORDS.split(), strict=True))
_SNEAKY_BITS = {"0": "\u2062", "1": "\u2064"}  # invisible times, invisible plus


def _base16(s: str) -> str:
    return base64.b16encode(s.encode()).decode()


def _base32(s: str) -> str:
    return base64.b32encode(s.encode()).decode()


def _hex(s: str) -> str:
    return binascii.b2a_hex(s.encode()).decode()


def _ascii85(s: str) -> str:
    return base64.a85encode(s.encode()).decode()


def _base85(s: str) -> str:
    return base64.b85encode(s.encode()).decode()


def _quoted_printable(s: str) -> str:
    return binascii.b2a_qp(s.encode()).decode()


def _uu(s: str) -> str:
    raw = s.encode()
    return "".join(
        binascii.b2a_uu(raw[i : i + _UU_LINE]).decode() for i in range(0, len(raw), _UU_LINE)
    )


def _mime(s: str) -> str:
    return quopri.encodestring(s.encode()).decode()


def _rot13(s: str) -> str:
    return s.translate(_ROT13)


def _atbash(s: str) -> str:
    return s.translate(_ATBASH)


def _leetspeak(s: str) -> str:
    toss = random.Random(s)
    return "".join(
        swapped if toss.random() > 0.5 else c
        for c, swapped in zip(s, s.translate(_LEET), strict=True)
    )


def _braille(s: str) -> str:
    out: list[str] = []
    for c in s:
        if c in "\n\r\t":
            out.append(c)
        elif c.isupper():
            if c.lower() in _BRAILLE:
                out += (_BRAILLE_CAPITAL, _BRAILLE[c.lower()])
        elif c in _BRAILLE:
            if c.isdigit():
                out.append(_BRAILLE_NUMBER)
            out.append(_BRAILLE[c])
    return "".join(out)


def _morse(s: str) -> str:
    return " ".join(_MORSE[c] for c in s.upper() if c in _MORSE)


def _nato(s: str) -> str:
    return " ".join(_NATO[c] for c in s.upper() if c in _NATO)


def _variant_selectors(s: str) -> str:
    return "".join(chr(_VARIANT_BLOCK + ord(c)) for c in s)


def _sneaky_bits(s: str) -> str:
    return "".join(
        "\u200b" if c == " " else "".join(_SNEAKY_BITS[bit] for bit in f"{ord(c):b}") for c in s
    )


#: Encoders whose alphabet is ASCII letters and digits only. garak's `_braille`
#: and `_morse` drop every character they have no cell or code for at ENCODE
#: time, so a mostly-non-Latin payload is a benign fragment before unpack ever
#: sees it — measuring unpack's recovery on it measures garak, not the pipeline
#: (#546, #423). The byte encoders (base*, UU, Ascii85) carry any text.
LATIN_ONLY = frozenset({"Braille", "Morse"})

#: The share of a payload's alphanumerics an ASCII-only encoder must be able to
#: carry for decoding it to be a fair measure of unpack rather than of garak.
CARRY_MIN_ASCII_ALNUM = 0.9


def carries(name: str, text: str) -> bool:
    """Whether encoder ``name`` can carry enough of ``text`` that decoding it
    measures trentina's unpack stage, not garak's lossy encoder (#546).

    A non-:data:`LATIN_ONLY` encoder carries everything. A Latin-only one
    (Braille, Morse) carries ``text`` only when at least
    :data:`CARRY_MIN_ASCII_ALNUM` of its alphanumerics are ASCII a-z/0-9 — the
    characters those alphabets have a code for; garak drops the rest."""
    if name not in LATIN_ONLY:
        return True
    alnums = [c for c in text if c.isalnum()]
    if not alnums:
        return False
    return sum(c.isascii() for c in alnums) / len(alnums) >= CARRY_MIN_ASCII_ALNUM


ENCODINGS: dict[str, Callable[[str], str]] = {
    "base16": _base16,
    "base32": _base32,
    "hex": _hex,
    "Ascii85": _ascii85,
    "base85": _base85,
    "quoted-printable": _quoted_printable,
    "UU": _uu,
    "MIME": _mime,
    "ROT13": _rot13,
    "Atbash": _atbash,
    "leetspeak": _leetspeak,
    "Braille": _braille,
    "Morse": _morse,
    "NATO alphabet": _nato,
    "Unicode variant selectors": _variant_selectors,
    "sneaky bits": _sneaky_bits,
}
"""garak's stdlib encodings, by the name the benchmark reports them under."""
