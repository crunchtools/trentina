"""A literal prefilter for the exact directive patterns (#709).

Most lines contain none of the words any pattern needs, yet each was run
through every pattern, then again in ROT13 and reversed. ``LITERALS`` names,
per pattern, words of which at least one must appear for it to match. One
Aho-Corasick pass over the raw line finds them in three spellings (plain,
ROT13, reversed); both transforms preserve substrings, so a ROT13 spelling in
the raw line is the plain word in the ROT13 line.

The filter only over-approximates: it picks which patterns to run, and the
real regex still decides. A line it cannot reason about (non-ASCII, where
case folding and ROT13 do not commute) gets no verdict for the ciphered
spellings and is scanned ungated.
"""

from __future__ import annotations

import codecs
import unicodedata
from dataclasses import dataclass

#: The key for the ``IMPORTANT:``-style prefix rule, which is not in ``PATTERNS``.
PREFIX = "_prefix"

#: Per pattern, the words of which at least one is present in any match
#: (lowercase). The rarest required word, not the first: ``show_prompt``
#: keys on ``prompt``, since ``show`` passes nearly everything.
LITERALS: dict[str, tuple[str, ...]] = {
    PREFIX: ("important", "instruction", "override", "admin"),
    "ignore_previous_instructions": ("ignore",),
    "ignore_all_instructions": ("ignore",),
    "disregard_instructions": ("disregard",),
    "forget_instructions": ("forget",),
    "new_instructions": ("instruction",),
    "do_not_follow": ("follow",),
    "supersede_instructions": ("supersede",),
    "void_instructions": ("instruction",),
    "developer_mode": ("developer",),
    "enter_special_mode": ("developer", "admin", "debug", "maintenance"),
    "activate_special_mode": ("activate",),
    "system_override": ("override",),
    "override_instructions": ("override",),
    "reveal_prompt": ("reveal",),
    "show_prompt": ("prompt",),
    "what_instructions": ("instructions",),
    "repeat_instructions": ("repeat",),
    "output_prompt": ("prompt",),
    "system_prompt_label": ("prompt",),
    "remove_restrictions": ("longer",),
    "act_unbound": ("bound",),
    "pretend_different": ("pretend",),
    "identity_hijack": (
        "without",
        "ignor",
        "bypass",
        "unrestrict",
        "unlimit",
        "obey",
        "rules",
        "limits",
        "restrict",
        "boundari",
    ),
    "new_role": ("role",),
    "as_an_ai_you_must": ("must",),
    "dan_jailbreak": ("anything",),
    "jailbreak_mode": ("jailbreak",),
    "bypass_safety": ("bypass", "override"),
    "disable_safety": ("disable",),
    "ignore_safety": ("ignore", "disregard"),
    "system_tag_injection": ("system",),
    "role_tag_injection": ("assistant", "developer", "tool", "function"),
    "bracketed_role_spoofing": ("system", "assistant", "internal"),
    "system_prefix_spoofing": ("system",),
    "execute_the_following": ("execute",),
    "run_this_command": ("command",),
}

_PLAIN, _ROT13, _REVERSED = 0, 1, 2


@dataclass(frozen=True)
class Unlocked:
    """Pattern names worth running on a line, and on its ROT13 and reversed forms.

    ``None`` means "no verdict: run the ungated check".
    """

    plain: frozenset[str]
    rot13: frozenset[str] | None
    reversed: frozenset[str] | None


class _Automaton:
    def __init__(self, literals: dict[str, tuple[str, ...]]) -> None:
        goto: list[dict[str, int]] = [{}]
        out: list[list[tuple[int, str]]] = [[]]
        for name, words in literals.items():
            for word in words:
                spellings = (
                    (_PLAIN, word),
                    (_ROT13, codecs.encode(word, "rot13")),
                    (_REVERSED, word[::-1]),
                )
                for kind, spelling in spellings:
                    state = 0
                    for ch in spelling:
                        if ch not in goto[state]:
                            goto.append({})
                            out.append([])
                            goto[state][ch] = len(goto) - 1
                        state = goto[state][ch]
                    out[state].append((kind, name))
        fail = [0] * len(goto)
        queue = list(goto[0].values())
        while queue:
            state = queue.pop(0)
            for ch, nxt in goto[state].items():
                queue.append(nxt)
                f = fail[state]
                while f and ch not in goto[f]:
                    f = fail[f]
                fail[nxt] = goto[f].get(ch, 0)
                out[nxt] = out[nxt] + out[fail[nxt]]
        self._goto, self._fail, self._out = goto, fail, out

    def scan(self, text: str) -> tuple[set[str], set[str], set[str]]:
        found: tuple[set[str], set[str], set[str]] = (set(), set(), set())
        goto, fail, out = self._goto, self._fail, self._out
        state = 0
        for ch in text:
            while state and ch not in goto[state]:
                state = fail[state]
            state = goto[state].get(ch, 0)
            if out[state]:
                for kind, name in out[state]:
                    found[kind].add(name)
        return found


_AUTOMATON = _Automaton(LITERALS)

_DOTLESS_I = unicodedata.lookup("LATIN SMALL LETTER DOTLESS I")


def unlock(line: str) -> Unlocked:
    """The patterns that could match ``line``, or its ROT13 or reversed form."""
    if line.isascii():
        plain, rot, rev = _AUTOMATON.scan(line.lower())
        return Unlocked(frozenset(plain), frozenset(rot), frozenset(rev))
    # Fold as re.IGNORECASE does: casefold covers the long s and the Kelvin
    # sign; the dotless i (U+0131) is the one equivalence it leaves out.
    folded = line.casefold().replace(_DOTLESS_I, "i")
    plain, _, _ = _AUTOMATON.scan(folded)
    return Unlocked(frozenset(plain), None, None)
