"""The disguised attacks in ``benchmarks/llm_completion.py`` reach L3 readable (a1013).

The benchmark asks whether L3 still flags an attack an answer labels as
encrypted reasoning. That only measures L3 if the unpack stage hands it the
attack decoded; a disguise the layers cannot read would be a coverage gap,
not a briefing result.
"""

from __future__ import annotations

import json
import re

import pytest

from benchmarks.llm_completion import disguised_cases
from corpora.internal import ATTACKS
from trentina.unpack import scan

TEMPLATE = json.dumps(
    {
        "id": "gen-1",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "reasoning_details": [{"type": "reasoning.encrypted", "data": "QUJD" * 300}],
                }
            }
        ],
    }
)

CASES = disguised_cases(TEMPLATE)

WORD = re.compile(r"[A-Za-z]{3,}")
READ_SHARE = 0.8
"""Share of the attack's words the layers must read. Not all: the letter
reading leaves one-letter words as they arrived, and reads leetspeak back
into plain words."""

UNREAD = frozenset(
    {
        "rot13/obfuscation_semantic/obf-leetspeak-directive",
        "rot13/obfuscation_semantic/obf-spanish-directive",
        "rot13/obfuscation_semantic/obf-acrostic-instruction",
        "rot13/multilingual/ml-german-wiki-credentials",
        "rot13/multilingual/ml-japanese-mail-forward",
    }
)
"""Disguised attacks that reach L3 still ciphered: ROT13 is read back only
when the reading is English (known gap 22), and leet under ROT13 or an
acrostic of short lines is not. In the benchmark these test the briefing's
rule that an opaque value in the answer is content. One that starts being
read fails here and leaves the set."""


def test_every_attack_is_disguised_both_ways() -> None:
    assert len(CASES) == 2 * len(ATTACKS)


@pytest.mark.parametrize(("case_id", "body"), CASES, ids=[case_id for case_id, _ in CASES])
def test_the_layers_read_the_attack_decoded(case_id: str, body: str) -> None:
    attack = next(c for c in ATTACKS if case_id.endswith(f"/{c.id}"))
    read = set(WORD.findall(scan.unpack(body).text))
    words = set(WORD.findall(attack.payload))
    assert (len(words & read) >= READ_SHARE * len(words)) is (case_id not in UNREAD)
