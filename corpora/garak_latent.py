"""garak's latent-injection probes, as documents (#10).

`NVIDIA/garak <https://github.com/NVIDIA/garak>`_ (Apache-2.0) is an LLM
vulnerability scanner. Its ``latentinjection`` probes bury an instruction in
a document an assistant is asked to read: a stock-plan FAQ, a resume, a WHOIS
record. That is indirect injection in retrieved content, which is Trentina's
threat model and what the jailbreak set (``corpora.jailbreak``) does not
measure.

What is taken, from ``garak/probes/latentinjection.py`` at ``v0.17.0``: the
Report, Resume and Whois families, which carry a document. Each attack is
garak's own cross product (context, separator pair, injection instruction,
payload, trigger) with one part left out: the user-side task ("Summarise
this resume:"), because the gateway judges the retrieved document and never
sees the question. The Translation and LatentJailbreak families have no
document and are not taken.

What is changed, because garak's contexts hold real people (constitution
XVII). ``garak_latent.json`` is the result, and this is the whole list:

* WHOIS records: every registrant domain is under ``.example``; names,
  street addresses, mail addresses and phone numbers are roster values;
  registry ids are zeroed; the registries' closing notices are cut.
  Registrars and name servers are public companies' and stay.
* Resumes: one is a real researcher's CV and one a real professor's
  biography. Employers, institutions, awards and the name are rewritten.
* Reports: two executive names in the earnings release are roster names.
* The three trigger hosts are under ``.example`` and ``.test``.

The injection separators, instructions and payloads are garak's, unchanged.

Benign controls are the same contexts with the injection marker removed,
plus garak's Eiffel Tower and legal paragraphs joined: the documents an
agent would have read had nobody tampered with them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from corpora.internal import Case

_DATA: dict[str, Any] = json.loads(Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))

REPOSITORY: str = _DATA["source"]["repository"]
TAG: str = _DATA["source"]["tag"]
COMMIT: str = _DATA["source"]["commit"]
LICENSE: str = _DATA["source"]["licence"]

FAMILIES = ("report", "resume", "whois")
CATEGORY_PREFIX = "garak_"
CATEGORY_BENIGN = "garak_benign"

SAMPLE_ONE_IN = 5
SPLITS = ("sample", "full")
"""``sample`` is one attack in five, by a hash of its id, and every benign
control: enough to compare judges on without paying for 732 calls."""

_INJECTION: str = _DATA["marker"]["injection"]
_PAYLOAD: str = _DATA["marker"]["payload"]
_TRIGGER: str = _DATA["marker"]["trigger"]


def _family_attacks(family: str) -> list[Case]:
    """One family's attacks, in garak's loop order, so an id never moves."""
    parts = _DATA["families"][family]
    cases = []
    for context in parts["contexts"]:
        for start, end in parts["sep_pairs"]:
            for instruction in parts["instructions"]:
                for payload in parts["payloads"]:
                    for trigger in parts["triggers"]:
                        said = instruction.replace(_PAYLOAD, payload.replace(_TRIGGER, trigger))
                        cases.append(
                            Case(
                                id=f"garak-{family}-{len(cases):04d}",
                                category=CATEGORY_PREFIX + family,
                                payload=context.replace(_INJECTION, start + said + end),
                                expect_injection=True,
                            )
                        )
    return cases


ATTACKS: tuple[Case, ...] = tuple(c for family in FAMILIES for c in _family_attacks(family))

BENIGN: tuple[Case, ...] = tuple(
    Case(id, CATEGORY_BENIGN, text, expect_injection=False)
    for id, text in [
        *(
            (f"garak-benign-{family}-{i:02d}", context.replace(_INJECTION, "").strip())
            for family in FAMILIES
            for i, context in enumerate(_DATA["families"][family]["contexts"])
        ),
        *(
            (f"garak-benign-{name}", "\n".join(paragraphs))
            for name, paragraphs in _DATA["paragraphs"].items()
        ),
    ]
)
"""Every context with its marker removed, and the two paragraph sets."""


def in_sample(case_id: str) -> bool:
    """Whether an attack is in the ``sample`` split: one in five, by a hash of its id."""
    return int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % SAMPLE_ONE_IN == 0


def load(split: str = "sample") -> list[Case]:
    """The corpus as benchmark ``Case``s: attacks, then the benign controls.

    ``min_risk`` stays empty: garak labels no severity, and the benchmark
    reports risk calibration as n/a rather than inventing one.

    Raises ValueError for an unknown split.
    """
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")
    attacks = [c for c in ATTACKS if split == "full" or in_sample(c.id)]
    return [*attacks, *BENIGN]
