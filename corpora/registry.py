"""Every corpus in this directory: what it is called, whose it is, how it is held.

``docs/corpora.md`` is the account of where each one came from and why.
``tests/test_corpora_registry.py`` holds the two together: a module here
with no record, or a record with no section in that page, fails.
"""

from __future__ import annotations

from dataclasses import dataclass

VENDORED = "vendored"
FETCHED = "fetched"


@dataclass(frozen=True)
class Corpus:
    """One corpus.

    Attributes:
        name: Its heading in ``docs/corpora.md``.
        module: The module under ``corpora/`` that holds or loads it.
        source: Who wrote the text.
        licence: The licence the text is under (SPDX id).
        storage: ``VENDORED`` (in this repository) or ``FETCHED`` (downloaded
            at a pinned revision into ``corpora/data/`` and checked by hash).
        prefix: The category prefix that marks its cases in a run that mixes
            corpora, so each is reported apart. Empty when it has none.
    """

    name: str
    module: str
    source: str
    licence: str
    storage: str
    prefix: str = ""


OURS = "written for this repository"

CORPORA: tuple[Corpus, ...] = (
    Corpus("Internal", "internal", OURS, "AGPL-3.0-or-later", VENDORED),
    Corpus("L1 patterns", "l1_patterns", OURS, "AGPL-3.0-or-later", VENDORED),
    Corpus("OWASP test list", "owasp", "OWASP Cheat Sheet Series", "CC-BY-SA-4.0", VENDORED),
    Corpus("Benign operations output", "benign_ops", OURS, "AGPL-3.0-or-later", VENDORED),
    Corpus("Detonation", "detonation", OURS, "AGPL-3.0-or-later", VENDORED),
    Corpus(
        "Jailbreak classification",
        "jailbreak",
        "jackhhao/jailbreak-classification",
        "Apache-2.0",
        FETCHED,
        prefix="external_",
    ),
    Corpus("InjecAgent", "injecagent", "uiuc-kang-lab/InjecAgent", "MIT", FETCHED),
)

SUPPORT: frozenset[str] = frozenset({"fetch", "registry"})
"""Modules here that hold no corpus."""
