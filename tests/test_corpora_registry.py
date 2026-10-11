"""The corpora directory, its registry and ``docs/corpora.md`` say the same thing."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from corpora import benign_ops, detonation, injecagent, internal, jailbreak
from corpora.registry import CORPORA, FETCHED, SUPPORT, VENDORED, Corpus

_ROOT = Path(__file__).resolve().parent.parent
_PAGE = (_ROOT / "docs" / "corpora.md").read_text(encoding="utf-8")


def test_every_module_is_a_registered_corpus_or_support() -> None:
    modules = {p.stem for p in (_ROOT / "corpora").glob("*.py")} - {"__init__"}
    assert modules == {c.module for c in CORPORA} | SUPPORT


@pytest.mark.parametrize("corpus", CORPORA, ids=lambda c: c.module)
def test_a_corpus_imports_and_has_its_section(corpus: Corpus) -> None:
    importlib.import_module(f"corpora.{corpus.module}")
    assert corpus.storage in (VENDORED, FETCHED)
    assert f"\n### {corpus.name}\n" in _PAGE
    row = next(line for line in _PAGE.splitlines() if f"`corpora/{corpus.module}.py`" in line)
    assert corpus.licence in row
    assert corpus.storage in row


def test_a_fetched_corpus_names_its_pin_on_the_page() -> None:
    assert jailbreak.REVISION[:12] in _PAGE
    assert injecagent.INJECAGENT_COMMIT[:12] in _PAGE


def test_the_registry_repeats_each_loader_licence() -> None:
    held = {c.module: c.licence for c in CORPORA}
    assert held["jailbreak"] == jailbreak.LICENSE
    assert held["injecagent"] == injecagent.INJECAGENT_LICENSE


def test_ids_are_unique_across_the_vendored_corpora() -> None:
    ids = [
        *(c.id for c in internal.CORPUS),
        *(c.id for c in benign_ops.BENIGN),
        *(c.id for c in detonation.CARRIERS),
        *(c.id for c in detonation.ACTION_ATTACKS),
        *(c.id for c in detonation.BENIGN_INSERTS),
    ]
    assert len(ids) == len(set(ids))


def test_a_category_prefix_marks_one_corpus_only() -> None:
    prefixes = [c.prefix for c in CORPORA if c.prefix]
    assert len(prefixes) == len(set(prefixes))
    assert jailbreak.CATEGORY_PREFIX in prefixes
    for category in internal.CATEGORIES:
        assert not category.startswith(tuple(prefixes))
