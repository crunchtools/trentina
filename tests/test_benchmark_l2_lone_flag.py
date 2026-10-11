"""The L2 lone-flag join (#404): its arithmetic, and that it reads each result shape."""

from __future__ import annotations

from benchmarks import l2_lone_flag as lone
from benchmarks import prompt_pack
from corpora import disclosed
from corpora.fetch import CACHE_DIR
from corpora.internal import CORPUS

JUDGE = "google/gemini-2.5-flash-lite"


def _l2_flags(*texts: str) -> lone.Callable[[str], bool]:
    return lambda text: text in texts


def test_tally_splits_the_judges_misses_by_l2s_label() -> None:
    cases = [
        lone.Judged("caught", attack=True, detected=True),
        lone.Judged("only L2", attack=True, detected=False),
        lone.Judged("nobody", attack=True, detected=False),
        lone.Judged("clean", attack=False, detected=False),
        lone.Judged("L2 alone refuses", attack=False, detected=False),
        lone.Judged("both refuse", attack=False, detected=True),
    ]
    row = lone.tally(
        "set", JUDGE, cases, _l2_flags("only L2", "L2 alone refuses", "both refuse"), 2
    )
    assert (row.attacks, row.cleared, row.cleared_l2, row.cleared_both) == (3, 2, 1, 1)
    # A benign document both refuse costs nothing extra: the judge refused it anyway.
    assert (row.benign, row.judge_flagged, row.only_l2) == (3, 1, 1)
    assert row.unmatched == 2


def test_a_pack_result_is_read_by_the_cases_it_names() -> None:
    held_out = prompt_pack.split_cases("held-out", prompt_pack.TRAIN_EXTERNAL, CACHE_DIR)
    attack = next(c for c in held_out if c.expect_injection)
    benign = next(c for c in held_out if not c.expect_injection)
    run = {
        "split": "held-out",
        "model": JUDGE,
        "pack": "generic",
        "missed": [attack.id, "a-case-this-checkout-no-longer-has"],
        "flagged_benign": [benign.id],
    }
    row = lone.pack_row(run, _l2_flags(attack.payload))
    assert row.attacks == sum(c.expect_injection for c in held_out)
    assert (row.cleared, row.cleared_l2, row.cleared_both) == (1, 1, 0)
    assert (row.judge_flagged, row.only_l2, row.unmatched) == (1, 0, 1)


def test_a_judge_result_is_read_by_document() -> None:
    documents = lone.embedded_documents()
    attack = next(name for name in documents if "+" in name and "benign" not in name)
    clean = next(name for name in documents if "+" not in name)
    run = {
        "model": JUDGE,
        "briefing": "benign",
        "verdicts": [
            {"document": attack, "condition": "attack", "detected": False},
            {"document": clean, "condition": "clean", "detected": False},
            {"document": "not-a-document", "condition": "attack", "detected": False},
        ],
    }
    row = lone.judged_row(run, _l2_flags(documents[clean]))
    assert row.source.endswith("briefing benign")
    assert (row.attacks, row.cleared, row.cleared_both) == (1, 1, 1)
    assert (row.benign, row.only_l2, row.unmatched) == (1, 1, 1)


def test_one_judges_corpora_are_one_row() -> None:
    internal, published = CORPUS[0], disclosed.CORPUS[0]

    def result(
        case_id: str, expect: bool, detected: bool, error: bool = False
    ) -> dict[str, object]:
        row = {"id": case_id, "expect_injection": expect, "detected": detected, "error": error}
        return {"providers": [{"model": JUDGE, "cases": [row]}]}

    runs = [
        result(internal.id, internal.expect_injection, detected=True),
        result(published.id, expect=True, detected=False),
        result(published.id, expect=True, detected=False, error=True),
    ]
    row = lone.corpora_row(runs, _l2_flags(published.payload))
    assert row.judge == JUDGE
    assert (row.cleared, row.cleared_l2, row.unmatched) == (1, 1, 1)


def test_render_is_one_line_per_row() -> None:
    row = lone.tally("set", JUDGE, [lone.Judged("a", attack=True, detected=False)], _l2_flags(), 0)
    table = lone.render([row, row]).splitlines()
    assert len(table) == 4
    assert table[2] == f"| set | {JUDGE} | 1 | 1 | 0 | 1 | 0 | 0 | 0 |"
