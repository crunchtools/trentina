"""The L2 lone-flag join (#404): its arithmetic, and that it reads each result shape."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

from benchmarks import l2_lone_flag as lone
from benchmarks import prompt_pack
from corpora import disclosed
from corpora.fetch import CACHE_DIR
from corpora.internal import CORPUS
from trentina.quarantine.classifier import ClassifierResult

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

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


def test_corpora_results_are_gathered_by_judge() -> None:
    internal, published = CORPUS[0], disclosed.CORPUS[0]
    other = "anthropic/claude-haiku-4.5"

    def cases(case_id: str, expect: bool, detected: bool, error: bool = False) -> list[object]:
        return [{"id": case_id, "expect_injection": expect, "detected": detected, "error": error}]

    runs = [
        # One result with two providers, then a second result for the first judge.
        {
            "providers": [
                {"model": JUDGE, "cases": cases(internal.id, internal.expect_injection, True)},
                {"model": other, "cases": cases(published.id, expect=True, detected=True)},
            ]
        },
        {"providers": [{"model": JUDGE, "cases": cases(published.id, True, detected=False)}]},
        {"providers": [{"model": JUDGE, "cases": cases(published.id, True, False, error=True)}]},
    ]
    first, second = lone.corpora_rows(runs, _l2_flags(published.payload))
    assert (first.judge, first.cleared, first.cleared_l2, first.unmatched) == (JUDGE, 1, 1, 1)
    assert (second.judge, second.attacks, second.cleared) == (other, 1, 0)


def test_meeting_notes_are_a_row_of_their_own() -> None:
    """#450: all benign, so the number is how many only L2 refuses."""
    notes = lone.notes_texts()
    linked, plain = "meeting_notes-00", "meeting_notes_unlinked-00"
    verdicts = [
        {"id": linked, "expect_injection": False, "detected": False},
        {"id": plain, "expect_injection": False, "detected": False},
    ]
    (row,) = lone.corpora_rows(
        [{"providers": [{"model": JUDGE, "cases": verdicts}]}], _l2_flags(notes[linked])
    )
    assert (row.source, row.judge) == (lone.NOTES, JUDGE)
    assert (row.attacks, row.benign, row.judge_flagged, row.only_l2) == (0, 2, 0, 1)


def test_l2_reads_each_text_unpacked_and_once(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def classify(text: str) -> ClassifierResult | None:
        asked.append(text)
        if "silent" in text:
            return None
        label = "MALICIOUS" if "attack" in text else "BENIGN"
        return ClassifierResult(label=label, score=0.9, latency_ms=1.0)

    monkeypatch.setattr(lone, "classify", classify)
    flagged = lone._l2_flags()
    packed = "Note: " + base64.b64encode(b"an attack hidden in base64, long enough").decode()
    assert [flagged(packed), flagged(packed), flagged("benign"), flagged("silent")] == [
        True,
        True,
        False,
        False,
    ]
    assert asked == ["Note: an attack hidden in base64, long enough", "benign", "silent"]


def test_main_needs_a_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lone, "is_classifier_available", lambda: False)
    assert lone.main([]) == 2


def test_main_writes_the_table_and_the_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    published = disclosed.CORPUS[0]
    case = {"id": published.id, "expect_injection": True, "detected": False, "error": False}
    result = tmp_path / "benchmark.json"
    result.write_text(json.dumps({"providers": [{"model": JUDGE, "cases": [case]}]}))
    monkeypatch.setattr(lone, "is_classifier_available", lambda: True)
    monkeypatch.setattr(lone, "model_info", lambda: None)
    monkeypatch.setattr(lone, "_l2_flags", lambda: _l2_flags(published.payload))

    rows = tmp_path / "rows.json"
    assert lone.main(["--corpora", str(result), "--json", str(rows)]) == 0
    assert f"| internal, garak, disclosed | {JUDGE} | 1 | 1 | 1 | 0 |" in capsys.readouterr().out
    assert json.loads(rows.read_text())[0]["cleared_l2"] == 1


def test_render_is_one_line_per_row() -> None:
    row = lone.tally("set", JUDGE, [lone.Judged("a", attack=True, detected=False)], _l2_flags(), 0)
    table = lone.render([row, row]).splitlines()
    assert len(table) == 4
    assert table[2] == f"| set | {JUDGE} | 1 | 1 | 0 | 1 | 0 | 0 | 0 |"
