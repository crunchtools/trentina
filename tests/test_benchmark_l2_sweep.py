"""The offline L2 threshold sweep (issue #86): arithmetic and harness wiring."""

from __future__ import annotations

import json
from itertools import pairwise
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from benchmarks import l2_sweep
from benchmarks import provider_benchmark as bench
from corpora.internal import CORPUS, Case
from trentina.quarantine.classifier import ClassifierResult

if TYPE_CHECKING:
    from pathlib import Path

SCORED = [(0.95, True), (0.80, True), (0.30, True), (0.60, False), (0.10, False)]


def test_point_counts_at_or_above_as_flagged() -> None:
    p = l2_sweep.point(SCORED, 0.60)
    assert (p.tp, p.fn, p.fp, p.tn) == (2, 1, 1, 1)
    assert p.detection == pytest.approx(2 / 3)
    assert p.fp_rate == pytest.approx(0.5)
    assert p.precision == pytest.approx(2 / 3)


@pytest.mark.parametrize(
    ("scored", "zeroed"),
    [
        ([(0.9, False)], "detection"),
        ([(0.9, True)], "fp_rate"),
        ([(0.1, True), (0.1, False)], "precision"),
    ],
)
def test_empty_denominator_reads_zero(scored: list[tuple[float, bool]], zeroed: str) -> None:
    assert getattr(l2_sweep.point(scored, 0.5), zeroed) == 0.0


def test_sweep_is_monotone() -> None:
    points = l2_sweep.sweep(SCORED)
    assert [p.threshold for p in points] == list(l2_sweep.DEFAULT_GRID)
    for lo, hi in pairwise(points):
        assert hi.tp <= lo.tp
        assert hi.fp <= lo.fp


def test_best_searches_observed_scores() -> None:
    # 0.80 catches 2/3 with 0 FP (J 0.67); 0.30 is J 0.5, 0.60 is J 0.17.
    top = l2_sweep.best(SCORED)
    assert top is not None
    assert top.threshold == pytest.approx(0.80)


def test_best_returns_an_off_grid_observed_score() -> None:
    scored = [(0.8123, True), (0.95, True), (0.30, True), (0.60, False), (0.10, False)]
    top = l2_sweep.best(scored)
    assert top is not None
    assert top.threshold == 0.8123


def test_best_breaks_a_tie_toward_the_higher_cutoff() -> None:
    # 0.9: 1/2 attacks, 0/2 FP (J 0.5). 0.5: 2/2 attacks, 1/2 FP (J 0.5).
    tied = [(0.9, True), (0.5, True), (0.7, False), (0.1, False)]
    top = l2_sweep.best(tied)
    assert top is not None
    assert top.threshold == pytest.approx(0.9)


def test_best_prefers_flagging_nothing_when_scores_do_not_separate() -> None:
    top = l2_sweep.best([(0.5, True), (0.5, False)])
    assert top is not None
    assert top.threshold > 0.5
    assert top.tp + top.fp == 0


@pytest.mark.parametrize("scored", [[], [(0.9, True)], [(0.1, False)]])
def test_best_undefined_without_both_classes(scored: list[tuple[float, bool]]) -> None:
    assert l2_sweep.best(scored) is None


def test_markdown_marks_current_and_warns_on_small_benign_set() -> None:
    md = l2_sweep.render_markdown(SCORED, 0.5)
    assert "| **0.50** |" in md
    assert "Low resolution" in md
    assert "Best separation" not in md


def test_markdown_without_benign_calls_fp_undefined() -> None:
    md = l2_sweep.render_markdown([(0.9, True), (0.2, True)], 0.5)
    assert "FP rate is undefined" in md
    assert "Best separation" not in md


def test_markdown_names_best_cutoff_on_enough_benign() -> None:
    scored = [*SCORED, *[(0.05, False)] * l2_sweep.MIN_BENIGN_FOR_FP]
    md = l2_sweep.render_markdown(scored, 0.5)
    assert "Low resolution" not in md
    assert "Best separation" in md


def test_markdown_inserts_off_grid_current() -> None:
    md = l2_sweep.render_markdown(SCORED, 0.72)
    assert "| **0.72** |" in md


def test_markdown_without_scores_says_so() -> None:
    assert "No scores were produced" in l2_sweep.render_markdown([], 0.5, unscored=4)


def test_threshold_in_force_is_the_models_own() -> None:
    """A profile leaves l2_threshold unset, so the loaded model decides (#350)."""
    from trentina.config import DEFAULT_CLASSIFIER_THRESHOLD
    from trentina.gateway.profile import DefenseConfig
    from trentina.quarantine.classifier import ModelInfo

    assert DefenseConfig().l2_threshold is None
    with patch.object(bench, "model_info", return_value=None):
        assert bench.l2_threshold_in_force() == DEFAULT_CLASSIFIER_THRESHOLD
    model = ModelInfo(id="m", revision="r", threshold=0.7, malicious=(1,))
    with patch.object(bench, "model_info", return_value=model):
        assert bench.l2_threshold_in_force() == 0.7


def _fake_score(text: str, **_: object) -> ClassifierResult:
    return ClassifierResult(label="BENIGN", score=len(text) % 97 / 100, latency_ms=0.0)


def test_l2_only_run_writes_scores_and_sweep_without_providers(tmp_path: Path) -> None:
    with (
        patch.object(bench, "is_classifier_available", return_value=True),
        patch("trentina.defense.classify_async", side_effect=_fake_score),
        patch.object(bench, "available_providers", side_effect=AssertionError("no providers")),
    ):
        rc = bench.main(["--l2-only", "--limit", "6", "--out", str(tmp_path)])
    assert rc == 0
    (json_path,) = tmp_path.glob("*.json")
    payload = json.loads(json_path.read_text())
    assert payload["providers"] == []
    l2 = payload["l2"]["internal"]
    assert len(l2["scores"]) == 6
    assert all(s is not None for s in l2["scores"].values())
    assert len(l2["sweep"]) == len(l2_sweep.DEFAULT_GRID)
    (md_path,) = tmp_path.glob("*.md")
    assert "## L2 threshold sweep" in md_path.read_text()


def test_missing_model_yields_none_scores(tmp_path: Path) -> None:
    with patch.object(bench, "is_classifier_available", return_value=False):
        rc = bench.main(["--l2-only", "--limit", "3", "--out", str(tmp_path)])
    assert rc == 0
    (json_path,) = tmp_path.glob("*.json")
    payload = json.loads(json_path.read_text())
    assert set(payload["l2"]["internal"]["scores"].values()) == {None}
    assert payload["l2"]["internal"]["best_threshold"] is None


async def test_score_l2_reads_each_payload_once_as_it_arrived() -> None:
    # A zero-width space inside a word: L1 counts it, L2 still reads only the
    # arrived bytes (#359).
    case = Case(id="zw", category="t", payload="ig\u200bnore this", expect_injection=True)

    async def score(_text: str, **_: object) -> ClassifierResult:
        return ClassifierResult(label="BENIGN", score=0.2, latency_ms=0.0)

    with (
        patch.object(bench, "is_classifier_available", return_value=True),
        patch("trentina.defense.classify_async", side_effect=score) as spy,
    ):
        scores = await bench.score_l2([case])
    assert [c.args[0] for c in spy.call_args_list] == [case.payload]
    assert scores == {"zw": 0.2}


async def test_score_l2_records_a_failed_scan_as_none() -> None:
    cases = list(CORPUS[:2])

    async def score(text: str, **_: object) -> ClassifierResult:
        if text == cases[0].payload:
            raise RuntimeError("boom")
        return ClassifierResult(label="BENIGN", score=0.3, latency_ms=0.0)

    with (
        patch.object(bench, "is_classifier_available", return_value=True),
        patch("trentina.defense.classify_async", side_effect=score),
    ):
        scores = await bench.score_l2(cases)
    assert scores == {cases[0].id: None, cases[1].id: 0.3}


def test_provider_run_attaches_each_cases_own_score(tmp_path: Path) -> None:
    cases = list(CORPUS[:3])
    scores = {c.id: round(0.1 * (i + 1), 6) for i, c in enumerate(cases)}

    async def fake_scores(_: list[Case]) -> dict[str, float | None]:
        return dict(scores)

    async def fake_run(provider: str, run_cases: list[Case], *_: object) -> bench.ProviderReport:
        report = bench.ProviderReport(provider=provider, model="m")
        for c in reversed(run_cases):
            report.results.append(
                bench.CaseResult(
                    id=c.id,
                    category=c.category,
                    expect_injection=c.expect_injection,
                    min_risk=c.min_risk,
                    detected=True,
                    risk_level="high",
                    latency_ms=1.0,
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=0.0,
                    error=False,
                )
            )
        return report

    with (
        patch.object(bench, "available_providers", return_value=["gemini"]),
        patch.object(bench, "score_l2", side_effect=fake_scores),
        patch.object(bench, "run_provider", side_effect=fake_run),
    ):
        rc = bench.main(["--limit", "3", "--out", str(tmp_path)])
    assert rc == 0
    (json_path,) = tmp_path.glob("*.json")
    (provider,) = json.loads(json_path.read_text())["providers"]
    assert {c["id"]: c["l2_malicious_score"] for c in provider["cases"]} == scores
