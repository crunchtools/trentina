"""The agent-egress-bench's deterministic axes, as a regression gate (#507).

The DLP (credential detector) and SSRF (route rails) axes need no judge, so
they run in ordinary CI, not only on a hand-dispatched benchmark. A credential
that stops being caught, or a rail that stops refusing, fails here.
"""

from __future__ import annotations

import pytest

from benchmarks.egress_bench import _rail_reason, score_deterministic
from corpora.egress_bench import CASES, CATEGORIES, DETERMINISTIC, JUDGED, EgressCase

_VALID_KINDS = {"request", "rail", "response"}


def test_the_corpus_is_well_formed() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)), "case ids must be unique"
    assert {c.kind for c in CASES} <= _VALID_KINDS
    assert {c.category for c in CASES} <= set(CATEGORIES)
    # A rail case that should block must name the reason it expects.
    for c in CASES:
        if c.kind == "rail" and c.expect_block:
            assert c.rail_reason is not None, f"{c.id}: no expected rail reason"


def test_the_two_axes_partition_the_corpus() -> None:
    det, judged, whole = (
        {c.id for c in DETERMINISTIC},
        {c.id for c in JUDGED},
        {c.id for c in CASES},
    )
    assert det | judged == whole
    assert not (det & judged)


@pytest.mark.parametrize("case", DETERMINISTIC, ids=lambda c: c.id)
def test_every_deterministic_case_scores_as_expected(case: EgressCase) -> None:
    blocked, note = score_deterministic(case)
    assert note is None, note  # a rail-reason mismatch is a note; there must be none
    assert blocked is case.expect_block


def test_each_rail_case_refuses_with_its_named_reason() -> None:
    for case in (c for c in CASES if c.kind == "rail"):
        reason = _rail_reason(case)
        if case.expect_block:
            assert reason == case.rail_reason, f"{case.id}: {reason}"
        else:
            assert reason is None, f"{case.id}: unexpectedly refused with {reason}"


def test_the_benign_suite_covers_both_axes() -> None:
    benign = [c for c in CASES if c.category == "benign"]
    assert any(c.kind == "request" for c in benign)  # the detector half
    assert any(c.kind == "response" for c in benign)  # the judged half
