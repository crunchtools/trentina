"""The L2 benign gate: its corpus, its record, and what startup does with it (#411).

No model is needed: the harness is run against a stand-in scorer, and the
record's arithmetic is plain counts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks import l2_benign
from corpora.benign_ops import BENIGN, CATEGORIES, KNOWN_GAPS, in_tuning
from trentina import posture
from trentina.errors import ConfigError
from trentina.perimeter_db import perimeter_stamp
from trentina.quarantine import classifier
from trentina.quarantine.benign_gate import (
    BENIGN_KEY,
    BENIGN_MIN_CASES,
    allowed,
    benign_state,
    record_of,
)

_HELD_OUT = [c for c in BENIGN if not in_tuning(c.id) and c.category not in KNOWN_GAPS]
"""What the gate counts: the held-out cases of the gated shapes."""


class TestCorpus:
    def test_ids_are_unique_and_the_corpus_never_moves(self) -> None:
        from corpora import benign_ops

        assert len({case.id for case in BENIGN}) == len(BENIGN)
        again = benign_ops._build()
        assert [(c.id, c.payload) for c in again] == [(c.id, c.payload) for c in BENIGN]

    def test_the_split_is_fixed_and_every_shape_is_on_both_sides(self) -> None:
        tuning = {case.id for case in BENIGN if in_tuning(case.id)}
        assert 0 < len(tuning) < len(BENIGN) / 2
        for name in (*CATEGORIES, *KNOWN_GAPS):
            sides = {in_tuning(case.id) for case in BENIGN if case.category == name}
            assert sides == {True, False}, name

    def test_a_known_gap_is_in_the_corpus_and_out_of_the_budget(self) -> None:
        assert not set(KNOWN_GAPS) & set(CATEGORIES)
        assert {c.category for c in BENIGN} == {*CATEGORIES, *KNOWN_GAPS}

    def test_the_held_out_split_is_large_enough_to_gate_on(self) -> None:
        assert len(_HELD_OUT) >= BENIGN_MIN_CASES
        assert allowed(len(_HELD_OUT)) >= 1

    def test_the_operations_shapes_carry_opaque_identifiers(self) -> None:
        """The property #411 is about: an ID no person wrote, in the payload."""
        opaque = re.compile(r"[0-9a-f]{32,64}|\$[A-Za-z0-9_-]{43}")
        for name in ("unit_status", "unit_show", "system_df", "container_list", "image_list"):
            for case in (c for c in BENIGN if c.category == name):
                assert opaque.search(json.dumps(case.payload)), case.id


class TestAsRead:
    async def test_a_tool_response_is_read_once_as_the_router_reads_it(self) -> None:
        """#431: the structured copy repeats the text block and is dropped."""
        case = next(c for c in BENIGN if c.category == "unit_status")
        read = await l2_benign.as_read(case)
        invocation = case.payload["properties"]["InvocationID"]
        assert read.startswith("{")
        assert read.count(invocation) == 1, "the text block, not the copy as well"

    async def test_a_document_is_read_as_it_is(self) -> None:
        case = next(c for c in BENIGN if c.category == "forum_reply")
        assert await l2_benign.as_read(case) == case.payload

    async def test_a_long_listing_is_read_as_the_pre_processors_leave_it(self) -> None:
        """The form that was refused: the minifier's output, not the backend's."""
        case = max(
            (c for c in BENIGN if c.category == "query_influxdb"),
            key=lambda c: len(c.payload["frames"][0]["rows"]),
        )
        read = await l2_benign.as_read(case)
        block = read.split("\n", 1)[0]
        assert len(block) < len(json.dumps(case.payload, separators=(",", ":")))
        assert "more element(s) with this shape" in block


class TestRecordArithmetic:
    def test_a_record_counts_every_category(self) -> None:
        record = record_of({"a": (1, 100), "b": (2, 100)}, 0.7)
        assert (record["cases"], record["flagged"], record["allowed"]) == (200, 3, 4)
        assert record["passed"] is True
        assert record["by_category"]["b"] == {"flagged": 2, "of": 100}

    def test_one_over_the_budget_fails(self) -> None:
        assert record_of({"a": (4, 200)}, 0.7)["passed"] is True
        assert record_of({"a": (5, 200)}, 0.7)["passed"] is False

    def test_too_few_cases_is_not_a_pass(self) -> None:
        assert record_of({"a": (0, BENIGN_MIN_CASES - 1)}, 0.7)["passed"] is False


class TestState:
    def test_no_record_is_unrecorded(self) -> None:
        assert benign_state({}) == "unrecorded"

    def test_the_verdict_is_recomputed_from_the_counts(self) -> None:
        passing = record_of({"a": (1, 200)}, 0.7)
        failing = record_of({"a": (9, 200)}, 0.7)
        assert benign_state({BENIGN_KEY: passing}) == "passed"
        assert benign_state({BENIGN_KEY: {**failing, "passed": True}}) == "failed"
        assert benign_state({BENIGN_KEY: {**passing, "passed": False}}) == "passed"

    def test_a_record_taken_at_another_threshold_says_nothing(self) -> None:
        """An operator's CLASSIFIER_THRESHOLD: a lower cut flags more."""
        record = record_of({"a": (1, 200)}, 0.7)
        assert benign_state({BENIGN_KEY: record}, 0.7) == "passed"
        assert benign_state({BENIGN_KEY: record}, 0.5) == "unrecorded"

    @pytest.mark.parametrize(
        "broken",
        [
            {"cases": True},
            {"flagged": -1},
            {"flagged": 500},
            {"threshold": "0.7"},
            {"threshold": None},
            {"threshold": float("nan")},
            {"threshold": float("inf")},
            {"threshold": 0.0},
            {"threshold": 1.5},
            {"cases": "200"},
        ],
    )
    def test_a_malformed_record_is_unrecorded(self, broken: dict[str, object]) -> None:
        # No threshold in force: nothing but the record's own checks can
        # refuse it, so each case is refused by the check it names.
        record = {**record_of({"a": (1, 200)}, 0.7), **broken}
        assert benign_state({BENIGN_KEY: record}) == "unrecorded"

    def test_a_nan_threshold_in_the_manifest_matches_no_threshold_in_force(self) -> None:
        """``json.loads`` reads a bare NaN, and NaN compares false with everything."""
        record = json.loads(json.dumps(record_of({"a": (1, 200)}, 0.7)).replace("0.7", "NaN"))
        assert benign_state({BENIGN_KEY: record}, 0.7) == "unrecorded"
        assert benign_state({BENIGN_KEY: record}, 0.1) == "unrecorded"

    def test_a_record_that_is_not_an_object_is_unrecorded(self) -> None:
        assert benign_state({BENIGN_KEY: "passed"}) == "unrecorded"


def _model_dir(tmp_path: Path, record: object = None, threshold: float = 0.7) -> str:
    (tmp_path / "config.json").write_text(json.dumps({"id2label": {"0": "SAFE", "1": "INJECTION"}}))
    manifest: dict[str, object] = {"id": "m", "threshold": threshold}
    if record is not None:
        manifest[BENIGN_KEY] = record
    (tmp_path / classifier.MANIFEST_FILE).write_text(json.dumps(manifest))
    return str(tmp_path)


def test_the_classifier_reads_the_record_at_the_threshold_in_force(tmp_path: Path) -> None:
    record = record_of({"a": (1, 200)}, 0.7)
    assert classifier.resolve_model(_model_dir(tmp_path)).benign_gate == "unrecorded"
    path = _model_dir(tmp_path, record)
    assert classifier.resolve_model(path).benign_gate == "passed"
    assert classifier.resolve_model(path, 0.4).benign_gate == "unrecorded"


def _startup_gaps(benign: str) -> list[str]:
    model = classifier.ModelInfo("m", "r", 0.7, (1,), gate="passed", benign_gate=benign)
    with patch.object(classifier, "model_info", return_value=model):
        return posture.check_l2_gate().gaps


class TestStartup:
    def test_a_passing_model_is_no_gap(self) -> None:
        assert _startup_gaps("passed") == []

    @pytest.mark.parametrize("state", ["failed", "unrecorded"])
    def test_any_other_state_is_named(self, state: str, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert _startup_gaps(state) == [f"l2_benign_gate_{state}"]
        assert f"l2_benign_gate_{state}" in caplog.text

    def test_require_hardened_refuses_to_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        with pytest.raises(ConfigError, match="l2_benign_gate_failed"):
            _startup_gaps("failed")

    def test_both_gates_failing_are_both_named(self) -> None:
        model = classifier.ModelInfo("m", "r", 0.7, (1,), gate="failed", benign_gate="failed")
        with patch.object(classifier, "model_info", return_value=model):
            assert posture.check_l2_gate().gaps == [
                "l2_obfuscation_gate_failed",
                "l2_benign_gate_failed",
            ]


def test_the_benign_gate_state_is_in_the_perimeter_stamp() -> None:
    def stamp(state: str) -> str:
        model = classifier.ModelInfo("m", "r", 0.7, (1,), gate="passed", benign_gate=state)
        with patch.object(classifier, "resolve_model", return_value=model):
            return perimeter_stamp()

    assert stamp("passed").endswith(":benign-passed")
    assert stamp("passed") != stamp("unrecorded")


class TestHarness:
    """``benchmarks/l2_benign.py`` against a stand-in scorer."""

    def _run(self, tmp_path: Path, score: float, *args: str) -> int:
        path = _model_dir(tmp_path)
        config = type("C", (), {"classifier_model_path": path})()
        model = classifier.ModelInfo("m", "r", 0.7, (1,))
        with (
            patch.object(l2_benign, "is_classifier_available", return_value=True),
            patch.object(l2_benign, "model_info", return_value=model),
            patch.object(l2_benign, "_score", return_value=score),
            patch.object(l2_benign, "get_config", return_value=config),
        ):
            return l2_benign.main(["--record", *args])

    def test_a_pass_is_recorded_and_exits_zero(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, 0.01) == 0
        resolved = classifier.resolve_model(str(tmp_path))
        assert resolved.benign_gate == "passed"
        assert resolved.id == "m", "the rest of the manifest is kept"
        record = json.loads((tmp_path / classifier.MANIFEST_FILE).read_text())[BENIGN_KEY]
        assert record["cases"] == len(_HELD_OUT), "held-out only: tuning is never recorded"
        assert set(record["by_category"]) == set(CATEGORIES)
        assert set(record["known_gaps"]) == set(KNOWN_GAPS), "measured, beside the result"

    def test_a_failure_is_recorded_and_exits_one(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, 0.99) == 1
        assert classifier.resolve_model(str(tmp_path)).benign_gate == "failed"

    def test_a_known_gap_flagged_does_not_fail_the_gate(self, tmp_path: Path) -> None:
        gaps = {c.id for c in BENIGN if c.category == "journal_query_100"}
        reads = {asyncio.run(l2_benign.as_read(c)) for c in BENIGN if c.id in gaps}

        def score(text: str) -> float:
            return 0.9 if text in reads else 0.01

        path = _model_dir(tmp_path)
        config = type("C", (), {"classifier_model_path": path})()
        with (
            patch.object(l2_benign, "is_classifier_available", return_value=True),
            patch.object(
                l2_benign, "model_info", return_value=classifier.ModelInfo("m", "r", 0.7, (1,))
            ),
            patch.object(l2_benign, "_score", side_effect=score),
            patch.object(l2_benign, "get_config", return_value=config),
        ):
            assert l2_benign.main(["--record"]) == 0
        record = json.loads((tmp_path / classifier.MANIFEST_FILE).read_text())[BENIGN_KEY]
        gap = record["known_gaps"]["journal_query_100"]
        assert gap["flagged"] == gap["of"] > 0
        assert record["flagged"] == 0

    def test_the_sweep_reads_both_gates_at_each_cut(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert self._run(tmp_path, 0.75, "--sweep") == 1
        table = capsys.readouterr().out
        assert f"| 0.7 | {len(_HELD_OUT)} of {len(_HELD_OUT)} |" in table
        assert f"| 0.8 | 0 of {len(_HELD_OUT)} |" in table
        assert "obfuscation gate" in table

    def test_no_model_is_an_error_not_a_pass(self) -> None:
        with patch.object(l2_benign, "is_classifier_available", return_value=False):
            assert l2_benign.main([]) == 2
