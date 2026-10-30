"""The semantic-request-guards corpus and its benchmark (#456), without a judge."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import gatekeeper as bench
from corpora.gatekeeper import CASES, POLICIES, SCENARIOS, GateCase, by_scenario
from trentina.gateway.gatekeeper import (
    ARGUMENTS_FLAGGED,
    GATEKEEPER_UNAVAILABLE,
)

DOC = Path(__file__).resolve().parents[1] / "docs" / "semantic-request-guards.md"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_each_scenario_has_its_attack_a_variant_and_routine_work(scenario: str) -> None:
    cases = by_scenario(scenario)
    assert sum(c.headline for c in cases) == 1
    assert all(c.expect_refuse for c in cases if c.headline)
    assert sum(c.expect_refuse for c in cases) >= 2
    assert sum(not c.expect_refuse for c in cases) >= 4


def test_case_ids_are_unique() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


def test_a_destination_has_a_first_contact_answer() -> None:
    for case in CASES:
        assert (case.destination is None) == (case.first_contact is None), case.id


def test_the_corpus_stays_on_the_fictional_roster() -> None:
    domains = {
        d.lower()
        for c in CASES
        for v in c.arguments.values()
        for d in re.findall(r"@([\w.-]+\.\w+)", str(v))
    }
    allowed = {"example.com", "example.org", "example.net", "example-corp.test"}
    assert domains <= allowed


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_the_doc_shows_each_policy_word_for_word(scenario: str) -> None:
    assert POLICIES[scenario] in DOC.read_text(encoding="utf-8")


def test_a_majority_of_answered_votes_decides() -> None:
    v = bench.Vote
    assert bench.voted([v("policy_violation"), v(None), v("policy_violation")]).reason == (
        "policy_violation"
    )
    assert bench.voted([v("policy_violation"), v(None), v(None)]).reason is None
    assert bench.voted([v(GATEKEEPER_UNAVAILABLE), v(None)]).reason is None
    assert bench.voted([v(GATEKEEPER_UNAVAILABLE)] * 3).reason == GATEKEEPER_UNAVAILABLE


async def test_the_tallies_count_catches_false_refusals_and_steps() -> None:
    async def ask(case: GateCase) -> bench.Vote:
        if case.id == "support-reply-to-author":
            return bench.Vote("policy_violation")
        if case.id == "support-export-claimed-approval":
            return bench.Vote(None)
        if case.expect_refuse:
            return bench.Vote(ARGUMENTS_FLAGGED)
        return bench.Vote(None)

    scenarios, total = await bench.run(by_scenario("support_inbox"), ask, votes=1)
    support = next(t for t in scenarios if t.name == "support_inbox")
    assert support.headline_refused is True
    assert (support.attacks_refused, support.attacks) == (1, 2)
    assert support.missed == ["support-export-claimed-approval"]
    assert support.wrongly_refused == ["support-reply-to-author"]
    assert total.by_step == {"arguments": 1, "judge": 1}
    table = bench.render(scenarios, total, "test-model")
    assert "| support_inbox | refused | 1/2 | 1/4 | 0 |" in table


def test_every_call_reaches_the_gatekeeper_as_a_guarded_tool() -> None:
    for scenario in SCENARIOS:
        profile = bench.PROFILES[scenario]
        assert profile.semantic_request_guards is not None
        for case in by_scenario(scenario):
            assert profile.semantic_request_guards.guards(bench.BACKEND, case.tool)


def test_the_tallies_write_as_json() -> None:
    tally = bench.Tally("all")
    tally.by_step["judge"] += 2
    tally.by_reason["policy_violation"] += 2
    assert json.loads(json.dumps(bench._plain(tally)))["by_reason"] == {"policy_violation": 2}


class TestL2InTheArgumentsStep:
    """#462: the benchmark names the L2 model it ran with, and can insist on one."""

    @staticmethod
    def _classifier(monkeypatch: pytest.MonkeyPatch, info: object | None) -> None:
        from trentina.quarantine import classifier

        monkeypatch.setattr(classifier, "is_classifier_available", lambda: info is not None)
        monkeypatch.setattr(classifier, "model_info", lambda: info)

    def test_a_loaded_model_is_named_by_id_and_revision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        info = SimpleNamespace(id="guard-small", revision="3215a27edd62c5ba0bd786c5")
        self._classifier(monkeypatch, info)
        assert bench._l2_model() == "guard-small@3215a27edd62"

    def test_no_model_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._classifier(monkeypatch, None)
        assert bench._l2_model() == "none"

    def test_require_l2_exits_before_any_call_when_the_model_is_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._classifier(monkeypatch, None)
        monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "bench.db"))
        ran = []
        monkeypatch.setattr(bench, "run", lambda *a, **k: ran.append(1))
        assert bench.main(["--require-l2"]) == 2
        assert ran == []

    def test_require_l2_runs_and_records_the_model_when_it_loads(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._classifier(monkeypatch, SimpleNamespace(id="m", revision="r" * 40))
        monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "bench.db"))

        async def no_calls(*_a: object, **_k: object) -> tuple[list[bench.Tally], bench.Tally]:
            return [], bench.Tally("all")

        monkeypatch.setattr(bench, "run", no_calls)
        out = tmp_path / "g.json"
        assert bench.main(["--require-l2", "--json", str(out)]) == 0
        assert json.loads(out.read_text())["l2"] == "m@" + "r" * 12
