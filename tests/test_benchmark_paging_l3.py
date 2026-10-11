"""The split-attack benchmark (#448): how it arranges an attack, and what it counts.

No judge and no model: the layers are a callable that flags a part holding
the words it is told to look for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from benchmarks import paging_l3 as bench
from trentina import database
from trentina.quarantine.classifier import GUARD_TOKENS

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

ATTACK = " ".join(f"attack{i}" for i in range(40))


@pytest.fixture(autouse=True)
def _words(monkeypatch: pytest.MonkeyPatch) -> None:
    """A word is a token, as when the benchmark runs with no L2 model."""
    monkeypatch.setattr(bench.classifier, "token_starts", lambda _text: None)


def _fill() -> Iterator[str]:
    return bench.filler([f"benign paragraph {n} of the filler text." for n in range(50)], 400)


def _flags(*words: str) -> Callable[[bench.Reading], Awaitable[bench.Verdict]]:
    async def ask(reading: bench.Reading) -> bench.Verdict:
        read = (reading.lead_in + reading.text).split()
        return bench.Verdict(l3=all(word in read for word in words), l2=False)

    return ask


class TestArrangements:
    def test_a_cut_is_inside_the_attack_and_loses_nothing(self) -> None:
        for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
            first, second = bench.cut(ATTACK, fraction)
            assert first and second
            assert first + second == ATTACK
        first, _ = bench.cut(ATTACK, 0.25)
        assert len(first.split()) == 10

    def test_the_lead_in_is_the_last_guard_tokens_of_the_part_before(self) -> None:
        text = " ".join(f"w{i}" for i in range(200))
        assert bench.tail(text).split() == [f"w{i}" for i in range(200 - GUARD_TOKENS, 200)]
        assert bench.tail("a b c") == "a b c"

    def test_whole_is_one_part_holding_all_of_it(self) -> None:
        (part,) = bench.whole(ATTACK, _fill())
        assert ATTACK in part.text
        assert "attack0" not in part.lead_in
        assert part.text.startswith("benign")
        assert part.text.endswith(".")
        assert f"\n\n{ATTACK}\n\n" in part.text

    def test_adjacent_parts_touch_and_the_second_is_read_behind_the_first(self) -> None:
        ending, opening = bench.adjacent(ATTACK, 0.5, _fill())
        assert opening.number == ending.number + 1
        assert ending.text.endswith("attack19 ")
        assert opening.text.startswith("attack20 ")
        assert opening.lead_in == bench.tail(ending.text)
        # 20 words of the attack are within the 64 the lead-in carries.
        assert "attack0" in opening.lead_in.split()

    def test_apart_parts_do_not_touch_and_no_lead_in_carries_a_piece(self) -> None:
        ending, opening = bench.apart(ATTACK, _fill())
        assert (ending.number, opening.number) == (2, bench.PARTS)
        assert "attack19" in ending.text and "attack20" in opening.text
        assert "attack" not in opening.lead_in
        assert "attack" not in ending.lead_in

    def test_filler_is_a_different_stretch_each_time(self) -> None:
        fill = _fill()
        first, second = next(fill), next(fill)
        assert first != second
        assert len(first) >= 400


class TestCounting:
    async def test_split_rows_count_only_what_is_caught_whole(self) -> None:
        attacks = [("seen", ATTACK), ("missed", "nothing the judge looks for")]
        tallies, floor = await bench.run(attacks, _flags("attack0", "attack39"), 400)
        by_name = {tally.name: tally for tally in tallies}
        assert (by_name["whole"].of, by_name["whole"].l3) == (2, 1)
        assert by_name["whole"].lost == ["missed"]
        # The lead-in carries a short attack's first piece into the next part.
        assert (by_name["adjacent, cut at 50%"].of, by_name["adjacent, cut at 50%"].l3) == (1, 1)
        # Nothing carries it across four parts.
        assert (by_name["apart (parts 2 and 6)"].of, by_name["apart (parts 2 and 6)"].l3) == (1, 0)
        assert by_name["apart (parts 2 and 6)"].lost == ["seen"]
        assert (floor.of, floor.l3) == (bench.CONTROLS, 0)

    async def test_a_part_the_judge_did_not_answer_is_not_a_miss(self) -> None:
        async def silent(_reading: bench.Reading) -> bench.Verdict:
            return bench.Verdict(l3=None, l2=None)

        tallies, floor = await bench.run([("seen", ATTACK)], silent, 400)
        assert (tallies[0].of, tallies[0].unanswered) == (0, 1)
        assert floor.unanswered == bench.CONTROLS

    def test_votes_are_a_majority_of_the_answers_given(self) -> None:
        yes, no, silent = (bench.Verdict(l3=v, l2=False) for v in (True, False, None))
        assert bench.voted([yes, yes, no]).l3 is True
        assert bench.voted([yes, no, no]).l3 is False
        assert bench.voted([yes, silent, silent]).l3 is True
        assert bench.voted([silent, silent]).l3 is None

    def test_the_report_names_what_each_cut_lost(self) -> None:
        tallies = [bench.Tally("whole", 3, 3), bench.Tally("apart", 3, 1, lost=["b", "a"])]
        text = bench.render(tallies, bench.Tally("no attack", 6), 5)
        assert "3 of 3 attacks caught by L3 whole" in text
        assert "| apart | 3 | 1 | 0 | 0 | 0 |" in text
        assert "Lost apart: `a`, `b`" in text


@pytest.mark.usefixtures("env")
async def test_a_part_is_judged_through_defend_behind_its_lead_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real ``defend()``, with only the model calls replaced."""
    detect = AsyncMock(return_value={"injection_detected": True, "risk_level": "high"})
    monkeypatch.setattr("trentina.defense.quarantine_detect", detect)
    monkeypatch.setattr("trentina.defense.classify_async", AsyncMock(return_value=None))
    reading = bench.Reading("the second piece and more.", "the end of the part before ", 4)
    verdict = await bench.judge(reading)
    assert verdict == bench.Verdict(l3=True, l2=None)
    assert detect.await_args.args[0] == "the end of the part before the second piece and more."
    assert "part 4 of 6" in detect.await_args.kwargs["layer1_context"]
    assert database.get_db().execute("SELECT count(*) FROM detections").fetchone()[0] == 0


@pytest.mark.usefixtures("env")
async def test_an_unreachable_judge_is_unanswered_and_not_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gap = AsyncMock(return_value={"l3_unavailable": True, "injection_detected": False})
    monkeypatch.setattr("trentina.defense.quarantine_detect", gap)
    monkeypatch.setattr("trentina.defense.classify_async", AsyncMock(return_value=None))
    assert (await bench.judge(bench.Reading("text", "", 2))).l3 is None


def test_main_needs_a_judge(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(bench, "get_config", type("NoJudge", (), {"has_llm": False}))
    assert bench.main([]) == 2
    assert "no judge" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--votes", "--concurrency"])
def test_a_count_of_none_is_refused_before_anything_runs(flag: str) -> None:
    with pytest.raises(SystemExit):
        bench.main([flag, "0"])
