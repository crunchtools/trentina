"""The git judge's own decisions, with the layers stubbed (spec 027 phase 1).

The transport tests drive real git through the route; these feed
``GitJudge`` objects directly, so each rule of the grouping is pinned on its
own: L1 and L2 on every unit, a suspicious score judged alone at L3, a clean
group credited to each unit, a flagged group judged again unit by unit, the
quota as a gap, and a second judging of the same text served from the cache.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from trentina.defense import Screened
from trentina.gateway import git_judge
from trentina.gateway.git_pack import PackObject
from trentina.l1.pipeline import PipelineResult, PipelineStats
from trentina.quarantine.classifier import ClassifierResult

from . import git_harness as harness

L2_MARK = "L2-PLANTED-INSTRUCTION"
L3_MARK = "L3-PLANTED-INSTRUCTION"
BORDER = "BORDERLINE-TEXT"
HALF_A, HALF_B = "FIRST-HALF-OF-IT", "SECOND-HALF-OF-IT"


class Layers:
    """Fakes for ``screen`` and ``judge_l3`` that count what they were asked."""

    def __init__(self, *, quota: bool = False) -> None:
        self.screened: list[str] = []
        self.asked: list[str] = []
        self.quota = quota

    async def screen(self, content: str, *, source: str) -> Screened:
        self.screened.append(content)
        score = 0.99 if L2_MARK in content else 0.5 if BORDER in content else 0.01
        label = "MALICIOUS" if score > 0.9 else "BENIGN"
        return Screened(
            read=content,
            pipeline=PipelineResult(
                content=content,
                stats=PipelineStats(),
                input_size=len(content),
                output_size=len(content),
            ),
            classification=ClassifierResult(label=label, score=score, latency_ms=0.0),
            l2_truncated=False,
            unread=(),
        )

    async def judge_l3(self, text: str, defense: Any, briefing: str) -> dict[str, Any]:
        self.asked.append(text)
        if self.quota:
            return {"injection_detected": False, "l3_unavailable": True, "l3_quota": True}
        flagged = L3_MARK in text or (HALF_A in text and HALF_B in text)
        return {"injection_detected": flagged, "risk_level": "high" if flagged else "none"}


@pytest.fixture(autouse=True)
def layers(monkeypatch: pytest.MonkeyPatch) -> Layers:
    fake = Layers()
    monkeypatch.setattr(git_judge, "screen", fake.screen)
    monkeypatch.setattr(git_judge, "judge_l3", fake.judge_l3)
    git_judge.reset_git_verdicts()
    return fake


def _blob(text: str) -> PackObject:
    data = text.encode()
    oid = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
    return PackObject(oid=oid, kind="blob", content=data, offset=0)


async def _judged(*objects: PackObject) -> git_judge.GitJudge:
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    for obj in objects:
        judge.submit(obj)
    judge.close()
    await judge.start(60.0)
    return judge


def _flagged(judge: git_judge.GitJudge) -> dict[str, str]:
    return {oid: layer for _kind, oid, layer, _risk in judge.outcome().flagged}


async def test_l2_flags_without_asking_l3(layers: Layers) -> None:
    bad, good = _blob(f"x\n{L2_MARK}\n"), _blob("an ordinary file\n")
    judge = await _judged(bad, good)
    assert _flagged(judge) == {bad.oid: "L2"}
    assert not any(L2_MARK in asked for asked in layers.asked)


async def test_clean_units_share_one_l3_call(layers: Layers) -> None:
    blobs = [_blob(f"ordinary file number {n}\n") for n in range(5)]
    judge = await _judged(*blobs)
    assert judge.outcome().flagged == [] and judge.outcome().pending == 0
    assert len(layers.asked) == 1, "a clean group is one call, credited to each unit"


async def test_a_suspicious_score_is_judged_alone(layers: Layers) -> None:
    border = _blob(f"{BORDER}\n")
    await _judged(border, *[_blob(f"ordinary file number {n}\n") for n in range(3)])
    assert [BORDER in asked for asked in layers.asked].count(True) == 1
    assert any(asked.strip() == BORDER for asked in layers.asked), "never diluted"


async def test_a_flagged_group_is_judged_again_unit_by_unit(layers: Layers) -> None:
    bad = _blob(f"{L3_MARK}\n")
    good = [_blob(f"ordinary file number {n}\n") for n in range(3)]
    judge = await _judged(bad, *good)
    assert _flagged(judge) == {bad.oid: "L3"}
    assert len(layers.asked) == 1 + 4


async def test_an_instruction_only_the_group_carries_flags_every_unit_in_it() -> None:
    halves = [_blob(f"{HALF_A}\n"), _blob(f"{HALF_B}\n")]
    judge = await _judged(*halves)
    assert set(_flagged(judge)) == {blob.oid for blob in halves}


async def test_a_spent_quota_is_a_gap_and_is_not_cached(layers: Layers) -> None:
    layers.quota = True
    blob = _blob("an ordinary file\n")
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "l3_quota")]
    layers.quota = False
    again = await _judged(blob)
    assert again.outcome().unjudged == []
    assert len(layers.screened) == 2, "an unanswered verdict was not kept"


async def test_the_same_text_twice_is_judged_once(layers: Layers) -> None:
    blob = _blob("an ordinary file\n")
    await _judged(blob)
    second = await _judged(blob)
    assert len(layers.screened) == 1
    assert second.stats["cached"] == 1


async def test_a_message_in_an_encoding_tools_read_differently_is_flagged() -> None:
    data = (
        b"tree " + b"0" * 40 + b"\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n"
        b"encoding UTF-7\n\nhello\n"
    )
    commit = PackObject(oid="c" * 40, kind="commit", content=data, offset=0)
    judge = await _judged(commit)
    assert _flagged(judge) == {commit.oid: "L1"}


async def test_a_flagged_name_in_a_listing_is_found() -> None:
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    judge.submit_names(["refs/heads/main", f"refs/heads/{L2_MARK}"])
    judge.close()
    await judge.start(60.0)
    assert {oid for _k, oid, _l, _r in judge.outcome().flagged} == {f"ref:refs/heads/{L2_MARK}"}
