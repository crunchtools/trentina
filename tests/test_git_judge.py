"""The git judge's own decisions, with the layers stubbed (spec 027 phase 1).

The transport tests drive real git through the route; these feed
``GitJudge`` objects directly, so each rule of the grouping is pinned on its
own: L1 and L2 on every unit, a suspicious score judged alone at L3, a clean
group credited to each unit, a flagged group debited to each unit, the
quota as a gap, and a second judging of the same text served from the cache.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from typing import Any

import pytest

from trentina.defense import Screened
from trentina.gateway import git_judge
from trentina.l1.pipeline import PipelineResult, PipelineStats
from trentina.quarantine.classifier import ClassifierResult
from trentina.unpack.git_pack import PackObject

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


async def test_an_l2_flag_is_still_judged_at_l3_alone_and_stands(layers: Layers) -> None:
    bad, good = _blob(f"x\n{L2_MARK}\n"), _blob("an ordinary file\n")
    judge = await _judged(bad, good)
    assert _flagged(judge) == {bad.oid: "L2"}, "L3 finding it clean does not clear it"
    assert [asked for asked in layers.asked if L2_MARK in asked] == [f"x\n{L2_MARK}\n"]


async def test_an_l2_flag_l3_could_not_judge_stands_uncached(layers: Layers) -> None:
    layers.quota = True
    bad = _blob(f"x\n{L2_MARK}\n")
    judge = await _judged(bad)
    assert _flagged(judge) == {bad.oid: "L2"}
    layers.quota = False
    layers.asked.clear()
    await _judged(bad)
    assert layers.asked, "judged again: an unfinished verdict was not cached"


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


async def test_a_flagged_group_flags_each_unit_without_asking_again(layers: Layers) -> None:
    bad = _blob(f"{L3_MARK}\n")
    good = [_blob(f"ordinary file number {n}\n") for n in range(3)]
    judge = await _judged(bad, *good)
    assert set(_flagged(judge)) == {blob.oid for blob in (bad, *good)}
    assert set(_flagged(judge).values()) == {"L3"}
    assert len(layers.asked) == 1, "L3 reads each unit once"


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


async def test_a_verdict_in_memory_expires_with_the_ttl(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#817 holds here too: a verdict is served for the TTL from its judgement, not for
    the life of the process."""
    blob = _blob("an ordinary file\n")
    await _judged(blob)
    git_judge.reset_git_verdicts()  # the in-memory cache only: the store still has it
    from trentina import perimeter_db

    perimeter_db.delete_git_verdicts()
    await _judged(blob)
    assert len(layers.screened) == 2
    later = git_judge.time.time() + 25 * 3600
    monkeypatch.setattr(git_judge.time, "time", lambda: later)
    await _judged(blob)
    assert len(layers.screened) == 3, "a day-old verdict is judged again"


# --- the tip's files, judged whole ---------------------------------------------------


def _oid(kind: str, data: bytes) -> str:
    return hashlib.sha1(
        b"%s %d\0" % (kind.encode(), len(data)) + data, usedforsecurity=False
    ).hexdigest()


def _tree(*entries: tuple[str, str, PackObject]) -> PackObject:
    data = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(obj.oid)
        for mode, name, obj in entries
    )
    return PackObject(oid=_oid("tree", data), kind="tree", content=data, offset=0)


def _commit(tree: PackObject) -> PackObject:
    data = (
        f"tree {tree.oid}\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nmessage\n".encode()
    )
    return PackObject(oid=_oid("commit", data), kind="commit", content=data, offset=0)


class Wholes:
    """``judge_l3`` calls, split into whole-file ones by their briefing."""

    def __init__(self) -> None:
        self.whole: list[str] = []
        self.other: list[str] = []


@pytest.fixture
def wholes(monkeypatch: pytest.MonkeyPatch) -> Wholes:
    seen = Wholes()

    async def judge_l3(text: str, _defense: Any, briefing: str) -> dict[str, Any]:
        (seen.whole if "whole" in briefing else seen.other).append(text)
        return {"injection_detected": False, "risk_level": "none"}

    monkeypatch.setattr(git_judge, "judge_l3", judge_l3)
    return seen


async def _fetched(wants: list[str], *objects: PackObject) -> git_judge.GitJudge:
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
        wants=wants,
    )
    for obj in objects:
        judge.submit(obj)
    judge.finish_pack()
    judge.close()
    await judge.start(60.0)
    return judge


async def test_tip_files_are_judged_whole_and_older_versions_are_not(wholes: Wholes) -> None:
    readme, notes = _blob("the readme, version two\n" * 3), _blob("some notes about it\n" * 3)
    older = _blob("the readme, version one\n" * 3)
    tree = _tree(("100644", "README", readme), ("100644", "NOTES", notes))
    commit = _commit(tree)
    judge = await _fetched([commit.oid], commit, tree, readme, notes, older)
    assert judge.stats["l3_whole"] == 2
    assert sorted(wholes.whole) == sorted([readme.content.decode(), notes.content.decode()])
    assert not any(older.content.decode() in text for text in wholes.whole)
    assert judge.outcome().flagged == [] and judge.outcome().pending == 0


async def test_a_tip_file_over_the_whole_limit_is_not_judged_whole(
    wholes: Wholes, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trentina.config import Config, get_config

    small, big = _blob("tiny\n"), _blob("a much longer file, with words in it. " * 40)
    monkeypatch.setattr(Config, "whole_tokens", property(lambda _self: 50))
    assert get_config().whole_tokens == 50
    tree = _tree(("100644", "small", small), ("100644", "big", big))
    commit = _commit(tree)
    judge = await _fetched([commit.oid], commit, tree, small, big)
    assert judge.stats["l3_whole"] == 1
    assert wholes.whole == ["tiny\n"]


async def test_a_blob_wanted_by_id_is_judged_whole(wholes: Wholes) -> None:
    lazy = _blob("a file fetched on its own, at checkout\n")
    judge = await _fetched([lazy.oid], lazy)
    assert judge.stats["l3_whole"] == 1
    assert wholes.whole == [lazy.content.decode()]


async def test_nothing_is_judged_whole_without_a_want(wholes: Wholes) -> None:
    judge = await _fetched([], _blob("a file nobody asked for\n"))
    assert judge.stats["l3_whole"] == 0 and wholes.whole == []


async def test_judging_past_its_deadline_leaves_the_rest_unjudged(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``judge_deadline``: what is still out when it passes is unjudged
    (``deadline``), named so, and not kept as a verdict."""

    async def slow(content: str, *, source: str) -> Screened:
        await asyncio.sleep(5)
        return await layers.screen(content, source=source)

    monkeypatch.setattr(git_judge, "screen", slow)
    blob = _blob("an ordinary file\n")
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    judge.submit(blob)
    judge.close()
    await judge.start(0.1)
    assert judge.outcome().unjudged == [("blob", blob.oid, "deadline")]
    assert git_judge._memory_get(next(iter(judge._objects))) is git_judge._MISS


async def test_waiting_on_l3_calls_already_finished_returns() -> None:
    """A call whose discard callback has not run yet is done, and gather over
    done tasks returns without yielding: waiting on it again would spin."""

    class Counted(set[asyncio.Task[None]]):
        checks = 0

        def __bool__(self) -> bool:
            self.checks += 1
            assert self.checks < 4, "done() spun on finished calls"
            return len(self) > 0

    dispatch = git_judge._Dispatch.__new__(git_judge._Dispatch)
    finished = asyncio.ensure_future(asyncio.sleep(0))
    await finished
    dispatch._tasks = Counted({finished})
    await dispatch.done()
    assert not dispatch._tasks


async def test_an_object_the_reader_kept_is_unjudged_too_large() -> None:
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    judge.submit_unread("c" * 40, "blob", "too_large")
    judge.close()
    await judge.start(60.0)
    outcome = judge.outcome()
    assert outcome.unjudged == [("blob", "c" * 40, "too_large")]
    assert outcome.total == 1 and not outcome.flagged


def _binary(data: bytes) -> PackObject:
    oid = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
    return PackObject(oid=oid, kind="blob", content=data, offset=0)


async def test_a_binary_over_its_limit_is_unread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(git_judge, "MAX_BINARY_BYTES", 8)
    blob = _binary(b"\x00\x01\x02" * 8)
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "binary_unread")]


async def test_a_binary_the_unpack_stage_could_not_read_is_unread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class View:
        text = ""
        unread = ("image/png",)

    async def unreadable(_reader: Any, _blob: bytes) -> View:
        return View()

    monkeypatch.setattr(git_judge, "run_unpacking", unreadable)
    blob = _binary(b"\x00\x01\x02" * 8)
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "binary_unread")]


def test_the_suspicious_mark_reads_its_setting(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from trentina.config import DEFAULT_GIT_SUSPICIOUS, Config

    monkeypatch.setenv("TRENTINA_GIT_SUSPICIOUS", "0.35")
    assert Config().git_suspicious == 0.35
    monkeypatch.setenv("TRENTINA_GIT_SUSPICIOUS", "lots")
    assert Config().git_suspicious == DEFAULT_GIT_SUSPICIOUS
    assert "TRENTINA_GIT_SUSPICIOUS is not a number" in caplog.text


async def test_nothing_spends_l3_past_the_deadline(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One unit is at L3 while another is still being screened when the
    deadline passes: the L3 call in flight is cancelled, not left running."""
    finished: list[str] = []

    async def slow_l3(text: str, _defense: Any, _briefing: str) -> dict[str, Any]:
        await asyncio.sleep(0.3)
        finished.append(text)
        return {"injection_detected": False, "risk_level": "none"}

    async def screen(content: str, *, source: str) -> Screened:
        if "slow" in content:
            await asyncio.sleep(5)
        return await layers.screen(content, source=source)

    monkeypatch.setattr(git_judge, "judge_l3", slow_l3)
    monkeypatch.setattr(git_judge, "screen", screen)
    judge = git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    judge.submit(_blob(f"{BORDER}\n"))  # alone at L3 at once
    judge.submit(_blob("a slow file\n"))
    judge.close()
    await judge.start(0.15)
    await asyncio.sleep(0.5)
    assert finished == []


def _tag(target: PackObject, name: str) -> PackObject:
    data = (
        f"object {target.oid}\ntype {target.kind}\ntag {name}\ntagger A <a@b> 0 +0000\n\nrelease\n"
    ).encode()
    return PackObject(oid=_oid("tag", data), kind="tag", content=data, offset=0)


async def test_a_wanted_tag_of_a_tag_reaches_nested_files_and_skips_submodules(
    wholes: Wholes,
) -> None:
    top, deep = _blob("a file at the top\n"), _blob("a file two trees down\n")
    inner = _tree(("100644", "deep.txt", deep))
    middle = _tree(("40000", "inner", inner))
    module = _blob("not a blob at all: a submodule's commit id\n")
    tree = _tree(("100644", "top.txt", top), ("40000", "middle", middle), ("160000", "lib", module))
    commit = _commit(tree)
    outer = _tag(_tag(commit, "v1"), "v1-signed")
    await _fetched(
        [outer.oid], outer, _tag(commit, "v1"), commit, tree, middle, inner, top, deep, module
    )
    assert sorted(wholes.whole) == sorted([top.content.decode(), deep.content.decode()])
    assert module.content.decode() not in wholes.whole, "a submodule is out of scope"


async def test_a_screen_that_fails_leaves_the_unit_l2_unavailable_and_uncached(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(_content: str, *, source: str) -> Screened:
        raise RuntimeError(f"model gone for {source}")

    monkeypatch.setattr(git_judge, "screen", broken)
    blob = _blob("an ordinary file\n")
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "l2_unavailable")]
    assert layers.asked == []
    assert not git_judge._memory


async def test_a_screen_with_no_classification_is_l2_unavailable(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_l2(content: str, *, source: str) -> Screened:
        return dataclasses.replace(await layers.screen(content, source=source), classification=None)

    monkeypatch.setattr(git_judge, "screen", no_l2)
    blob = _blob("an ordinary file\n")
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "l2_unavailable")]


@pytest.mark.parametrize("failure", ["raises", "unavailable"])
async def test_an_l3_that_fails_leaves_the_unit_l3_unavailable_and_uncached(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    async def broken(_text: str, _defense: Any, _briefing: str) -> dict[str, Any]:
        if failure == "raises":
            raise RuntimeError("provider down")
        return {"injection_detected": False, "l3_unavailable": True}

    monkeypatch.setattr(git_judge, "judge_l3", broken)
    blob = _blob("an ordinary file\n")
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "l3_unavailable")]
    assert not git_judge._memory


async def test_a_unit_l2_read_only_part_of_is_unjudged(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def head_only(content: str, *, source: str) -> Screened:
        return dataclasses.replace(await layers.screen(content, source=source), l2_truncated=True)

    monkeypatch.setattr(git_judge, "screen", head_only)
    blob = _blob("an ordinary file\n")
    judge = await _judged(blob)
    assert judge.outcome().unjudged == [("blob", blob.oid, "too_large")]
    assert layers.asked == [] and not git_judge._memory
