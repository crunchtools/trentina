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
import threading
import time
from typing import Any

import pytest

from trentina.defense import Screened
from trentina.gateway import git_judge
from trentina.l1.pipeline import PipelineResult, PipelineStats
from trentina.l1.shadows import ShadowStats
from trentina.quarantine import quota
from trentina.quarantine.classifier import ClassifierResult
from trentina.unpack.git_pack import PackObject

from . import git_harness as harness

L2_MARK = "L2-PLANTED-INSTRUCTION"
L1_MARK = "L1-PLANTED-SHADOW"
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
        stats = (
            PipelineStats(shadows=ShadowStats(files=1)) if L1_MARK in content else PipelineStats()
        )
        return Screened(
            read=content,
            pipeline=PipelineResult(
                content=content,
                stats=stats,
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


async def test_an_l1_flag_is_still_judged_at_l3_alone_and_stands(layers: Layers) -> None:
    bad, good = _blob(f"x\n{L1_MARK}\n"), _blob("an ordinary file\n")
    judge = await _judged(bad, good)
    assert _flagged(judge) == {bad.oid: "L1"}, "L3 finding it clean does not clear it"
    assert [asked for asked in layers.asked if L1_MARK in asked] == [f"x\n{L1_MARK}\n"]


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


async def test_a_detection_row_that_cannot_be_written_leaves_the_flag(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(**_fields: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(git_judge, "record_detection", refuse)
    bad = _blob(f"{L2_MARK}\n")
    judge = await _judged(bad)
    assert _flagged(judge) == {bad.oid: "L2"}
    assert "detection row lost" in caplog.text
    assert L2_MARK not in caplog.text and "disk full" not in caplog.text


async def test_l3_in_judging_is_charged_to_the_grant_not_the_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The quota is set around the background task, so a real charge reaches
    the grant's counter and never the profile's."""
    profile = harness.profile()
    grant = profile.git[harness.REMOTE].model_copy(update={"l3_daily_quota": 1})

    async def charged(*_args: Any) -> dict[str, Any]:
        if quota.charge_for_call(profile) is None:
            return {"injection_detected": False, "l3_unavailable": True, "l3_quota": True}
        return {"injection_detected": False, "risk_level": "none"}

    monkeypatch.setattr(git_judge, "judge_l3", charged)
    quota.reset()
    judge = git_judge.GitJudge(
        profile=profile,
        grant=grant,
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )
    first, second = _blob(f"{BORDER} one\n"), _blob(f"{BORDER} two\n")
    judge.submit(first)
    judge.submit(second)
    judge.close()
    await judge.start(60.0)
    assert [gap for _k, _oid, gap in judge.outcome().unjudged] == ["l3_quota"]
    assert quota._git_usage[profile.grant_owner][1] == 1
    assert profile.name not in quota._usage, "the profile's counter is untouched"
    quota.reset()


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


async def test_a_verdict_in_memory_holds_until_the_cap(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#817 holds here too: a verdict is served from its judgement up to the
    cap, not for the life of the process."""
    blob = _blob("an ordinary file\n")
    await _judged(blob)
    git_judge.reset_git_verdicts()  # the in-memory cache only: the store still has it
    from trentina import perimeter_db

    perimeter_db.delete_git_verdicts()
    await _judged(blob)
    assert len(layers.screened) == 2
    now = git_judge.time.time()
    monkeypatch.setattr(git_judge.time, "time", lambda: now + 25 * 3600)
    await _judged(blob)
    assert len(layers.screened) == 2, "a day-old verdict still holds"
    monkeypatch.setattr(git_judge.time, "time", lambda: now + git_judge.VERDICT_TTL + 1)
    await _judged(blob)
    assert len(layers.screened) == 3, "past the cap it is judged again"


def test_the_ttl_setting_caps_git_verdicts_and_unset_leaves_thirty_days(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from trentina import config

    monkeypatch.delenv("TRENTINA_VERDICT_TTL_HOURS", raising=False)
    monkeypatch.setattr(config, "_config", None)
    assert git_judge.verdict_ttl() == git_judge.VERDICT_TTL
    monkeypatch.setenv("TRENTINA_VERDICT_TTL_HOURS", "6")
    monkeypatch.setattr(config, "_config", None)
    assert git_judge.verdict_ttl() == 6 * 3600.0
    monkeypatch.setenv("TRENTINA_VERDICT_TTL_HOURS", "100000")
    monkeypatch.setattr(config, "_config", None)
    assert git_judge.verdict_ttl() == git_judge.VERDICT_TTL, "clamped to the cap"


async def test_a_set_ttl_expires_git_verdicts_in_memory_and_in_the_store(
    layers: Layers, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trentina import config, perimeter_db

    monkeypatch.setenv("TRENTINA_VERDICT_TTL_HOURS", "2")
    monkeypatch.setattr(config, "_config", None)
    perimeter_db.delete_git_verdicts()
    blob = _blob("a file judged under a short ttl\n")
    await _judged(blob)
    now = git_judge.time.time()
    monkeypatch.setattr(git_judge.time, "time", lambda: now + 3600)
    await _judged(blob)
    assert len(layers.screened) == 1, "an hour old, from memory"
    git_judge.reset_git_verdicts()
    monkeypatch.setattr(perimeter_db.time, "time", lambda: now + 3 * 3600)
    monkeypatch.setattr(git_judge.time, "time", lambda: now + 3 * 3600)
    await _judged(blob)
    assert len(layers.screened) == 2, "past the setting, the store's copy is stale too"


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


async def test_a_tip_file_the_tip_budget_had_no_room_for_is_named_unjudged(
    wholes: Wholes, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, tip = _blob("an older file from history\n"), _blob("the file at the tip\n")
    monkeypatch.setattr(git_judge, "MAX_TIP_BYTES", git_judge._held(old.content))
    tree = _tree(("100644", "file", tip))
    commit = _commit(tree)
    judge = await _fetched([commit.oid], commit, tree, old, tip)
    assert wholes.whole == []
    assert judge.outcome().unjudged == [("blob", tip.oid, "backlog")]


async def test_the_backlog_counts_a_units_memory_not_its_characters() -> None:
    ascii_unit = git_judge.Unit(key="a", text="x" * 100, lead_in="", source_type="git_blob")
    wide_unit = git_judge.Unit(key="b", text="\U0001f600" * 100, lead_in="", source_type="git_blob")
    assert ascii_unit.size >= 100
    assert wide_unit.size >= 400, "four bytes a character, as Python holds it"


async def test_one_profile_reads_on_one_thread_and_leaves_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running: dict[str, int] = {}
    peak: dict[str, int] = {}
    both = 0
    real = git_judge.chunk_blob
    lock = threading.Lock()

    def counting(content: bytes, secret: bytes) -> Any:
        nonlocal both
        who = content.split(b" ", 1)[0].decode()
        with lock:
            running[who] = running.get(who, 0) + 1
            peak[who] = max(peak.get(who, 0), running[who])
            both = max(both, sum(running.values()))
        time.sleep(0.05)
        with lock:
            running[who] -= 1
        return real(content, secret)

    monkeypatch.setattr(git_judge, "chunk_blob", counting)
    first, second, other = _fresh(), _fresh(), _fresh()
    other.profile = other.profile.model_copy(update={"name": "another"})
    await asyncio.gather(
        *(
            judge.add(_blob(f"{who} {n} line\n" * 1000))
            for n in range(3)
            for judge, who in ((first, "mine"), (second, "mine"), (other, "theirs"))
        )
    )
    assert peak["mine"] == 1, "two fetches of one profile share one thread"
    assert both == 2, "another profile's fetch read beside them"


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


def _fresh() -> git_judge.GitJudge:
    return git_judge.GitJudge(
        profile=harness.profile(),
        grant=harness.profile().git[harness.REMOTE],
        source="git:forge/acme/widgets",
        call_ref="ref",
        chunk_secret=b"k" * 32,
    )


async def test_a_large_object_is_chunked_off_the_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    real = git_judge.chunk_blob

    def recording(content: bytes, secret: bytes) -> Any:
        seen.append(threading.current_thread().name)
        time.sleep(0.2)  # a hostile blob: long enough that a blocked loop would show
        return real(content, secret)

    monkeypatch.setattr(git_judge, "chunk_blob", recording)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    judge = _fresh()
    watching = asyncio.ensure_future(ticker())
    await judge.add(_blob("a short line\n" * 1000))
    watching.cancel()
    assert seen
    assert seen[0].startswith("git-read"), "chunked in a worker thread"
    assert ticks > 10, "the loop kept turning while the blob was read"
    assert judge.stats["units"] > 0


async def test_a_large_tree_is_recorded_on_the_loop_for_the_tip_walk() -> None:
    entries = b"".join(b"100644 f%d.txt\0" % n + bytes([n % 256]) * 20 for n in range(300))
    tree = PackObject(oid="a" * 40, kind="tree", content=entries, offset=0)
    judge = _fresh()
    await judge.add(tree)
    assert len(judge._trees["a" * 40]) == 300
    assert judge.stats["units"] == 300


async def test_one_large_object_is_read_at_a_time_per_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = peak = 0
    real = git_judge.chunk_blob
    lock = threading.Lock()

    def counting(content: bytes, secret: bytes) -> Any:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return real(content, secret)

    monkeypatch.setattr(git_judge, "chunk_blob", counting)
    judge = _fresh()
    await asyncio.gather(*(judge.add(_blob(f"{n} line\n" * 1000)) for n in range(4)))
    assert peak == 1


async def test_a_large_object_cancelled_mid_read_is_a_deadline_gap_and_its_late_result_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started, release = threading.Event(), threading.Event()
    real = git_judge.chunk_blob

    def blocked(content: bytes, secret: bytes) -> Any:
        started.set()
        release.wait(10)
        return real(content, secret)

    monkeypatch.setattr(git_judge, "chunk_blob", blocked)
    blob = _blob(f"x\n{L2_MARK}\n" + "a short line\n" * 1000)
    judge = _fresh()
    adding = asyncio.ensure_future(judge.add(blob))
    while not started.is_set():
        await asyncio.sleep(0.01)
    adding.cancel()
    with pytest.raises(asyncio.CancelledError):
        await adding
    assert judge.outcome().unjudged == [("blob", blob.oid, "deadline")]
    release.set()
    await asyncio.get_running_loop().run_in_executor(git_judge._POOL, lambda: None)
    judge.close()
    await judge.start(60.0)
    outcome = judge.outcome()
    assert outcome.unjudged == [("blob", blob.oid, "deadline")]
    assert not outcome.flagged
    assert judge.stats["units"] == 0, "the late chunks were never added"
    assert not git_judge._memory, "no verdict was cached for the object"
