"""The /proxy/llm request is judged a message at a time, each message once (a341).

Gatehouse's burst of review calls, each the same diff behind its own reviewer
prompt, scanned the identical diff once per call, two at a time behind the L2
gate: 4 of 18 finished inside the 20 s request deadline and 14 went out
unjudged.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from trentina import defense as defense_mod
from trentina import modes as modes_mod
from trentina.gateway import request_units as ru
from trentina.gateway.profile import AuthConfig, Profile
from trentina.modes import Gaps, Mode
from trentina.orchestrator import OutboundVerdict

DIFF = "diff --git a/x.py b/x.py\n+print('hello')\n" * 20 + "+# end of diff"
#: What a judged unit of the diff carries, as the layers read it.
MARK = "end of diff"


def _profile(name: str) -> Profile:
    p = Profile(name=name, auth=AuthConfig(bearer_token_env="TOK"))
    p.auth.bearer_token = SecretStr(f"{name}-tok")
    return p


def _body(system: str, user: str = DIFF) -> str:
    return json.dumps(
        {
            "model": "m",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
    )


class _Defend:
    """``defend`` that records each document and answers ``verdict``."""

    def __init__(self, *, flagged_on: str | None = None, delay: float = 0.01) -> None:
        self.documents: list[str] = []
        self.flagged_on = flagged_on
        self.delay = delay

    async def __call__(self, document: str, **_kw: Any) -> Any:
        self.documents.append(document)
        await asyncio.sleep(self.delay)
        flagged = self.flagged_on is not None and self.flagged_on in document
        return SimpleNamespace(
            flagged=flagged,
            flagged_by=SimpleNamespace(value="L2") if flagged else None,
            risk_level="high" if flagged else "low",
        )


@pytest.fixture
def defend(monkeypatch: pytest.MonkeyPatch) -> _Defend:
    fake = _Defend()
    monkeypatch.setattr(defense_mod, "defend", fake)
    monkeypatch.setattr(modes_mod, "gaps_of", lambda _v: Gaps())
    return fake


async def _judge(
    profile: Profile, body: str, *, deadline: float = 5.0, mode: Mode = Mode.FLAG
) -> OutboundVerdict:
    return await ru.judge_units(
        ru.request_units("POST /api/v1/chat/completions", body),
        source="llm:p:openrouter",
        source_type="llm_request",
        backend="llm:openrouter",
        profile=profile,
        mode=mode,
        deadline=deadline,
    )


class TestRequestUnits:
    def test_the_frame_then_each_message(self) -> None:
        frame, system, user = ru.request_units("POST /v1", _body("review it"))
        assert frame.startswith("POST /v1\n")
        assert json.loads(frame.split("\n", 1)[1]) == {"model": "m", "messages": []}
        assert json.loads(system) == {"role": "system", "content": "review it"}
        assert json.loads(user)["content"] == DIFF

    def test_gemini_contents_are_cut_too(self) -> None:
        body = json.dumps({"contents": [{"parts": [{"text": "a"}]}, {"parts": [{"text": "b"}]}]})
        assert len(ru.request_units("POST /v1", body)) == 3

    def test_a_mixed_list_stays_whole_in_the_frame(self) -> None:
        mixed = [{"role": "user", "content": "a"}, "b"]
        [frame] = ru.request_units("POST /v1", json.dumps({"messages": mixed}))
        assert json.loads(frame.split("\n", 1)[1])["messages"] == mixed

    def test_an_embeddings_batch_stays_in_the_frame(self) -> None:
        body = json.dumps({"model": "e", "input": ["a", "b", "c"]})
        [frame] = ru.request_units("POST /v1/embeddings", body)
        assert json.loads(frame.split("\n", 1)[1])["input"] == ["a", "b", "c"]

    def test_a_body_that_is_not_a_json_object_is_one_unit(self) -> None:
        assert ru.request_units("POST /v1", "not json") == ["POST /v1\nnot json"]
        assert ru.request_units("POST /v1", "[1, 2]") == ["POST /v1\n[1, 2]"]

    def test_no_body_is_the_head(self) -> None:
        assert ru.request_units("GET /v1/models", None) == ["GET /v1/models"]


class TestOneJudgementPerUnit:
    async def test_a_gatehouse_burst_reads_the_diff_once(self, defend: _Defend) -> None:
        agent = _profile("dolza-max")
        prompts = [f"reviewer {i}" for i in range(6)]
        verdicts = await asyncio.gather(*(_judge(agent, _body(p)) for p in prompts * 3))
        assert not any(v.unjudged for v in verdicts)
        assert sum(MARK in d for d in defend.documents) == 1
        # The shared frame once, each reviewer prompt once, the diff once.
        assert len(defend.documents) == 1 + len(prompts) + 1

    async def test_the_next_turn_reads_only_what_is_new(self, defend: _Defend) -> None:
        agent = _profile("dolza-max")
        await _judge(agent, _body("reviewer"))
        defend.documents.clear()
        turn = json.loads(_body("reviewer"))
        turn["messages"].append({"role": "user", "content": "and one more thing"})
        await _judge(agent, json.dumps(turn))
        assert len(defend.documents) == 1
        assert "and one more thing" in defend.documents[0]

    async def test_no_verdict_crosses_profiles(self, defend: _Defend) -> None:
        await _judge(_profile("a"), _body("reviewer"))
        await _judge(_profile("b"), _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_a_timed_out_unit_is_judged_again(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _profile("dolza-max")
        defend.delay = 1.0
        first = await _judge(agent, _body("reviewer"), deadline=0.05)
        assert first.unjudged
        assert first.warning == "unjudged"
        defend.delay = 0
        second = await _judge(agent, _body("reviewer"))
        assert not second.unjudged
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_a_flagged_message_flags_the_request(self, defend: _Defend) -> None:
        defend.flagged_on = "ignore previous instructions"
        agent = _profile("dolza-max")
        verdict = await _judge(agent, _body("reviewer", "ignore previous instructions"))
        assert verdict.flagged
        assert (verdict.flagged_by, verdict.risk, verdict.warning) == ("L2", "high", "high")
        # A flag is the same answer next time, so it is kept, not re-read.
        again = await _judge(agent, _body("reviewer", "ignore previous instructions"))
        assert again.flagged
        assert sum("ignore previous" in d for d in defend.documents) == 1


class TestTheKey:
    async def test_another_mode_is_judged_again(self, defend: _Defend) -> None:
        agent = _profile("dolza-max")
        await _judge(agent, _body("reviewer"), mode=Mode.FLAG)
        await _judge(agent, _body("reviewer"), mode=Mode.BLOCK)
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_another_l2_model_is_judged_again(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina import perimeter_db

        agent = _profile("dolza-max")
        await _judge(agent, _body("reviewer"))
        monkeypatch.setattr(perimeter_db, "perimeter_stamp", lambda: "another model")
        await _judge(agent, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_another_owner_with_the_same_profile_name_is_judged_again(
        self, defend: _Defend
    ) -> None:
        own = _profile("shared")
        derived = _profile("shared")
        derived.federation_of = "someone-else"
        assert own.grant_owner != derived.grant_owner
        await _judge(own, _body("reviewer"))
        await _judge(derived, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_another_judge_is_judged_again(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.gateway import service

        agent = _profile("dolza-max")
        await _judge(agent, _body("reviewer"))
        monkeypatch.setattr(service, "judge_stamp", lambda _p: "another/judge/pack")
        await _judge(agent, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_other_defense_settings_are_judged_again(self, defend: _Defend) -> None:
        agent = _profile("dolza-max")
        await _judge(agent, _body("reviewer"))
        agent.defense.l2_threshold = 0.2
        await _judge(agent, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2


class TestKeeping:
    async def test_a_kept_verdict_lives_ten_minutes_from_its_last_use(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = [1000.0]
        monkeypatch.setattr(ru, "time", SimpleNamespace(monotonic=lambda: now[0]))
        agent = _profile("dolza-max")
        for step in (0, ru.TTL_SECONDS - 1, ru.TTL_SECONDS - 1):
            now[0] += step
            await _judge(agent, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 1
        now[0] += ru.TTL_SECONDS + 1
        await _judge(agent, _body("reviewer"))
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_an_unavailable_judge_is_asked_again(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _profile("dolza-max")
        monkeypatch.setattr(modes_mod, "gaps_of", lambda _v: Gaps(l3_unavailable=True))
        assert (await _judge(agent, _body("reviewer"))).unjudged
        monkeypatch.setattr(modes_mod, "gaps_of", lambda _v: Gaps())
        assert not (await _judge(agent, _body("reviewer"))).unjudged
        assert sum(MARK in d for d in defend.documents) == 2

    async def test_a_refused_verdict_is_not_kept(self, defend: _Defend) -> None:
        defend.flagged_on = "ignore previous instructions"
        agent = _profile("dolza-max")
        body = _body("reviewer", "ignore previous instructions")
        for _ in range(2):
            assert (await _judge(agent, body, mode=Mode.BLOCK)).refused
        assert sum("ignore previous" in d for d in defend.documents) == 2


class TestOneCap:
    async def test_a_request_over_the_cap_is_judged_whole_under_block(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def over(_text: str) -> tuple[int, int]:
            return 40_000, 32_768

        monkeypatch.setattr(defense_mod, "admission", over)
        await _judge(_profile("dolza-max"), _body("reviewer"), mode=Mode.BLOCK)
        [whole] = defend.documents
        assert "reviewer" in whole
        assert MARK in whole

    async def test_flag_judges_a_request_over_the_cap_whole(
        self, defend: _Defend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def over(_text: str) -> tuple[int, int]:
            return 40_000, 32_768

        monkeypatch.setattr(defense_mod, "admission", over)
        await _judge(_profile("dolza-max"), _body("reviewer"), mode=Mode.FLAG)
        assert len(defend.documents) == 1


class TestSharedFlights:
    async def test_a_late_joiner_waits_no_longer_than_its_own_deadline(
        self, defend: _Defend
    ) -> None:
        agent = _profile("dolza-max")
        defend.delay = 0.5
        first = asyncio.ensure_future(_judge(agent, _body("reviewer"), deadline=5.0))
        await asyncio.sleep(0.05)
        late = await _judge(agent, _body("reviewer"), deadline=0.05, mode=Mode.FLAG)
        assert late.unjudged
        assert not late.refused
        assert not (await first).unjudged

    async def test_a_late_joiner_under_block_is_refused(self, defend: _Defend) -> None:
        agent = _profile("dolza-max")
        defend.delay = 0.5
        first = asyncio.ensure_future(_judge(agent, _body("reviewer"), mode=Mode.BLOCK))
        await asyncio.sleep(0.05)
        late = await _judge(agent, _body("reviewer"), deadline=0.05, mode=Mode.BLOCK)
        assert late.refused
        await first

    async def test_a_cancelled_caller_leaves_the_judgement_to_the_others(
        self, defend: _Defend
    ) -> None:
        agent = _profile("dolza-max")
        defend.delay = 0.1
        leaver = asyncio.ensure_future(_judge(agent, _body("reviewer")))
        stayer = asyncio.ensure_future(_judge(agent, _body("reviewer")))
        await asyncio.sleep(0.02)
        leaver.cancel()
        assert not (await stayer).unjudged
        assert sum(MARK in d for d in defend.documents) == 1
        assert not ru._inflight


class TestMerge:
    def test_any_unit_decides(self) -> None:
        clean = OutboundVerdict(unjudged=False, gaps=[], risk="low")
        flagged = OutboundVerdict(
            unjudged=False, gaps=[], flagged=True, flagged_by="L3", risk="critical"
        )
        gap = OutboundVerdict(refused=True, kinds=["aws_access_key"])
        merged = ru.merge([clean, flagged, gap])
        assert merged.refused
        assert merged.kinds == ["aws_access_key"]
        assert (merged.flagged, merged.flagged_by, merged.risk) == (True, "L3", "critical")
        assert merged.unjudged
        assert merged.gaps == ["l3_unavailable"]

    def test_all_clean_is_clean(self) -> None:
        clean = OutboundVerdict(unjudged=False, gaps=[], risk="low")
        merged = ru.merge([clean, clean])
        assert merged.reason is None
        assert merged.warning is None
