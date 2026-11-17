"""A burst of identical agent requests costs one judgement and holds nothing.

Gatehouse runs eight review agents at once, each sending the same diff through
``/proxy/llm``. That was eight L3 calls for one answer, a 60-second request
deadline that held every agent's turn when the judge was slow, and L2 permits
held by scans whose callers had already timed out.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from pydantic import SecretStr

from trentina import defense
from trentina.gateway import llm_proxy
from trentina.gateway.context import profile_context
from trentina.gateway.llm_policy import Reason
from trentina.gateway.profile import AuthConfig, LlmKeyOverride, Profile
from trentina.modes import Mode
from trentina.quarantine import classifier, l3_cache

if TYPE_CHECKING:
    from trentina.transports.perimeter import InTree

pytestmark = pytest.mark.usefixtures("standalone_l3")


def _profile(name: str, *, model: str | None = None) -> Profile:
    p = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TOK"),
        llm_keys={"gemini": LlmKeyOverride(api_key_env=f"{name.upper()}_GEMINI_KEY")},
    )
    p.auth.bearer_token = SecretStr(f"{name}-tok")
    p.llm_keys["gemini"].api_key = SecretStr(f"{name}-key")
    p.defense.model = model
    return p


class _Judge:
    """A slow L3 that counts how often it is asked."""

    def __init__(self, verdict: dict[str, Any] | None = None, delay: float = 0.05) -> None:
        self.calls = 0
        self.verdict = verdict or {"injection_detected": False, "risk_level": "low"}
        self.delay = delay

    async def __call__(self, content: str, layer1_context: str | None = None) -> dict[str, Any]:
        self.calls += 1
        await asyncio.sleep(self.delay)
        return dict(self.verdict)


async def _judge_as(profile: Profile, content: str, briefing: str = "brief") -> dict[str, Any]:
    with profile_context(profile):
        return await defense._stage_two(content, profile.defense, briefing)


class TestOneJudgementPerBurst:
    async def test_eight_identical_concurrent_requests_make_one_l3_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = _Judge()
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        agent = _profile("gatehouse")
        verdicts = await asyncio.gather(*(_judge_as(agent, "the same diff") for _ in range(8)))
        assert judge.calls == 1
        assert all(v == judge.verdict for v in verdicts)

    async def test_a_finished_verdict_is_reused_until_it_expires(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = _Judge(delay=0)
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        clock = [1000.0]
        monkeypatch.setattr(l3_cache.time, "monotonic", lambda: clock[0])
        agent = _profile("gatehouse")
        await _judge_as(agent, "diff")
        clock[0] += l3_cache.TTL_SECONDS - 1
        await _judge_as(agent, "diff")
        assert judge.calls == 1
        clock[0] += 2
        await _judge_as(agent, "diff")
        assert judge.calls == 2

    @pytest.mark.parametrize(
        ("second", "briefing", "model"),
        [
            ("other diff", "brief", None),  # different content
            ("diff", "L2 flagged it", None),  # different briefing: not the same judgement
            ("diff", "brief", "gemini-other"),  # different model config
        ],
    )
    async def test_anything_but_identical_is_judged_again(
        self, monkeypatch: pytest.MonkeyPatch, second: str, briefing: str, model: str | None
    ) -> None:
        judge = _Judge(delay=0)
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        await _judge_as(_profile("a"), "diff")
        await _judge_as(_profile("a", model=model), second, briefing)
        assert judge.calls == 2

    async def test_an_unavailable_judge_is_not_cached(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = _Judge({"injection_detected": False, "l3_unavailable": True}, delay=0)
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        agent = _profile("gatehouse")
        await _judge_as(agent, "diff")
        await _judge_as(agent, "diff")
        assert judge.calls == 2

    async def test_profiles_share_a_verdict_on_identical_bytes_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The key holds no profile: identical bytes share a verdict, and that
        # is all they share. What one caller gets is its own copy.
        judge = _Judge(delay=0)
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        first = await _judge_as(_profile("alpha"), "diff")
        first["summary"] = "alpha's annotation"
        second = await _judge_as(_profile("beta"), "diff")
        assert judge.calls == 1
        assert "summary" not in second

    async def test_a_caller_past_its_deadline_leaves_the_judgement_for_the_rest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = _Judge(delay=0.1)
        monkeypatch.setattr(defense, "quarantine_detect", judge)
        agent = _profile("gatehouse")
        impatient = asyncio.ensure_future(_judge_as(agent, "diff"))
        patient = asyncio.ensure_future(_judge_as(agent, "diff"))
        await asyncio.sleep(0.01)
        impatient.cancel()
        assert await patient == judge.verdict
        assert judge.calls == 1

    def test_the_cache_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(l3_cache, "MAX_ENTRIES", 3)
        judge = _Judge(delay=0)
        monkeypatch.setattr(defense, "quarantine_detect", judge)

        async def burst() -> None:
            for i in range(5):
                await _judge_as(_profile("a"), f"diff {i}")

        asyncio.run(burst())
        assert len(l3_cache._verdicts) == 3


class TestRequestJudgeDeadline:
    def test_the_default_is_twenty_seconds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_LLM_JUDGE_DEADLINE", raising=False)
        assert llm_proxy.llm_judge_deadline() == 20.0

    @pytest.mark.parametrize(("raw", "expected"), [("5", 5.0), ("0", 1.0), ("soon", 20.0)])
    def test_the_setting_is_read_and_bounded(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: float
    ) -> None:
        monkeypatch.setenv("TRENTINA_LLM_JUDGE_DEADLINE", raw)
        assert llm_proxy.llm_judge_deadline() == expected

    async def test_a_request_scan_past_the_setting_is_refused_under_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_LLM_JUDGE_DEADLINE", "1")
        # The completion deadline is not the request's: leave it long.
        monkeypatch.setattr(llm_proxy, "_JUDGE_DEADLINE", 60.0)

        async def hanging_defend(*_a: Any, **_k: Any) -> Any:
            await asyncio.sleep(30)
            raise AssertionError("the request deadline should have cancelled this")

        monkeypatch.setattr(defense, "defend", hanging_defend)
        agent = _profile("blocker")
        ctx = cast(
            "InTree",
            SimpleNamespace(op=SimpleNamespace(profile=agent), instance=SimpleNamespace(name="x")),
        )
        started = time.monotonic()
        with pytest.raises(llm_proxy.MarkedRefusalError) as refused:
            await llm_proxy._judge_request(ctx, "POST /v1/messages", Mode.BLOCK)
        assert time.monotonic() - started < 5
        assert refused.value.reason == Reason.UNJUDGED.value


class TestTimedOutScanFreesItsPermit:
    async def test_a_scan_whose_caller_timed_out_stops_and_hands_the_permit_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "1")
        monkeypatch.setattr(classifier, "_gate", None)
        windows = 0
        lock = threading.Lock()

        def one_window(_ids: list[int], _mask: list[int]) -> tuple[str, float]:
            nonlocal windows
            with lock:
                windows += 1
            time.sleep(0.02)
            return "BENIGN", 0.0

        # The real windowing loop over a long input: 400 windows, ~8 s of
        # inference if nothing stops it.
        monkeypatch.setattr(classifier, "is_classifier_available", lambda: True)
        monkeypatch.setattr(classifier, "_model", None)
        monkeypatch.setattr(
            classifier,
            "_tokenizer",
            SimpleNamespace(num_special_tokens_to_add=lambda: 2, cls_token_id=0, sep_token_id=1),
        )
        monkeypatch.setattr(classifier, "_encode", lambda text: [5] * (len(text) * 10))
        monkeypatch.setattr(classifier, "_classify_segment", one_window)
        monkeypatch.setattr(
            classifier, "get_config", lambda: SimpleNamespace(admission_tokens=10_000_000)
        )

        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.1):
                await classifier.classify_async("x" * 18_000)
        # The next burst gets the permit within a window or two, not after
        # the eight seconds the abandoned scan would have run.
        started = time.monotonic()
        result = await asyncio.wait_for(classifier.classify_async("y"), timeout=2)
        assert result is not None
        assert time.monotonic() - started < 1
        assert windows < 50
