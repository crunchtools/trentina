"""The adaptive L3 limiter: fair queue, priority, AIMD (#216, #867)."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest

from trentina.config import get_config
from trentina.errors import QuarantineAgentError
from trentina.gateway import loader
from trentina.gateway.context import profile_context
from trentina.gateway.profile import AuthConfig, Profile
from trentina.quarantine import classifier
from trentina.quarantine.limiter import (
    AdaptiveLimiter,
    Outcome,
    Priority,
    l3_priority,
    l3_throttle_budget,
    limited_generate,
    limiter_for,
)
from trentina.quarantine.providers import get_provider
from trentina.quarantine.providers.base import (
    Provider,
    ProviderResult,
    parse_retry_after,
    status_error,
)

JUDGE = ("gemini", "test-model")


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


class TestGrowth:
    async def test_slow_start_doubles_per_window(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=2, ceiling=64)
        for _ in range(2):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 4
        for _ in range(4):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 8

    async def test_additive_after_first_throttle(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=8, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 4
        await asyncio.sleep(0.3)  # the minimum pause
        for _ in range(4):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 5

    async def test_ceiling(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=6)
        for _ in range(20):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 6

    async def test_other_failures_do_not_move_the_limit(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        for _ in range(10):
            lim.release(await lim.acquire(), Outcome.FAILED)
        assert lim.limit == 4
        assert lim.in_flight == 0


class TestThrottle:
    async def test_one_halving_per_epoch(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=16, ceiling=64)
        epochs = [await lim.acquire() for _ in range(16)]
        # Sixteen requests in flight together all come back 429: one signal.
        for epoch in epochs:
            lim.release(epoch, Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 8
        assert lim.throttles == 16

    async def test_floor_is_one(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=64)
        for _ in range(3):
            lim.release(lim.epoch, Outcome.THROTTLED, retry_after=0.0)
            lim.in_flight += 1  # release() assumes a held slot
        assert lim.limit == 1

    async def test_retry_after_pauses_new_requests(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=0.3)
        assert lim.resume_in() > 0.2
        waiter = asyncio.ensure_future(lim.acquire())
        await asyncio.sleep(0.1)
        assert not waiter.done()
        await asyncio.wait_for(waiter, timeout=1.0)

    async def test_no_retry_after_still_pauses(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED)
        assert lim.resume_in() >= 0.9


class TestQueue:
    async def test_fifo_within_priority(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        order: list[int] = []

        async def take(n: int) -> None:
            epoch = await lim.acquire()
            order.append(n)
            lim.release(epoch, Outcome.FAILED)

        tasks = [asyncio.ensure_future(take(n)) for n in range(5)]
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(*tasks)
        assert order == [0, 1, 2, 3, 4]

    async def test_foreground_before_background(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        order: list[str] = []

        async def take(label: str, priority: Priority) -> None:
            l3_priority.set(priority)
            epoch = await lim.acquire()
            order.append(label)
            lim.release(epoch, Outcome.FAILED)

        background = [asyncio.ensure_future(take(f"bg{n}", Priority.BACKGROUND)) for n in range(3)]
        await _settle()
        foreground = asyncio.ensure_future(take("fg", Priority.FOREGROUND))
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(*background, foreground)
        assert order[0] == "fg"

    async def test_cancelled_waiter_leaves_no_slot_behind(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        waiter = asyncio.ensure_future(lim.acquire())
        await _settle()
        waiter.cancel()
        await _settle()
        lim.release(held, Outcome.FAILED)
        assert lim.in_flight == 0
        lim.release(await lim.acquire(), Outcome.OK)

    async def test_concurrency_never_exceeds_limit(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=3, ceiling=3)
        peak = 0

        async def work() -> None:
            nonlocal peak
            epoch = await lim.acquire()
            peak = max(peak, lim.in_flight)
            await asyncio.sleep(0.001)
            lim.release(epoch, Outcome.OK)

        await asyncio.gather(*(work() for _ in range(30)))
        assert peak == 3


def _profile(name: str) -> Profile:
    return Profile(name=name, auth=AuthConfig(bearer_token_env="X"))


class TestFairShare:
    """Profiles sharing a key waited FIFO behind one profile's backlog (#867)."""

    @staticmethod
    async def _drain(
        lim: AdaptiveLimiter, calls: list[tuple[str, str]], priority: Priority | None = None
    ) -> list[str]:
        held = await lim.acquire()
        order: list[str] = []

        async def take(label: str) -> None:
            if priority is not None:
                l3_priority.set(priority)
            epoch = await lim.acquire()
            order.append(label)
            lim.release(epoch, Outcome.FAILED)

        tasks = []
        for profile, label in calls:
            with profile_context(_profile(profile)):
                tasks.append(asyncio.ensure_future(take(label)))
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(*tasks)
        return order

    async def test_a_backlog_delays_another_profile_by_one_turn(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        calls = [("alpha", f"a{i}") for i in range(6)] + [("beta", "b0")]
        order = await self._drain(lim, calls)
        assert order.index("b0") == 1, order

    async def test_profiles_take_turns_and_each_stays_fifo(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        calls = [("alpha", f"a{i}") for i in range(3)] + [("beta", f"b{i}") for i in range(3)]
        order = await self._drain(lim, calls)
        assert order == ["a0", "b0", "a1", "b1", "a2", "b2"]

    async def test_a_federation_ingress_shares_its_profiles_turn(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        ingress = _profile("alpha-federation")
        object.__setattr__(ingress, "federation_of", "alpha")
        waiters = []
        for profile in (_profile("alpha"), ingress):
            with profile_context(profile):
                waiters.append(asyncio.ensure_future(lim.acquire()))
        await _settle()
        assert list(lim._waiters[Priority.FOREGROUND]) == ["alpha"]
        assert len(lim._waiters[Priority.FOREGROUND]["alpha"]) == 2
        lim.release(held, Outcome.FAILED)
        for waiter in waiters:
            lim.release(await asyncio.wait_for(waiter, timeout=1), Outcome.OK)

    async def test_foreground_still_goes_before_any_profiles_background(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        order: list[str] = []

        async def take(label: str, priority: Priority) -> None:
            l3_priority.set(priority)
            epoch = await lim.acquire()
            order.append(label)
            lim.release(epoch, Outcome.FAILED)

        with profile_context(_profile("alpha")):
            background = asyncio.ensure_future(take("bg", Priority.BACKGROUND))
        await _settle()
        with profile_context(_profile("beta")):
            foreground = asyncio.ensure_future(take("fg", Priority.FOREGROUND))
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(background, foreground)
        assert order == ["fg", "bg"]

    async def test_a_cancelled_waiter_leaves_no_turn_behind(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        with profile_context(_profile("alpha")):
            waiter = asyncio.ensure_future(lim.acquire())
        await _settle()
        waiter.cancel()
        await _settle()
        assert not lim._waiters[Priority.FOREGROUND]
        lim.release(held, Outcome.FAILED)
        assert lim.in_flight == 0

    async def test_a_pause_refuses_one_profiles_turn_and_keeps_anothers(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        refused, kept = [], []
        for profile, budget, waiters in (("alpha", 0.1, refused), ("beta", 5.0, kept)):
            token = l3_throttle_budget.set(budget)
            try:
                with profile_context(_profile(profile)):
                    waiters.extend(asyncio.ensure_future(lim.acquire()) for _ in range(2))
            finally:
                l3_throttle_budget.reset(token)
        await _settle()
        lim.release(held, Outcome.THROTTLED, retry_after=0.5)
        await asyncio.gather(*refused, return_exceptions=True)
        assert all(isinstance(w.exception(), QuarantineAgentError) for w in refused)
        assert list(lim._waiters[Priority.FOREGROUND]) == ["beta"]
        first = await asyncio.wait_for(kept[0], timeout=2)
        lim.release(first, Outcome.OK)
        lim.release(await asyncio.wait_for(kept[1], timeout=2), Outcome.OK)
        assert not lim._waiters[Priority.FOREGROUND]

    async def test_unbound_work_on_a_live_gateway_queues_rather_than_failing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The boot warm-up runs with no profile bound; it takes one shared turn.
        monkeypatch.setattr(loader, "get_active_config", object)
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        waiter = asyncio.ensure_future(lim.acquire())
        await _settle()
        assert None in lim._waiters[Priority.FOREGROUND]
        lim.release(held, Outcome.FAILED)
        lim.release(await asyncio.wait_for(waiter, timeout=1), Outcome.OK)


class _FakeProvider(Provider):
    def __init__(self, error: QuarantineAgentError | None = None) -> None:
        self._model = JUDGE[1]
        self.judge = JUDGE
        self.error = error

    async def generate(self, *_args: object, **_kwargs: object) -> ProviderResult:
        if self.error is not None:
            raise self.error
        return ProviderResult(text="{}")


class TestLimitedGenerate:
    async def test_success_releases_the_slot(self) -> None:
        await limited_generate(_FakeProvider(), system_prompt="s", user_content="u")
        assert limiter_for(JUDGE).in_flight == 0

    async def test_429_restamps_retry_after_with_the_real_pause(self) -> None:
        err = QuarantineAgentError("HTTP 429", status_code=429, retry_after=2.0)
        with pytest.raises(QuarantineAgentError) as info:
            await limited_generate(_FakeProvider(err), system_prompt="s", user_content="u")
        assert info.value.retry_after is not None
        assert 1.5 < info.value.retry_after <= 2.0
        assert limiter_for(JUDGE).in_flight == 0
        assert limiter_for(JUDGE).throttles == 1


class TestRetryAfter:
    def test_delta_seconds(self) -> None:
        assert parse_retry_after("7") == 7.0

    def test_http_date(self) -> None:
        # 2015-10-21 07:28:00 GMT, ten seconds after "now".
        assert parse_retry_after("Wed, 21 Oct 2015 07:28:10 GMT", now=1445412480.0) == 10.0

    def test_garbage_and_missing(self) -> None:
        assert parse_retry_after("soon") is None
        assert parse_retry_after(None) is None

    def test_status_error_keeps_the_header(self) -> None:
        request = httpx.Request("POST", "https://example.invalid")
        response = httpx.Response(429, headers={"Retry-After": "3"}, request=request)
        exc = httpx.HTTPStatusError("throttled", request=request, response=response)
        err = status_error(exc)
        assert err.status_code == 429
        assert err.retry_after == 3.0


class TestLimitedGenerateFailures:
    async def test_other_error_releases_and_leaves_the_limit(self) -> None:
        err = QuarantineAgentError("HTTP 500", status_code=500)
        with pytest.raises(QuarantineAgentError):
            await limited_generate(_FakeProvider(err), system_prompt="s", user_content="u")
        lim = limiter_for(JUDGE)
        assert lim.in_flight == 0
        assert lim.throttles == 0
        assert lim.resume_in() == 0

    async def test_cancellation_releases_the_slot(self) -> None:
        gate = asyncio.Event()

        class _Hanging(_FakeProvider):
            async def generate(self, *_a: object, **_kw: object) -> ProviderResult:
                await gate.wait()
                return ProviderResult(text="{}")

        call = asyncio.ensure_future(
            limited_generate(_Hanging(), system_prompt="s", user_content="u")
        )
        await _settle()
        assert limiter_for(JUDGE).in_flight == 1
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        assert limiter_for(JUDGE).in_flight == 0


class TestL2Gate:
    async def test_concurrent_scans_respect_the_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "2")
        monkeypatch.setattr(classifier, "_gate", None)
        lock = threading.Lock()
        running = peak = 0

        def fake_classify(*_a: object, **_kw: object) -> None:
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.02)
            with lock:
                running -= 1

        monkeypatch.setattr(classifier, "classify", fake_classify)
        await asyncio.gather(*(classifier.classify_async("x") for _ in range(8)))
        assert peak == 2


class TestStaleSuccess:
    async def test_successes_from_before_a_halving_do_not_regrow_it(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=8, ceiling=64)
        epochs = [await lim.acquire() for _ in range(8)]
        lim.release(epochs[0], Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 4
        for epoch in epochs[1:]:
            lim.release(epoch, Outcome.OK)
        assert lim.limit == 4


class TestPausedBeyondBudget:
    async def test_a_call_during_a_long_pause_is_refused_unsent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "5")
        lim = limiter_for(JUDGE)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=60.0)
        provider = _FakeProvider()
        with pytest.raises(QuarantineAgentError) as info:
            await limited_generate(provider, system_prompt="s", user_content="u")
        assert info.value.status_code == 429
        assert info.value.retry_after is not None
        assert info.value.retry_after > 5
        assert lim.in_flight == 0


class TestL2GateUnderCancellation:
    async def test_a_cancelled_scan_keeps_its_permit_until_the_thread_ends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "1")
        monkeypatch.setattr(classifier, "_gate", None)
        release = threading.Event()
        monkeypatch.setattr(classifier, "classify", lambda *_a, **_kw: release.wait(2))

        first = asyncio.ensure_future(classifier.classify_async("x"))
        await asyncio.sleep(0.05)
        first.cancel()
        second = asyncio.ensure_future(classifier.classify_async("y"))
        await asyncio.sleep(0.05)
        # The first thread is still running, so the second may not start.
        assert classifier._gate is not None
        assert classifier._gate[1].locked()
        release.set()
        await asyncio.wait_for(second, timeout=2)


class TestJudgeStamp:
    @pytest.mark.parametrize(
        ("name", "env", "model", "expected"),
        [
            ("gemini", "GEMINI_API_KEY", "judge-model", ("gemini", "judge-model")),
            ("openai", "OPENAI_API_KEY", None, ("openai", "gpt-4o-mini")),
            ("openai", "OPENAI_API_KEY", "gpt-4.1", ("openai", "gpt-4.1")),
        ],
    )
    def test_get_provider_names_the_model_actually_called(
        self,
        monkeypatch: pytest.MonkeyPatch,
        name: str,
        env: str,
        model: str | None,
        expected: tuple[str, str],
    ) -> None:
        monkeypatch.setenv(env, "k")
        monkeypatch.delenv("QUARANTINE_MODEL", raising=False)
        get_config()
        assert get_provider(name, model=model).judge == expected


class TestGrantedThenCancelled:
    async def test_a_slot_granted_to_a_cancelled_caller_is_returned(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        waiter = asyncio.ensure_future(lim.acquire())
        await _settle()
        lim.release(held, Outcome.FAILED)  # grants the slot to the waiter...
        waiter.cancel()  # ...which is cancelled before it resumes
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert lim.in_flight == 0
        lim.release(await asyncio.wait_for(lim.acquire(), timeout=1), Outcome.OK)


class TestPauseRefusesQueuedCallers:
    async def test_a_waiter_is_refused_when_a_later_pause_outlasts_its_budget(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        token = l3_throttle_budget.set(5.0)
        try:
            waiter = asyncio.ensure_future(lim.acquire())
            await _settle()
        finally:
            l3_throttle_budget.reset(token)
        # The in-flight call comes back 429 with a pause longer than 5s.
        lim.release(held, Outcome.THROTTLED, retry_after=60.0)
        with pytest.raises(QuarantineAgentError) as info:
            await waiter
        assert info.value.status_code == 429
        assert lim.in_flight == 0

    async def test_a_waiter_with_room_in_its_budget_keeps_waiting(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        token = l3_throttle_budget.set(300.0)
        try:
            waiter = asyncio.ensure_future(lim.acquire())
            await _settle()
        finally:
            l3_throttle_budget.reset(token)
        lim.release(held, Outcome.THROTTLED, retry_after=0.3)
        await asyncio.wait_for(waiter, timeout=2)


class TestRefusedWaitersArePruned:
    async def test_refused_waiters_leave_the_queue(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        token = l3_throttle_budget.set(5.0)
        try:
            waiters = [asyncio.ensure_future(lim.acquire()) for _ in range(3)]
            await _settle()
        finally:
            l3_throttle_budget.reset(token)
        lim.release(held, Outcome.THROTTLED, retry_after=60.0)
        await asyncio.gather(*waiters, return_exceptions=True)
        assert not any(lim._waiters[p] for p in Priority)


class TestStaleThrottleExtendsPause:
    async def test_a_stale_429_that_lengthens_the_pause_refuses_waiters(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=2, ceiling=2)
        first, second = await lim.acquire(), await lim.acquire()
        token = l3_throttle_budget.set(5.0)
        try:
            waiter = asyncio.ensure_future(lim.acquire())
            await _settle()
        finally:
            l3_throttle_budget.reset(token)
        lim.release(first, Outcome.THROTTLED, retry_after=1.0)  # fits the budget
        await _settle()
        assert not waiter.done()
        lim.release(second, Outcome.THROTTLED, retry_after=60.0)  # stale epoch, longer pause
        with pytest.raises(QuarantineAgentError):
            await waiter


class TestGoogleRetryInfo:
    def _error(self, body: object, headers: dict[str, str] | None = None) -> QuarantineAgentError:
        request = httpx.Request("POST", "https://example.invalid")
        response = httpx.Response(429, json=body, headers=headers or {}, request=request)
        return status_error(httpx.HTTPStatusError("throttled", request=request, response=response))

    def test_gemini_retry_delay_from_the_body(self) -> None:
        body = {
            "error": {
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {"@type": "type.googleapis.com/google.rpc.QuotaFailure"},
                    {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "50.5s"},
                ],
            }
        }
        assert self._error(body).retry_after == 50.5

    def test_header_wins_over_body(self) -> None:
        body = {"error": {"details": [{"@type": "google.rpc.RetryInfo", "retryDelay": "50s"}]}}
        assert self._error(body, {"Retry-After": "3"}).retry_after == 3.0

    def test_no_hint_anywhere(self) -> None:
        assert self._error({"error": {"message": "slow down"}}).retry_after is None
        assert self._error(["not", "a", "dict"]).retry_after is None

    def test_body_that_is_not_json(self) -> None:
        request = httpx.Request("POST", "https://example.invalid")
        response = httpx.Response(429, content=b"<html>slow down</html>", request=request)
        err = status_error(httpx.HTTPStatusError("throttled", request=request, response=response))
        assert err.retry_after is None
