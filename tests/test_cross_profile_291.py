"""Cross-profile channels, second sweep (#291).

Each class is one piece of shared state that profile A could change and
profile B could observe. Every test drives A, then asks whether anything B
reads moved: a verdict's latency, a fetch refusal, an aggregate's build time,
a log line, an L3 refusal, a place in the L2 queue.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from mcp.types import ListToolsResult, Tool
from pydantic import SecretStr
from starlette.testclient import TestClient

from tests.egress_harness import route
from trentina.client import fetch_url
from trentina.errors import EgressRefusedError, QuarantineAgentError
from trentina.gateway import compress
from trentina.gateway.app import MCP_SESSION_ID_HEADER, gateway_app
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.ingress_defense import scan_tool_response
from trentina.gateway.loader import GatewayConfig, register_active_config
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.router import _profile_backend_urls, _profile_tools_cache
from trentina.gateway.sessions import SessionRegistry
from trentina.quarantine import classifier
from trentina.quarantine.classifier import ClassifierResult
from trentina.quarantine.limiter import limited_generate, limiter_for
from trentina.quarantine.providers import Provider, ProviderResult, get_provider
from trentina.reach import egress
from trentina.tools.reconnect import reconnect_backend

SHARED_URL = "http://mcp-shared:8000/mcp"


def _profile(name: str, bearer: str | None = None) -> Profile:
    profile = Profile(
        name=name,
        short_names=False,
        auth=AuthConfig(bearer_token_env="X"),
        backends={"shared": Backend(url=SHARED_URL, tools_allow=["*"])},
    )
    profile.auth.bearer_token = SecretStr(bearer or f"{name}-bearer")
    return profile


class TestResponseVerdictCache:
    """A hit answers in ms and a miss in seconds: B could tell what A fetched."""

    async def test_another_profiles_verdict_is_not_served(self) -> None:
        alpha, beta = _profile("alpha"), _profile("beta")
        verdict = MagicMock(
            flagged=False,
            classification=ClassifierResult("BENIGN", 0.01, 1.0),
            l3_assessment={"injection_detected": False},
            l2_truncated=False,
            l3_truncated=False,
            oversize=None,
        )
        with patch(
            "trentina.gateway.ingress_defense.defend",
            AsyncMock(return_value=verdict),
        ) as judged:
            for profile in (alpha, alpha, beta):
                await scan_tool_response(
                    profile=profile,
                    backend_name="shared",
                    tool_name="get_doc",
                    content_blocks=[{"type": "text", "text": "object 7 of N"}],
                    structured_content=None,
                )
        assert judged.call_count == 2, "alpha's second call hits; beta's first is its own miss"


class TestResolverSlots:
    """A black-holed name server held every lookup slot, gateway-wide."""

    async def test_one_profiles_stalled_lookups_leave_anothers_fetch_alone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = threading.Event()

        def lookup(host: str, _port: int) -> list[str]:
            if host == "blackhole.example":
                release.wait(5)
            return ["93.184.215.14"]

        route(monkeypatch, lambda _r: httpx.Response(200, text="ok"))
        monkeypatch.setattr(egress, "_lookup", lookup)
        monkeypatch.setattr(egress, "RESOLVE_TIMEOUT", 0.05)
        monkeypatch.setattr(egress, "MAX_LOOKUPS", 16)
        monkeypatch.setattr(egress, "_lookup_slots", threading.BoundedSemaphore(16))
        try:
            with profile_context(_profile("alpha")):
                stalled = await asyncio.gather(
                    *(fetch_url("https://blackhole.example/") for _ in range(16)),
                    return_exceptions=True,
                )
            assert all(isinstance(r, EgressRefusedError) for r in stalled)
            with profile_context(_profile("beta")):
                content = (await fetch_url("https://example.com/")).content
            assert content == "ok"
        finally:
            release.set()
            deadline = time.monotonic() + 5
            while egress._lookup_slots._value < 16 and time.monotonic() < deadline:
                await asyncio.sleep(0.01)


class TestReconnectInvalidation:
    """B reads its own ``surface.built_at``; A's reconnect must not move it."""

    async def test_an_agent_reconnect_drops_only_its_own_aggregate(self, tmp_path: Any) -> None:
        alpha, beta = _profile("alpha"), _profile("beta")
        profiles = {"alpha": alpha, "beta": beta}
        set_profiles(profiles)
        register_active_config(tmp_path / "profiles.yaml", GatewayConfig(profiles=profiles), {})
        for name in profiles:
            _profile_tools_cache[name] = [{"name": "shared__get_doc"}]
            _profile_backend_urls[name] = {SHARED_URL}

        async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
            return ListToolsResult(tools=[Tool(name="get_doc", description="", input_schema={})])

        try:
            with (
                profile_context(alpha),
                patch("trentina.gateway.backend._do_list_tools", side_effect=ok),
            ):
                result = await reconnect_backend("shared")
        finally:
            compress._profiles = None
        assert result["reconnected"] is True
        assert "alpha" not in _profile_tools_cache
        assert "beta" in _profile_tools_cache


class TestSessionCensus:
    """Every profile's session count was in the agent-readable journal."""

    def test_no_log_line_names_another_profiles_sessions(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        alice = _profile("alice")
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        client = TestClient(gateway_app({"alice": alice}, sessions=sessions))
        caplog.set_level(logging.DEBUG)
        sessions.create_session("bob-the-other-agent")
        caplog.clear()

        sessions.create_session("alice")
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer alice-bearer", MCP_SESSION_ID_HEADER: "0" * 32},
        )

        assert resp.status_code == 404
        assert "bob-the-other-agent" not in caplog.text


class _KeyedProvider(Provider):
    def __init__(self, fingerprint: str, error: QuarantineAgentError | None = None) -> None:
        self._model = "m"
        self.judge = ("openrouter", "m")
        self.key_ordinal = fingerprint
        self.error = error

    async def generate(self, *_args: object, **_kwargs: object) -> ProviderResult:
        if self.error is not None:
            raise self.error
        return ProviderResult(text="{}")


class TestL3LimiterKey:
    """A provider throttles per key; the limiter paused every key on the model."""

    async def test_one_keys_throttle_does_not_refuse_another_keys_call(self) -> None:
        throttled = QuarantineAgentError("HTTP 429", status_code=429, retry_after=60.0)
        with pytest.raises(QuarantineAgentError):
            await limited_generate(
                _KeyedProvider("aaaa", throttled), system_prompt="s", user_content="u"
            )
        result = await limited_generate(_KeyedProvider("bbbb"), system_prompt="s", user_content="u")
        assert result.text == "{}"
        assert limiter_for(("openrouter", "m"), "aaaa").resume_in() > 30

    async def test_the_fingerprint_is_per_key_and_never_the_key(self) -> None:
        one = get_provider("openrouter", SecretStr("sk-or-alpha-secret"), "x/y")
        two = get_provider("openrouter", SecretStr("sk-or-beta-secret"), "x/y")
        again = get_provider("openrouter", SecretStr("sk-or-alpha-secret"), "x/z")
        assert one.key_ordinal != two.key_ordinal
        assert again.key_ordinal == one.key_ordinal
        assert re.fullmatch(r"key\d+", one.key_ordinal), "an ordinal, nothing of the key"
        assert limiter_for(one.judge, one.key_ordinal) is not limiter_for(
            two.judge, two.key_ordinal
        )


class TestL2FairShare:
    """One FIFO queue made B wait behind A's whole backlog."""

    async def test_a_backlog_delays_another_profile_by_one_turn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "1")
        monkeypatch.setattr(classifier, "_gate", None)
        order: list[str] = []
        lock = threading.Lock()

        def fake_classify(text: str, **_kw: object) -> None:
            with lock:
                order.append(text)
            time.sleep(0.01)

        monkeypatch.setattr(classifier, "classify", fake_classify)
        with profile_context(_profile("alpha")):
            backlog = [asyncio.ensure_future(classifier.classify_async(f"a{i}")) for i in range(6)]
        await asyncio.sleep(0)
        with profile_context(_profile("beta")):
            mine = asyncio.ensure_future(classifier.classify_async("b0"))
        await asyncio.gather(*backlog, mine)
        assert order.index("b0") <= 2, order

    async def test_a_cancelled_waiter_passes_its_turn_on(self) -> None:
        gate = classifier.FairGate(1)
        await gate.acquire("alpha")
        waiting = asyncio.ensure_future(gate.acquire("beta"))
        await asyncio.sleep(0)
        waiting.cancel()
        gate.release()
        await asyncio.wait_for(gate.acquire("gamma"), timeout=1)
        assert gate.locked()
