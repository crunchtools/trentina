"""Sending a profile's own grant to its backend, and the backend_auth tool (#479, part 3)."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx2
import pytest
from pydantic import SecretStr

from tests.backend_oauth_harness import login, profile_with_era
from trentina.gateway import backend, backend_oauth, backend_tokens
from trentina.gateway.backend import (
    ResponseCap,
    call_backend_tool,
    list_backend_tools,
    revalidate_backend_tools,
)
from trentina.gateway.backend_tokens import BackendGrant
from trentina.gateway.circuit import State, breaker
from trentina.gateway.context import profile_context
from trentina.gateway.errors import BackendCallError, BackendNeedsAuthError
from trentina.outcomes import Outcome, classify_exception
from trentina.tools import backend_auth
from trentina.tools.backend_auth import (
    backend_auth_revoke,
    backend_auth_start,
    backend_auth_status,
)

if TYPE_CHECKING:
    from trentina.gateway.profile import Profile

CANARY = "zqx7canary"


def _grant(token: str, generation: int = 0) -> BackendGrant:
    return BackendGrant(
        access_token=SecretStr(token),
        refresh_token=SecretStr("refresh"),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        issuer="https://auth.era.example",
        token_endpoint="https://auth.era.example/token",
        client_id="client-1",
        obtained_at=datetime.now(UTC),
        generation=generation,
    )


class _Backend:
    """Stands in for the MCP session: records headers, plays scripted replies."""

    def __init__(self) -> None:
        self.headers: list[dict[str, str] | None] = []
        self.script: list[str] = []

    def _next(self, cap: ResponseCap | None) -> None:
        step = self.script.pop(0) if self.script else "ok"
        if step == "401" and cap is not None:
            cap.unauthorized = True
            raise RuntimeError("Server returned an error response")
        if step == "accepted_then_drop" and cap is not None:
            cap.call_accepted = True
            raise RuntimeError("stream dropped")
        if step == "fail":
            raise RuntimeError(f"transport broke Bearer {CANARY}-token")

    async def call(
        self, _url: str, headers: dict[str, str] | None, *_: Any, cap: Any = None, **__: Any
    ) -> Any:
        self.headers.append(headers)
        self._next(cap)
        return SimpleNamespace(content=[], is_error=False, structured_content=None)

    async def list(self, _url: str, headers: dict[str, str] | None, cap: Any = None) -> Any:
        self.headers.append(headers)
        self._next(cap)

        return SimpleNamespace(tools=[])


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, server: Any, profiles: dict[str, Profile]) -> _Backend:
    del server, profiles  # the store and the live config the calls read
    stub = _Backend()
    monkeypatch.setattr(backend, "_do_call_tool", stub.call)
    monkeypatch.setattr(backend, "_do_list_tools", stub.list)
    monkeypatch.setattr(backend, "_auth_cooldown", {})
    monkeypatch.setattr(backend, "save_tool_list", lambda *_a: None)
    monkeypatch.setattr(backend_auth, "_starts", {})
    breaker.reset()
    backend._tool_list_cache.clear()
    return stub


async def _store_grant(profile: Profile) -> None:
    store = backend_tokens.backend_token_store()
    assert store is not None
    era = profile.backends["era"]
    async with store.locked(profile.name, "era"):
        await store.put_grant(profile.name, "era", era, _grant("access-1"), expected_generation=0)


async def _call(profile: Profile) -> Any:
    with profile_context(profile):
        return await call_backend_tool("era", profile.backends["era"], "spend", {})


class TestTheGrantIsSent:
    async def test_the_calling_profiles_token_is_the_one_sent(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        await _store_grant(profiles["josui"])
        await _call(profiles["josui"])
        assert fake.headers[-1] == {"Authorization": "Bearer access-1"}

    async def test_a_profile_without_a_grant_is_told_to_authorize(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        await _store_grant(profiles["josui"])
        for _ in range(5):
            with pytest.raises(
                BackendNeedsAuthError, match=r'backend_auth with action="start"'
            ) as caught:
                await _call(profiles["kagetora"])
        assert classify_exception(caught.value) is Outcome.NEEDS_AUTH
        assert fake.headers == []
        assert breaker.get_state(profiles["josui"].backends["era"].url) is State.CLOSED
        await _call(profiles["josui"])

    async def test_no_bound_profile_is_a_gateway_error(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        with pytest.raises(Exception, match="no calling profile"):
            await call_backend_tool("era", profiles["josui"].backends["era"], "spend", {})


class TestA401:
    async def test_is_refreshed_once_and_retried(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _store_grant(profiles["josui"])
        asked: list[int | None] = []

        async def refreshed(_p: Profile, _n: str, *, stale_generation: int | None = None) -> Any:
            asked.append(stale_generation)
            return _grant("access-2", 2) if stale_generation is not None else _grant("access-1", 1)

        monkeypatch.setattr(backend_oauth, "fresh_grant", refreshed)
        fake.script = ["401", "ok"]
        await _call(profiles["josui"])
        assert [h["Authorization"] for h in fake.headers if h] == [
            "Bearer access-1",
            "Bearer access-2",
        ]
        assert asked == [None, 1]

    async def test_twice_is_needs_auth_then_a_cooldown(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        refreshes = 0

        async def refreshed(_p: Profile, _n: str, *, stale_generation: int | None = None) -> Any:
            nonlocal refreshes
            refreshes += stale_generation is not None
            return _grant("access", 1)

        monkeypatch.setattr(backend_oauth, "fresh_grant", refreshed)
        fake.script = ["401", "401"]
        with pytest.raises(BackendNeedsAuthError):
            await _call(profiles["josui"])
        with pytest.raises(BackendNeedsAuthError):
            await _call(profiles["josui"])
        assert refreshes == 1
        assert len(fake.headers) == 2
        assert breaker.get_state(profiles["josui"].backends["era"].url) is State.CLOSED

    async def test_a_call_the_backend_accepted_is_never_sent_twice(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        await _store_grant(profiles["josui"])
        fake.script = ["accepted_then_drop"]
        with pytest.raises(BackendCallError):
            await _call(profiles["josui"])
        assert len(fake.headers) == 1


class TestTheHooks:
    async def test_only_a_401_to_a_request_that_ran_nothing_counts(self) -> None:
        cap = ResponseCap(1024)

        async def answer(method: str, url_method: str, status: int) -> None:
            body = b'{"jsonrpc":"2.0","id":1,"method":"%s"}' % method.encode()
            request = httpx2.Request(url_method, "https://mcp.example/mcp", content=body)
            await cap.tag(request)
            await cap.hook(httpx2.Response(status, request=request))

        await answer("x", "GET", 401)
        assert not cap.unauthorized
        await answer("notifications/initialized", "POST", 401)
        assert not cap.unauthorized
        await answer("tools/call", "POST", 200)
        assert cap.call_accepted
        cap.reset()
        await answer("initialize", "POST", 401)
        assert cap.unauthorized
        assert not cap.call_accepted


class TestLists:
    async def test_one_profiles_missing_grant_does_not_fail_anothers_list(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        await _store_grant(profiles["josui"])
        era = profiles["josui"].backends["era"]
        results = await asyncio.gather(
            list_backend_tools("era", era, profiles["kagetora"]),
            list_backend_tools("era", era, profiles["josui"]),
            return_exceptions=True,
        )
        assert isinstance(results[0], BackendNeedsAuthError)
        assert results[1] == []
        assert backend._inflight == {}

    async def test_the_warm_ups_leave_an_oauth_backend_alone(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        era = profiles["josui"].backends["era"]
        backend._tool_list_cache[era.url] = [{"name": "spend"}]
        assert await revalidate_backend_tools("era", era) is False
        assert fake.headers == []


class TestTheTool:
    async def test_start_status_revoke(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
    ) -> None:
        josui = profiles["josui"]
        with profile_context(josui):
            started = await backend_auth_start("era")
            assert started["link"].startswith("https://gw.example/oauth/backend/start?flow=")
            assert (await backend_auth_status("era"))["backends"][0]["authorized"] is False
        await login(server, josui)
        with profile_context(josui):
            status = await backend_auth_status()
            assert status["backends"][0]["authorized"] is True
            assert "access" not in repr(status)
            assert (await backend_auth_revoke("era"))["revoked"] is True
            assert (await backend_auth_status("era"))["backends"][0]["authorized"] is False
        store = backend_tokens.backend_token_store()
        assert store is not None
        assert await store.get_client("josui", "era", josui.backends["era"]) is not None

    async def test_another_profiles_backend_is_not_reachable(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
    ) -> None:
        with profile_context(profiles["josui"]):
            refused = await backend_auth_start("not-mine")
        assert "error" in refused
        assert refused["available"] == ["era"]

    async def test_self_authorize_gates_an_agent(self, fake: _Backend) -> None:
        locked = profile_with_era("takeda", self_authorize=False)
        with profile_context(locked):
            assert "error" in await backend_auth_start("era")
            assert "error" in await backend_auth_revoke("era")

    async def test_starts_are_rate_limited(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(backend_auth, "STARTS_PER_HOUR", 2)
        with profile_context(profiles["josui"]):
            answers = [await backend_auth_start("era") for _ in range(3)]
        assert "link" in answers[1]
        assert "over 2 logins" in answers[2]["error"]


class TestAfterLogin:
    async def test_the_hook_hears_theprofile_with_era(
        self,
        server: Any,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        heard: list[str] = []

        async def hook(profile_name: str) -> None:
            heard.append(profile_name)

        monkeypatch.setattr(backend_oauth, "_on_grant_stored", [hook])
        await login(server, profiles["josui"])
        assert heard == ["josui"]


class TestNothingLeaks:
    async def test_tokens_stay_out_of_logs(
        self,
        fake: _Backend,
        profiles: dict[str, Profile],
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        caplog.set_level(logging.DEBUG)

        async def refreshed(_p: Profile, _n: str, **_: Any) -> Any:
            return _grant(f"{CANARY}-raw-token-0123456789", 1)

        monkeypatch.setattr(backend_oauth, "fresh_grant", refreshed)
        fake.script = ["401", "fail"]
        with pytest.raises(BackendCallError):
            await _call(profiles["josui"])
        assert CANARY not in caplog.text


class TestRevocationAtTheServer:
    """RFC 7009 revocation at the endpoint pinned when the grant was issued (#499)."""

    async def _revoke(self, server: Any, profile: Profile) -> dict[str, Any]:
        await login(server, profile)
        with profile_context(profile):
            result = await backend_auth_revoke("era")
        store = backend_tokens.backend_token_store()
        assert store is not None
        assert await store.get_grant(profile.name, "era", profile.backends["era"]) is None
        return result

    async def test_the_pinned_endpoint_is_told_refresh_token_first(
        self, fake: _Backend, server: Any, profiles: dict[str, Profile]
    ) -> None:
        server.revocation = True
        result = await self._revoke(server, profiles["josui"])
        assert result["revoked"] is True
        assert result["remote"] == "revoked"
        assert [(r["token"], r["token_type_hint"]) for r in server.revoked] == [
            ("refresh-1", "refresh_token"),
            ("access-1", "access_token"),
        ]
        assert server.revoked[0]["authorization"].startswith("Basic ")

    async def test_a_grant_without_a_pinned_endpoint_sends_nothing(
        self, fake: _Backend, server: Any, profiles: dict[str, Profile]
    ) -> None:
        result = await self._revoke(server, profiles["josui"])
        assert result["revoked"] is True
        assert result["remote"] == "revocation_endpoint_not_pinned"
        assert "settings" in result["note"]
        assert server.revoked == []

    async def test_the_endpoint_is_not_rediscovered_at_revoke(
        self, fake: _Backend, server: Any, profiles: dict[str, Profile]
    ) -> None:
        await login(server, profiles["josui"])
        server.revocation = True  # advertised only after the grant was issued
        with profile_context(profiles["josui"]):
            result = await backend_auth_revoke("era")
        assert result["remote"] == "revocation_endpoint_not_pinned"
        assert server.revoked == []

    @pytest.mark.parametrize("status", [400, 503])
    async def test_a_refusal_is_reported_and_the_grant_is_still_deleted(
        self, fake: _Backend, server: Any, profiles: dict[str, Profile], status: int
    ) -> None:
        server.revocation = True
        server.revoke_status = status
        result = await self._revoke(server, profiles["josui"])
        assert result["revoked"] is True
        assert result["remote"] == "revocation_refused"
        assert "body-must-not-leak" not in repr(result)

    async def test_an_unreachable_server_is_reported_and_the_grant_is_still_deleted(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        server.revocation = True
        await login(server, profiles["josui"])

        async def down(*_a: Any, **_k: Any) -> Any:
            raise backend_oauth.BackendAuthError("unreachable")

        monkeypatch.setattr(backend_oauth, "_request", down)
        with profile_context(profiles["josui"]):
            result = await backend_auth_revoke("era")
        assert result["revoked"] is True
        assert result["remote"] == "revocation_unreachable"

    async def test_a_slow_server_does_not_hold_up_the_delete(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        server.revocation = True
        await login(server, profiles["josui"])

        async def slow(*_a: Any, **_k: Any) -> Any:
            await asyncio.sleep(10)

        monkeypatch.setattr(backend_oauth, "_request", slow)
        monkeypatch.setattr(backend_oauth, "REVOKE_DEADLINE", 0.01)
        with profile_context(profiles["josui"]):
            result = await backend_auth_revoke("era")
        assert result["revoked"] is True
        assert result["remote"] == "revocation_unreachable"

    async def test_the_grant_is_gone_and_the_lock_free_during_the_remote_call(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        profile = profiles["josui"]
        await login(server, profile)
        store = backend_tokens.backend_token_store()
        assert store is not None
        seen: dict[str, Any] = {}

        async def remote(_s: Any, p: Profile, name: str, cfg: Any, grant: Any) -> str:
            seen["grant"] = await store.get_grant(p.name, name, cfg)
            async with store.locked(p.name, name):  # would deadlock if still held
                seen["lock_free"] = True
            seen["passed"] = grant
            return "revoked"

        monkeypatch.setattr(backend_auth, "revoke_remote", remote)
        with profile_context(profile):
            result = await backend_auth_revoke("era")
        assert result == {"backend": "era", "revoked": True, "remote": "revoked"}
        assert seen["grant"] is None
        assert seen["lock_free"] is True
        assert seen["passed"] is not None

    async def test_the_local_delete_stands_when_the_remote_call_raises(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        profile = profiles["josui"]
        await login(server, profile)

        async def boom(*_a: Any, **_k: Any) -> str:
            raise RuntimeError("boom")

        monkeypatch.setattr(backend_auth, "revoke_remote", boom)
        with profile_context(profile):
            result = await backend_auth_revoke("era")
        assert result["error"] == "RuntimeError"
        store = backend_tokens.backend_token_store()
        assert store is not None
        assert await store.get_grant(profile.name, "era", profile.backends["era"]) is None

    async def test_no_token_reaches_a_log(
        self,
        fake: _Backend,
        server: Any,
        profiles: dict[str, Profile],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        server.revocation = True
        server.revoke_status = 400
        await self._revoke(server, profiles["josui"])
        assert "revocation refused (status 400)" in caplog.text
        for secret in ("refresh-1", "access-1", "secret-client", "body-must-not-leak"):
            assert secret not in caplog.text

    async def test_a_grant_sealed_before_the_field_existed_still_opens(
        self, fake: _Backend, profiles: dict[str, Profile]
    ) -> None:
        store = backend_tokens.backend_token_store()
        assert store is not None
        era = profiles["josui"].backends["era"]
        async with store.locked("josui", "era"):
            await store.put_grant("josui", "era", era, _grant("access-1"), expected_generation=0)
        envelope = await store._records.get("josui:era", collection=backend_tokens._GRANTS)
        record = json.loads(store._fernet.decrypt(envelope["ct"].encode()))
        del record["revocation_endpoint"]
        envelope["ct"] = store._fernet.encrypt(json.dumps(record).encode()).decode("ascii")
        await store._records.put("josui:era", envelope, collection=backend_tokens._GRANTS)
        old = await store.get_grant("josui", "era", era)
        assert old is not None
        assert old.revocation_endpoint is None
