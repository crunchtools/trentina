"""Every gateway ingress judges on the calling profile's own provider (RT #1505).

Only internal tool dispatch used to bind the profile, so proxied tool
responses, Matrix syncs, alerts and /proxy/llm/ completions ran L3 unbound, on the
global provider and its key, whatever the profile's ``defense.provider`` said.
Each test sends one payload through one ingress and records which provider L3
was actually called with.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from trentina.errors import QuarantineAgentError
from trentina.gateway.backend import BackendCall
from trentina.gateway.profile import (
    AlertIngressConfig,
    AuthConfig,
    Backend,
    DefenseConfig,
    LlmKeyOverride,
    MatrixIngressConfig,
    Profile,
)
from trentina.gateway.router import route_jsonrpc

PAYLOAD = "Quarterly report: revenue up, costs flat, nothing unusual to note here."


@pytest.fixture
def judged() -> Iterator[list[tuple[str, str | None]]]:
    """Every (provider, key) L3 was asked to use. Refuses, so nothing else runs."""
    calls: list[tuple[str, str | None]] = []

    async def record(**kwargs: Any) -> Any:
        key = kwargs["api_key"]
        calls.append((kwargs["provider_name"], key.get_secret_value() if key else None))
        raise QuarantineAgentError("recorded")

    with patch("trentina.quarantine.agent._call_throttle_aware", side_effect=record):
        yield calls


def _profile(**more: Any) -> Profile:
    p = Profile(
        short_names=False,  # calls below use <backend>__<tool>
        name="agent1",
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="flag", provider="openrouter"),
        llm_keys={"openrouter": LlmKeyOverride(api_key=SecretStr("agent1-key"))},
        backends={"cms": Backend(url="http://cms:8000/mcp")},
        **more,
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


def _only_own(calls: list[tuple[str, str | None]]) -> None:
    assert calls, "L3 was never called"
    assert set(calls) == {("openrouter", "agent1-key")}, calls


@pytest.mark.asyncio
async def test_a_proxied_tool_response(judged: list[tuple[str, str | None]]) -> None:
    reply = BackendCall(
        content=[{"type": "text", "text": PAYLOAD}], is_error=False, structured_content=None
    )
    with (
        patch(
            "trentina.transports.mcp.call_backend_tool",
            AsyncMock(return_value=reply),
        ),
        patch("trentina.gateway.audit._audit"),
    ):
        await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "cms__get_page", "arguments": {}},
            },
        )
    _only_own(judged)


@pytest.mark.asyncio
async def test_an_llm_completion(judged: list[tuple[str, str | None]]) -> None:
    from trentina.gateway import llm_proxy

    llm_proxy._schedule_completion_scan(PAYLOAD.encode(), len(PAYLOAD), "openai", _profile())
    await asyncio.gather(*llm_proxy._scan_tasks)
    _only_own(judged)


def test_an_alert(judged: list[tuple[str, str | None]], monkeypatch: pytest.MonkeyPatch) -> None:
    from starlette.testclient import TestClient

    from tests.test_alert_ingress import AUTH, _alert_app, _mock_forward_http

    _mock_forward_http(monkeypatch)
    profile = _profile(
        alert_ingress=AlertIngressConfig(token_env="ALERT_TOK", forward_url="http://x:1/hook")
    )
    assert profile.alert_ingress is not None
    profile.alert_ingress.token = SecretStr("tok")
    client = TestClient(_alert_app({"agent1": profile}), headers=AUTH)
    assert client.post("/alert", json={"output": PAYLOAD}).status_code == 200
    _only_own(judged)


def test_a_matrix_sync(
    judged: list[tuple[str, str | None]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from starlette.testclient import TestClient

    from tests.test_matrix_proxy import AGENT_NET, AGENT_PEER, _FakeUpstream, _matrix_app
    from trentina.gateway import matrix_proxy

    sync = {
        "rooms": {
            "join": {
                "!r:x": {
                    "timeline": {
                        "events": [{"type": "m.room.message", "content": {"body": PAYLOAD}}]
                    }
                }
            }
        }
    }
    monkeypatch.setattr(
        matrix_proxy, "matrix_pinned_send", _FakeUpstream(json.dumps(sync).encode())
    )
    profile = _profile(matrix_ingress=MatrixIngressConfig(source_networks=[AGENT_NET]))
    client = TestClient(_matrix_app({"agent1": profile}), client=AGENT_PEER)
    assert client.get("/matrix/_matrix/client/v3/sync").status_code == 200
    _only_own(judged)


@pytest.mark.parametrize(
    ("provider", "keys", "warns"),
    [
        ("openrouter", {}, True),
        ("openrouter", {"openrouter": LlmKeyOverride(api_key=SecretStr("k"))}, False),
        ("ollama", {}, False),
    ],
)
def test_a_profile_without_its_own_key_is_warned_about(
    provider: str, keys: dict[str, Any], warns: bool, caplog: pytest.LogCaptureFixture
) -> None:
    from trentina.gateway.loader import _check_judges

    profile = Profile(
        short_names=False,  # calls below use <backend>__<tool>
        name="agent1",
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="flag", provider=provider),
        llm_keys=keys,
    )
    _check_judges({"agent1": profile})
    assert ("has no llm_keys" in caplog.text) is warns


@pytest.mark.asyncio
async def test_a_profile_without_its_key_never_falls_back_to_the_global_one(
    judged: list[tuple[str, str | None]],
) -> None:
    """Refused, not rerouted: L3 is reported unavailable and no provider is called."""
    profile = _profile()
    profile.llm_keys = {}
    reply = BackendCall(
        content=[{"type": "text", "text": PAYLOAD}], is_error=False, structured_content=None
    )
    with (
        patch(
            "trentina.transports.mcp.call_backend_tool",
            AsyncMock(return_value=reply),
        ),
        patch("trentina.gateway.audit._audit"),
    ):
        resp = await route_jsonrpc(
            profile,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "cms__get_page", "arguments": {}},
            },
        )
    assert judged == []
    assert resp["result"]["_trentina_warning"]["l3_unavailable"] is True
