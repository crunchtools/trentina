"""An audit row can be joined to the rows written beside it (#357).

A detection used to share nothing with the call that raised it but a
profile, a tool and a clock, and two calls of one session shared nothing at
all. What a decoy trip is traced back along is held here.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from trentina.config import get_config
from trentina.database import get_db, record_detection
from trentina.gateway import internal
from trentina.gateway.app import gateway_app
from trentina.gateway.context import current_session
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.surface import wire_bytes, wire_digest
from trentina.transports.mcp import route_jsonrpc

from .mode_harness import MALICIOUS, layers

pytestmark = pytest.mark.usefixtures("env", "real_server")

FETCH = {"name": f"web{NAMESPACE_SEP}fetch_tool", "arguments": {"url": "https://example.com/doc"}}


@pytest.fixture
def real_server() -> Iterator[None]:
    from trentina.server import mcp

    saved = internal._server
    internal.register_internal_server(mcp)
    try:
        yield
    finally:
        internal._server = saved


def _profile() -> Profile:
    profile = Profile(
        short_names=False,
        name="alpha",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={"web": Backend(url="internal://web", tools_allow=["*"])},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return profile


async def _call(params: Any) -> dict[str, Any]:
    return await route_jsonrpc(
        _profile(), {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    )


def _calls() -> list[dict[str, Any]]:
    rows = get_db().execute("SELECT * FROM gateway_calls ORDER BY id").fetchall()
    return [dict(row) for row in rows]


async def test_a_detection_carries_the_reference_of_the_call_that_raised_it(
    tmp_path: Path,
) -> None:
    with layers(tmp_path, classification=MALICIOUS):
        await _call(FETCH)
    (call,) = _calls()
    detections = get_db().execute("SELECT call_ref, flagged_by FROM detections").fetchall()
    assert [(d["call_ref"], d["flagged_by"]) for d in detections] == [(call["call_ref"], "L2")]
    assert len(call["call_ref"]) == 16


async def test_every_call_has_its_own_reference_and_the_same_result_the_same_digest(
    tmp_path: Path,
) -> None:
    with layers(tmp_path):
        await _call(FETCH)
        await _call(FETCH)
    first, second = _calls()
    assert first["call_ref"] != second["call_ref"]
    assert first["content_digest"] == second["content_digest"] is not None


async def test_a_refused_call_has_a_reference_and_no_digest() -> None:
    await _call({"name": "nope", "arguments": {}})
    (call,) = _calls()
    assert call["call_ref"]
    assert call["content_digest"] is None


async def test_calls_made_under_a_session_carry_it_and_others_carry_none(tmp_path: Path) -> None:
    with layers(tmp_path):
        await _call(FETCH)
        token = current_session.set("0123456789abcdef")
        try:
            await _call(FETCH)
            await _call(FETCH)
        finally:
            current_session.reset(token)
    assert [call["session"] for call in _calls()] == [None, "0123456789abcdef", "0123456789abcdef"]


def test_the_session_in_the_audit_is_a_fingerprint_of_the_header() -> None:
    profile = _profile()
    client = TestClient(gateway_app({"alpha": profile}))
    headers = {"Authorization": "Bearer x"}
    opened = client.post(
        "/alpha/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers=headers,
    )
    session = opened.headers["mcp-session-id"]
    client.post(
        "/alpha/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "nope"}},
        headers={**headers, "mcp-session-id": session},
    )
    # The app wrote from its own thread, so the row is read on a connection of this one.
    reader = sqlite3.connect(get_config().db_path)
    ((recorded,),) = reader.execute("SELECT session FROM gateway_calls").fetchall()
    assert len(recorded) == 16
    assert recorded not in session


def test_a_detection_recorded_outside_a_call_has_no_reference() -> None:
    record_detection("web", "https://example.com/x", "example.com", {}, "high")
    row = get_db().execute("SELECT call_ref FROM detections").fetchone()
    assert row["call_ref"] is None


def test_the_digest_is_of_the_bytes_the_size_counts() -> None:
    result = {"content": [{"type": "text", "text": "héllo"}]}
    size, digest = wire_digest(result)
    assert size == wire_bytes(result)
    assert digest != wire_digest({"content": []})[1]
    assert len(digest) == 16
