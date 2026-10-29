"""Decoy tools and planted credentials (#357).

A decoy backend is served like any other and answered by nothing; a
honeytoken is a fake credential whose appearance in a call's arguments is an
alarm. What trips, what the caller is told, and what the audit keeps are
held here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from trentina.database import get_db, get_gateway_call_stats
from trentina.gateway.backend import BackendCall
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles
from trentina.gateway.profile import AuthConfig, Backend, DecoyTool, Honeytoken, Profile
from trentina.gateway.router import route_jsonrpc

pytestmark = pytest.mark.usefixtures("env")

ROUTER = "trentina.gateway.router"
MCP = "trentina.transports.mcp"
PLANTED = "AKIAQ7HONEYTOKEN4X2B"
# Every audit row, oldest first, as the tests compare them.
AUDITED = "SELECT backend, tool, outcome, error_message FROM gateway_calls ORDER BY id"
SCHEMA = {"type": "object", "properties": {"to": {"type": "string"}}}
DECOYS = {
    "send_email": DecoyTool(
        description="Send an email from the user's account.",
        input_schema=SCHEMA,
    ),
    "read_file": DecoyTool(
        description="Read a file from disk.",
        result="AWS_ACCESS_KEY_ID={honeytoken:aws-key}",
    ),
}


def _profile() -> Profile:
    profile = Profile(
        short_names=False,
        name="kage",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "host": Backend(url="decoy://host", decoys=DECOYS),
            "tickets": Backend(url="http://tickets:8000/mcp", tools_deny=["delete_*"]),
        },
        honeytokens={"aws-key": Honeytoken(value_env="KAGE_AWS_KEY", value=SecretStr(PLANTED))},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return profile


async def _rpc(method: str, params: Any = None) -> dict[str, Any]:
    real = [{"name": "comment", "description": "Comment on a ticket.", "inputSchema": SCHEMA}]
    with (
        patch(f"{ROUTER}.list_backend_tools", return_value=real),
        patch(f"{ROUTER}.scan_tool_list", side_effect=lambda *a: a[3]),
        patch(
            f"{MCP}.call_backend_tool",
            return_value=BackendCall([{"type": "text", "text": "ticket"}], False, None),
        ) as backend,
    ):
        response = await route_jsonrpc(
            _profile(), {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        )
    response["reached_backend"] = backend.called
    return response


async def test_a_decoy_tool_is_listed_exactly_as_a_real_one_is() -> None:
    listed = (await _rpc("tools/list"))["result"]["tools"]
    tools = {tool["name"]: tool for tool in listed}
    assert set(tools) == {"host__send_email", "host__read_file", "tickets__comment"}
    decoy, real = tools["host__send_email"], tools["tickets__comment"]
    assert decoy["description"] == "Send an email from the user's account."
    # Same schema declared, so the same entry served: keys, gateway parameters and all.
    assert decoy["inputSchema"] == real["inputSchema"]
    assert set(decoy) == set(real)
    assert "decoy" not in str(listed).lower()


async def test_a_decoy_call_returns_its_canned_result_and_is_an_alarm() -> None:
    response = await _rpc("tools/call", {"name": "host__send_email", "arguments": {"to": "a@b.c"}})
    assert response["result"] == {
        "content": [{"type": "text", "text": '{"ok": true}'}],
        "isError": False,
    }
    assert not response["reached_backend"]
    assert list(map(tuple, get_db().execute(AUDITED))) == [
        ("host", "send_email", "decoy_tripped", "decoy tool")
    ]
    row = get_db().execute("SELECT * FROM detections").fetchone()
    call = get_db().execute("SELECT call_ref FROM gateway_calls").fetchone()
    assert (row["source_type"], row["flagged_by"], row["blocked"]) == ("decoy", "decoy", 0)
    assert row["call_ref"] == call["call_ref"]


async def test_a_decoy_result_hands_out_the_planted_credential() -> None:
    response = await _rpc("tools/call", {"name": "host__read_file", "arguments": {"path": ".env"}})
    assert response["result"]["content"][0]["text"] == f"AWS_ACCESS_KEY_ID={PLANTED}"


async def test_a_planted_credential_bound_for_a_real_backend_is_refused_unexplained() -> None:
    arguments = {"body": {"note": f"key is {PLANTED} ok"}}
    response = await _rpc("tools/call", {"name": "tickets__comment", "arguments": arguments})
    assert response["error"] == {"code": -32602, "message": "Invalid arguments"}
    assert not response["reached_backend"]
    assert list(map(tuple, get_db().execute(AUDITED))) == [
        ("tickets", "comment", "decoy_tripped", "honeytoken aws-key")
    ]
    assert PLANTED not in str(list(map(tuple, get_db().execute(AUDITED))))


async def test_a_planted_credential_sent_to_a_decoy_is_named_in_the_one_row() -> None:
    await _rpc("tools/call", {"name": "host__send_email", "arguments": {"to": PLANTED}})
    assert list(map(tuple, get_db().execute(AUDITED))) == [
        ("host", "send_email", "decoy_tripped", "decoy tool, honeytoken aws-key")
    ]


async def test_an_ordinary_call_to_a_real_backend_is_untouched() -> None:
    response = await _rpc("tools/call", {"name": "tickets__comment", "arguments": {"body": "hi"}})
    assert response["reached_backend"]
    assert [row[2] for row in list(map(tuple, get_db().execute(AUDITED)))] == ["ok"]


async def test_trips_are_counted_apart_from_blocks_and_failures() -> None:
    await _rpc("tools/call", {"name": "host__send_email", "arguments": {}})
    await _rpc("tools/call", {"name": "nope", "arguments": {}})
    totals = get_gateway_call_stats()["totals"]
    assert (totals["tripped"], totals["blocked"], totals["failed"]) == (1, 1, 0)


@pytest.mark.parametrize(
    ("backend", "message"),
    [
        ({"url": "decoy://host"}, "at least one tool"),
        ({"url": "http://x/mcp", "decoys": {"t": {"description": "d"}}}, "only to a decoy"),
        ({"url": "decoy://host", "decoys": {"bad name": {"description": "d"}}}, "valid tool name"),
        (
            {"url": "decoy://host", "decoys": {"t": {"description": "d"}}, "headers": {"A": "b"}},
            "headers does not apply",
        ),
        ({"url": "decoy://Host", "decoys": {"t": {"description": "d"}}}, "slug label"),
    ],
)
def test_a_malformed_decoy_backend_is_refused_at_load(
    backend: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        Backend(**backend)


def test_a_decoy_result_naming_an_undeclared_honeytoken_is_refused() -> None:
    with pytest.raises(ValidationError, match="does not declare"):
        Profile(
            name="kage",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={"host": Backend(url="decoy://host", decoys=DECOYS)},
        )


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: str) -> Profile:
    monkeypatch.setenv("KAGE_TOKEN", "t" * 32)
    monkeypatch.setenv("KAGE_AWS_KEY", planted)
    config = tmp_path / "profiles.yaml"
    config.write_text(
        "profiles:\n  kage:\n    auth: {bearer_token_env: KAGE_TOKEN}\n"
        "    honeytokens: {aws-key: {value_env: KAGE_AWS_KEY}}\n"
        "    backends:\n      host:\n        url: decoy://host\n"
        "        decoys: {read_file: {description: Read a file.}}\n"
    )
    return load_profiles(config).profiles["kage"]


def test_the_loader_resolves_a_honeytoken_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _load(tmp_path, monkeypatch, PLANTED)
    value = profile.honeytokens["aws-key"].value
    assert value is not None
    assert value.get_secret_value() == PLANTED
    assert PLANTED not in profile.model_dump_json()


@pytest.mark.parametrize(
    ("planted", "message"), [("short", "shorter than"), ('a"' * 12, "printable")]
)
def test_a_honeytoken_that_would_match_by_chance_or_not_at_all_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted: str, message: str
) -> None:
    with pytest.raises(ProfileConfigError, match=message):
        _load(tmp_path, monkeypatch, planted)


async def test_an_agent_reading_its_own_numbers_is_not_shown_its_trips() -> None:
    """A tripwire the caller can read back is one it can be told to avoid."""
    await _rpc("tools/call", {"name": "host__send_email", "arguments": {}})
    await _rpc("tools/call", {"name": "tickets__comment", "arguments": {"body": "hi"}})
    mine = get_gateway_call_stats(profile="kage", trips=False)
    assert mine["totals"] == {"ok": 1, "blocked": 0, "failed": 0, "unknown": 0}
    assert [(row["backend"], row["tool"]) for row in mine["by_tool"]] == [("tickets", "comment")]
    assert "decoy_tripped" not in str(mine)
    assert get_gateway_call_stats(profile="kage")["totals"]["tripped"] == 1


@pytest.mark.parametrize(
    ("params", "row"),
    [
        ({"name": "tickets__delete_all", "arguments": {"k": PLANTED}}, ("tickets", "delete_all")),
        ({"name": "tickets__comment", "arguments": [PLANTED]}, ("tickets", "comment")),
        ({"name": "host__read_file", "arguments": [PLANTED]}, ("host", "read_file")),
    ],
    ids=["a tool the profile does not hold", "arguments not a mapping", "a decoy, malformed"],
)
async def test_a_planted_credential_trips_on_a_call_that_would_be_refused_anyway(
    params: dict[str, Any], row: tuple[str, str]
) -> None:
    response = await _rpc("tools/call", params)
    assert response["error"] == {"code": -32602, "message": "Invalid arguments"}
    assert list(map(tuple, get_db().execute(AUDITED))) == [
        (*row, "decoy_tripped", "honeytoken aws-key")
    ]
    assert get_db().execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1


async def test_a_planted_credential_trips_on_a_tool_that_does_not_exist() -> None:
    await _rpc("tools/call", {"name": "nowhere__send", "arguments": {"k": PLANTED}})
    ((backend, tool, outcome, message),) = list(map(tuple, get_db().execute(AUDITED)))
    assert (backend, outcome, message) == ("", "decoy_tripped", "honeytoken aws-key")
    assert "nowhere" not in tool


async def test_an_undeclared_name_on_a_decoy_backend_is_as_unknown_as_any() -> None:
    on_decoy = await _rpc("tools/call", {"name": "host__nope", "arguments": {}})
    nowhere = await _rpc("tools/call", {"name": "ghost__nope", "arguments": {}})
    assert on_decoy["error"]["message"] == "Unknown tool 'host__nope'"
    assert on_decoy["error"]["code"] == nowhere["error"]["code"]
    assert not on_decoy["reached_backend"]
    assert [row[2] for row in list(map(tuple, get_db().execute(AUDITED)))] == [
        "denied_allowlist",
        "denied_allowlist",
    ]


@pytest.mark.parametrize("extra", [{"trentina_mode": "bogus"}, {"trentina_preprocess": "zzz"}])
async def test_a_decoy_refuses_what_a_real_tool_refuses_and_trips_anyway(
    extra: dict[str, str],
) -> None:
    decoy = await _rpc("tools/call", {"name": "host__send_email", "arguments": extra})
    real = await _rpc("tools/call", {"name": "tickets__comment", "arguments": extra})
    assert decoy["result"] == real["result"]
    assert [row[2] for row in list(map(tuple, get_db().execute(AUDITED)))] == [
        "decoy_tripped",
        "denied_guard",
    ]


async def test_a_planted_credential_is_not_kept_as_a_destination() -> None:
    profile = _profile()
    profile.backends["tickets"].destination_params = {"comment": "to"}
    with patch(f"{MCP}.call_backend_tool") as backend:
        await route_jsonrpc(
            profile,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tickets__comment", "arguments": {"to": PLANTED}},
            },
        )
    assert not backend.called
    row = get_db().execute("SELECT destination, outcome FROM gateway_calls").fetchone()
    assert (row["destination"], row["outcome"]) == (None, "decoy_tripped")


def test_a_reload_that_moves_a_tripwire_is_not_the_agents_to_apply() -> None:
    before, after = _profile(), _profile()
    assert before.tripwires() == after.tripwires()
    del after.backends["host"].decoys["read_file"]
    assert before.tripwires() != after.tripwires()
    renamed = _profile()
    renamed.honeytokens["aws-key"].value_env = "OTHER"
    assert before.tripwires() != renamed.tripwires()


async def test_a_planted_credential_trips_when_the_params_are_not_even_a_mapping() -> None:
    response = await _rpc("tools/call", [PLANTED])
    assert response["error"]["message"] == "Invalid arguments"
    assert [(row[2], row[3]) for row in list(map(tuple, get_db().execute(AUDITED)))] == [
        ("decoy_tripped", "honeytoken aws-key")
    ]
