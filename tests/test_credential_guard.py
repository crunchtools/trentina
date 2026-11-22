"""The credential check on a tool call's arguments (#862).

Fake credentials are built at runtime from split literals so no scanner reads
this file as a leak.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from tests.refusal_shape import refused, refused_text
from trentina.credential_shapes import CredentialKind as K
from trentina.gateway.backend import BackendCall
from trentina.gateway.guards import refused_credentials
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import AuthConfig, Backend, ParameterConstraint, Profile
from trentina.transports.mcp import route_jsonrpc

_BODY = "Zq7" * 14
GITHUB = "gh" + "p_" + "A" * 36
OPENAI = "sk" + "-proj-" + _BODY
BEARER = "Bearer " + _BODY


def _backend(**kw: Any) -> Backend:
    return Backend(url="http://luna:8000/mcp", tools_allow=["*"], **kw)


class TestRefusedCredentials:
    def test_a_github_token_is_refused_by_kind(self) -> None:
        assert refused_credentials("t", {"q": "use " + GITHUB}, _backend()) == [K.GITHUB_TOKEN]

    def test_an_openai_key_is_refused(self) -> None:
        assert refused_credentials("t", {"key": OPENAI}, _backend()) == [K.OPENAI_KEY]

    def test_an_authorization_bearer_is_refused(self) -> None:
        found = refused_credentials("t", {"h": "Authorization: " + BEARER}, _backend())
        assert K.AUTHORIZATION in found

    def test_a_percent_encoded_key_is_found_revealed(self) -> None:
        encoded = "".join(f"%{ord(ch):02x}" for ch in GITHUB)
        assert refused_credentials("t", {"q": encoded}, _backend()) == [K.GITHUB_TOKEN]

    def test_a_key_in_a_mapping_key_is_found(self) -> None:
        assert refused_credentials("t", {"q": {GITHUB: "x"}}, _backend()) == [K.GITHUB_TOKEN]

    def test_a_key_escaped_in_every_character_is_found(self) -> None:
        escaped = "".join(f"\\u{ord(c):04x}" for c in OPENAI)
        assert refused_credentials("t", {"q": escaped}, _backend()) == [K.OPENAI_KEY]

    def test_an_allowed_raw_kind_does_not_hide_an_escaped_one(self) -> None:
        escaped = "".join(f"%{ord(c):02X}" for c in OPENAI)
        backend = _backend(credentials_allowed={"t": ["github_token"]})
        assert refused_credentials("t", {"a": GITHUB, "b": escaped}, backend) == [K.OPENAI_KEY]

    def test_a_unicode_escaped_key_is_found_revealed(self) -> None:
        escaped = f"\\u{ord(OPENAI[0]):04x}" + OPENAI[1:]
        assert refused_credentials("t", {"q": escaped}, _backend()) == [K.OPENAI_KEY]

    def test_kinds_are_sorted_and_carry_no_value(self) -> None:
        found = refused_credentials("t", {"a": OPENAI, "b": GITHUB}, _backend())
        assert found == sorted(found)
        assert len(found) == 2
        assert all(GITHUB not in str(k) and OPENAI not in str(k) for k in found)

    def test_no_arguments_is_clean(self) -> None:
        assert refused_credentials("t", {}, _backend()) == []

    def test_plain_arguments_are_clean(self) -> None:
        assert refused_credentials("t", {"q": "hello", "n": 3}, _backend()) == []


class TestAllowlist:
    def test_a_tool_list_allows_that_kind_only(self) -> None:
        b = _backend(credentials_allowed={"t": [K.GITHUB_TOKEN.value]})
        assert refused_credentials("t", {"a": GITHUB}, b) == []
        assert refused_credentials("t", {"a": GITHUB, "b": OPENAI}, b) == [K.OPENAI_KEY]

    def test_other_tools_are_still_refused(self) -> None:
        b = _backend(credentials_allowed={"t": [K.GITHUB_TOKEN.value]})
        assert refused_credentials("other", {"a": GITHUB}, b) == [K.GITHUB_TOKEN]

    def test_a_backend_wide_list_covers_every_tool(self) -> None:
        b = _backend(credentials_allowed=[K.GITHUB_TOKEN.value])
        assert refused_credentials("t", {"a": GITHUB}, b) == []
        assert refused_credentials("u", {"a": GITHUB}, b) == []
        assert refused_credentials("u", {"a": OPENAI}, b) == [K.OPENAI_KEY]

    def test_the_star_tool_key_covers_every_tool(self) -> None:
        b = _backend(credentials_allowed={"*": [K.OPENAI_KEY.value]})
        assert refused_credentials("anything", {"a": OPENAI}, b) == []

    def test_star_kind_allows_all(self) -> None:
        b = _backend(credentials_allowed={"t": ["*"]})
        assert refused_credentials("t", {"a": OPENAI, "b": GITHUB}, b) == []
        assert refused_credentials("u", {"a": OPENAI}, b) == [K.OPENAI_KEY]

    def test_tool_and_star_entries_combine(self) -> None:
        b = _backend(credentials_allowed={"*": [K.OPENAI_KEY.value], "t": [K.GITHUB_TOKEN.value]})
        assert refused_credentials("t", {"a": OPENAI, "b": GITHUB}, b) == []


class TestValidation:
    @pytest.mark.parametrize(
        "value",
        [
            ["not_a_kind"],
            ["*", "github_token"],
            ["github_token", "github_token"],
            [],
            "github_token",
            {"t": []},
            {"t": "github_token"},
            {"bad tool!": ["github_token"]},
            {"t": ["*", "openai_key"]},
            [["github_token"]],
            {"t": [{"kind": "jwt"}]},
        ],
        ids=[
            "unknown",
            "star-mixed",
            "duplicate",
            "empty",
            "non-list",
            "empty-per-tool",
            "per-tool-non-list",
            "bad-tool-name",
            "per-tool-star-mixed",
            "unhashable-list",
            "unhashable-mapping",
        ],
    )
    def test_a_malformed_allowance_fails_the_load(self, value: Any) -> None:
        with pytest.raises(ValidationError, match="credentials_allowed"):
            _backend(credentials_allowed=value)

    def test_a_decoy_backend_refuses_it(self) -> None:
        with pytest.raises(ValidationError, match="credentials_allowed"):
            Backend(
                url="decoy://bait",
                decoys={"t": {"description": "d", "result": "r"}},
                credentials_allowed=["*"],
            )

    def test_a_list_normalizes_to_the_star_tool(self) -> None:
        b = _backend(credentials_allowed=[K.GITHUB_TOKEN.value])
        assert b.credentials_allowed == {"*": [K.GITHUB_TOKEN.value]}

    def test_every_kind_the_detector_names_is_accepted(self) -> None:
        for kind in K:
            assert _backend(credentials_allowed=[kind.value]).credentials_allowed


_SCHEMAS: dict[str, dict[str, Any]] = {
    "echo": {"properties": {"text": {"type": "string"}}},
    "needs_n": {
        "properties": {"text": {"type": "string"}, "n": {"type": "integer", "minimum": 1}},
        "required": ["n"],
    },
}


async def _call(
    tmp_path: Any,
    arguments: dict[str, Any],
    backend: Backend | None = None,
    tool: str = "echo",
    mode: Any = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], Any]:
    """(response, calls the backend received, the audit row)."""
    import trentina.database as db_mod
    from tests.test_gateway_router import _fake_db_config
    from trentina.gateway.backend import _tool_list_cache

    db_mod._db = None
    backend = backend or _backend()
    profile = Profile(
        short_names=False,
        name="guarded",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={"luna": backend},
    )
    profile.auth.bearer_token = SecretStr("x")
    seen: list[dict[str, Any]] = []

    async def fake_call(_bn: str, _b: Backend, _tn: str, args: dict[str, Any]) -> BackendCall:
        seen.append(args)
        return BackendCall(
            content=[{"type": "text", "text": "ok"}], is_error=False, structured_content=None
        )

    async def fake_scan(**_kwargs: Any) -> Any:
        return type("D", (), {"blocked": False, "extraction": None, "warning": None})()

    _tool_list_cache[(backend.url, "")] = [
        {"name": n, "inputSchema": s, "annotations": {"readOnlyHint": False}}
        for n, s in _SCHEMAS.items()
    ]
    args = dict(arguments)
    if mode is not None:
        args["trentina_mode"] = mode
    try:
        with (
            patch("trentina.transports.mcp.call_backend_tool", side_effect=fake_call),
            patch("trentina.gateway.parts.scan_tool_response", side_effect=fake_scan) as scan,
            patch("trentina.orchestrator.scan_tool_response", scan),
            patch("trentina.database.get_config") as cfg,
        ):
            _fake_db_config(cfg, str(tmp_path / "cred.db"))
            resp = await route_jsonrpc(
                profile,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": f"luna{NAMESPACE_SEP}{tool}", "arguments": args},
                },
            )
            row = db_mod.get_db().execute("SELECT * FROM gateway_calls ORDER BY id DESC").fetchone()
    finally:
        _tool_list_cache.pop((backend.url, ""), None)
        db_mod._db = None
    return resp, seen, row


class TestEndToEnd:
    async def test_a_credential_is_refused_and_the_backend_not_contacted(
        self, tmp_path: Any
    ) -> None:
        resp, seen, row = await _call(tmp_path, {"text": "tok " + GITHUB})

        assert refused(resp)["reason"] == "denied_guard"
        assert seen == []
        assert row["outcome"] == "denied_guard"
        assert "credential_in_request" in row["error_message"]
        assert K.GITHUB_TOKEN.value in row["error_message"]
        assert "echo" in row["error_message"]
        assert GITHUB not in row["error_message"]
        assert GITHUB not in refused_text(resp)
        assert GITHUB not in json.dumps(dict(row), default=str)

    @pytest.mark.parametrize("mode", ["flag", "block", {"redact": "what is in it"}])
    async def test_every_mode_is_refused(self, tmp_path: Any, mode: Any) -> None:
        resp, seen, row = await _call(tmp_path, {"text": GITHUB}, mode=mode)

        assert refused(resp)["reason"] == "denied_guard"
        assert seen == []
        assert row["outcome"] == "denied_guard"

    async def test_an_allowed_kind_is_forwarded(self, tmp_path: Any) -> None:
        backend = _backend(credentials_allowed={"echo": [K.GITHUB_TOKEN.value]})
        resp, seen, row = await _call(tmp_path, {"text": GITHUB}, backend)

        assert "result" in resp
        assert seen == [{"text": GITHUB}]
        assert row["outcome"] == "ok"

    async def test_another_kind_is_still_refused_under_an_allowance(self, tmp_path: Any) -> None:
        backend = _backend(credentials_allowed={"echo": [K.GITHUB_TOKEN.value]})
        resp, seen, row = await _call(tmp_path, {"text": OPENAI}, backend)

        assert refused(resp)["reason"] == "denied_guard"
        assert seen == []
        assert K.OPENAI_KEY.value in row["error_message"]

    async def test_a_literal_request_guard_outranks_it(self, tmp_path: Any) -> None:
        backend = _backend(
            literal_request_guards={"echo": {"text": ParameterConstraint(deny=["*ban*"])}}
        )
        resp, seen, row = await _call(tmp_path, {"text": "ban " + GITHUB}, backend)

        assert refused(resp)["reason"] == "denied_guard"
        assert seen == []
        assert "credential_in_request" not in row["error_message"]

    async def test_a_credential_outranks_an_invalid_schema_argument(self, tmp_path: Any) -> None:
        resp, seen, row = await _call(tmp_path, {"text": GITHUB, "n": 0}, tool="needs_n")

        assert refused(resp)["reason"] == "denied_guard"
        assert seen == []
        assert row["outcome"] == "denied_guard"
        assert "credential_in_request" in row["error_message"]

    async def test_a_clean_call_is_forwarded(self, tmp_path: Any) -> None:
        resp, seen, row = await _call(tmp_path, {"text": "hello"})

        assert "result" in resp
        assert seen == [{"text": "hello"}]
        assert row["outcome"] == "ok"
