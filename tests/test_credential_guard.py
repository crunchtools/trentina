"""The credential check on a tool call's arguments (#862).

Fake credentials are built at runtime from split literals so no scanner reads
this file as a leak.
"""

from __future__ import annotations

import base64
import json
import random
import time
import uuid
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from tests.refusal_shape import refused, refused_text
from trentina.credential_shapes import CredentialKind as K
from trentina.credential_shapes import kinds
from trentina.gateway.backend import BackendCall
from trentina.gateway.config_guard import credentials_widened
from trentina.gateway.guards import refused_credentials
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.outbound import EXPANSION_KIND, every_credential
from trentina.gateway.profile import AuthConfig, Backend, ParameterConstraint, Profile
from trentina.tools.reload import _hold_perimeter_fields
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

    def test_a_double_entity_encoded_key_is_found(self) -> None:
        encoded = "&amp;#103;" + GITHUB[1:]
        assert refused_credentials("t", {"q": encoded}, _backend()) == [K.GITHUB_TOKEN]

    def test_a_zero_width_character_inside_a_key_does_not_hide_it(self) -> None:
        split = GITHUB[:10] + "\u200b" + GITHUB[10:]
        assert refused_credentials("t", {"q": split}, _backend()) == [K.GITHUB_TOKEN]

    def test_a_fullwidth_key_is_found(self) -> None:
        fullwidth = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in GITHUB)
        assert refused_credentials("t", {"q": fullwidth}, _backend()) == [K.GITHUB_TOKEN]

    @pytest.mark.parametrize(
        "prose",
        [
            "a basic src/trentina/gateway/guards.py fix",
            "A Basic src/trentina/gateway/guards.py fix",
            "the bearer credentials_allowed_well_formed check",
            "the Bearer token_variants_matcher_for path is cached",
            "see https://docs.example/find?key=rhel&token=next",
            "Bearer token, Basic auth, and a ?secret=placeholder in the docs",
        ],
    )
    def test_prose_about_credentials_is_not_refused(self, prose: str) -> None:
        assert refused_credentials("t", {"body": prose}, _backend()) == []

    def test_a_real_authorization_value_is_still_refused(self) -> None:
        value = "Basic " + "dXNlcjpwYXNzd29yZDEyMzQ1Ng=="
        assert refused_credentials("t", {"h": value}, _backend()) == [K.AUTHORIZATION]

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
    reply: str = "ok",
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
            content=[{"type": "text", "text": reply}], is_error=False, structured_content=None
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


class TestAnAgentReloadHoldsTheAllowance:
    """An allowance lets a key out, so only an operator may change it (#883)."""

    def _profile(self, allowance: dict[str, list[str]] | None) -> Profile:
        backend = _backend(credentials_allowed=allowance or {})
        return Profile(name="ag", auth=AuthConfig(bearer_token_env="TOK"), backends={"b": backend})

    def test_a_widening_is_held(self) -> None:
        before, after = self._profile(None), self._profile({"*": ["*"]})
        assert "backends.b.credentials_allowed" in _hold_perimeter_fields(before, after)
        assert after.backends["b"].credentials_allowed == {}

    def test_a_backend_new_to_the_reload_brings_none(self) -> None:
        before = Profile(name="ag", auth=AuthConfig(bearer_token_env="TOK"), backends={})
        after = self._profile({"t": ["jwt"]})
        assert "backends.b.credentials_allowed" in _hold_perimeter_fields(before, after)
        assert after.backends["b"].credentials_allowed == {}

    def test_a_backend_holding_an_allowance_keeps_its_destination(self) -> None:
        before = self._profile({"t": ["jwt"]})
        after = self._profile({"t": ["jwt"]})
        after.backends["b"].url = "http://exfil.example/mcp"
        held = _hold_perimeter_fields(before, after)
        assert "backends.b.url" in held
        assert after.backends["b"].url == before.backends["b"].url

    def test_a_backend_with_no_allowance_may_move(self) -> None:
        before, after = self._profile(None), self._profile(None)
        after.backends["b"].url = "http://elsewhere.example/mcp"
        assert "backends.b.url" not in _hold_perimeter_fields(before, after)

    def test_an_unchanged_allowance_is_not_reported(self) -> None:
        before, after = self._profile({"t": ["jwt"]}), self._profile({"t": ["jwt"]})
        assert "backends.b.credentials_allowed" not in _hold_perimeter_fields(before, after)


class TestARepointedBackendNeedsItsAllowanceApprovedAgain:
    """An allowance was approved for where the keys went (#882 review)."""

    def _profiles(self, url: str, allowance: list[str]) -> dict[str, Profile]:
        backend = Backend(url=url, credentials_allowed=allowance)
        profile = Profile(
            name="ag", auth=AuthConfig(bearer_token_env="TOK"), backends={"b": backend}
        )
        return {"ag": profile}

    def test_a_new_url_stages_the_whole_allowance(self) -> None:
        before = self._profiles("http://luna:8000/mcp", ["*"])
        after = self._profiles("http://exfil.example/mcp", ["*"])
        assert credentials_widened(before, after) == {
            "credentials_allowed:ag.b.*": "any credential may leave in the arguments of every tool"
            ", sent to http://exfil.example (transport mcp, carrier from the url)"
        }

    def test_the_same_url_stages_nothing(self) -> None:
        before = self._profiles("http://luna:8000/mcp", ["*"])
        after = self._profiles("http://luna:8000/mcp", ["*"])
        assert credentials_widened(before, after) == {}

    def test_a_new_url_with_no_allowance_stages_nothing(self) -> None:
        backend = Backend(url="http://exfil.example/mcp")
        after = {
            "ag": Profile(
                name="ag", auth=AuthConfig(bearer_token_env="TOK"), backends={"b": backend}
            )
        }
        assert credentials_widened(self._profiles("http://luna:8000/mcp", ["jwt"]), after) == {}

    def test_the_row_names_the_origin_never_the_url_credential(self) -> None:
        before = self._profiles("http://luna:8000/mcp", ["jwt"])
        after = self._profiles("http://user:pw@exfil.example:8443/mcp?token=x", ["jwt"])
        (row,) = credentials_widened(before, after).values()
        assert row == (
            "jwt may leave in the arguments of every tool, "
            "sent to http://exfil.example:8443 (transport mcp, carrier from the url)"
        )

    def test_two_destinations_stage_different_rows(self) -> None:
        """An approval opened for one host cannot be spent on a write restaged to another."""
        before = self._profiles("http://luna:8000/mcp", ["*"])
        harmless = credentials_widened(before, self._profiles("http://luna:9000/mcp", ["*"]))
        hostile = credentials_widened(before, self._profiles("http://exfil.example/mcp", ["*"]))
        assert harmless != hostile


def _urlsafe(rng: random.Random, n: int) -> str:
    return base64.urlsafe_b64encode(rng.randbytes(n)).decode().rstrip("=")


class TestAuthorizationRecall:
    """The #882 re-review: prose kept out structurally, not by narrowing the token."""

    @pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "Basic"])
    def test_random_tokens_are_found_under_any_scheme_case(self, scheme: str) -> None:
        rng = random.Random(862)
        tokens = [_urlsafe(rng, 32) for _ in range(500)]
        tokens += [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(500)]
        missed = [t for t in tokens if K.AUTHORIZATION not in kinds(f"{scheme} {t}")]
        assert missed == []

    def test_a_base64_basic_credential_with_a_slash_is_found(self) -> None:
        value = base64.b64encode(b"svc-account:pa?ss>w0rd!").decode()
        assert "/" in value or "+" in value
        assert K.AUTHORIZATION in kinds("Authorization: Basic " + value)

    @pytest.mark.parametrize(
        "prose",
        [
            "Bearer credentialsAllowedWellFormed",
            "Basic CredentialsAllowedWellFormed",
            "bearer release-notes-for-rhel-eleven",
            "Bearer docs/credential-guard.md section",
        ],
    )
    def test_identifiers_and_paths_after_the_scheme_are_prose(self, prose: str) -> None:
        assert K.AUTHORIZATION not in kinds(prose)


class TestQueryValues:
    @pytest.mark.parametrize(
        "query",
        ["?token=nextpagecursorabcdef", "?key=rhel-baseos-packages", "&KEY=lowercaseonlyvalue"],
    )
    def test_a_lowercase_value_is_a_setting(self, query: str) -> None:
        assert K.QUERY_SECRET not in kinds(query)

    @pytest.mark.parametrize("query", ["?api_key=Ab3dEfGh1jKlMnOp", "?SIG=0123456789abcdef0123"])
    def test_a_value_with_a_digit_or_capital_is_a_secret(self, query: str) -> None:
        assert K.QUERY_SECRET in kinds(query)


class TestUnmaskingBounds:
    def test_a_combining_mark_or_variation_selector_inside_a_key_does_not_hide_it(self) -> None:
        for mark in ("\u0301", "\ufe0f", "\U000e0100"):
            assert refused_credentials("t", {"q": GITHUB[:6] + mark + GITHUB[6:]}, _backend()) == [
                K.GITHUB_TOKEN
            ]

    def test_an_nfkc_bomb_is_refused_cheaply(self) -> None:
        bomb = "\ufdfa" * 200_000
        start = time.perf_counter()
        assert every_credential(bomb) == [EXPANSION_KIND]
        assert time.perf_counter() - start < 2.0
        assert refused_credentials("t", {"q": bomb}, _backend()) == [EXPANSION_KIND]

    @pytest.mark.parametrize("text", ["محمد \ufdfa \ufdfa", "\u2026" * 40])
    def test_short_text_that_more_than_doubles_is_not_a_bomb(self, text: str) -> None:
        assert every_credential(text) == []

    def test_ordinary_non_ascii_text_is_not_a_bomb(self) -> None:
        text = "日本語のテキスト、\ufb01 ligature, \uff83\uff9e\uff70\uff80。" * 2000
        assert every_credential(text) == []

    def test_a_destination_with_no_origin_is_the_sentinel_and_refused(self) -> None:
        from trentina.gateway.config_guard import UNSHOWABLE_DESTINATION
        from trentina.tools.config import ConfigWriteError, _credential_facts

        auth = AuthConfig(bearer_token_env="TOK")
        backend = Backend(url="http://luna:8000/mcp", credentials_allowed=["jwt"])
        before = {"ag": Profile(name="ag", auth=auth, backends={"b": backend})}
        after = {"ag": Profile(name="ag", auth=auth, backends={"b": backend})}
        after["ag"].backends["b"] = Backend.model_construct(
            url="plugin:no-host", transport="mcp", carrier=None, credentials_allowed={"*": ["jwt"]}
        )
        added = credentials_widened(before, after)
        assert added == {"credentials_allowed:ag.b.*": UNSHOWABLE_DESTINATION}
        with pytest.raises(ConfigWriteError):
            _credential_facts(added)
