"""Tests for gateway/llm_proxy.py — provider loading and proxy behavior."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr, ValidationError
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from trentina import config as config_mod
from trentina import database as database_mod
from trentina.gateway import llm_proxy
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.llm_proxy import (
    LlmProvider,
    _proxy_llm,
    load_llm_providers,
    validate_profile_llm_keys,
)
from trentina.gateway.profile import (
    AuthConfig,
    LlmKeyOverride,
    Profile,
)
from trentina.gateway.proxy_utils import normalize_proxy_path

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response


@pytest.fixture(autouse=True)
def audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Every proxied call writes an audit row (#297); keep it out of the real DB."""
    path = tmp_path / "trentina.db"
    monkeypatch.setenv("QUARANTINE_DB", str(path))
    config_mod._config = None
    database_mod._db = None
    yield path
    database_mod._db = None
    config_mod._config = None


def _rows(path: Path) -> list[sqlite3.Row]:
    """Read the audit on this thread; the app wrote it on TestClient's."""
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT profile, backend, tool, outcome, error_message, destination, "
            "destination_kind FROM gateway_calls ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


class TestProxyPathNormalization:
    """Path traversal prevention for proxy endpoints."""

    def test_clean_path_passes(self) -> None:
        assert normalize_proxy_path("v1/chat/completions") == "v1/chat/completions"

    def test_empty_path_passes(self) -> None:
        assert normalize_proxy_path("") == ""

    def test_dotdot_rejected(self) -> None:
        assert normalize_proxy_path("../admin") is None

    def test_dotdot_middle_rejected(self) -> None:
        assert normalize_proxy_path("v1/../admin/secret") is None

    def test_encoded_dotdot_rejected(self) -> None:
        assert normalize_proxy_path("v1/%2e%2e/admin") is None

    def test_backslash_dotdot_rejected(self) -> None:
        assert normalize_proxy_path("v1\\..\\admin") is None

    def test_single_dot_rejected(self) -> None:
        assert normalize_proxy_path("v1/./completions") is None

    def test_deep_path_passes(self) -> None:
        assert normalize_proxy_path("v1beta/models/gemini-pro:generateContent") == (
            "v1beta/models/gemini-pro:generateContent"
        )


class TestLlmProviderModel:
    """Pydantic validation for LlmProvider."""

    def test_valid_provider(self) -> None:
        provider = LlmProvider(
            enabled=True,
            upstream="https://api.anthropic.com",
            auth_header="x-api-key",
            api_key_env="ANTHROPIC_API_KEY",
        )
        assert provider.upstream == "https://api.anthropic.com"

    def test_http_upstream_rejected(self) -> None:
        with pytest.raises(ValidationError, match="https://"):
            LlmProvider(
                upstream="http://api.anthropic.com",
                auth_header="x-api-key",
                api_key_env="KEY",
            )

    def test_trailing_slash_stripped(self) -> None:
        provider = LlmProvider(
            upstream="https://api.openai.com/",
            auth_header="Authorization",
            api_key_env="KEY",
        )
        assert provider.upstream == "https://api.openai.com"

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LlmProvider(
                upstream="https://api.openai.com",
                auth_header="Authorization",
                api_key_env="KEY",
                unknown_field="bad",
            )


class TestLoadLlmProviders:
    """Provider loading from the llm_providers config section."""

    def test_empty_section_returns_empty(self) -> None:
        assert load_llm_providers({}) == {}

    def test_disabled_provider_skipped(self) -> None:
        section: dict[str, Any] = {
            "anthropic": {
                "enabled": False,
                "upstream": "https://api.anthropic.com",
                "auth_header": "x-api-key",
                "api_key_env": "ANTHROPIC_API_KEY",
            }
        }
        assert load_llm_providers(section) == {}

    def test_missing_api_key_env_fails_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("MISSING_KEY_FOR_TEST", raising=False)
        section: dict[str, Any] = {
            "test": {
                "enabled": True,
                "upstream": "https://example.com",
                "api": "openai",
                "auth_header": "Authorization",
                "api_key_env": "MISSING_KEY_FOR_TEST",
            }
        }
        with pytest.raises(ProfileConfigError, match="not set or empty"):
            load_llm_providers(section)

    def test_key_from_file_variant(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A provider key mounted as a file never enters the environment (#268)."""
        secret = tmp_path / "key"
        secret.write_text("sk-from-file\n")
        monkeypatch.delenv("TEST_LLM_KEY", raising=False)
        monkeypatch.setenv("TEST_LLM_KEY_FILE", str(secret))
        section: dict[str, Any] = {
            "openai": {
                "enabled": True,
                "upstream": "https://api.openai.com",
                "auth_header": "Authorization",
                "api_key_env": "TEST_LLM_KEY",
            }
        }
        provider = load_llm_providers(section)["openai"]
        assert provider.api_key is not None
        assert provider.api_key.get_secret_value() == "sk-from-file"

    def test_valid_provider_loaded(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("TEST_LLM_KEY", "sk-test")
        section: dict[str, Any] = {
            "openai": {
                "enabled": True,
                "upstream": "https://api.openai.com",
                "auth_header": "Authorization",
                "auth_prefix": "Bearer ",
                "api_key_env": "TEST_LLM_KEY",
            }
        }
        providers = load_llm_providers(section)
        assert "openai" in providers
        assert providers["openai"].api_key.get_secret_value() == "sk-test"

    def test_non_dict_entry_raises(self) -> None:
        section: dict[str, Any] = {"bad": "not-a-dict"}
        with pytest.raises(ProfileConfigError, match="must be a mapping"):
            load_llm_providers(section)


def _gemini_provider() -> LlmProvider:
    provider = LlmProvider(
        enabled=True,
        upstream="https://generativelanguage.googleapis.com",
        auth_header="x-goog-api-key",
        api_key_env="GLOBAL_GEMINI_KEY",
    )
    provider.api_key = SecretStr("global-key")
    return provider


def _profile(name: str, token: str, keys: dict[str, str]) -> Profile:
    """Build a Profile with a resolved bearer token and resolved llm_keys."""
    p = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TOK"),
        llm_keys={
            provider: LlmKeyOverride(api_key_env=f"{name.upper()}_{provider.upper()}_KEY")
            for provider in keys
        },
    )
    p.auth.bearer_token = SecretStr(token)
    for provider, value in keys.items():
        p.llm_keys[provider].api_key = SecretStr(value)
    return p


class TestValidateProfileLlmKeys:
    """Startup cross-validation of profile llm_keys against configured providers."""

    def test_valid_reference_passes(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"agent1": _profile("agent1", "tok", {"gemini": "k-key"})}
        validate_profile_llm_keys(providers, profiles)  # no raise

    def test_dangling_reference_fails_closed(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"agent1": _profile("agent1", "tok", {"openai": "k-key"})}
        with pytest.raises(ProfileConfigError, match="not a configured"):
            validate_profile_llm_keys(providers, profiles)

    def test_profile_without_llm_keys_passes(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"agent2": _profile("agent2", "tok", {})}
        validate_profile_llm_keys(providers, profiles)  # no raise

    def test_dangling_reference_with_no_providers_fails_closed(self) -> None:
        """llm_keys referencing a provider is a misconfig even when none are enabled."""
        profiles = {"agent1": _profile("agent1", "tok", {"gemini": "k-key"})}
        with pytest.raises(ProfileConfigError, match="not a configured"):
            validate_profile_llm_keys({}, profiles)


class _FakeUpstreamResp:
    """Minimal stand-in for httpx.Response used by _streaming_response."""

    def __init__(self) -> None:
        self.status_code = 200
        self.headers = {"content-type": "application/json"}

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield b'{"ok": true}'

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """Captures the request built by the proxy so tests can assert headers."""

    def __init__(self) -> None:
        self.captured_headers: dict[str, str] = {}
        self.captured_url: str = ""
        self.captured_body: bytes | None = None
        self.sent = False

    def build_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        content: Any = None,
    ) -> Any:
        self.captured_url = url
        self.captured_headers = headers or {}
        self.captured_body = content
        return object()

    async def send(self, request: Any, stream: bool = False) -> _FakeUpstreamResp:
        self.sent = True
        return _FakeUpstreamResp()


class TestProxyLlm:
    """End-to-end behavior of the authenticated LLM proxy endpoint."""

    def _client(
        self, providers: dict[str, LlmProvider], profiles: dict[str, Profile]
    ) -> TestClient:
        async def endpoint(request: Request) -> Response:
            return await _proxy_llm(request, providers, profiles)

        app = Starlette(
            routes=[
                Route(
                    "/llm/{provider}/{path:path}",
                    endpoint,
                    methods=["GET", "POST"],
                )
            ]
        )
        return TestClient(app)

    def _fixtures(self) -> tuple[dict[str, LlmProvider], dict[str, Profile]]:
        providers = {"gemini": _gemini_provider()}
        profiles = {
            "agent1": _profile("agent1", "agent1-tok", {"gemini": "agent1-key"}),
            "agent3": _profile("agent3", "agent3-tok", {"gemini": "agent3-key"}),
            "agent2": _profile("agent2", "agent2-tok", {}),
        }
        return providers, profiles

    def test_unknown_provider_404(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/nonesuch/v1/x", headers={"authorization": "Bearer agent1-tok"})
        assert resp.status_code == 404

    def test_x_api_key_is_not_a_token_off_anthropic(self) -> None:
        """Only the Anthropic shape reads the gateway token from x-api-key."""
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x", headers={"x-api-key": "agent1-tok"})
        assert resp.status_code == 401

    def test_missing_token_401(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x")
        assert resp.status_code == 401

    def test_unknown_token_401(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x", headers={"authorization": "Bearer nope"})
        assert resp.status_code == 401

    def test_profile_without_key_502(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x", headers={"authorization": "Bearer agent2-tok"})
        assert resp.status_code == 502

    def test_success_injects_profile_key_and_strips_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        providers, profiles = self._fixtures()
        fake = _FakeClient()
        monkeypatch.setattr(llm_proxy, "_get_llm_client", lambda: fake)
        client = self._client(providers, profiles)

        resp = client.post(
            "/llm/gemini/v1beta/models/gemini-2.5-flash:generateContent",
            headers={"authorization": "Bearer agent1-tok"},
            content=b'{"contents": []}',
        )
        assert resp.status_code == 200
        assert fake.captured_headers.get("x-goog-api-key") == "agent1-key"
        assert not any(k.lower() == "authorization" for k in fake.captured_headers)

    def test_success_selects_correct_profile_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        providers, profiles = self._fixtures()
        fake = _FakeClient()
        monkeypatch.setattr(llm_proxy, "_get_llm_client", lambda: fake)
        client = self._client(providers, profiles)

        client.post(
            "/llm/gemini/v1beta/models/gemini-2.5-flash:generateContent",
            headers={"authorization": "Bearer agent3-tok"},
            content=b"{}",
        )
        assert fake.captured_headers.get("x-goog-api-key") == "agent3-key"

    def test_path_traversal_rejected(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post(
            "/llm/gemini/v1/..%2fadmin",
            headers={"authorization": "Bearer agent1-tok"},
        )
        assert resp.status_code == 400


def _anthropic_provider() -> LlmProvider:
    provider = LlmProvider(
        enabled=True,
        upstream="https://api.anthropic.com",
        auth_header="x-api-key",
        api_key_env="GLOBAL_ANTHROPIC_KEY",
    )
    provider.api_key = SecretStr("global-key")
    return provider


_PLAIN: dict[str, Any] = {
    "model": "claude-sonnet-4-5",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "hi"}],
}


class TestProxyAdmission:
    """#297: a provider-run tool never reaches the provider, and every call is audited."""

    def _client(self, fake: _FakeClient, monkeypatch: pytest.MonkeyPatch) -> TestClient:
        monkeypatch.setattr(llm_proxy, "_get_llm_client", lambda: fake)
        providers = {"anthropic": _anthropic_provider()}
        profiles = {"agent1": _profile("agent1", "agent1-tok", {"anthropic": "agent1-key"})}

        async def endpoint(request: Request) -> Response:
            return await _proxy_llm(request, providers, profiles)

        app = Starlette(
            routes=[Route("/llm/{provider}/{path:path}", endpoint, methods=["GET", "POST"])]
        )
        return TestClient(app)

    def _post(self, client: TestClient, body: dict[str, Any], **headers: str) -> Any:
        return client.post(
            "/llm/anthropic/v1/messages",
            headers={"authorization": "Bearer agent1-tok", **headers},
            content=json.dumps(body).encode(),
        )

    def test_mcp_servers_refused_and_audited(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        body = {
            **_PLAIN,
            "mcp_servers": [{"type": "url", "url": "https://evil.example/mcp", "name": "x"}],
        }
        resp = self._post(client, body, **{"anthropic-beta": "mcp-client-2025-04-04"})
        assert resp.status_code == 403
        assert resp.json()["error"]["reason"] == "mcp_servers"
        assert not fake.sent
        [row] = _rows(audit_db)
        assert row["profile"] == "agent1"
        assert row["backend"] == "llm:anthropic"
        assert row["outcome"] == "denied_guard"
        assert row["error_message"] == "mcp_servers"

    def test_web_fetch_tool_refused_and_audited(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        body = {**_PLAIN, "tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}
        resp = self._post(client, body)
        assert resp.status_code == 403
        assert resp.json()["error"]["reason"] == "server_tool"
        assert not fake.sent
        [row] = _rows(audit_db)
        assert (row["outcome"], row["error_message"]) == ("denied_guard", "server_tool")

    def test_plain_completion_passes_and_is_audited(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        body = {**_PLAIN, "tools": [{"name": "read_file", "input_schema": {"type": "object"}}]}
        resp = self._post(client, body)
        assert resp.status_code == 200
        assert fake.sent
        assert fake.captured_url == "https://api.anthropic.com/v1/messages"
        assert json.loads(fake.captured_body or b"") == body
        [row] = _rows(audit_db)
        assert row["tool"] == "messages"
        assert row["outcome"] == "ok"
        assert row["error_message"] is None
        assert (row["destination"], row["destination_kind"]) == ("claude-sonnet-4-5", "model")

    def test_headers_are_allowlisted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        self._post(
            client,
            _PLAIN,
            **{
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "mcp-client-2025-04-04, interleaved-thinking-2025-05-14",
                "openai-organization": "org-elsewhere",
                "x-stainless-lang": "python",
            },
        )
        sent = {k.lower(): v for k, v in fake.captured_headers.items()}
        assert sent["anthropic-version"] == "2023-06-01"
        assert sent["anthropic-beta"] == "interleaved-thinking-2025-05-14"
        assert "openai-organization" not in sent
        assert "x-stainless-lang" not in sent
        assert "authorization" not in sent
        assert sent["x-api-key"] == "agent1-key"

    def _post_x_api_key(self, client: TestClient, **headers: str) -> Any:
        return client.post(
            "/llm/anthropic/v1/messages",
            headers=headers,
            content=json.dumps(_PLAIN).encode(),
        )

    def test_x_api_key_carries_gateway_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Anthropic SDKs send their key as x-api-key to a proxy (Hermes does)."""
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        resp = self._post_x_api_key(client, **{"x-api-key": "agent1-tok"})
        assert resp.status_code == 200
        sent = {k.lower(): v for k, v in fake.captured_headers.items()}
        assert sent["x-api-key"] == "agent1-key"
        assert "agent1-tok" not in sent.values()

    def test_wrong_x_api_key_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        resp = self._post_x_api_key(client, **{"x-api-key": "not-a-token"})
        assert resp.status_code == 401
        assert not fake.sent

    def test_authorization_wins_over_x_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        resp = self._post_x_api_key(
            client, authorization="Bearer not-a-token", **{"x-api-key": "agent1-tok"}
        )
        assert resp.status_code == 401
        assert not fake.sent

    def test_duplicate_key_refused_before_upstream(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Raw bytes would let the provider's parser read the other ``tools``."""
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        raw = (
            b'{"model":"claude-sonnet-4-5","max_tokens":8,"messages":[],'
            b'"tools":[{"type":"web_search_20250305","name":"web_search"}],"tools":[]}'
        )
        resp = client.post(
            "/llm/anthropic/v1/messages",
            headers={"authorization": "Bearer agent1-tok"},
            content=raw,
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["reason"] == "malformed_body"
        assert not fake.sent

    def test_unlisted_endpoint_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        resp = client.post(
            "/llm/anthropic/v1/files",
            headers={"authorization": "Bearer agent1-tok"},
            content=b"{}",
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["reason"] == "endpoint_not_allowed"
        assert not fake.sent

    def test_oversize_body_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(llm_proxy, "MAX_LLM_REQUEST_BYTES", 64)
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        resp = self._post(client, {**_PLAIN, "system": "x" * 200})
        assert resp.status_code == 413
        assert not fake.sent

    def test_refusal_detail_is_not_logged(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The refused type is the caller's own text: back to it, never to the journal."""
        fake = _FakeClient()
        client = self._client(fake, monkeypatch)
        canary = "canary_tool_type_7f3a"
        with caplog.at_level("DEBUG"):
            resp = self._post(client, {**_PLAIN, "tools": [{"type": canary}]})
        assert resp.json()["error"]["detail"] == canary
        assert canary not in caplog.text

    def test_no_key_is_audited(self, audit_db: Path) -> None:
        providers = {"anthropic": _anthropic_provider()}
        profiles = {"agent2": _profile("agent2", "agent2-tok", {})}

        async def endpoint(request: Request) -> Response:
            return await _proxy_llm(request, providers, profiles)

        app = Starlette(routes=[Route("/llm/{provider}/{path:path}", endpoint, methods=["POST"])])
        resp = TestClient(app).post(
            "/llm/anthropic/v1/messages", headers={"authorization": "Bearer agent2-tok"}
        )
        assert resp.status_code == 502
        [row] = _rows(audit_db)
        assert row["outcome"] == "denied_allowlist"


class TestProviderApi:
    """The API shape decides the admission policy, so it is never guessed."""

    def test_known_host_infers_api(self) -> None:
        assert _anthropic_provider().api == "anthropic"

    def test_unknown_host_without_api_fails_closed(self) -> None:
        with pytest.raises(ValidationError, match="api must be set"):
            LlmProvider(
                enabled=True,
                upstream="https://api.groq.com/openai",
                auth_header="Authorization",
                api_key_env="K",
            )

    def test_disabled_unknown_host_without_api_does_not_stop_startup(self) -> None:
        """Production's disabled perplexity/xai/mistral entries crash-looped 0.49.0."""
        section = {
            "mistral": {
                "enabled": False,
                "upstream": "https://api.mistral.ai",
                "auth_header": "Authorization",
                "api_key_env": "MISTRAL_API_KEY",
            }
        }
        assert load_llm_providers(section) == {}

    def test_enabled_unknown_host_without_api_names_the_entry(self) -> None:
        section = {
            "groq": {
                "enabled": True,
                "upstream": "https://api.groq.com/openai",
                "auth_header": "Authorization",
                "api_key_env": "K",
            }
        }
        expected = r"llm_providers\.groq: entry: .*api must be set"
        with pytest.raises(ProfileConfigError, match=expected):
            load_llm_providers(section)

    def test_unknown_host_with_api_loads(self) -> None:
        provider = LlmProvider(
            upstream="https://api.groq.com/openai",
            api="openai",
            auth_header="Authorization",
            api_key_env="K",
        )
        assert provider.api == "openai"
