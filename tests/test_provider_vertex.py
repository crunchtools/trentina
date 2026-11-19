"""Tests for the Vertex AI provider and its OAuth token source (fully offline)."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from trentina.errors import MalformedResponseError, QuarantineAgentError
from trentina.quarantine.providers import base
from trentina.quarantine.providers.vertex import (
    VertexProvider,
    validate_vertex_target,
)
from trentina.quarantine.providers.vertex_auth import (
    EXPIRY_SKEW,
    GOOGLE_OAUTH_URL,
    TokenSource,
    parse_credentials,
)

_REAL_CLIENT = httpx.AsyncClient
PROJECT = "my-project-123"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
USER_ADC = json.dumps(
    {
        "type": "authorized_user",
        "client_id": "cid",
        "client_secret": "SECRET-VALUE",
        "refresh_token": "REFRESH-VALUE",
    }
)
SA_ADC = json.dumps(
    {
        "type": "service_account",
        "client_email": "sa@my-project-123.iam.gserviceaccount.com",
        "private_key": PEM,
        "private_key_id": "kid1",
    }
)
OK_BODY = {
    "candidates": [{"content": {"parts": [{"text": "hello"}]}}],
    "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
}

Handler = Callable[[httpx.Request], httpx.Response]


class Net:
    """Routes every httpx.AsyncClient to in-memory handlers and records requests."""

    def __init__(self) -> None:
        self.token_requests: list[httpx.Request] = []
        self.api_requests: list[httpx.Request] = []
        self.token_handler: Handler = self._token_ok
        self.api_handler: Handler = lambda req: httpx.Response(200, json=OK_BODY)
        self.minted = 0

    def _token_ok(self, req: httpx.Request) -> httpx.Response:
        self.minted += 1
        return httpx.Response(200, json={"access_token": f"tok{self.minted}", "expires_in": 3600})

    def handle(self, req: httpx.Request) -> httpx.Response:
        if str(req.url) == GOOGLE_OAUTH_URL:
            self.token_requests.append(req)
            return self.token_handler(req)
        self.api_requests.append(req)
        return self.api_handler(req)


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> Net:
    n = Net()

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        return _REAL_CLIENT(*args, transport=httpx.MockTransport(n.handle), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return n


def _provider(region: str = "us-central1", adc: str = USER_ADC) -> VertexProvider:
    return VertexProvider(adc, "gemini-2.5-flash", PROJECT, region)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_success_request_shape(net: Net) -> None:
    result = await _provider().generate("sys", "user", {"type": "object"})
    assert (result.text, result.input_tokens, result.output_tokens) == ("hello", 10, 5)
    req = net.api_requests[0]
    assert str(req.url) == (
        "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project-123"
        "/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
    )
    assert req.headers["authorization"] == "Bearer tok1"
    assert "x-goog-api-key" not in req.headers
    assert "access_token" not in str(req.url)
    body = json.loads(req.content)
    assert body["system_instruction"]["parts"][0]["text"] == "sys"
    assert body["contents"][0]["parts"][0]["text"] == "user"
    assert body["generationConfig"]["responseSchema"] == {"type": "object"}


async def test_global_region_host(net: Net) -> None:
    await _provider("global").generate("s", "u")
    assert str(net.api_requests[0].url).startswith(
        "https://aiplatform.googleapis.com/v1/projects/my-project-123/locations/global/"
    )


async def test_401_refreshes_and_retries_once(net: Net) -> None:
    net.api_handler = lambda req: (
        httpx.Response(200, json=OK_BODY)
        if req.headers["authorization"] == "Bearer tok2"
        else httpx.Response(401)
    )
    result = await _provider().generate("s", "u")
    assert result.text == "hello"
    assert len(net.token_requests) == 2
    assert [r.headers["authorization"] for r in net.api_requests] == ["Bearer tok1", "Bearer tok2"]


async def test_401_twice_is_not_retryable(net: Net) -> None:
    from trentina.quarantine.agent import _RETRYABLE_STATUS_CODES

    net.api_handler = lambda req: httpx.Response(401)
    with pytest.raises(QuarantineAgentError) as err:
        await _provider().generate("s", "u")
    assert err.value.status_code == 401
    assert err.value.status_code not in _RETRYABLE_STATUS_CODES
    assert len(net.api_requests) == 2


async def test_429_keeps_status(net: Net) -> None:
    net.api_handler = lambda req: httpx.Response(429, headers={"retry-after": "7"})
    with pytest.raises(QuarantineAgentError) as err:
        await _provider().generate("s", "u")
    assert (err.value.status_code, err.value.retry_after) == (429, 7.0)


async def test_token_cached_across_calls(net: Net) -> None:
    p = _provider()
    await p.generate("s", "u")
    await p.generate("s", "u")
    assert len(net.token_requests) == 1
    assert len(net.api_requests) == 2


async def test_token_refreshed_after_expiry_skew(net: Net) -> None:
    clock = Clock()
    ts = TokenSource(parse_credentials(USER_ADC), clock)
    assert await ts.token() == "tok1"
    clock.now += 3600 - EXPIRY_SKEW - 1
    assert await ts.token() == "tok1"
    clock.now += 2
    assert await ts.token() == "tok2"
    assert len(net.token_requests) == 2


async def test_concurrent_token_calls_hit_endpoint_once(net: Net) -> None:
    ts = TokenSource(parse_credentials(USER_ADC))
    results = await asyncio.gather(*(ts.token() for _ in range(10)))
    assert set(results) == {"tok1"}
    assert len(net.token_requests) == 1


async def test_concurrent_401s_refresh_once(net: Net) -> None:
    ts = TokenSource(parse_credentials(USER_ADC))
    stale = await ts.token()
    results = await asyncio.gather(*(ts.refresh_after_401(stale) for _ in range(5)))
    assert set(results) == {"tok2"}
    assert len(net.token_requests) == 2


async def test_authorized_user_grant_form(net: Net) -> None:
    await TokenSource(parse_credentials(USER_ADC)).token()
    form = parse_qs(net.token_requests[0].content.decode())
    assert form == {
        "grant_type": ["refresh_token"],
        "client_id": ["cid"],
        "client_secret": ["SECRET-VALUE"],
        "refresh_token": ["REFRESH-VALUE"],
    }


def _unb64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


async def test_service_account_jwt_verifies(net: Net) -> None:
    await TokenSource(parse_credentials(SA_ADC)).token()
    form = parse_qs(net.token_requests[0].content.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    head, claims_b64, sig = form["assertion"][0].split(".")
    KEY.public_key().verify(
        _unb64(sig), f"{head}.{claims_b64}".encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    assert json.loads(_unb64(head)) == {"alg": "RS256", "typ": "JWT", "kid": "kid1"}
    claims = json.loads(_unb64(claims_b64))
    assert claims["iss"] == "sa@my-project-123.iam.gserviceaccount.com"
    assert claims["aud"] == GOOGLE_OAUTH_URL
    assert claims["scope"] == "https://www.googleapis.com/auth/cloud-platform"
    assert claims["exp"] == claims["iat"] + 3600


def _ec_pem() -> str:
    return (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        json.dumps({"type": "external_account"}),
        json.dumps({"type": "authorized_user", "client_id": "a", "client_secret": "b"}),
        json.dumps({"type": "service_account", "client_email": "a@b"}),
        json.dumps({"type": "service_account", "client_email": "a@b", "private_key": "junk"}),
        json.dumps({"type": "service_account", "client_email": "a@b", "private_key": _ec_pem()}),
        json.dumps({**json.loads(USER_ADC), "token_uri": "https://evil.example/token"}),
    ],
)
def test_malformed_credentials_refused(raw: str) -> None:
    with pytest.raises(QuarantineAgentError) as err:
        parse_credentials(raw)
    msg = str(err.value)
    assert "SECRET-VALUE" not in msg and "REFRESH-VALUE" not in msg and "junk" not in msg


def test_matching_token_uri_accepted() -> None:
    assert parse_credentials(json.dumps({**json.loads(USER_ADC), "token_uri": GOOGLE_OAUTH_URL}))


def test_credentials_repr_hides_secrets() -> None:
    assert "SECRET-VALUE" not in repr(parse_credentials(USER_ADC))


async def test_token_endpoint_invalid_grant_not_retryable(net: Net) -> None:
    net.token_handler = lambda req: httpx.Response(
        400,
        json={
            "error": "invalid_grant",
            "error_description": "REFRESH-VALUE is bad for SECRET-VALUE",
        },
    )
    with pytest.raises(QuarantineAgentError) as err:
        await _provider().generate("s", "u")
    assert err.value.status_code == 401
    msg = str(err.value)
    assert "invalid_grant" in msg and "refused" in msg
    assert "REFRESH-VALUE" not in msg and "SECRET-VALUE" not in msg
    assert net.api_requests == []


async def test_token_endpoint_503_retryable(net: Net) -> None:
    net.token_handler = lambda req: httpx.Response(503)
    with pytest.raises(QuarantineAgentError) as err:
        await TokenSource(parse_credentials(USER_ADC)).token()
    assert err.value.status_code == 503


async def test_token_endpoint_network_error(net: Net) -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=req)

    net.token_handler = boom
    with pytest.raises(QuarantineAgentError) as err:
        await TokenSource(parse_credentials(USER_ADC)).token()
    assert err.value.status_code is None


@pytest.mark.parametrize(
    "body",
    [
        {"expires_in": 3600},
        {"access_token": "t", "expires_in": "3600"},
        {"access_token": "t"},
    ],
)
async def test_malformed_token_response(net: Net, body: dict[str, Any]) -> None:
    net.token_handler = lambda req: httpx.Response(200, json=body)
    with pytest.raises(MalformedResponseError):
        await TokenSource(parse_credentials(USER_ADC)).token()


async def test_non_json_token_response(net: Net) -> None:
    net.token_handler = lambda req: httpx.Response(200, content=b"<html>")
    with pytest.raises(MalformedResponseError):
        await TokenSource(parse_credentials(USER_ADC)).token()


async def test_enforce_no_tools_still_applied(net: Net, monkeypatch: pytest.MonkeyPatch) -> None:
    from trentina.quarantine.providers import vertex

    def with_tools(*_: Any) -> dict[str, Any]:
        return {"tools": [{}]}

    monkeypatch.setattr(vertex, "generate_content_body", with_tools)
    with pytest.raises(QuarantineAgentError, match="SECURITY"):
        await _provider().generate("s", "u")
    assert net.api_requests == [] and base.TOOL_KEYS


@pytest.mark.parametrize(
    ("project", "region", "model"),
    [
        ("Bad_Project", "us-central1", "m"),
        ("my-project-123/../x", "us-central1", "m"),
        ("my-project-123", "us-central1/../x", "m"),
        ("my-project-123", "evil.com#", "m"),
        ("my-project-123", "us-central1", "m/../x"),
        ("my-project-123", "us-central1", "m:generateContent?x=1"),
        ("my-project-123", "us-central1", ""),
    ],
)
def test_invalid_target_refused(project: str, region: str, model: str) -> None:
    with pytest.raises(QuarantineAgentError):
        VertexProvider(USER_ADC, model, project, region)


def test_validate_vertex_target_accepts_good() -> None:
    validate_vertex_target(PROJECT, "global")
    validate_vertex_target(PROJECT, "europe-west4")
