"""A fake MCP resource and OAuth authorization server for backend OAuth tests (#479).

It answers through the real egress guard (``tests.egress_harness.route``), so
every request in a test is address-checked, pinned and refused on a redirect
exactly as in production. The ``server`` and ``profiles`` fixtures that wire
it in live in ``conftest.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from trentina.gateway import backend_tokens
from trentina.gateway.backend_oauth import complete, start
from trentina.gateway.profile import AuthConfig, Backend, BackendAuth, Profile

MCP = "https://mcp.era.example/mcp"
ISSUER = "https://auth.era.example"


@dataclass
class FakeServer:
    """An MCP resource and its authorization server, by host and path."""

    issuer: str = ISSUER
    pkce: list[str] = field(default_factory=lambda: ["S256"])
    auth_methods: list[str] = field(default_factory=lambda: ["client_secret_basic", "none"])
    iss_supported: bool = False
    resource: str = "https://mcp.era.example/mcp"
    token_status: int = 200
    token_error: str | None = None
    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    refresh_tokens: dict[str, int] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    issued: int = 0
    #: Advertise ``revocation_endpoint`` (RFC 7009), answer it with ``revoke_status``.
    revocation: bool = False
    revoke_status: int = 200
    revoked: list[dict[str, str]] = field(default_factory=list)
    overrides: dict[tuple[str, str], httpx.Response] = field(default_factory=dict)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.url.host, request.url.path)
        if key in self.overrides:
            return self.overrides[key]
        routes = {
            ("mcp.era.example", "/mcp"): lambda _r: self.challenge(),
            ("mcp.era.example", "/.well-known/oauth-protected-resource/mcp"): (
                lambda _r: self.resource_doc()
            ),
            ("auth.era.example", "/.well-known/oauth-authorization-server"): lambda _r: (
                httpx.Response(200, json=self.metadata())
            ),
            ("auth.era.example", "/register"): self.register,
            ("auth.era.example", "/token"): self.token,
            ("auth.era.example", "/revoke"): self.revoke,
        }
        answer = routes.get(key)
        return answer(request) if answer else httpx.Response(404)

    def challenge(self) -> httpx.Response:
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.era.example/'
                '.well-known/oauth-protected-resource/mcp"'
            },
        )

    def resource_doc(self) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "resource": self.resource,
                "authorization_servers": [self.issuer],
                "scopes_supported": ["read"],
            },
        )

    def revoke(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.revoked.append({**form, "authorization": request.headers.get("authorization", "")})
        return httpx.Response(self.revoke_status, text="body-must-not-leak")

    def metadata(self) -> dict[str, Any]:
        extra = (
            {"revocation_endpoint": "https://auth.era.example/revoke"} if self.revocation else {}
        )
        return {
            **extra,
            "issuer": self.issuer,
            "authorization_endpoint": "https://auth.era.example/authorize",
            "token_endpoint": "https://auth.era.example/token",
            "registration_endpoint": "https://auth.era.example/register",
            "code_challenge_methods_supported": self.pkce,
            "token_endpoint_auth_methods_supported": self.auth_methods,
            "authorization_response_iss_parameter_supported": self.iss_supported,
            "response_types_supported": ["code"],
        }

    def register(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        client_id = f"client-{len(self.clients) + 1}"
        info = {**body, "client_id": client_id}
        if body["token_endpoint_auth_method"] != "none":
            info["client_secret"] = f"secret-{client_id}"
        self.clients[client_id] = info
        return httpx.Response(201, json=info)

    def authorize(self, authorize_url: str) -> tuple[str, str]:
        """What a human consenting at the server produces: (state, code)."""
        query = {k: v[0] for k, v in parse_qs(urlsplit(authorize_url).query).items()}
        code = f"code-{len(self.codes) + 1}"
        self.codes[code] = query
        return query["state"], code

    def _client_of(self, request: httpx.Request, form: dict[str, str]) -> str | None:
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            client_id, _, secret = base64.b64decode(header[6:]).decode().partition(":")
            ok = self.clients.get(client_id, {}).get("client_secret") == secret
            return client_id if ok else None
        return form.get("client_id")

    def token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        client_id = self._client_of(request, form)
        if self.token_status != 200 or client_id is None:
            return httpx.Response(
                self.token_status if client_id else 401,
                json={"error": self.token_error or "invalid_client"},
            )
        if form["grant_type"] == "authorization_code":
            asked = self.codes.pop(form["code"], None)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest())
                .decode()
                .rstrip("=")
            )
            if asked is None or asked["code_challenge"] != challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
        elif self.refresh_tokens.pop(form["refresh_token"], None) is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        self.issued += 1
        refresh = f"refresh-{self.issued}"
        self.refresh_tokens[refresh] = self.issued
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{self.issued}",
                "token_type": "bearer",
                "expires_in": 3600,
                "refresh_token": refresh,
                "scope": "read",
            },
        )


def profile_with_era(
    name: str, *, self_authorize: bool = True, url: str = MCP, **auth: Any
) -> Profile:
    era = Backend(url=url, auth=BackendAuth(type="oauth", self_authorize=self_authorize, **auth))
    return Profile(name=name, auth=AuthConfig(bearer_token_env="TOKEN"), backends={"era": era})


def token_store() -> backend_tokens.BackendTokenStore:
    store = backend_tokens.backend_token_store()
    assert store is not None
    return store


async def authorize_url(link: str) -> str:
    page = parse_qs(urlsplit(link).query)["flow"][0]
    flow = await token_store().peek_flow(backend_tokens.flow_key(page))
    assert flow is not None
    return flow.authorize_url


async def login(server: FakeServer, profile: Profile) -> None:
    link = await start(profile, "era", authorized_by="self")
    state, code = server.authorize(await authorize_url(link))
    await complete(state, code, None, None)
