"""Every token the OAuth proxy issues answers to one profile (#298).

The proxy has one JWT audience for every proxied profile, so the audience
cannot tell an agent profile's token from an operator profile's. The binding can:
``/authorize`` records which profile the flow named, ``/token`` moves that onto
the issued token's lineage, a refresh keeps it, and ``bound_profile`` is what
``verify_oauth`` asks.

The host here is the slice of ``OAuthProxy`` the mixin touches, over a real
in-memory key-value store; FastMCP's own exchange is what ``_Upstream`` fakes.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any, ClassVar

import pytest
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import AuthorizeError, TokenError

from trentina.gateway.oauth_binding import (
    BindTokensToProfile,
    resolve_profile,
)

_jti = itertools.count()


@dataclass
class _Mapping:
    upstream_token_id: str


@dataclass
class _Token:
    access_token: str
    refresh_token: str


@dataclass
class _Client:
    client_id: str


@dataclass
class _Code:
    code_challenge: str


@dataclass
class _Refresh:
    token: str


class _Issuer:
    """``"<use>:<jti>"`` stands in for a signed FastMCP JWT."""

    def verify_token(self, token: str, **kwargs: str) -> dict[str, Any]:
        use, _, jti = token.partition(":")
        if use != kwargs.get("expected_token_use", "access"):
            raise ValueError("token_use mismatch")
        return {"jti": jti}


class _Mappings:
    def __init__(self) -> None:
        self.rows: dict[str, _Mapping] = {}

    async def get(self, key: str) -> _Mapping | None:
        return self.rows.get(key)


class _Upstream:
    """FastMCP's exchanges: mint a token pair pointing at one upstream set."""

    def __init__(self) -> None:
        self._client_storage = MemoryStore()
        self._jti_mapping_store = _Mappings()
        self.jwt_issuer = _Issuer()

    def _issue(self, upstream: str) -> _Token:
        access, refresh = f"a{next(_jti)}", f"r{next(_jti)}"
        self._jti_mapping_store.rows[access] = _Mapping(upstream)
        self._jti_mapping_store.rows[refresh] = _Mapping(upstream)
        return _Token(f"access:{access}", f"refresh:{refresh}")

    async def exchange_authorization_code(self, client: Any, authorization_code: Any) -> _Token:
        return self._issue(f"up-{authorization_code.code_challenge}")

    async def exchange_refresh_token(self, client: Any, refresh_token: Any, scopes: Any) -> _Token:
        _, _, jti = refresh_token.token.partition(":")
        return self._issue(self._jti_mapping_store.rows[jti].upstream_token_id)


class _Proxy(BindTokensToProfile, _Upstream):
    pass


async def _login(proxy: _Proxy, profile: str, challenge: str = "c1") -> _Token:
    client = _Client("cid")
    await proxy.bind_flow(client.client_id, challenge, profile)
    return await proxy.exchange_authorization_code(client, _Code(challenge))


class TestBinding:
    async def test_a_token_answers_to_the_profile_its_flow_named(self) -> None:
        proxy = _Proxy()
        token = await _login(proxy, "agent-profile")
        assert await proxy.bound_profile(token.access_token) == "agent-profile"

    async def test_a_refresh_stays_on_the_same_profile(self) -> None:
        proxy = _Proxy()
        first = await _login(proxy, "agent-profile")
        second = await proxy.exchange_refresh_token(
            _Client("cid"), _Refresh(first.refresh_token), []
        )
        assert await proxy.bound_profile(second.access_token) == "agent-profile"

    async def test_two_flows_two_profiles(self) -> None:
        proxy = _Proxy()
        agent = await _login(proxy, "agent-profile", "c1")
        operator = await _login(proxy, "operator-profile", "c2")
        assert await proxy.bound_profile(agent.access_token) == "agent-profile"
        assert await proxy.bound_profile(operator.access_token) == "operator-profile"

    async def test_an_unbound_flow_gets_no_token(self) -> None:
        """A code from a flow authorize never bound (pre-0.49.0) is refused."""
        proxy = _Proxy()
        with pytest.raises(TokenError) as exc:
            await proxy.exchange_authorization_code(_Client("cid"), _Code("never-bound"))
        assert exc.value.error == "invalid_grant"

    async def test_an_unbound_refresh_token_is_refused(self) -> None:
        proxy = _Proxy()
        orphan = proxy._issue("up-orphan")
        with pytest.raises(TokenError):
            await proxy.exchange_refresh_token(_Client("cid"), _Refresh(orphan.refresh_token), [])

    async def test_an_unbound_token_is_bound_to_nothing(self) -> None:
        proxy = _Proxy()
        orphan = proxy._issue("up-orphan")
        assert await proxy.bound_profile(orphan.access_token) is None

    async def test_a_refresh_token_is_not_an_access_token(self) -> None:
        proxy = _Proxy()
        token = await _login(proxy, "agent-profile")
        assert await proxy.bound_profile(token.refresh_token) is None

    async def test_a_live_challenge_cannot_be_repointed(self) -> None:
        proxy = _Proxy()
        await proxy.bind_flow("cid", "c1", "agent-profile")
        with pytest.raises(AuthorizeError):
            await proxy.bind_flow("cid", "c1", "operator-profile")

    async def test_pkce_is_required(self) -> None:
        with pytest.raises(AuthorizeError):
            await _Proxy().bind_flow("cid", None, "agent-profile")


class TestResolveProfile:
    RESOURCES: ClassVar[dict[str, str]] = {
        "https://gw/gateway/a/mcp": "a",
        "https://gw/gateway/b/mcp": "b",
    }

    def test_the_indicator_names_the_profile(self) -> None:
        assert resolve_profile("https://gw/gateway/b/mcp", self.RESOURCES, normalize=str) == "b"

    def test_no_indicator_with_two_profiles_names_none(self) -> None:
        assert resolve_profile(None, self.RESOURCES, normalize=str) is None

    def test_no_indicator_with_one_profile_names_it(self) -> None:
        one = {"https://gw/gateway/a/mcp": "a"}
        assert resolve_profile(None, one, normalize=str) == "a"

    def test_an_unknown_indicator_names_none(self) -> None:
        assert resolve_profile("https://gw/gateway/z/mcp", self.RESOURCES, normalize=str) is None
