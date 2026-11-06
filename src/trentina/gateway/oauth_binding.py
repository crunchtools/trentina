"""Bind every token the OAuth proxy issues to the one profile it was issued for.

The proxy holds one JWT audience for the whole gateway (FastMCP's
``OAuthProxy`` stores a single resource URL), so before #298 a token minted
for an agent-role profile verified at an operator-role profile that
allowlisted the same email. The allowlist was the only line between profiles,
and an agent that holds its own profile's token is exactly the caller that line
does not stop.

The binding has two halves, both kept in the proxy's own encrypted store:

- **The flow.** ``/authorize`` resolves the RFC 8707 ``resource`` to a profile
  and records it under ``(client_id, code_challenge)``. Those two are what the
  authorization code carries back to ``/token``; FastMCP's code record has no
  resource field, and the PKCE challenge is unique per flow.
- **The token.** ``/token`` consumes the flow record and binds the issued
  token's upstream token set, which a refresh keeps, so every access token in
  the lineage answers to the same profile.

A token with no binding is refused at verify, which is what a token issued
before 0.49.0 is: its client re-authorizes once. A gateway with one proxied
profile binds a flow with no indicator to that profile; with more, a flow
that names none is refused at ``/authorize`` rather than issued a token that
could never be used.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict

from ..logsafe import exc_kind

logger = logging.getLogger(__name__)

#: How long ``/authorize`` -> ``/token`` may take. FastMCP gives its own
#: transaction fifteen minutes; the flow record matches it.
FLOW_TTL_SECONDS = 15 * 60

#: How long a token's binding outlives its last refresh. Re-stamped on every
#: refresh, so only a lineage idle this long loses it, and its upstream
#: refresh token falls back to the same year in FastMCP.
TOKEN_BINDING_TTL_SECONDS = 365 * 24 * 3600

_COLLECTION = "trentina-token-bindings"


class TokenBinding(BaseModel):
    """The profile a flow or a token lineage belongs to."""

    model_config = ConfigDict(extra="forbid", strict=True)

    profile: str


def flow_key(client_id: str, code_challenge: str) -> str:
    """The store key for one authorization flow. Hashed: both parts are client-chosen."""
    digest = hashlib.sha256(f"{client_id}\0{code_challenge}".encode()).hexdigest()
    return f"flow:{digest}"


def token_key(upstream_token_id: str) -> str:
    """The store key for one token lineage."""
    return f"token:{upstream_token_id}"


def profile_resources(base_url: str, proxied: list[str]) -> dict[str, str]:
    """Each proxied profile's normalized RFC 8707 resource URL, to its name."""
    from fastmcp.server.auth.identity_assertion import normalize_resource_url

    return {normalize_resource_url(f"{base_url}/gateway/{name}/mcp"): name for name in proxied}


def resolve_profile(
    requested: str | None, resources: dict[str, str], *, normalize: Any
) -> str | None:
    """The profile an ``/authorize`` request names, or None if it names none we serve.

    ``resources`` maps each proxied profile's normalized resource URL to its
    name. No indicator resolves only when there is exactly one profile it could
    mean; otherwise the token would have no profile to belong to.
    """
    if not requested:
        if len(resources) == 1:
            return next(iter(resources.values()))
        return None
    return resources.get(normalize(str(requested)))


if TYPE_CHECKING:

    class _BindingHost:
        """The slice of ``OAuthProxy`` this mixin uses, for the type checker only."""

        _client_storage: Any
        _jti_mapping_store: Any
        jwt_issuer: Any

        async def exchange_authorization_code(
            self, client: Any, authorization_code: Any
        ) -> Any: ...

        async def exchange_refresh_token(
            self, client: Any, refresh_token: Any, scopes: list[str]
        ) -> Any: ...
else:
    _BindingHost = object


class BindTokensToProfile(_BindingHost):
    """Mixin: bind each issued token to its profile, and answer which one.

    Must precede the provider in the MRO, like ``PromoteOnExchange``. Kept out
    of ``__init__.py`` for the same reason that one is: the provider class is
    defined inside a function, and every method there counts against it.
    """

    _binding_adapter: Any = None

    #: Each proxied profile's normalized resource URL, to its name. Set by
    #: the gateway when it builds the provider.
    gateway_profiles: ClassVar[dict[str, str]] = {}

    async def bind_authorization(self, client: Any, params: Any, requested: str | None) -> None:
        """Bind the flow ``/authorize`` is starting to the profile ``requested`` names.

        ``requested`` is the indicator as the client sent it, read before the
        gateway clears it for the base class. A flow that names no profile is
        refused here, never issued a token no profile would accept.
        """
        from fastmcp.server.auth.identity_assertion import normalize_resource_url
        from mcp.server.auth.provider import AuthorizeError

        profile = resolve_profile(
            requested, self.gateway_profiles, normalize=normalize_resource_url
        )
        if profile is None:
            raise AuthorizeError(
                error="invalid_target",
                error_description="A resource indicator naming one profile is required",
            )
        await self.bind_flow(client.client_id, getattr(params, "code_challenge", None), profile)

    def _bindings(self) -> Any:
        """The binding collection, built on first use over the proxy's own store."""
        if self._binding_adapter is None:
            from key_value.aio.adapters.pydantic import PydanticAdapter

            self._binding_adapter = PydanticAdapter[TokenBinding](
                key_value=self._client_storage,
                pydantic_model=TokenBinding,
                default_collection=_COLLECTION,
                raise_on_validation_error=True,
            )
        return self._binding_adapter

    async def bind_flow(self, client_id: str, code_challenge: str | None, profile: str) -> None:
        """Record which profile an authorization flow is for. Called by ``authorize``."""
        from mcp.server.auth.provider import AuthorizeError

        if not code_challenge:
            raise AuthorizeError(error="invalid_request", error_description="PKCE is required")
        key = flow_key(client_id, code_challenge)
        existing = await self._bindings().get(key=key)
        if existing is not None and existing.profile != profile:
            # One challenge, two resources: a second flow reusing a live
            # challenge must not re-point the first one's token.
            raise AuthorizeError(
                error="invalid_request", error_description="code_challenge already in use"
            )
        await self._bindings().put(
            key=key, value=TokenBinding(profile=profile), ttl=FLOW_TTL_SECONDS
        )

    async def _upstream_id(self, token: str, use: str = "access") -> str | None:
        """The upstream token set a FastMCP token points at, or None if it is not ours."""
        try:
            payload = self.jwt_issuer.verify_token(token, expected_token_use=use)
        except Exception as exc:
            logger.debug("oauth-binding: token did not verify (%s)", exc_kind(exc))
            return None
        jti = payload.get("jti")
        if not isinstance(jti, str):
            return None
        mapping = await self._jti_mapping_store.get(key=jti)
        return getattr(mapping, "upstream_token_id", None)

    async def _bind_token(self, access_token: str, profile: str) -> None:
        from mcp.server.auth.provider import TokenError

        upstream = await self._upstream_id(access_token)
        if upstream is None:
            # Ours a moment ago; failing here hands the client an error, not
            # a token that verifies everywhere.
            raise TokenError("invalid_grant", "issued token could not be bound")
        await self._bindings().put(
            key=token_key(upstream),
            value=TokenBinding(profile=profile),
            ttl=TOKEN_BINDING_TTL_SECONDS,
        )

    async def exchange_authorization_code(self, client: Any, authorization_code: Any) -> Any:
        """Issue only for a flow ``authorize`` bound, then bind what was issued."""
        from mcp.server.auth.provider import TokenError

        key = flow_key(client.client_id, getattr(authorization_code, "code_challenge", "") or "")
        flow = await self._bindings().get(key=key)
        if flow is None:
            raise TokenError("invalid_grant", "authorization is not bound to a profile")
        token = await super().exchange_authorization_code(client, authorization_code)
        await self._bindings().delete(key=key)
        await self._bind_token(token.access_token, flow.profile)
        return token

    async def exchange_refresh_token(
        self, client: Any, refresh_token: Any, scopes: list[str]
    ) -> Any:
        """Refresh only a bound lineage, and keep the new tokens on its profile."""
        from mcp.server.auth.provider import TokenError

        upstream = await self._upstream_id(refresh_token.token, use="refresh")
        bound = await self._bindings().get(key=token_key(upstream)) if upstream else None
        if bound is None:
            raise TokenError("invalid_grant", "refresh token is not bound to a profile")
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        await self._bind_token(token.access_token, bound.profile)
        return token

    async def bound_profile(self, token: str) -> str | None:
        """The profile ``token`` was issued for, or None: unbound, or not ours.

        ``verify_oauth`` asks this after the token itself verified, and refuses
        any answer but the profile being called.
        """
        upstream = await self._upstream_id(token)
        if upstream is None:
            return None
        bound = await self._bindings().get(key=token_key(upstream))
        return bound.profile if bound is not None else None
