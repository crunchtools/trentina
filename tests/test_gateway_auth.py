"""Tests for gateway/auth.py — bearer-token verification."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from trentina.gateway.auth import (
    resolve_profile_by_token,
    verify_bearer,
    verify_oauth,
)
from trentina.gateway.errors import (
    AuthError,
    OAuthChallengeError,
    OAuthForbiddenError,
)
from trentina.gateway.profile import (
    AuthConfig,
    OAuthConfig,
    Profile,
)


def _profile_with_token(value: str, name: str = "t") -> Profile:
    """Build a Profile with a pre-resolved bearer token for test convenience."""
    p = Profile(name=name, auth=AuthConfig(bearer_token_env="TEST"))
    p.auth.bearer_token = SecretStr(value)
    return p


class _StubAccessToken:
    """Stand-in for fastmcp's AccessToken — only .claims is read by verify_oauth."""

    def __init__(self, claims: dict[str, object] | None) -> None:
        self.claims = claims


class _StubProvider:
    """Fake PROXY provider: verify_token forwards to load_access_token.

    ``token_map`` maps a presented token string to the AccessToken (or None)
    the real provider would return after swapping and re-validating upstream.

    The forwarding is not a convenience — it mirrors fastmcp's
    ``OAuthProvider.verify_token``, which is literally
    ``return await self.load_access_token(token)``. That is what lets one
    gateway call site serve proxy and delegated modes alike.
    """

    def __init__(
        self,
        token_map: dict[str, _StubAccessToken | None],
        bound: dict[str, str] | None = None,
    ) -> None:
        self._token_map = token_map
        self._bound = bound
        self.calls: list[str] = []

    async def load_access_token(self, token: str) -> _StubAccessToken | None:
        self.calls.append(token)
        return self._token_map.get(token)

    async def bound_profile(self, token: str) -> str | None:
        """Every token is bound to the default test profile unless told otherwise."""
        if self._bound is None:
            return "gemini-app"
        return self._bound.get(token)

    async def verify_token(self, token: str) -> _StubAccessToken | None:
        return await self.load_access_token(token)


class _StubVerifier:
    """Fake DELEGATED verifier: verify_token only, no load_access_token.

    Deliberately missing the proxy method, so any code path that reaches for
    it fails loudly instead of silently working in proxy mode only.
    """

    def __init__(self, token_map: dict[str, _StubAccessToken | None]) -> None:
        self._token_map = token_map
        self.calls: list[str] = []

    async def verify_token(self, token: str) -> _StubAccessToken | None:
        self.calls.append(token)
        return self._token_map.get(token)

    async def bound_profile(self, _token: str) -> str | None:
        return "gemini-app"


def _oauth_profile(*emails: str, name: str = "gemini-app") -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TEST"),
        oauth=OAuthConfig(enabled=True, allowed_emails=list(emails)),
    )


class TestVerifyOAuth:
    """OAuth path: provider validation plus the profile email allowlist."""

    async def test_allowed_email_passes(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "alice@example.com", "email_verified": True})}
        )
        await verify_oauth("Bearer tok", profile, provider)
        assert provider.calls == ["tok"]

    async def test_email_match_case_insensitive(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "Alice@Example.com", "email_verified": "true"})}
        )
        await verify_oauth("Bearer tok", profile, provider)

    async def test_no_provider_is_challenge(self) -> None:
        profile = _oauth_profile("alice@example.com")
        with pytest.raises(OAuthChallengeError, match="provider not configured"):
            await verify_oauth("Bearer tok", profile, None)

    async def test_missing_header_is_challenge(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider({})
        with pytest.raises(OAuthChallengeError, match="missing"):
            await verify_oauth(None, profile, provider)

    async def test_malformed_header_is_challenge(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider({})
        with pytest.raises(OAuthChallengeError, match="malformed"):
            await verify_oauth("Basic tok", profile, provider)

    async def test_invalid_token_is_challenge(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider({"tok": None})
        with pytest.raises(OAuthChallengeError, match="invalid or expired"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_unverified_email_is_forbidden(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "alice@example.com", "email_verified": False})}
        )
        with pytest.raises(OAuthForbiddenError, match="verified email"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_missing_email_is_forbidden(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider({"tok": _StubAccessToken({"email_verified": True})})
        with pytest.raises(OAuthForbiddenError, match="verified email"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_email_only_profile_ignores_sub(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "alice@example.com", "email_verified": True})}
        )
        await verify_oauth("Bearer tok", profile, provider)

    async def test_pinned_subject_passes(self) -> None:
        profile = _oauth_profile("alice@example.com")
        assert profile.oauth is not None
        profile.oauth.allowed_subjects = ["1001"]
        provider = _StubProvider(
            {
                "tok": _StubAccessToken(
                    {"sub": "1001", "email": "alice@example.com", "email_verified": True}
                )
            }
        )
        await verify_oauth("Bearer tok", profile, provider)

    @pytest.mark.parametrize("sub", ["2002", None, ""])
    async def test_a_reassigned_email_is_forbidden(self, sub: str | None) -> None:
        """#458: the address is allowlisted and verified, but the account is not Alice's."""
        profile = _oauth_profile("alice@example.com")
        assert profile.oauth is not None
        profile.oauth.allowed_subjects = ["1001"]
        claims = {"email": "alice@example.com", "email_verified": True}
        if sub is not None:
            claims["sub"] = sub
        provider = _StubProvider({"tok": _StubAccessToken(claims)})
        with pytest.raises(OAuthForbiddenError, match="subject not permitted"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_a_pinned_subject_still_needs_the_email(self) -> None:
        profile = _oauth_profile("alice@example.com")
        assert profile.oauth is not None
        profile.oauth.allowed_subjects = ["1001"]
        provider = _StubProvider(
            {
                "tok": _StubAccessToken(
                    {"sub": "1001", "email": "eve@evil.com", "email_verified": True}
                )
            }
        )
        with pytest.raises(OAuthForbiddenError, match="email not permitted"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_email_not_on_allowlist_is_forbidden(self) -> None:
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "eve@evil.com", "email_verified": True})}
        )
        with pytest.raises(OAuthForbiddenError, match="not permitted"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_a_token_bound_to_another_profile_is_challenged(self) -> None:
        """#298: one JWT audience covers every proxied profile, so the binding
        is what keeps an agent seat's token out of an operator seat that
        allowlists the same human."""
        operator = _oauth_profile("alice@example.com", name="operator-seat")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "alice@example.com", "email_verified": True})},
            bound={"tok": "agent-seat"},
        )
        with pytest.raises(OAuthChallengeError, match="not issued for this profile"):
            await verify_oauth("Bearer tok", operator, provider)

    async def test_an_unbound_token_is_challenged(self) -> None:
        """A token from before 0.49.0 has no binding: its client re-authorizes."""
        profile = _oauth_profile("alice@example.com")
        provider = _StubProvider(
            {"tok": _StubAccessToken({"email": "alice@example.com", "email_verified": True})},
            bound={},
        )
        with pytest.raises(OAuthChallengeError, match="not issued for this profile"):
            await verify_oauth("Bearer tok", profile, provider)

    async def test_a_verifier_that_cannot_bind_is_refused(self) -> None:
        """Fail closed: no binding answer is never read as 'bound here'."""

        class _Unbinding:
            async def verify_token(self, _token: str) -> _StubAccessToken:
                return _StubAccessToken({"email": "alice@example.com", "email_verified": True})

        with pytest.raises(OAuthChallengeError, match="cannot bind"):
            await verify_oauth("Bearer tok", _oauth_profile("alice@example.com"), _Unbinding())

    async def test_forbidden_and_challenge_are_auth_errors(self) -> None:
        # Both subclass AuthError so existing except-blocks stay correct.
        assert issubclass(OAuthChallengeError, AuthError)
        assert issubclass(OAuthForbiddenError, AuthError)


class TestVerifyBearer:
    """Bearer-token verification covers the full set of failure paths."""

    def test_valid_token_passes(self) -> None:
        p = _profile_with_token("good-token")
        verify_bearer("Bearer good-token", p)

    def test_missing_header_rejected(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="missing"):
            verify_bearer(None, p)
        with pytest.raises(AuthError, match="missing"):
            verify_bearer("", p)

    def test_malformed_no_scheme(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("good-token", p)

    def test_malformed_wrong_scheme(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("Basic abc123", p)

    def test_malformed_no_token(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("Bearer ", p)

    def test_wrong_token_rejected(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="invalid token"):
            verify_bearer("Bearer bad-token", p)

    def test_case_insensitive_scheme(self) -> None:
        p = _profile_with_token("good-token")
        verify_bearer("bearer good-token", p)
        verify_bearer("BEARER good-token", p)
        verify_bearer("BeArEr good-token", p)

    def test_unresolved_profile_token_rejected(self) -> None:
        """Loader normally guarantees this, but defense-in-depth."""
        p = Profile(name="t", auth=AuthConfig(bearer_token_env="TEST"))
        with pytest.raises(AuthError, match="not resolved"):
            verify_bearer("Bearer x", p)


class TestResolveProfileByToken:
    """Reverse token->profile resolution for the LLM proxy (no profile in URL)."""

    def _registry(self) -> dict[str, Profile]:
        return {
            "agent1": _profile_with_token("agent1-token", "agent1"),
            "agent3": _profile_with_token("agent3-token", "agent3"),
        }

    def test_matching_token_resolves_profile(self) -> None:
        registry = self._registry()
        result = resolve_profile_by_token("Bearer agent3-token", registry)
        assert result is not None
        assert result.name == "agent3"

    def test_unknown_token_returns_none(self) -> None:
        assert resolve_profile_by_token("Bearer nope", self._registry()) is None

    def test_missing_header_returns_none(self) -> None:
        assert resolve_profile_by_token(None, self._registry()) is None
        assert resolve_profile_by_token("", self._registry()) is None

    def test_malformed_header_returns_none(self) -> None:
        registry = self._registry()
        assert resolve_profile_by_token("agent1-token", registry) is None
        assert resolve_profile_by_token("Basic agent1-token", registry) is None
        assert resolve_profile_by_token("Bearer ", registry) is None

    def test_case_insensitive_scheme(self) -> None:
        registry = self._registry()
        result = resolve_profile_by_token("bearer agent1-token", registry)
        assert result is not None
        assert result.name == "agent1"

    def test_unresolved_token_profiles_skipped(self) -> None:
        """A profile whose token was never resolved must never match."""
        registry: dict[str, Profile] = {
            "unresolved": Profile(name="unresolved", auth=AuthConfig(bearer_token_env="TEST")),
        }
        assert resolve_profile_by_token("Bearer anything", registry) is None

    def test_empty_registry_returns_none(self) -> None:
        assert resolve_profile_by_token("Bearer x", {}) is None

    def test_duplicate_token_returns_first_match(self) -> None:
        """Docstring guarantees first-match-wins for a duplicate-token misconfig."""
        registry: dict[str, Profile] = {
            "first": _profile_with_token("shared-token", "first"),
            "second": _profile_with_token("shared-token", "second"),
        }
        result = resolve_profile_by_token("Bearer shared-token", registry)
        assert result is not None
        assert result.name == "first"
