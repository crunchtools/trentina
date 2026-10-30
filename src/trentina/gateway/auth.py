"""Bearer-token authentication for gateway endpoints.

Constant-time comparison via `hmac.compare_digest` defends against timing
oracles. Errors carry no token content.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING, Any

from .errors import AuthError, OAuthChallengeError, OAuthForbiddenError

if TYPE_CHECKING:
    from .profile import OAuthConfig, Profile


def _email_verified(value: Any) -> bool:
    """Google reports ``email_verified`` as a bool or the string ``"true"``.

    Treat only an explicit affirmative as verified; a missing or falsey value
    is unverified, because an unverified email is not an identity we allowlist.
    """
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def verify_bearer(authorization_header: str | None, profile: Profile) -> None:
    """Verify the Authorization header against the profile's resolved bearer token.

    The header must use the `Bearer` scheme (case-insensitive). The presented
    token is compared in constant time against the profile's resolved token,
    which the loader set at startup from the env var named in the profile.

    Args:
        authorization_header: Raw value of the request `Authorization` header,
            or None if the header is absent.
        profile: The profile being accessed.

    Raises:
        AuthError: header missing, malformed, profile token not resolved, or
            token mismatch. Caller maps this to HTTP 401.
    """
    if not authorization_header:
        raise AuthError("missing authorization")

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise AuthError("malformed authorization")

    # Two distinct faults, kept distinct: an OAuth-only profile never had a
    # static token (0.15.0), while a declared one that did not resolve is a
    # misconfiguration the loader should already have refused.
    if profile.auth is None:
        raise AuthError("profile has no static bearer token")

    if profile.auth.bearer_token is None:
        raise AuthError("profile token not resolved")

    expected = profile.auth.bearer_token.get_secret_value()
    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise AuthError("invalid token")


def verify_edge_jwt_header(
    authorization_header: str | None, profile: Profile
) -> tuple[str, str] | None:
    """Verify a federated peer's edge JWT, for a profile that is a federation ingress.

    Only a profile with ``federation.peers`` engages this path (#592, C1); for
    any other profile it returns None so the caller falls through to OAuth or a
    challenge, exactly as before. Returns ``(peer, sub)`` — the name of the peer
    whose key verified the token (the actor) and the real caller — on success.
    Returns None when there is no credential to try. Raises ``AuthError`` (→ 401)
    when a credential IS presented but fails: a federation ingress's credential
    is the edge JWT, so a bad one is fail-closed, never a fall-through.

    C1 only authenticates. C2 binds ``(peer, sub)`` into the request context so
    the upstream's audit and guards see the real caller.
    """
    if profile.federation is None or not profile.federation.peers:
        return None
    if not authorization_header:
        return None
    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return None

    from .edge_key import EdgeKeyError, load_public_key, verify_edge_jwt

    peers = {
        name: load_public_key(peer.public_key)
        for name, peer in profile.federation.peers.items()
    }
    try:
        return verify_edge_jwt(presented, peers, aud=profile.name)
    except EdgeKeyError as exc:
        raise AuthError("invalid edge token") from exc


async def verify_oauth(
    authorization_header: str | None,
    profile: Profile,
    verifier: Any,
) -> Any:
    """Verify an OAuth bearer for an OAuth-enabled profile, and return it.

    One code path serves both modes, because both expose the same
    ``async verify_token(token) -> AccessToken | None``. In PROXY mode the
    presented token is a FastMCP-issued reference token and fastmcp's
    ``OAuthProvider.verify_token`` forwards to ``load_access_token``, which
    swaps it for the stored upstream Google token and re-validates that live
    against Google. In DELEGATED mode the token was minted by the external
    issuer itself and the verifier checks it there. Either way a revoked or
    expired session fails here, not just at issue time, and the verified
    identity's email is matched against the profile allowlist.

    Args:
        authorization_header: Raw ``Authorization`` header value, or None.
        profile: The OAuth-enabled profile being accessed.
        verifier: The thing that validates tokens for this profile — the
            gateway's proxy provider, a delegated verifier, or None if the
            gateway came up without either (a config error for an enabled
            profile).

    Returns:
        The verified access token, so the caller can audit-log the identity.

    Raises:
        OAuthChallengeError: no provider, no usable token, or a token bound to
            another profile — caller returns 401 with a ``WWW-Authenticate``
            challenge so the client discovers the flow.
        OAuthForbiddenError: token valid but the email is absent, unverified,
            or not on ``profile.oauth.allowed_emails``, or the profile pins
            ``allowed_subjects`` and the ``sub`` is not on it — caller
            returns 403.
    """
    if verifier is None:
        # An enabled profile with no verifier means the gateway failed to build
        # one (missing client credentials). A challenge is pointless — there is
        # no authorization server to discover — but it is the safe 401 default.
        raise OAuthChallengeError("oauth provider not configured")

    if profile.oauth is None or not profile.oauth.enabled:
        raise OAuthChallengeError("oauth not enabled for profile")

    if not authorization_header:
        raise OAuthChallengeError("missing authorization")

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise OAuthChallengeError("malformed authorization")

    access = await verifier.verify_token(presented)
    if access is None:
        raise OAuthChallengeError("invalid or expired token")

    # TRUST: bound_profile(token) == profile.name -> token admitted here.
    # Tier: the gateway's own record of which profile a flow named (proxy
    # mode, gateway/oauth_binding.py) or the per-profile audience pin
    # (delegated). One JWT audience covers every proxied profile, so without
    # this a token issued to an agent seat verified at an operator seat that
    # allowlists the same email (#298). A verifier that cannot say is refused,
    # never assumed bound; a challenge, so the client re-authorizes for here.
    bound_profile = getattr(verifier, "bound_profile", None)
    if bound_profile is None:
        raise OAuthChallengeError("verifier cannot bind a token to a profile")
    if await bound_profile(presented) != profile.name:
        raise OAuthChallengeError("token was not issued for this profile")

    _check_identity(access.claims or {}, profile.oauth)
    return access


def _check_identity(claims: dict[str, Any], oauth: OAuthConfig) -> None:
    """Admit a verified identity only if the profile's allowlists name it.

    Raises:
        OAuthForbiddenError: the email is absent, unverified or not allowed,
            or the profile pins subjects and this ``sub`` is not one of them.
    """
    email = claims.get("email")
    if not email or not _email_verified(claims.get("email_verified")):
        raise OAuthForbiddenError("token has no verified email")

    if email.strip().lower() not in oauth.allowed_emails:
        raise OAuthForbiddenError("email not permitted for profile")

    # TRUST: sub in allowed_subjects -> the account, not just the address.
    # Google can give an address to a different account (a renamed Workspace
    # user, a lapsed custom domain), and that account's token carries the
    # allowlisted email verified. It never reuses a sub (#458).
    subjects = oauth.allowed_subjects
    if subjects and str(claims.get("sub") or "") not in subjects:
        raise OAuthForbiddenError("subject not permitted for profile")


def resolve_profile_by_token(
    authorization_header: str | None, registry: dict[str, Profile]
) -> Profile | None:
    """Resolve which profile a bearer token belongs to, or None.

    Used by the LLM proxy, which — unlike the gateway routes — carries no
    profile in its URL. The presented token is compared in constant time
    against every profile's resolved bearer token; the first match wins.

    Constant-time comparison runs for every profile so a valid token cannot be
    distinguished from an invalid one by response timing. The number of
    profiles is not secret.

    Args:
        authorization_header: Raw `Authorization` header value, or None.
        registry: Loaded profile registry (name -> Profile).

    Returns:
        The matching Profile, or None if the header is missing, malformed, or
        matches no profile.
    """
    if not authorization_header:
        return None

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return None

    presented_bytes = presented.encode("utf-8")
    match: Profile | None = None
    for profile in registry.values():
        if profile.auth is None or profile.auth.bearer_token is None:
            continue
        expected = profile.auth.bearer_token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(presented_bytes, expected) and match is None:
            match = profile
    return match
