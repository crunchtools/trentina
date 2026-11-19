"""Google OAuth for Vertex AI: ADC file parsing and access-token caching.

Raw httpx and ``cryptography`` only (no google-auth, per constitution §I.2).
Nothing here logs or raises with a refresh token, client secret, private key,
assertion or access token in the text.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ...errors import MalformedResponseError, QuarantineAgentError
from .base import json_object, status_error

if TYPE_CHECKING:
    from collections.abc import Callable

#: Pinned. A credential file's own ``token_uri`` is honoured only when it is
#: exactly this: a file must not be able to send the refresh token or a signed
#: assertion to a host of its choosing.
GOOGLE_OAUTH_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TOKEN_TIMEOUT = 30.0
EXPIRY_SKEW = 300.0
"""Seconds before expiry at which a cached token counts as stale."""
MAX_TOKEN_RESPONSE = 64 * 1024
JWT_LIFETIME = 3600
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# OAuth answers a dead credential with these; none of them heals on retry.
_REFUSED_STATUSES = frozenset({400, 401, 403})


@dataclass(frozen=True)
class VertexCredentials:
    """A parsed ADC file. ``repr`` is suppressed so secrets stay out of logs."""

    kind: str
    client_id: str = ""
    client_secret: str = ""
    refresh_token: str = ""
    client_email: str = ""
    private_key_id: str = ""
    private_key: rsa.RSAPrivateKey | None = None

    def __repr__(self) -> str:
        return f"VertexCredentials(kind={self.kind!r})"


def _field(adc: dict[str, Any], name: str) -> str:
    value = adc.get(name)
    if not isinstance(value, str) or not value:
        raise QuarantineAgentError(f"Vertex credentials: missing or invalid field '{name}'")
    return value


def parse_credentials(raw: str) -> VertexCredentials:
    """Parse the JSON of a Google ADC file, or raise QuarantineAgentError."""
    try:
        adc = json.loads(raw)
    except (ValueError, RecursionError):
        raise QuarantineAgentError("Vertex credentials: not valid JSON") from None
    if not isinstance(adc, dict):
        raise QuarantineAgentError("Vertex credentials: not a JSON object")

    token_uri = adc.get("token_uri")
    if token_uri is not None and token_uri != GOOGLE_OAUTH_URL:
        raise QuarantineAgentError(f"Vertex credentials: token_uri must be {GOOGLE_OAUTH_URL}")

    kind = adc.get("type")
    if kind == "authorized_user":
        return VertexCredentials(
            kind=kind,
            client_id=_field(adc, "client_id"),
            client_secret=_field(adc, "client_secret"),
            refresh_token=_field(adc, "refresh_token"),
        )
    if kind == "service_account":
        email = _field(adc, "client_email")
        pem = _field(adc, "private_key")
        try:
            key = serialization.load_pem_private_key(pem.encode(), password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            # cryptography's messages can name PEM internals; ours names the field.
            raise QuarantineAgentError("Vertex credentials: private_key is not a PEM key") from None
        if not isinstance(key, rsa.RSAPrivateKey):
            raise QuarantineAgentError("Vertex credentials: private_key is not an RSA key")
        key_id = adc.get("private_key_id")
        return VertexCredentials(
            kind=kind,
            client_email=email,
            private_key_id=key_id if isinstance(key_id, str) else "",
            private_key=key,
        )
    raise QuarantineAgentError(
        "Vertex credentials: type must be authorized_user or service_account"
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_assertion(creds: VertexCredentials, now: int) -> str:
    """The RS256 JWT a service account trades for an access token."""
    if creds.private_key is None:
        raise QuarantineAgentError("Vertex credentials: not a service account")
    header: dict[str, str] = {"alg": "RS256", "typ": "JWT"}
    if creds.private_key_id:
        header["kid"] = creds.private_key_id
    claims = {
        "iss": creds.client_email,
        "scope": SCOPE,
        "aud": GOOGLE_OAUTH_URL,
        "iat": now,
        "exp": now + JWT_LIFETIME,
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    sig = creds.private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(sig)}"


class TokenSource:
    """Caches one access token; a refresh is one request however many callers."""

    def __init__(
        self,
        credentials: VertexCredentials,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._creds = credentials
        self._clock = clock
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_at = 0.0

    def _fresh(self) -> bool:
        return self._token is not None and self._clock() < self._expires_at - EXPIRY_SKEW

    async def token(self) -> str:
        """A cached access token, refreshed once it is within EXPIRY_SKEW of expiry."""
        if self._token is not None and self._fresh():
            return self._token
        async with self._lock:
            if self._token is not None and self._fresh():  # refreshed while we waited
                return self._token
            return await self._refresh()

    async def refresh_after_401(self, stale: str) -> str:
        """A token newer than *stale*: force a refresh only if nobody already has."""
        async with self._lock:
            if self._token is not None and self._token != stale and self._fresh():
                return self._token
            return await self._refresh()

    def _grant(self) -> dict[str, str]:
        """The token request form: a refresh-token grant, or a signed JWT."""
        creds = self._creds
        if creds.kind == "service_account":
            return {
                "grant_type": JWT_BEARER_GRANT,
                "assertion": sign_assertion(creds, int(time.time())),
            }
        return {
            "grant_type": "refresh_token",
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "refresh_token": creds.refresh_token,
        }

    async def _refresh(self) -> str:
        """Fetch a token. The caller holds the lock."""
        try:
            # nosemgrep: trentina-httpx-client-outside-egress -- fixed URL
            async with httpx.AsyncClient(timeout=httpx.Timeout(TOKEN_TIMEOUT)) as client:
                resp = await client.post(GOOGLE_OAUTH_URL, data=self._grant())
        except httpx.TimeoutException:
            raise QuarantineAgentError("Vertex token request timed out") from None
        except httpx.RequestError as exc:
            # The exception type, not str(exc): a request error can echo the URL.
            raise QuarantineAgentError(
                f"Vertex token request failed: {type(exc).__name__}"
            ) from None

        if resp.status_code in _REFUSED_STATUSES:
            # Status 401 (non-retryable) carrying only the OAuth ``error`` code:
            # error_description and the rest of the body are never echoed.
            try:
                error = json_object(resp.content[:MAX_TOKEN_RESPONSE]).get("error")
            except MalformedResponseError:
                error = None
            code = (
                f": {error[:64]}"
                if isinstance(error, str) and error.replace("_", "").isalnum()
                else ""
            )
            raise QuarantineAgentError(f"Vertex credentials refused{code}", status_code=401)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise status_error(exc) from None

        # A 200 we cannot use is a MalformedResponseError, like any provider
        # answering 200 with the wrong shape (#294): the fallback treats it as a failure.
        if len(resp.content) > MAX_TOKEN_RESPONSE:
            raise MalformedResponseError("token response is too large")
        body = json_object(resp.content)
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not isinstance(token, str) or not token:
            raise MalformedResponseError("token response has no access_token")
        if not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0:
            raise MalformedResponseError("token response has no valid expires_in")
        self._token = token
        self._expires_at = self._clock() + expires_in
        return token
