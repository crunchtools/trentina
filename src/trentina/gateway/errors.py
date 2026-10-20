"""Gateway-specific error types.

Error messages here are deliberately terse. They never disclose bearer-token
content, profile contents beyond the profile name, or backend connection
details to the consumer. Detail goes to the structured log only.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for gateway errors."""


class ProfileConfigError(GatewayError):
    """Raised at startup when the profiles YAML is missing or invalid.

    Gateway routes are not mounted if profile loading fails while
    TRENTINA_GATEWAY_ENABLED is true. Fails closed.
    """


class AuthError(GatewayError):
    """Raised on missing, malformed, or mismatched bearer token.

    Maps to HTTP 401 with no body detail beyond a fixed string.
    """


class OAuthChallengeError(AuthError):
    """Raised when an OAuth-enabled profile got no usable OAuth credential.

    Covers a missing/malformed Authorization header and a token that fails
    upstream validation. Maps to HTTP 401 with a ``WWW-Authenticate: Bearer
    resource_metadata=…`` challenge so an MCP client discovers the flow.
    """


class OAuthForbiddenError(AuthError):
    """Raised when a valid Google identity is not permitted by the profile.

    The token verified against Google, but its email is absent, unverified,
    or not on the profile's ``oauth.allowed_emails``. Maps to HTTP 403: a new
    login will not help, so no ``WWW-Authenticate`` challenge is issued.
    """


class ProfileNotFoundError(GatewayError):
    """Raised when a request targets a profile not in the loaded registry.

    Maps to HTTP 404.
    """


class ScopeError(GatewayError):
    """Raised when a caller asks an admin tool for something outside its role.

    Covers three refusals, all of which are answered the same way — say no,
    name nothing: no calling profile is bound to the call, the action needs the
    operator role, or the named backend is not in the caller's own profile. The
    message never names another profile or its backends, so a refusal is not an
    existence oracle for the rest of the gateway.
    """


class BackendCallError(GatewayError):
    """Raised when a backend MCP call fails (network, timeout, malformed response).

    Maps to JSON-RPC error -32603 (internal error) and HTTP 502 to the consumer.
    """


class BackendRejectedCallError(BackendCallError):
    """The backend answered and refused the request itself.

    Bad arguments, an unknown method, a malformed request: the caller's
    mistake, reported by a backend that is up. It never counts toward the
    circuit breaker, which tracks whether a backend is reachable, and it
    audits as ``tool_error`` rather than ``backend_error``.
    """

    outcome_hint = "tool_error"


class BackendNeedsAuthError(BackendCallError):
    """The calling profile holds no usable grant for an ``auth`` backend (#479).

    Raised before the backend is contacted, or after it refused a freshly
    refreshed grant. Never counts toward the circuit breaker: the backend is
    fine, this profile has not been authorized to it. The message is what the
    agent reads, so it says what to do.
    """

    outcome_hint = "needs_auth"

    def __init__(self, backend: str) -> None:
        super().__init__(
            f"backend {backend!r} is not authorized for this profile: call "
            f'backend_auth with action="start" and backend="{backend}", then send '
            "the link it returns to your human"
        )
        self.backend = backend


class BackendResponseTooLargeError(BackendCallError):
    """The backend's response passed the byte cap while it streamed (#267).

    The read stopped there, so nothing was judged and nothing is delivered:
    the router answers with the oversize refusal admission gives, and it
    audits as a defense block. The backend answered, so the breaker counts a
    success.
    """

    outcome_hint = "blocked_defense"

    def __init__(self, message: str, *, cap_bytes: int) -> None:
        super().__init__(message)
        self.cap_bytes = cap_bytes
