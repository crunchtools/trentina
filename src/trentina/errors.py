"""Error hierarchy for trentina.

All errors scrub credentials from messages before surfacing to users.
"""

from __future__ import annotations

import re
from typing import Any


def scrub_credentials(message: str) -> str:
    """Remove API keys and tokens from error messages."""
    return re.sub(
        r"(key|token|secret|password|authorization)[=:\s]+\S+",
        r"\1=[REDACTED]",
        message,
        flags=re.IGNORECASE,
    )


class TrentinaError(Exception):
    """Base error for all trentina operations."""

    def __init__(self, message: str) -> None:
        super().__init__(scrub_credentials(message))


class FetchError(TrentinaError):
    """Raised when fetching a URL fails."""

    def __init__(
        self,
        url: str,
        reason: str,
        *,
        status_code: int | None = None,
        error_body: str | None = None,
    ) -> None:
        super().__init__(f"Failed to fetch {url}: {reason}")
        self.status_code = status_code
        self.error_body = error_body


EGRESS_REASONS = frozenset(
    {
        "scheme",
        "port",
        "non_global_address",
        "unresolvable",
        "resolver_busy",
        "too_many_redirects",
        "downgrade",
        "encoded",
        "redirect",
    }
)


class EgressRefusedError(TrentinaError):
    """A gateway-side fetch was refused before it left the host (#260).

    The reason is from a closed set and the message carries nothing else: a
    refusal that named the resolved address would map the internal network
    for whoever asked.
    """

    def __init__(self, reason: str) -> None:
        if reason not in EGRESS_REASONS:
            raise ValueError(f"unknown egress reason {reason!r}")
        super().__init__(f"Egress refused: {reason}")
        self.reason = reason


class L1Error(TrentinaError):
    """Raised when L1 encounters an unrecoverable error."""


class QuarantineAgentError(TrentinaError):
    """Raised when the L3 provider call fails.

    ``status_code`` is the provider's HTTP status, when there was one.
    ``retry_after`` is seconds to wait before asking that provider again: the
    driver sets it from a 429's Retry-After header, and ``limited_generate``
    replaces it with the pause the L3 limiter will actually enforce.
    """

    def __init__(
        self,
        reason: str,
        status_code: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"Q-Agent error: {reason}")
        self.status_code = status_code
        # Seconds the provider asked us to wait, from its Retry-After header.
        self.retry_after = retry_after


class MalformedResponseError(QuarantineAgentError):
    """The provider replied, but not with JSON its schema allows.

    Not JSON, not an object, or outside the response schema (#294). Asked
    again once (0.43.1), then the judge is unavailable. ``detail`` is ours —
    a schema path — never text from the response.
    """

    def __init__(self, detail: str = "not JSON") -> None:
        super().__init__(f"Malformed provider response: {detail}")


class TruncatedResponseError(QuarantineAgentError):
    """The provider stopped at the output-token cap, so its JSON is cut short.

    Deliberately not a ``MalformedResponseError``: that one is asked again
    once, and the same request hits the same cap (#358). It carries no
    status code, so no fallback provider is tried either. A detection turn
    cut short is ``l3_unavailable`` like any other provider error. Redact
    reports it as ``t2_truncated``, which tells the caller to ask for less,
    where ``t2_unavailable`` says try later.
    """

    def __init__(self) -> None:
        super().__init__("response cut at the output-token cap")


class SearchCanaryLeakedError(QuarantineAgentError):
    """L0 repeated its system prompt's canary: whatever it read steered it.

    Its own type because it is the one search failure that is the defense
    working, not the provider breaking (#293).
    """

    def __init__(self) -> None:
        super().__init__("SECURITY: canary leaked in L0 search response")


class BlockedSourceError(TrentinaError):
    """Refused: flagged, not fully judged, or on the blocklist.

    ``refusal`` is the structured body the gateway hands the agent under
    ``_trentina_refusal`` of an ordinary tool result (``router._refused``):
    why, which layer or gap, and the modes this caller may try next.
    Gateway-authored fields only — never payload text, never L3 prose.
    """

    def __init__(self, source: str, reason: str, *, refusal: dict[str, Any] | None = None) -> None:
        super().__init__(f"Refused {source}: {reason}")
        self.refusal: dict[str, Any] = refusal or {"reason": reason, "alternatives": []}


class ModeNotPermittedError(TrentinaError):
    """The call asked for a mode the caller's policy does not allow."""

    def __init__(self, mode: str, allowed: list[str]) -> None:
        super().__init__(
            f"Parameter 'trentina_mode' value not in allow list (permitted: {', '.join(allowed)})"
        )
        self.mode = mode


class PromptParamGoneError(ModeNotPermittedError):
    """A call still sent ``trentina_prompt``, which 0.43.0 no longer reads.

    Refused rather than ignored: ignoring it would answer the tool's default
    question instead of the one the caller asked.
    """

    def __init__(self) -> None:
        TrentinaError.__init__(
            self,
            "Parameter 'trentina_prompt' no longer exists (0.43.0); "
            'pass trentina_mode={"redact": "<question>"}',
        )
        self.mode = "redact"


class TransformNotPermittedError(TrentinaError):
    """The call named a transform the caller's policy does not offer (#183)."""

    def __init__(self, offered: list[str]) -> None:
        super().__init__(
            "Parameter 'trentina_preprocess' value not in allow list "
            f"(permitted: {', '.join(offered) or 'none'})"
        )


class TransformFailedError(TrentinaError):
    """A transform the call depends on did not run, so nothing is delivered.

    Names the processor and how it failed, never the payload.
    """

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"Transform {name!r} could not run ({reason}); content withheld")
        self.processor = name


FILE_READ_REASONS = frozenset(
    {
        "not_found",
        "not_a_file",
        "not_a_directory",
        "too_large",
        "unsupported_type",
        "binary",
        "too_many_entries",
        "outside_read_roots",
        "denied_path",
        "changed_during_read",
        "not_found_or_denied",
    }
)


class FileReadError(TrentinaError):
    """Raised when read_tool or dir_tool refuses or fails a local path (#261).

    ``reason`` is one of ``FILE_READ_REASONS``, and the message carries that
    code plus an optional number, NEVER the path: the caller already knows
    the path it sent, and the message reaches logs and audit rows that other
    agents can read (#262). A refusal that echoed ``/config/profiles.yaml``
    would confirm the file's existence to whoever reads the log.

    ``detail`` is an optional non-path qualifier, such as the size cap. An
    unknown ``reason`` raises ``ValueError``: the set is closed on purpose.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in FILE_READ_REASONS:
            raise ValueError(f"unknown file read reason {reason!r}")
        self.reason = reason
        super().__init__(f"Cannot read: {reason}" + (f" ({detail})" if detail else ""))


class ContentSizeError(TrentinaError):
    """Raised when inline content exceeds the admission cap (#225)."""

    def __init__(self, tokens: int, cap: int) -> None:
        super().__init__(
            f"Content too large: {tokens} tokens, over the admission cap of {cap}. "
            "Split content into smaller chunks."
        )


class UnscannableContentError(TrentinaError):
    """Raised when untrusted content is too large for Layer 2 to scan in full.

    Failing closed here is deliberate.  A partial scan that returns BENIGN is
    worse than no scan, because it lets an attacker hide an injection past the
    token cap and still collect a clean bill of health.
    """

    def __init__(self, source: str, tokens: int, max_tokens: int) -> None:
        super().__init__(
            f"Cannot fully scan {source}: {tokens} tokens exceeds the "
            f"classifier limit of {max_tokens}. Untrusted content must be "
            "scanned in full. Split the content, or add the source to the "
            "trust allowlist if you vouch for it."
        )


class UnsupportedContentTypeError(TrentinaError):
    """Raised when a fetched body is not text the pipeline can reason about."""

    def __init__(
        self,
        url: str,
        content_type: str,
        *,
        redirect_chain: list[dict[str, object]] | None = None,
    ) -> None:
        parts = [
            (
                f"Refusing to fetch {url}: content-type {content_type!r} is not "
                "text. Binary bodies decode into garbage that wastes the "
                "L1 and L2 pipeline."
            ),
        ]
        if redirect_chain:
            hops = " -> ".join(
                f"{hop['url']} ({hop['status']} {hop.get('content_type', '')})"
                for hop in redirect_chain
            )
            parts.append(
                f"Redirect chain: {hops}. "
                "A page that redirects to a binary download (ZIP, PDF, etc.) "
                "is a known prompt-injection vector — the attacker wants the "
                "agent to curl/wget the archive directly and extract it."
            )
        super().__init__(" ".join(parts))
        self.redirect_chain = redirect_chain


class ConfigError(TrentinaError):
    """Raised for configuration problems."""
