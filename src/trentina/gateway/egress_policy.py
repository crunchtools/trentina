"""The reading half of the terminating egress route (#511): no I/O.

Everything the request line and headers decide, and how the forwarded request
and the returned response are shaped, with nothing that touches the network —
the split ``git_wire`` is to ``git_transport``. ``egress_http`` is the route.

The route is a REVERSE proxy to NAMED upstreams: the host is the operator's,
the path and query are the caller's (validated), and nothing a caller sends is
ever part of the host. A caller's own ``Authorization``/``Cookie`` never go
upstream — the profile's token is injected instead — and a backend's
``Set-Cookie`` never reaches the agent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlencode

from .proxy_utils import filter_response_headers

if TYPE_CHECKING:
    from http import HTTPStatus

    from .profile import EgressUpstream

#: Every refusal reason the route can carry. Closed, like ``git_wire.REASONS``.
REASONS = frozenset(
    {
        "unauthorized",
        "unknown_upstream",  # upstream not configured, or profile has no grant: one reason
        "method_not_listed",
        "path_not_listed",
        "bad_path",
        "too_large",
        "malformed_body",
        "not_json",  # body must be JSON for an upstream declaring body: json
        "binary_body",  # a non-UTF-8 verbatim body no layer can read
        "credential_in_request",
        "flagged",
        "not_fully_judged",
        "gatekeeper",  # the semantic-request-guards judge refused the request's intent (#511)
        "busy",  # the profile's in-flight slots are all taken
        "resolver_busy",
        "denied_guard",  # the address rail refused before a byte left (SSRF/
        # resolution); the specific guard reason rides in ``detail`` for the audit
        "redirect",
        "upstream_failed",
        "upstream_idle",
        "upstream_status",  # the destination returned >= 400
        "response_flagged",  # the response leg; distinct from a request refusal
        "response_unjudged",
        "response_binary",
    }
)

#: Request headers always forwarded (safe, non-credential). A grant's upstream
#: may add API-version-style headers through ``headers_allow``; nothing else is
#: forwarded, and a credential header never is.
BASE_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "content-type",
        "if-none-match",
        "if-modified-since",
        "range",
        "user-agent",
    }
)

#: Never forwarded upstream, whatever an allowlist says: the caller's own
#: credentials and the forwarding chain. The profile's token is injected instead.
_NEVER_FORWARD = frozenset({"authorization", "proxy-authorization", "cookie"})

USER_AGENT = "trentina-egress"


class EgressRefusedError(Exception):
    """A request the route refuses, with a closed reason and an HTTP status."""

    def __init__(
        self, status: HTTPStatus, reason: str, *, executed: bool = False, detail: str | None = None
    ) -> None:
        if reason not in REASONS:
            raise ValueError(f"reason {reason!r} not in the closed set")
        self.status = status
        self.reason = reason
        #: True when the destination already answered (the response leg): the
        #: request was sent, so a refusal here is "executed, response withheld".
        self.executed = executed
        #: A more specific, still log-safe audit string when the closed reason
        #: is a bucket — the gatekeeper's own reason and facts, say. The CALLER
        #: only ever sees ``reason``; ``detail`` is for the durable audit row.
        self.detail = detail
        super().__init__(reason)


def canonical_query(raw: str) -> str:
    """The query re-encoded from its parsed pairs, duplicates kept.

    Percent-encoding is canonicalized (this is the one rewrite, and it precedes
    judging); a generic API may repeat a key, so pairs are not collapsed.
    """
    if not raw:
        return ""
    return urlencode(parse_qsl(raw, keep_blank_values=True))


def build_url(upstream: EgressUpstream, path: str, query: str) -> str:
    """The upstream URL, built from the operator's origin and a validated path.

    The host is never anything the caller sent. ``path`` is already normalized
    and matched against the grant; it is percent-quoted here (``safe="/"``) so
    the bytes sent are byte-for-byte the path that was matched — a ``?`` or ``#``
    that slipped through becomes ``%3F``/``%23`` and cannot re-split the URL into
    a different endpoint, query or fragment at the destination.
    """
    url = f"{upstream.upstream}/{quote(path.lstrip('/'), safe='/')}"
    canonical = canonical_query(query)
    return f"{url}?{canonical}" if canonical else url


def forward_request_headers(
    arrived: list[tuple[str, str]], upstream: EgressUpstream
) -> dict[str, str]:
    """The caller's headers that may go upstream: an allowlist, never a strip-list.

    ``BASE_REQUEST_HEADERS`` plus the upstream's ``headers_allow``, minus the
    credential and forwarding headers that never leave whatever a list says.
    The injected credential is added later, by the route, and is not judged.
    """
    allowed = BASE_REQUEST_HEADERS | set(upstream.headers_allow)
    out: dict[str, str] = {}
    for name, value in arrived:
        lower = name.lower()
        if lower in _NEVER_FORWARD or lower.startswith("x-forwarded"):
            continue
        if lower in allowed:
            out[lower] = value
    out["user-agent"] = USER_AGENT
    return out


def response_headers(arrived: list[tuple[str, str]]) -> dict[str, str]:
    """The backend's response headers for the agent, with ``Set-Cookie`` dropped.

    ``filter_response_headers`` already drops hop-by-hop headers; a destination's
    session must not be planted on the agent through a judged path either.
    """
    out = filter_response_headers(arrived)
    return {k: v for k, v in out.items() if k.lower() != "set-cookie"}


def request_document(
    method: str, path: str, query: str, headers: dict[str, str], body: str | None
) -> str:
    """The outbound request as one document for the layers and the detector.

    The request line, the canonical query (prefixed ``?`` so the FIRST parameter
    is seen by the ``[?&]``-anchored credential patterns), the headers that will
    be forwarded (the injected credential is not among them yet), and the body.
    ``body`` is text the CALLER decoded to match what it forwards — raw for a
    ``verbatim`` upstream, the re-serialized object for a ``json`` one — so what
    is judged is what is sent. This is exactly what ``judge_outbound`` reads.
    """
    parts = [f"{method} {path}"]
    canonical = canonical_query(query)
    if canonical:
        parts.append(f"?{canonical}")
    parts.extend(f"{name}: {value}" for name, value in headers.items())
    if body:
        parts.append(body)
    return "\n".join(parts)
