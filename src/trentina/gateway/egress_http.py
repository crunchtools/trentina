"""Terminating HTTP(S) egress (#511): judge an agent's outbound request, then
re-originate it to a named upstream, on the main port alongside ``/proxy/llm`` and
``/proxy/git``.

    /proxy/http/{upstream}/{path}

What it decides, in order, each one deterministic:

- **who is calling**: the gateway bearer token, as on ``/proxy/llm`` and ``/proxy/git``.
  None of the caller's own credentials go upstream; the profile's token for the
  upstream is injected, so the agent never holds it.
- **which upstream and path**: a configured ``egress_upstreams`` name the
  profile was granted, and a path matched against the grant. The URL is built
  from the operator's origin and that path — never from anything the caller
  sent as a host. This is a reverse proxy to named destinations, not a
  proxy-to-anywhere.
- **what the request carries**: method, path, query, forwarded headers and body
  cross ``defend()`` as one document (``judge_outbound``), with a credential
  detector over the same document. Under ``block`` a credential, a flag or a
  blocking gap refuses before anything is sent — nothing executed. Under
  ``flag`` it is forwarded with the verdict on ``x-trentina-warning``.
- **its intent** (optional, ``block`` only): when the profile's
  ``semantic_request_guards`` names this upstream, the request — already past the
  layers — is handed to the profile's judge, with the gateway's own facts (the
  destination, whether the profile has reached it before, whether the session
  was flagged), and anything but an explicit allow refuses before it is sent
  (``gatekeeper``, ``gateway/gatekeeper.py``).
- **where it goes**: through the egress guard, to an address that was checked;
  no redirect is followed.
- **what comes back**: the response is untrusted content the agent will ingest,
  so it is judged like the ``fetch`` tool (``egress_response``) — buffered,
  judged, delivered or refused. A refusal here is "executed, response withheld"
  (#425): the request was sent.

Since #535 this module is the route's own half: ``admit`` (the path and the
grant), ``deliver`` (the body, the forwarded headers) and ``render`` (the deny
marker). Judging both edges, the semantic request guard, injecting the
credential, the dial and the echo scrub are the spine's
(``transports/perimeter.py``), which every judged route shares.

One ``gateway_calls`` row per request. A terminating judged proxy buffers and
judges the whole response: it cannot hand the agent bytes it has not read, so
byte-for-byte streaming (an SSE relay) is incompatible with judge-before-deliver
and stays out of scope — that is the tunnel's territory (known gap 26). A
response past the admission cap is refused ``too_large`` (executed) rather than
split into judged parts; the raw-HTTP caller has no ``read_part`` channel, so
response paging is a documented limit, not a planned slice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from starlette.responses import Response

from ..outcomes import Outcome
from ..transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Bearer,
    Context,
    Delivered,
    Grant,
    Instance,
    OperatorOrigin,
    Refusal,
    RefusedError,
    Route,
    Wire,
)
from .backend import response_byte_cap
from .destination import MAX_DESTINATION_CHARS, fingerprint
from .egress_policy import forward_request_headers
from .proxy_utils import PLAIN_TEXT, normalize_proxy_path

if TYPE_CHECKING:
    from collections.abc import Mapping

JSON = "application/json"
WARNING_HEADER = "x-trentina-warning"
REASON_HEADER = "X-Trentina-Reason"
#: The origin key every http instance has: one upstream per instance.
ORIGIN = "origin"

#: Every refusal this route answers: the spine's, and the route's own rails on
#: the path and the body. Keyed on the reason, not on whether the request
#: executed: a timeout is a backend error, not a defense block.
REFUSALS: Mapping[str, Refusal] = {
    **SPINE_REFUSALS,
    "method_not_listed": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_ALLOWLIST),
    "path_not_listed": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_ALLOWLIST),
    "bad_path": Refusal(HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD),
    "malformed_body": Refusal(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, Outcome.DENIED_GUARD),
    "not_json": Refusal(HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD),
}


@dataclass(frozen=True)
class HttpAdmitted(Admitted):
    """The normalized path below the instance, matched against the grant."""

    path: str = ""


def _unsafe_path(path: str) -> bool:
    """A decoded path that could re-split the URL or carry a control char."""
    return any(c in path for c in "?#") or any(ord(c) < 0x20 or c == "\x7f" for c in path)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen.add(key)
    return dict(pairs)


class HttpRoute(Route[HttpAdmitted, Context]):
    """``/proxy/http/<instance>/<path>``: a reverse proxy to operator-named origins."""

    name = "http"
    methods = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    auth = Bearer()
    refusals = REFUSALS

    def __init__(self) -> None:
        self.max_request_bytes = response_byte_cap()

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> HttpAdmitted:
        """The path, normalized and held to the grant.

        ``normalize_proxy_path`` handles '.'/'..'/backslash, but the path is
        also the grant's rail: a decoded '?' or '#' (or a control char / CRLF)
        would let the matched path and the sent path diverge. Refused here; the
        spine percent-quotes the rest, so what was matched is what is sent.
        """
        path = normalize_proxy_path(wire.path)
        if path is None or _unsafe_path(path):
            raise RefusedError("bad_path")
        if wire.method.upper() not in grant.methods:
            raise RefusedError("method_not_listed")
        paths = grant.options.get("paths", ())
        if paths and not any(fnmatchcase(f"/{path}", pattern) for pattern in paths):
            raise RefusedError("path_not_listed")
        host = instance.origins[ORIGIN].host
        return HttpAdmitted(
            origin=OperatorOrigin(ORIGIN),
            destination=f"{host[: MAX_DESTINATION_CHARS - 17]}#{fingerprint(path)}",
            path=path,
        )

    async def deliver(self, admitted: HttpAdmitted, ctx: Context) -> Delivered:
        """Read the body, forward the allowed headers and hand back the judged answer.

        A compressed body is refused: what is judged must be what the
        destination parses. A json instance's body is parsed and re-serialized,
        duplicate keys refused, so the destination parses the object judged.
        """
        wire = ctx.wire
        encoding = wire.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise RefusedError("malformed_body")
        declared = wire.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_request_bytes:
            raise RefusedError("too_large")
        body: bytes | None = await ctx.body.read() or None
        if body is not None and ctx.instance.options.get("body") == "json":
            try:
                # A `{"k":"<secret>","k":"ok"}` body is a smuggling shape:
                # judging one value while sending another is the hole #511 closed.
                parsed = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
            except ValueError:
                raise RefusedError("not_json") from None
            body = json.dumps(parsed, separators=(",", ":")).encode()
        allowed = ctx.instance.options.get("headers_allow", ())
        fwd = forward_request_headers(list(wire.headers.items()), allowed)
        return await ctx.upstream.send(
            wire.method, admitted.path, query=wire.query, headers=fwd, content=body
        )

    def render(self, refused: RefusedError) -> Response:
        """The deny marker, to its own caller: a closed reason, no payload, no L3 prose."""
        if refused.reason == "unauthorized":
            return Response(content="unauthorized\n", status_code=401, media_type=PLAIN_TEXT)
        body: dict[str, Any] = {
            "error": {"type": "trentina_refused", "reason": refused.reason},
            "blocked": True,
            "block_reason": refused.reason,
            "scanner": "trentina",
        }
        if refused.executed:
            # The request was sent; say so rather than imply it was not (#425).
            body["executed"] = True
            body["error"]["message"] = "executed by the destination, response withheld"
        return Response(
            content=json.dumps(body),
            status_code=refused.status or HTTPStatus.FORBIDDEN,
            media_type=JSON,
            headers={REASON_HEADER: refused.reason},
        )
