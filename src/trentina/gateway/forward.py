"""``forward``: an agent-chosen URL, judged both ways (#535, for #507).

    GET|POST /proxy/forward/<instance>/fetch?url=<absolute http(s) URL>

The one route whose destination the agent chooses rather than the operator. It
is ``fetch``'s reach on the route an egress benchmark drives (a fetch-style
proxy, agent-egress-bench's ``fetch_proxy``), and ``/proxy/http``'s judging:

- **which hosts**: the instance's ``hosts`` and the profile's grant, both, by
  NAME before anything is resolved. An address is never a host; ``*`` is any
  name and is approved by a person as that.
- **which ports and schemes**: http on 80, https on 443.
- **what it carries**: the request line, query, forwarded headers and body are
  judged before it leaves (layers, the credential detector, the semantic
  request guard), and the response before it is delivered. No profile token is
  ever injected: an agent-chosen host does not get one.
- **where it goes**: the host's every answer is checked on every call and never
  cached; no redirect is followed.

A refusal carries the egress-benchmark deny marker only when the gateway denied
or blocked: an upstream that could not be reached is not containment, and a
marker on one would make a published containment rate a lie.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

from starlette.responses import Response

from ..outcomes import Outcome
from ..transports.base import (
    HTTPS_PORT,
    SPINE_REFUSALS,
    Admitted,
    AgentUrl,
    Bearer,
    Context,
    Delivered,
    Grant,
    Instance,
    Refusal,
    RefusedError,
    Route,
    Wire,
)
from .backend import response_byte_cap
from .destination import MAX_DESTINATION_CHARS, fingerprint
from .egress_policy import forward_request_headers
from .proxy_utils import PLAIN_TEXT

if TYPE_CHECKING:
    from collections.abc import Mapping

JSON = "application/json"
WARNING_HEADER = "x-trentina-warning"
REASON_HEADER = "X-Trentina-Reason"
#: The one endpoint under an instance.
ENDPOINT = "fetch"

#: The outcomes a deny marker stands for: the gateway decided, the destination did not.
_CONTAINED = frozenset({Outcome.DENIED_GUARD, Outcome.DENIED_ALLOWLIST, Outcome.BLOCKED_DEFENSE})

REFUSALS: Mapping[str, Refusal] = {
    **SPINE_REFUSALS,
    "bad_url": Refusal(HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD),
    "method_not_listed": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_ALLOWLIST),
    "not_found": Refusal(HTTPStatus.NOT_FOUND, Outcome.DENIED_GUARD),
}


@dataclass(frozen=True)
class ForwardAdmitted(Admitted):
    """The agent's URL, split into what the spine sends."""

    path: str = ""
    query: str = ""


class ForwardRoute(Route[ForwardAdmitted, Context]):
    """``/proxy/forward/<instance>/fetch?url=...``: one agent-chosen URL."""

    name = "forward"
    methods = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
    auth = Bearer()
    refusals = REFUSALS
    ports = frozenset({80, HTTPS_PORT})

    def __init__(self) -> None:
        self.max_request_bytes = response_byte_cap()

    async def admit(self, wire: Wire, grant: Grant, _instance: Instance) -> ForwardAdmitted:
        """One absolute http(s) URL in ``url``, a method the grant lists."""
        if wire.path != ENDPOINT:
            raise RefusedError("not_found")
        urls = parse_qs(wire.query, keep_blank_values=True).get("url", [])
        if len(urls) != 1:
            raise RefusedError("bad_url")
        parts = urlsplit(urls[0])
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
            raise RefusedError("bad_url")
        if wire.method.upper() not in grant.methods:
            raise RefusedError("method_not_listed")
        host = parts.hostname.lower()
        return ForwardAdmitted(
            origin=AgentUrl(urls[0]),
            # The caller's host and a fingerprint of its path: never the path,
            # which can carry what the agent was asked to leak.
            destination=f"{host[: MAX_DESTINATION_CHARS - 17]}#{fingerprint(parts.path)}",
            path=parts.path.lstrip("/"),
            query=parts.query,
        )

    async def deliver(self, admitted: ForwardAdmitted, ctx: Context) -> Delivered:
        """Send it, judged both ways; hand back what the spine delivered."""
        wire = ctx.wire
        body = await ctx.body.read() or None
        return await ctx.upstream.send(
            wire.method,
            admitted.path,
            query=admitted.query,
            headers=forward_request_headers(list(wire.headers.items()), ()),
            content=body,
        )

    def render(self, refused: RefusedError) -> Response:
        """A JSON refusal, carrying the deny marker only when the gateway decided."""
        if refused.reason == "unauthorized":
            return Response(content="unauthorized\n", status_code=401, media_type=PLAIN_TEXT)
        body: dict[str, Any] = {"error": {"type": "trentina_refused", "reason": refused.reason}}
        if refused.outcome in _CONTAINED:
            body |= {"blocked": True, "block_reason": refused.reason, "scanner": "trentina"}
        if refused.executed:
            body["executed"] = True
            body["error"]["message"] = "executed by the destination, response withheld"
        return Response(
            content=json.dumps(body),
            status_code=refused.status or HTTPStatus.FORBIDDEN,
            media_type=JSON,
            headers={REASON_HEADER: refused.reason},
        )
