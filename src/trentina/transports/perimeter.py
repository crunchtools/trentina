"""The perimeter spine: what every route that carries an agent's traffic out shares (#535).

A ``Route`` (``transports.base``) declares its contract and implements three
hooks — ``admit``, ``deliver``, ``render`` — that are its own policy and wire
shape. Everything else is here, once:

* who the caller is (its gateway token), and a 401 with no audit row
  for a caller nobody knows, so an unknown caller cannot fill the database;
* which instance the request names and the profile's grant on it, one refusal
  for both so a refusal is no existence oracle;
* the per-profile slot cap, per route type, taken before any body byte is read;
* the dial: a route names an origin KEY and is handed a sealed ``Upstream``
  bound to the checked, pinned origin behind it;
* judging: the request before it leaves (layers, credential detector, the
  semantic request guard) and the response before it is delivered, with the
  injected credential scrubbed from what comes back;
* the refusal's status and audit outcome, from the route's declared table, and
  the ONE ``gateway_calls`` row, written by the route's audit policy.

A built-in route that judges its own protocol (an SSE stream, a git command
list) is handed ``InTree`` — the profile and the operation — which only the
gateway's own seeded routes receive (``transports/registry.py``).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import InitVar, dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import httpx
from starlette.requests import ClientDisconnect

from .. import logsafe
from ..errors import EgressRefusedError as GuardRefusedError
from ..gateway.auth import resolve_profile_by_token
from ..gateway.backend import response_byte_cap
from ..gateway.destination import Destination as AuditDestination
from ..gateway.egress_policy import build_url, request_document, response_headers
from ..gateway.gatekeeper import judge_egress
from ..gateway.modes_policy import effective_mode
from ..gateway.outbound import (
    REASON_CREDENTIAL,
    REASON_FLAGGED,
    REASON_UNJUDGED,
    body_text,
    judge_input,
)
from ..gateway.relay import NO_OPERATION, Operation, Relayed, Slots, upstream_outcome
from ..gateway.upstream import RESOLVER_BUSY, pinned_send
from ..modes import Mode
from ..orchestrator import judge_egress_response, judge_outbound
from ..outcomes import Outcome
from ..seal import UNSEALED, Seal, require
from .base import (
    HTTPS_PORT,
    Admitted,
    Audit,
    Body,
    Context,
    Delivered,
    Grant,
    Instance,
    OperatorOrigin,
    Origin,
    RefusedError,
    Upstream,
    Wire,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic import SecretStr
    from starlette.requests import Request

    from ..gateway.destination import DestinationKind
    from ..gateway.loader import GatewayConfig
    from ..gateway.profile import Profile
    from .base import Route

logger = logging.getLogger(__name__)

#: The token ``_dial`` holds to build a ``PinnedUpstream``; see ``trentina.seal``.
_UPSTREAM_SEAL = Seal("perimeter._dial")

_AUTHORIZATION = "authorization"
#: Headers only the gateway writes on a response; an upstream's are dropped.
_OURS = "x-trentina-"
#: Seconds a request or response judge may take before it counts as unjudged.
JUDGE_DEADLINE = 60.0
#: How much of a body is sniffed for a NUL byte before it is taken as text.
_SNIFF = 8192

_REQUEST_REASON = {
    REASON_CREDENTIAL: "credential_in_request",
    REASON_FLAGGED: "flagged",
    REASON_UNJUDGED: "not_fully_judged",
}


@dataclass(frozen=True)
class HeaderToken:
    """Inject the profile's secret as ``<header>: <prefix><secret>``."""

    header: str
    prefix: str


@dataclass(frozen=True)
class Bound:
    """An instance and a profile's grant on it, with what the spine alone holds:
    the secret it injects and how, and the label its log redaction carries."""

    instance: Instance
    grant: Grant
    secret: SecretStr | None
    injection: HeaderToken | None
    secret_label: str


def bind(config: GatewayConfig, profile: Profile, route: str, name: str) -> Bound | None:
    """The instance ``name`` of ``route`` and ``profile``'s grant on it, or None.

    Read from the configuration blocks each route had before ``proxies:``;
    #535 R12 replaces this body with the one lookup.
    """
    if route == "http":
        upstream = config.egress_upstreams.get(name)
        grant = profile.egress_http.get(name)
        if upstream is None or grant is None:
            return None
        credential = upstream.credential
        return Bound(
            instance=Instance(
                name=name,
                type=route,
                origins={"origin": Origin(upstream.host)},
                options={"body": upstream.body, "headers_allow": tuple(upstream.headers_allow)},
            ),
            grant=Grant(
                origins=frozenset({"origin"}),
                methods=frozenset(m.upper() for m in grant.methods),
                enforcement=Mode(grant.enforcement),
                options={"paths": tuple(grant.paths)},
            ),
            secret=grant.token if credential is not None else None,
            injection=HeaderToken(credential.header, credential.prefix) if credential else None,
            secret_label=grant.token_env or name,
        )
    return None


def _scrub(value: str, secret: str) -> str:
    """Remove the injected credential from a response value the agent will read.

    A linear ``str.replace`` over a fixed set of forms: the raw token and its
    fully percent-encoded and JSON ``\\uXXXX``-escaped copies (both hex cases),
    the forms a mechanical encoder produces. A deliberately PARTIAL or mixed
    encoding by the (operator-named) upstream is a documented best-effort residue
    — NOT chased with a per-character regex, which backtracks on a near-match,
    and a response body is untrusted input, so that regex would be a DoS.
    Best-effort defence in depth (#511): the real protection is that the agent
    never holds the token and the upstream is operator-named; this is the belt.
    """
    forms = (
        secret,
        "".join(f"%{ord(c):02x}" for c in secret),
        "".join(f"%{ord(c):02X}" for c in secret),
        "".join(f"\\u{ord(c):04x}" for c in secret),
        "".join(f"\\u{ord(c):04X}" for c in secret),
    )
    for form in forms:
        value = value.replace(form, "[REDACTED]")
    return value


def _is_text(content_type: str) -> bool:
    """Whether a response body is judged as text. Fail closed: a missing or
    unrecognized content type is NOT text — it is the binary_unread gap, so a
    body a layer cannot positively read is withheld under block rather than
    decoded with replacement characters and waved through."""
    ct = content_type.partition(";")[0].strip().lower()
    return (
        ct.startswith("text/")
        or ct.endswith(("+json", "+xml"))
        or ct in ("application/json", "application/xml", "application/javascript")
    )


def _from_guard(exc: GuardRefusedError) -> RefusedError:
    """The egress guard's refusal, as the spine's reason.

    Three buckets, by whether the request reached the upstream:
    ``resolver_busy`` is gateway load before the connection, nothing executed;
    ``redirect`` and ``encoded`` mean the upstream already ANSWERED, so the
    request executed and the response is withheld; everything else is the
    address rail firing before a byte leaves (a non-global address, an
    unresolvable host), a defense block whose specific reason rides in
    ``detail`` for the audit.
    """
    if exc.reason == RESOLVER_BUSY:
        return RefusedError("resolver_busy")
    if exc.reason == "redirect":
        return RefusedError("redirect", executed=True)
    if exc.reason in ("encoded", "too_many_redirects", "downgrade"):
        return RefusedError("upstream_failed", executed=True)
    return RefusedError("denied_guard", detail=exc.reason)


@dataclass
class PinnedUpstream(Upstream):
    """The sealed way out: sends go only to the one checked origin it was built for.

    Built by ``_dial`` alone, so holding one is proof the spine resolved the
    origin a route named from that route's own instance; a route cannot point
    it anywhere else, and never sees the credential it injects.
    """

    op: Operation
    route: str
    bound: Bound
    origin: Origin
    idle: float
    _seal: InitVar[Seal] = UNSEALED

    def __post_init__(self, _seal: Seal) -> None:
        require(_seal, _UPSTREAM_SEAL, "PinnedUpstream")

    async def send(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        headers: Mapping[str, str],
        content: bytes | None = None,
    ) -> Delivered:
        """Judge, inject, dial, read and judge; see ``Upstream.send``."""
        mode = effective_mode(self.op.profile, self.bound.grant.enforcement)
        sent = dict(headers)
        warning = await self._judge_request(method, path, query, sent, content, mode)
        # The profile's credential goes on after judging: it is never judged or logged.
        secret: str | None = None
        if self.bound.injection is not None and self.bound.secret is not None:
            secret = self.bound.secret.get_secret_value()
            logsafe.hold(secret, self.bound.secret_label)
            header = self.bound.injection.header.lower()
            sent[header] = f"{self.bound.injection.prefix}{secret}"
        port = "" if self.origin.port == HTTPS_PORT else f":{self.origin.port}"
        url = build_url(f"https://{self.origin.host}{port}", path, query)
        raw, status, content_type, hdrs = await self._fetch(method, url, sent, content)
        return await self._judge_response(raw, status, content_type, hdrs, mode, warning, secret)

    async def _judge_request(
        self,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        content: bytes | None,
        mode: Mode,
    ) -> str | None:
        """Judge what is about to be sent; refuse under block, return flag's warning.

        A body no layer can read as text is left out of the judged document and
        refused under block; the readable request — line, query, headers — is
        judged regardless. Under block a request past the layers then meets the
        profile's semantic request guard, if it names this instance.
        """
        # A json instance forwards a re-serialized object, judged unescaped; a
        # verbatim one forwards raw bytes, judged raw when they are UTF-8.
        judged_body: str | None = None
        if content and self.bound.instance.options.get("body") == "json":
            judged_body = body_text(content)
        elif content:
            try:
                judged_body = content.decode("utf-8")
            except UnicodeDecodeError:
                judged_body = None
        binary = bool(content) and judged_body is None
        if binary and mode is not Mode.FLAG:
            raise RefusedError("binary_body")
        document = request_document(method, f"/{path}", query, headers, judged_body)
        profile = self.op.profile
        name = self.bound.instance.name
        verdict = await judge_outbound(
            document,
            source=f"{self.route}:{profile.name}:{name}",
            source_type="egress_request",
            backend=f"{self.route}:{name}",
            profile=profile,
            mode=mode,
            deadline=JUDGE_DEADLINE,
        )
        if verdict.refused:
            reason = _REQUEST_REASON[verdict.reason or REASON_UNJUDGED]
            logger.warning("perimeter: request blocked profile=%s reason=%s", profile.name, reason)
            raise RefusedError(reason)
        warning = verdict.warning
        if warning is not None:
            self.op.flag_reason = _REQUEST_REASON[verdict.reason or REASON_UNJUDGED]
            logger.warning("perimeter: request %s (flag) profile=%s", warning, profile.name)
        if binary:
            self.op.flag_reason = self.op.flag_reason or "binary_body"
            warning = f"{warning},binary_unread" if warning else "binary_unread"
        if mode is Mode.BLOCK:
            await self._gatekeep(method, document)
        return warning

    async def _gatekeep(self, method: str, document: str) -> None:
        """The semantic request guard: the profile's judge decides the intent of
        a request already past the layers, when its guards name this instance.
        Anything but an explicit allow refuses, nothing sent."""
        profile = self.op.profile
        name = self.bound.instance.name
        cfg = profile.semantic_request_guards
        kind = self.op.destination_kind
        if cfg is None or not cfg.guards_egress(name) or not self.op.destination or kind is None:
            return
        refusal = await judge_egress(
            profile,
            cfg,
            backend=f"{self.route}:{name}",
            method=method,
            destination=AuditDestination(self.op.destination, kind),
            document=judge_input(document),
        )
        if refusal is not None:
            logger.warning(
                "perimeter: gatekeeper refused profile=%s reason=%s", profile.name, refusal.reason
            )
            raise RefusedError("gatekeeper", detail=refusal.audit)

    async def _fetch(
        self, method: str, url: str, headers: dict[str, str], content: bytes | None
    ) -> tuple[bytes, int, str, dict[str, str]]:
        """Send to the checked, pinned origin and read the bounded response.

        A connect-phase failure is ``upstream_failed`` with nothing executed; a
        read or write timeout is ``upstream_idle``, executed: the request went.
        """
        cap = response_byte_cap()
        try:
            async with pinned_send(
                self.op.profile, method, url, idle=self.idle, headers=headers, content=content
            ) as resp:
                if content is not None:
                    self.op.sent = len(content)
                buffer = bytearray()
                async for chunk in resp.aiter_raw():
                    buffer.extend(chunk)
                    if len(buffer) > cap:
                        raise RefusedError("too_large", executed=True)
                return (
                    bytes(buffer),
                    resp.status_code,
                    resp.headers.get("content-type", ""),
                    response_headers(list(resp.headers.items())),
                )
        except GuardRefusedError as exc:
            raise _from_guard(exc) from None
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            logger.warning("perimeter: upstream unreachable err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed") from None
        except httpx.TimeoutException:
            raise RefusedError("upstream_idle", executed=True) from None
        except httpx.HTTPError as exc:
            logger.warning("perimeter: upstream failed err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed", executed=True) from None

    async def _judge_response(
        self,
        raw: bytes,
        status: int,
        content_type: str,
        hdrs: dict[str, str],
        mode: Mode,
        warning: str | None,
        secret: str | None,
    ) -> Delivered:
        """Judge what came back as ingress, headers and (text) body as one document.

        Under block a flagged, unjudged or unreadable (binary) response is
        withheld — the request executed (#425). Under flag it is delivered with
        the finding as ``warning``. An echo of the injected credential is cut
        before the judge or the agent sees it.
        """
        self.op.received = len(raw)
        blocking = mode is Mode.BLOCK
        hdrs = {k: v for k, v in hdrs.items() if not k.lower().startswith(_OURS)}
        if secret:
            hdrs = {k: _scrub(v, secret) for k, v in hdrs.items()}
        header_doc = "\n".join(f"{name}: {value}" for name, value in hdrs.items())
        body_is_text = bool(raw) and _is_text(content_type) and b"\x00" not in raw[:_SNIFF]
        document = header_doc
        if body_is_text:
            text = raw.decode("utf-8", errors="replace")
            if secret:
                scrubbed = _scrub(text, secret)
                if scrubbed != text:
                    text, raw = scrubbed, scrubbed.encode()
            document = f"{header_doc}\n\n{text}" if header_doc else text
        if document.strip():
            judgement = await judge_egress_response(
                document,
                profile=self.op.profile,
                source=self.op.destination or self.origin.host,
                domain=self.origin.host,
                blocking=blocking,
                deadline=JUDGE_DEADLINE,
            )
            if judgement.refuse:
                reason = "response_flagged" if judgement.flagged else "response_unjudged"
                raise RefusedError(reason, executed=True)
            if judgement.flagged or judgement.unjudged:
                warning = warning or (judgement.risk if judgement.flagged else "unjudged")
        if raw and not body_is_text:
            if blocking:
                raise RefusedError("response_binary", executed=True)
            warning = warning or "binary_unread"
        self.op.settle(upstream_outcome(status), self.op.flag_reason)
        return Delivered(
            status=status, headers=hdrs, content_type=content_type, body=raw, warning=warning
        )


def _dial(
    op: Operation, route: Route[Any, Any], bound: Bound, admitted: Admitted
) -> PinnedUpstream:
    """The ``Upstream`` for the origin ``admitted`` named in its own instance.

    A key the instance does not hold, or the grant does not cover, is refused:
    a route names an origin, it never supplies one.
    """
    origin = admitted.origin
    if (
        not isinstance(origin, OperatorOrigin)
        or origin.key not in bound.instance.origins
        or origin.key not in bound.grant.origins
    ):
        raise RefusedError("unknown_upstream")
    return PinnedUpstream(
        op=op,
        route=route.name,
        bound=bound,
        origin=bound.instance.origins[origin.key],
        idle=route.idle,
        _seal=_UPSTREAM_SEAL,
    )


@dataclass
class InTree(Context):
    """The gateway's own routes also get the profile and the operation: they
    judge their own protocol under the profile's settings. Handed only to a
    route the registry seeded."""

    profile: Profile
    op: Operation


@dataclass
class Mount:
    """A route type as the gateway serves it."""

    route: Route[Any, Any]
    destination_kind: DestinationKind
    config: GatewayConfig
    in_tree: bool = False

    def __post_init__(self) -> None:
        self.slots = Slots(self.route.slots or 0)

    def bound(self, profile: Profile, name: str) -> Bound | None:
        """The instance and grant, read from the live configuration per request,
        so an operator reload applies in place once the route is mounted."""
        from ..gateway.loader import get_active_config

        active = get_active_config()
        config = active.config if active is not None else self.config
        return bind(config, profile, self.route.name, name)


def _spell(mount: Mount, refused: RefusedError) -> RefusedError:
    """``refused`` in this route's own words: its spelling, status and outcome.

    A reason the route did not declare is a fault in the route, answered as a
    gateway error rather than trusted to mean anything.
    """
    entry = mount.route.refusals.get(refused.reason)
    if entry is None:
        logger.error("perimeter: route=%s raised an undeclared refusal", mount.route.name)
        return RefusedError(
            "undeclared_refusal",
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            outcome=Outcome.GATEWAY_ERROR,
        )
    return RefusedError(
        entry.wire or refused.reason,
        status=refused.status or entry.status,
        outcome=refused.outcome or entry.outcome,
        executed=refused.executed,
        detail=refused.detail if mount.in_tree else None,
    )


async def serve(mount: Mount, request: Request, profiles: dict[str, Profile]) -> Any:
    """Answer one request on a route: authenticate, admit, slot, deliver, audit."""
    route = mount.route
    # The caller's gateway token: Authorization, then each fallback header.
    presented = request.headers.get(_AUTHORIZATION)
    for header in route.auth.fallback_headers:
        if presented is not None:
            break
        value = request.headers.get(header)
        presented = f"Bearer {value}" if value else None
    profile = resolve_profile_by_token(presented, profiles)
    if profile is None:
        logger.warning("perimeter: refused a caller of route=%s matching no profile", route.name)
        return route.render(_spell(mount, RefusedError("unauthorized")))
    op = Operation(
        profile,
        backend=f"{route.name}:{NO_OPERATION}",
        tool=request.method,
        destination_kind=mount.destination_kind,
    )
    op.only_on_finding = route.audit is Audit.ON_FINDING
    try:
        response = await _carry(mount, request, op)
    except RefusedError as raised:
        refused = _spell(mount, raised)
        if refused.outcome is not None:
            op.settle(refused.outcome, refused.detail or refused.reason)
        logger.info(
            "perimeter: refused route=%s profile=%s reason=%s",
            route.name,
            profile.name,
            refused.reason,
        )
        await op.finish()
        return route.render(refused)
    except (ClientDisconnect, TimeoutError, asyncio.CancelledError):
        await op.finish()
        raise
    except Exception as exc:
        logger.error(
            "perimeter: route=%s failed profile=%s err=%s at %s",
            route.name,
            profile.name,
            logsafe.exc_kind(exc),
            logsafe.exc_where(exc),
        )
        op.settle(Outcome.GATEWAY_ERROR)
        await op.finish()
        raise
    if not isinstance(response, Relayed):
        await op.finish()
    return response


async def _carry(mount: Mount, request: Request, op: Operation) -> Any:
    """Resolve the instance and grant, admit, take a slot, dial, deliver."""
    route = mount.route
    name = str(request.path_params.get("instance", ""))
    bound = mount.bound(op.profile, name)
    if bound is None:
        raise RefusedError("unknown_upstream")
    hidden = {_AUTHORIZATION} | {h.lower() for h in route.auth.fallback_headers}
    wire = Wire(
        method=request.method,
        path=str(request.path_params.get("path", "")),
        raw_path=request.scope.get("raw_path", b""),
        query=request.url.query,
        headers={k: v for k, v in request.headers.items() if k.lower() not in hidden},
        peer=None,
    )
    admitted = await route.admit(wire, bound.grant, bound.instance)
    # The row names the instance once the request is admitted to it; a request
    # refused on its own line or headers is recorded against the route alone.
    op.backend = f"{route.name}:{name}"
    if route.slots is not None and not op.take_slot(mount.slots):
        raise RefusedError("busy")
    op.destination = admitted.destination
    body = Body(request.stream(), route.max_request_bytes)
    upstream = _dial(op, route, bound, admitted)
    if mount.in_tree:
        ctx: Context = InTree(
            wire=wire,
            body=body,
            instance=bound.instance,
            grant=bound.grant,
            upstream=upstream,
            profile=op.profile,
            op=op,
        )
    else:
        ctx = Context(
            wire=wire, body=body, instance=bound.instance, grant=bound.grant, upstream=upstream
        )
    return await route.deliver(admitted, ctx)


def mount(server: Any, entry: Mount, profiles: dict[str, Profile]) -> None:
    """Serve ``entry``'s route on ``server`` at the route's path."""

    async def endpoint(request: Request) -> Any:
        return await serve(entry, request, profiles)

    server.custom_route(entry.route.path, methods=list(entry.route.methods))(endpoint)
    logger.info("perimeter: mounted route=%s", entry.route.name)
