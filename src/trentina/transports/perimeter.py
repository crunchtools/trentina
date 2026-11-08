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
import base64
import contextlib
import logging
from contextlib import asynccontextmanager
from dataclasses import InitVar, dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
from starlette.datastructures import Headers
from starlette.requests import ClientDisconnect
from starlette.responses import Response

from .. import logsafe, telemetry
from ..config import get_config
from ..errors import EgressRefusedError as GuardRefusedError
from ..gateway.auth import resolve_profile_by_token
from ..gateway.backend import response_byte_cap
from ..gateway.context import profile_context
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
from ..gateway.profile import is_dns_name, profile_for_address
from ..gateway.relay import NO_OPERATION, Operation, Relayed, Slots, upstream_outcome
from ..gateway.upstream import (
    MAX_POOL_CONNECTIONS,
    RESOLVER_BUSY,
    checked_target,
    forget_checked,
    matrix_pinned_send,
    pinned_send,
)
from ..logsafe import exc_kind
from ..modes import Mode
from ..orchestrator import judge_egress_response, judge_outbound
from ..outcomes import Outcome
from ..reach.egress import check_url, open_pinned
from ..seal import UNSEALED, Seal, require
from .base import (
    HTTP_PORT,
    HTTPS_PORT,
    Admitted,
    AgentUrl,
    Audit,
    Bearer,
    Body,
    Context,
    Delivered,
    Grant,
    Instance,
    Listener,
    Origin,
    PeerAddress,
    RefusedError,
    Upstream,
    Wire,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

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
#: A request carrying this may hold an address somebody named, not one that connected.
_FORWARDED_FOR = "x-forwarded-for"
#: Headers only the gateway writes on a response; an upstream's are dropped.
_OURS = "x-trentina-"
#: Where a delivered finding rides back on a judged response.
WARNING_HEADER = "x-trentina-warning"
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
class BasicAuth:
    """Inject the profile's secret as HTTP Basic, ``<username>:<secret>``."""

    username: str


@dataclass(frozen=True)
class Bound:
    """An instance and a profile's grant on it, with what the spine alone holds:
    the secret it injects and how, and the label its log redaction carries."""

    instance: Instance
    grant: Grant
    secret: SecretStr | None
    injection: HeaderToken | BasicAuth | None
    secret_label: str


@dataclass(frozen=True)
class Binding:
    """One question for a binder: the instance ``name`` and ``profile``'s grant
    on it, in what the gateway loaded — the file, and the LLM providers with
    their keys resolved (which bind at startup, as before #535)."""

    config: GatewayConfig
    providers: Mapping[str, Any]
    profile: Profile
    name: str


def _bind_http(asked: Binding) -> Bound | None:
    """An ``egress_upstreams`` entry and the profile's ``egress_http`` grant."""
    upstream = asked.config.egress_upstreams.get(asked.name)
    grant = asked.profile.egress_http.get(asked.name)
    if upstream is None or grant is None:
        return None
    credential = upstream.credential
    return Bound(
        instance=Instance(
            name=asked.name,
            type="http",
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
        secret_label=grant.token_env or asked.name,
    )


def _bind_llm(asked: Binding) -> Bound | None:
    """A loaded provider and the profile's key for it; a profile without one
    is bound, so its route can say so rather than say the provider is unknown."""
    provider = asked.providers.get(asked.name)
    if provider is None:
        return None
    key = asked.profile.llm_keys.get(asked.name)
    parts = urlsplit(provider.upstream)
    return Bound(
        instance=Instance(
            name=asked.name,
            type="llm",
            origins={
                "origin": Origin(
                    parts.hostname or "", parts.port or HTTPS_PORT, parts.path.rstrip("/")
                )
            },
            options={"api": provider.api, "allowed_models": tuple(provider.allowed_models)},
        ),
        grant=Grant(
            origins=frozenset({"origin"}),
            methods=frozenset(),
            enforcement=Mode(key.enforcement) if key is not None else Mode.BLOCK,
            options={"has_key": key is not None},
        ),
        secret=key.api_key if key is not None else None,
        injection=HeaderToken(provider.auth_header, provider.auth_prefix),
        secret_label=(key.api_key_env if key is not None else None) or asked.name,
    )


def _bind_git(asked: Binding) -> Bound | None:
    """A ``git_remotes`` entry and the profile's ``git`` lists, with a token."""
    remote = asked.config.git_remotes.get(asked.name)
    lists = asked.profile.git.get(asked.name)
    if remote is None or lists is None or lists.token is None:
        return None
    return Bound(
        instance=Instance(
            name=asked.name,
            type="git",
            origins={"origin": Origin(remote.host)},
            options={"hidden_refs": tuple(remote.hidden_refs)},
        ),
        grant=Grant(
            origins=frozenset({"origin"}),
            methods=frozenset({"GET", "POST"}),
            enforcement=Mode.BLOCK,
            # The repository and ref lists, without the token they carry.
            options={"git": lists.model_copy(update={"token": None})},
        ),
        secret=lists.token,
        injection=BasicAuth(remote.username),
        secret_label=lists.token_env,
    )


def _bind_egress(asked: Binding) -> Bound | None:
    """The profile's ``client_egress`` hosts: where its client may tunnel."""
    block = asked.profile.client_egress
    if block is None:
        return None
    return Bound(
        instance=Instance(name=asked.name, type="egress", origins={}, options={}),
        grant=Grant(
            origins=frozenset(),
            methods=frozenset(),
            enforcement=Mode.BLOCK,
            options={},
            hosts=frozenset(block.hosts),
        ),
        secret=None,
        injection=None,
        secret_label=asked.name,
    )


def _bind_matrix(asked: Binding) -> Bound | None:
    """The one homeserver ``matrix.upstream`` names, for a profile with ``matrix_ingress``."""
    if asked.profile.matrix_ingress is None:
        return None
    parts = urlsplit(str(asked.config.matrix.get("upstream", MATRIX_UPSTREAM)).rstrip("/"))
    return Bound(
        instance=Instance(
            name=asked.name,
            type="matrix",
            origins={"origin": Origin(parts.hostname or "", parts.port or HTTPS_PORT, parts.path)},
            options={},
        ),
        grant=Grant(
            origins=frozenset({"origin"}), methods=frozenset(), enforcement=Mode.BLOCK, options={}
        ),
        secret=None,
        injection=None,
        secret_label=asked.name,
    )


def _reachable(instance: list[str], grant: list[str]) -> frozenset[str]:
    """The hosts both the instance and the grant allow; ``*`` on either side
    is whatever the other allows, and on both is any host."""
    if "*" in instance:
        return frozenset(grant)
    if "*" in grant:
        return frozenset(instance)
    return frozenset(instance) & frozenset(grant)


def _bind_route(asked: Binding, route: str) -> Bound | None:
    """A ``forward`` or ``dist:`` instance of ``route`` and the profile's grant
    on it (#535): the hosts and origins both allow, and the token the grant
    names, sent only to the instance's own origins."""
    instance = asked.config.route_instances.get(asked.name)
    grant = asked.profile.route_grants.get(asked.name)
    if instance is None or grant is None:
        return None
    if instance.type != route and instance.type.rpartition(":")[2] != route:
        return None
    origins = {
        key: Origin(parts.hostname or "", parts.port or HTTPS_PORT, parts.path.rstrip("/"))
        for key, parts in ((k, urlsplit(v)) for k, v in instance.origins.items())
    }
    credential = instance.credential
    return Bound(
        instance=Instance(
            name=asked.name, type=instance.type, origins=origins, options=dict(instance.options)
        ),
        grant=Grant(
            origins=frozenset(grant.origins or origins) & frozenset(origins),
            methods=frozenset(grant.methods),
            enforcement=Mode(grant.enforcement),
            options=dict(grant.options),
            hosts=_reachable(instance.hosts, grant.hosts),
        ),
        secret=grant.token if credential is not None else None,
        injection=HeaderToken(credential.header, credential.prefix) if credential else None,
        secret_label=grant.token_env or asked.name,
    )


#: How each built-in route type finds an instance and a profile's grant on it,
#: in the configuration blocks ``proxies:`` normalizes into (#535 R12: one home
#: per fact, so these read the same objects whichever spelling the file used).
_BINDERS = {
    "http": _bind_http,
    "llm": _bind_llm,
    "git": _bind_git,
    "egress": _bind_egress,
    "matrix": _bind_matrix,
}
#: The homeserver ``matrix.upstream`` defaults to.
MATRIX_UPSTREAM = "https://matrix-client.matrix.org"


def bind(
    config: GatewayConfig,
    providers: Mapping[str, Any],
    profile: Profile,
    route: str,
    name: str,
) -> Bound | None:
    """The instance ``name`` of ``route`` and ``profile``'s grant on it, or None."""
    asked = Binding(config, providers, profile, name)
    binder = _BINDERS.get(route)
    return binder(asked) if binder is not None else _bind_route(asked, route)


def _credential(bound: Bound) -> tuple[str, str, str] | None:
    """The header the spine injects for ``bound``, its value, and the secret in it.

    Every form a secret is sent in is held from the logs (``logsafe``), the
    Basic encoding included: the token in the form it is sent is a secret too.
    """
    match bound.injection, bound.secret:
        case BasicAuth(username=username), stored if stored is not None:
            secret = stored.get_secret_value()
            encoded = base64.b64encode(f"{username}:{secret}".encode()).decode("ascii")
            for form in (secret, encoded):
                logsafe.hold(form, bound.secret_label)
            return "authorization", f"Basic {encoded}", secret
        case HeaderToken(header=header, prefix=prefix), stored if stored is not None:
            secret = stored.get_secret_value()
            logsafe.hold(secret, bound.secret_label)
            return header.lower(), f"{prefix}{secret}", secret
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
    #: An agent-chosen destination: its address is checked on every send, never
    #: pooled or cached, and no redirect is followed.
    agent: bool = False
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
        # The profile's credential goes on after judging: it is never judged or
        # logged, and never sent where the agent chose the destination.
        secret: str | None = None
        if not self.agent and (credential := _credential(self.bound)) is not None:
            header, value, secret = credential
            sent[header] = value
        url = build_url(self.origin.url, path, query)
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
            async with self._open(method, url, headers, content) as resp:
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
            if self.agent and exc.reason == "unresolvable":
                # An agent-chosen name that does not resolve is not reached,
                # not refused: no deny marker may stand for it (#535 R15).
                raise RefusedError("upstream_unreachable") from None
            raise _from_guard(exc) from None
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            logger.warning("perimeter: upstream unreachable err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed") from None
        except httpx.TimeoutException:
            raise RefusedError("upstream_idle", executed=True) from None
        except httpx.HTTPError as exc:
            logger.warning("perimeter: upstream failed err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed", executed=True) from None

    @asynccontextmanager
    async def _open(
        self, method: str, url: str, headers: dict[str, str], content: bytes | None
    ) -> AsyncIterator[httpx.Response]:
        """The send: the pinned pool for an operator origin; for an agent-chosen
        URL, a fresh check of its address and one pinned request, no redirect."""
        if not self.agent:
            async with pinned_send(
                self.op.profile, method, url, idle=self.idle, headers=headers, content=content
            ) as resp:
                yield resp
            return
        # The guard caps lookups per calling profile (#291), read off the bound caller.
        with profile_context(self.op.profile):
            target = await check_url(url)
        async with open_pinned(
            method, url, target, idle=self.idle, headers=headers, content=content
        ) as resp:
            yield resp

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
    """The ``Upstream`` for where ``admitted`` says the request goes.

    An operator origin is a KEY the instance and the grant both hold: a route
    names one, it never supplies one. An agent-chosen URL is held to the hosts
    both allow, by NAME before anything is resolved — never an address — and
    to the route's ports; its address is checked when it is sent.
    """
    origin = admitted.origin
    if isinstance(origin, AgentUrl):
        parts = urlsplit(origin.url)
        host = (parts.hostname or "").lower().removesuffix(".")
        try:
            named = parts.port
        except ValueError:
            raise RefusedError("port") from None
        # An explicit :0 is a port asked for, not the default: refused below.
        port = named if named is not None else HTTPS_PORT if parts.scheme == "https" else HTTP_PORT
        # A name the operator let reach a private address by env (a benchmark's
        # fixtures, on ports the runner picks) is let reach any port on it too:
        # the port rule stops an agent walking internal services, which is the
        # decision that name already carries (cto, #535).
        private = host in get_config().fetch_private_names
        if (
            parts.scheme not in ("http", "https")
            or port == 0
            or (port not in route.ports and not private)
        ):
            raise RefusedError("port")
        if not is_dns_name(host) or (
            "*" not in bound.grant.hosts and host not in bound.grant.hosts
        ):
            raise RefusedError("host_not_listed")
        target = Origin(host, port, scheme=parts.scheme)
        agent = True
    elif origin.key in bound.instance.origins and origin.key in bound.grant.origins:
        target, agent = bound.instance.origins[origin.key], False
    else:
        raise RefusedError("unknown_upstream")
    return PinnedUpstream(
        op=op,
        route=route.name,
        bound=bound,
        origin=target,
        idle=route.idle,
        agent=agent,
        _seal=_UPSTREAM_SEAL,
    )


async def send_exempt(
    profile: Profile,
    method: str,
    url: str,
    idle: float,
    headers: Mapping[str, str],
    content: AsyncIterator[bytes] | None = None,
) -> httpx.Response:
    """One pinned send to an operator origin without the terminating contract,
    the response returned open; the caller closes it.

    Matrix's own client follows a homeserver's redirects and reads its gzip, so
    neither is refused here. A failure to get an answer is a ``RefusedError``:
    ``resolver_busy`` (gateway load), ``denied_guard`` with the guard's reason,
    ``upstream_idle``, ``upstream_unreachable`` or ``upstream_failed``.
    """
    try:
        return await matrix_pinned_send(
            profile, method, url, idle=idle, headers=dict(headers), content=content
        )
    except GuardRefusedError as exc:
        if exc.reason == RESOLVER_BUSY:
            raise RefusedError(RESOLVER_BUSY) from None
        raise RefusedError("denied_guard", detail=exc.reason) from None
    except httpx.TimeoutException:
        raise RefusedError("upstream_idle") from None
    except httpx.ConnectError:
        raise RefusedError("upstream_unreachable") from None
    except httpx.HTTPError as exc:
        logger.warning("perimeter: upstream failed err=%s", logsafe.exc_kind(exc))
        raise RefusedError("upstream_failed") from None


async def read_decoded(resp: httpx.Response) -> AsyncIterator[bytes]:
    """An exempt response's body, content-encoding undone; a stream that fails
    part-way is ``upstream_failed``."""
    try:
        async for piece in resp.aiter_bytes():
            yield piece
    except httpx.HTTPError as exc:
        logger.warning("perimeter: upstream failed mid-stream err=%s", logsafe.exc_kind(exc))
        raise RefusedError("upstream_failed", executed=True) from None


@dataclass
class InTree(Context):
    """The gateway's own routes also get the profile and the operation: they
    judge their own protocol under the profile's settings. Handed only to a
    route the registry seeded.

    ``open`` is the send that does not judge, for a route that judges its own
    protocol; ``stream`` is the body as it arrives, uncapped, for a route that
    bounds it by its own rules. Neither is on ``Upstream``, which a plugin holds.
    """

    profile: Profile
    op: Operation
    raw: AsyncIterator[bytes]
    bound: Bound
    origin: Origin
    idle: float
    #: The pool's connections to the origin: at least the route's slots, so a
    #: fan-out the slot cap admits is not starved on the pool.
    max_connections: int

    def stream(self) -> AsyncIterator[bytes]:
        """The request body as it arrives, unread by the spine."""
        return self.raw

    async def open_exempt(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        headers: Mapping[str, str],
        content: AsyncIterator[bytes] | None = None,
    ) -> httpx.Response:
        """``open`` without the terminating contract: a 3xx is the caller's to
        follow and an encoded body is decoded by ``read_decoded``. For a route
        whose upstream answers a client that expects both (a Matrix homeserver).
        The response is closed when the operation finishes.
        """
        url = f"{self.origin.url}/{path}" + (f"?{query}" if query else "")
        resp = await send_exempt(self.profile, method, url, self.idle, headers, content)
        self.op.upstream.push_async_callback(resp.aclose)
        return resp

    async def chunks(self, resp: httpx.Response) -> AsyncIterator[bytes]:
        """An opened response's body as it arrives; a forge that goes quiet or
        drops the connection part-way is ``upstream_idle``/``upstream_failed``."""
        try:
            async for piece in resp.aiter_raw():
                yield piece
        except httpx.TimeoutException:
            raise RefusedError("upstream_idle", executed=True) from None
        except httpx.HTTPError as exc:
            logger.warning("perimeter: upstream failed mid-stream err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed", executed=True) from None

    async def open(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        headers: Mapping[str, str],
        content: bytes | AsyncIterator[bytes] | None = None,
    ) -> httpx.Response:
        """Send to the checked origin with the credential injected; the open
        response is closed when the operation finishes.

        The guard's ``resolver_busy`` is the gateway's load and ``redirect``
        the pinned contract's own rule; any other refusal of its is a verdict
        on the upstream, its reason kept as ``detail``.
        """
        sent = dict(headers)
        if (credential := _credential(self.bound)) is not None:
            sent[credential[0]] = credential[1]
        url = f"{self.origin.url}/{path}" + (f"?{query}" if query else "")
        try:
            return await self.op.upstream.enter_async_context(
                pinned_send(
                    self.profile,
                    method,
                    url,
                    idle=self.idle,
                    headers=sent,
                    content=content,
                    max_connections=self.max_connections,
                )
            )
        except GuardRefusedError as exc:
            if exc.reason in (RESOLVER_BUSY, "redirect"):
                raise RefusedError(exc.reason) from None
            raise RefusedError("denied_guard", detail=exc.reason) from None
        except httpx.TimeoutException:
            raise RefusedError("upstream_idle", executed=True) from None
        except httpx.ConnectError:
            raise RefusedError("upstream_unreachable") from None
        except httpx.HTTPError as exc:
            logger.warning("perimeter: upstream failed err=%s", logsafe.exc_kind(exc))
            raise RefusedError("upstream_failed") from None


@dataclass
class Mount:
    """A route type as the gateway serves it."""

    route: Route[Any, Any]
    destination_kind: DestinationKind
    config: GatewayConfig
    in_tree: bool = False
    #: The LLM providers loaded at startup, keys resolved; they bind then, as
    #: before #535, and a reload reports a change to them rather than apply it.
    providers: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.slots = Slots(self.route.slots or 0)

    def bound(self, profile: Profile, name: str) -> Bound | None:
        """The instance and grant, read from the live configuration per request,
        so an operator reload applies in place once the route is mounted."""
        from ..gateway.loader import get_active_config

        active = get_active_config()
        config = active.config if active is not None else self.config
        return bind(config, self.providers, profile, self.route.name, name)


def _spell(mount: Mount, refused: RefusedError) -> RefusedError:
    """``refused`` in this route's own words: its spelling, status and outcome.

    The raised refusal itself is filled in, so whatever a route's own subclass
    carries for its ``render`` stays with it. A reason the route did not
    declare is a fault in the route, answered as a gateway error rather than
    trusted to mean anything.
    """
    entry = mount.route.refusals.get(refused.reason)
    if entry is None:
        logger.error("perimeter: route=%s raised an undeclared refusal", mount.route.name)
        return RefusedError(
            "undeclared_refusal",
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            outcome=Outcome.GATEWAY_ERROR,
        )
    refused.reason = entry.wire or refused.reason
    refused.status = refused.status or entry.status
    refused.outcome = refused.outcome or entry.outcome
    if not mount.in_tree:
        refused.detail = None
    return refused


def _caller(
    route: Route[Any, Any], request: Request, profiles: dict[str, Profile]
) -> Profile | None:
    """The profile a request is from, or None.

    A bearer route reads ``Authorization``, then each fallback header in turn.
    A peer-address route takes the address that connected, and refuses any
    request carrying ``X-Forwarded-For``: uvicorn rewrites the peer from it for
    a trusted proxy, so the address may be one somebody named.
    """
    # TRUST: the bearer token, or the peer address, picks the profile (#330)
    #   untrusted: every header the caller sends
    #   judged-by: resolve_profile_by_token (constant time, every profile) or
    #     profile_for_address (one profile per address, loader-checked)
    #   on-failure: fail-closed; no profile, a refusal with no row
    #   owner: transports/perimeter._caller
    #   evidence: T2 uvicorn ProxyHeadersMiddleware rewrites scope["client"] only
    #     from x-forwarded-for; T3 gateway/auth.py, loader._check_matrix_networks
    auth = route.auth
    if isinstance(auth, PeerAddress):
        if _FORWARDED_FOR in request.headers:
            return None
        peer = request.client.host if request.client else None
        return profile_for_address(peer, profiles, auth.networks)
    presented = request.headers.get(_AUTHORIZATION)
    for header in auth.fallback_headers:
        if presented is not None:
            break
        value = request.headers.get(header)
        presented = f"Bearer {value}" if value else None
    return resolve_profile_by_token(presented, profiles)


async def serve(mount: Mount, request: Request, profiles: dict[str, Profile]) -> Any:
    """Answer one request on a route: authenticate, admit, slot, deliver, audit."""
    route = mount.route
    profile = _caller(route, request, profiles)
    if profile is None:
        logger.warning("perimeter: refused a caller of route=%s matching no profile", route.name)
        return route.render(_spell(mount, RefusedError("unauthorized")))
    # The agent's trace, so a model or egress call nests under its run (#556).
    telemetry.current_trace.set(telemetry.trace_from_request(request.headers))
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
        op.tool = refused.tool or op.tool
        op.destination = refused.destination or op.destination
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
        # A reason the route settled before it failed is kept: it is the row's.
        op.settle(Outcome.GATEWAY_ERROR, op.reason)
        await op.finish()
        raise
    if isinstance(response, Delivered):
        response = _answer_with(response)
    if not isinstance(response, Relayed):
        await op.finish()
    return response


def _answer_with(delivered: Delivered) -> Response:
    """A judged delivery as the response: its status, headers and body, and the
    finding a ``flag`` grant forwarded on ``x-trentina-warning``."""
    headers = dict(delivered.headers)
    if delivered.warning:
        headers[WARNING_HEADER] = delivered.warning
    return Response(
        content=delivered.body,
        status_code=delivered.status,
        media_type=delivered.content_type or None,
        headers=headers,
    )


async def _carry(mount: Mount, request: Request, op: Operation) -> Any:
    """Resolve the instance and grant, admit, take a slot, dial, deliver."""
    route = mount.route
    name = str(request.path_params.get("instance", ""))
    bound = mount.bound(op.profile, name)
    if bound is None:
        raise RefusedError("unknown_upstream")
    # The row names the instance once it is bound to one; a route with one
    # upstream and no instance segment is named by the route alone.
    op.backend = f"{route.name}:{name}" if name else route.name
    # The credential the caller authenticated with never reaches the route. A
    # peer-address route was handed none, so its Authorization is the caller's
    # own, for the upstream (a Matrix client's access token for its homeserver).
    hidden: set[str] = set()
    if isinstance(route.auth, Bearer):
        hidden = {_AUTHORIZATION} | {h.lower() for h in route.auth.fallback_headers}
    wire = Wire(
        method=request.method,
        path=str(request.path_params.get("path", "")),
        raw_path=request.scope.get("raw_path", b""),
        query=request.url.query,
        headers=Headers(
            raw=[
                (k, v) for k, v in request.headers.raw if k.decode("latin-1").lower() not in hidden
            ]
        ),
        peer=request.client.host
        if isinstance(route.auth, PeerAddress) and request.client
        else None,
    )
    admitted = await route.admit(wire, bound.grant, bound.instance)
    # What admit established goes on the row before the slot, so a busy
    # refusal says what it refused.
    op.tool = admitted.tool or op.tool
    op.destination = admitted.destination
    if route.slots is not None and not op.take_slot(mount.slots):
        raise RefusedError("busy")
    raw = request.stream()
    body = Body(raw, route.max_request_bytes)
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
            raw=raw,
            bound=bound,
            origin=upstream.origin,
            idle=route.idle,
            max_connections=max(MAX_POOL_CONNECTIONS, route.slots or 0),
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


# ---- Listeners: a raw stream on a port of its own (CONNECT). -----------------------

#: Seconds one checked address may take to accept a connection before the next.
CONNECT_TIMEOUT = 10.0
#: Bytes read from a new connection's buffer at a time.
_STREAM_LIMIT = 65536


async def open_stream(address: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to one checked address. A seam: tests point it at a local server."""
    return await asyncio.open_connection(address, port)


async def _dial_stream(
    profile: Profile, host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Resolve ``host`` through the egress guard and connect to what was checked,
    each checked address in turn; one that refuses or times out is passed over."""
    try:
        target = await checked_target(profile, host)
    except GuardRefusedError as exc:
        if exc.reason == RESOLVER_BUSY:
            raise RefusedError(RESOLVER_BUSY) from None
        raise RefusedError("denied_guard", detail=exc.reason) from None
    for address in target.addresses:
        with contextlib.suppress(OSError, TimeoutError):
            return await asyncio.wait_for(open_stream(address, port), CONNECT_TIMEOUT)
    raise RefusedError("upstream_unreachable")


@dataclass
class ListenerMount:
    """A built-in listener as the gateway serves it: where it binds, the
    server once started, and the connections it is carrying."""

    listener: Listener
    destination_kind: DestinationKind
    address: tuple[str, int]
    server: asyncio.Server | None = None
    tasks: set[asyncio.Task[None]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.slots = Slots(self.listener.slots)

    async def start(self) -> None:
        """Bind and accept, if not already."""
        if self.server is None:
            host, port = self.address
            self.server = await asyncio.start_server(self._accept, host, port, limit=_STREAM_LIMIT)
            bound = self.server.sockets[0].getsockname()[1]
            logger.warning("perimeter: listener=%s on port %d", self.listener.name, bound)

    async def stop(self) -> None:
        """Stop accepting and close every stream it is carrying."""
        if self.server is None:
            return
        self.server.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.server.wait_closed()
        self.server = None
        self.slots = Slots(self.listener.slots)
        forget_checked()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        try:
            await accept(self, reader, writer)
        finally:
            if task is not None:
                self.tasks.discard(task)
            writer.close()
            with contextlib.suppress(OSError, asyncio.CancelledError):
                await writer.wait_closed()


async def _head(entry: ListenerMount, reader: asyncio.StreamReader) -> bytes:
    """The request head, up to its blank line, within the listener's limits."""
    listener = entry.listener
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), listener.head_timeout)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        raise RefusedError("malformed_head") from None
    if len(head) > listener.head_limit:
        raise RefusedError("malformed_head")
    return head


def _spell_stream(entry: ListenerMount, refused: RefusedError) -> RefusedError:
    """``refused`` in the listener's own words; see ``_spell``."""
    entry_for = entry.listener.refusals.get(refused.reason)
    if entry_for is not None:
        refused.reason = entry_for.wire or refused.reason
        refused.status = refused.status or entry_for.status
        refused.outcome = refused.outcome or entry_for.outcome
    return refused


async def accept(
    entry: ListenerMount, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Carry one connection: who it is from, where it may go, the dial, the row.

    The connection's peer address picks the profile; a caller in no profile's
    networks is answered without a byte acted on and leaves no row. The
    destination ``admit`` names is held to the profile's hosts and the
    listener's ports, then dialled through the egress guard.
    """
    # TRUST: the peer address picks the profile (#442, after #330)
    #   untrusted: every byte the caller sends
    #   judged-by: nothing; an address is resolved, not judged
    #   on-failure: fail-closed; an address in no profile's networks is refused
    #   owner: transports/perimeter.accept
    #   evidence: T2 the address is the accepted socket's peer, and a listener
    #     reads no forwarding header; T3 loader._check_egress_networks
    from ..gateway.loader import get_active_config

    listener = entry.listener
    active = get_active_config()
    peer = writer.get_extra_info("peername")
    profile = None
    if active is not None and peer:
        profile = profile_for_address(peer[0], active.config.profiles, listener.auth.networks)
    if profile is None:
        logger.warning("perimeter: listener=%s refused a caller in no profile", listener.name)
        # Read the request before answering, without acting on it: closing on
        # unread bytes resets the connection and the caller never sees the status.
        with contextlib.suppress(RefusedError):
            await _head(entry, reader)
        await _answer(writer, listener.respond(_spell_stream(entry, RefusedError("unauthorized"))))
        return
    op = Operation(
        profile,
        backend=listener.name,
        tool=listener.operation,
        destination_kind=entry.destination_kind,
    )
    upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    try:
        upstream = await _tunnel(entry, reader, op, active.config if active else None)
        await listener.relay((reader, writer), upstream, op)
        op.settle(Outcome.OK)
    except RefusedError as raised:
        refused = _spell_stream(entry, raised)
        # Once the upstream is open the stream has been answered; closing is the answer.
        if upstream is None:
            await _answer(writer, listener.respond(refused))
        op.settle(refused.outcome or Outcome.DENIED_GUARD, refused.detail or refused.reason)
    except OSError as exc:
        logger.warning("perimeter: listener=%s stream failed err=%s", listener.name, exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR, "connect_failed")
    except asyncio.CancelledError:
        op.settle(Outcome.CANCELLED)
        raise
    finally:
        if upstream is not None:
            upstream[1].close()
        await op.finish()


async def _tunnel(
    entry: ListenerMount,
    reader: asyncio.StreamReader,
    op: Operation,
    config: GatewayConfig | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Decide one stream and dial it: the head, the destination it names, the
    profile's hosts, the listener's ports, a slot, and the checked addresses.

    Raises:
        RefusedError: any of those refused it; nothing has been answered yet.
    """
    listener, profile = entry.listener, op.profile
    bound = bind(config, {}, profile, listener.name, listener.name) if config else None
    admitted = listener.admit(await _head(entry, reader))
    op.destination = admitted.destination
    parts = urlsplit(admitted.origin.url if isinstance(admitted.origin, AgentUrl) else "")
    host, port = parts.hostname or "", parts.port or HTTPS_PORT
    if port not in listener.ports:
        raise RefusedError("port")
    if bound is None or host not in bound.grant.hosts:
        raise RefusedError("host_not_listed")
    if not op.take_slot(entry.slots):
        raise RefusedError("busy")
    return await _dial_stream(profile, host, port)


async def _answer(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    with contextlib.suppress(OSError):
        await writer.drain()
