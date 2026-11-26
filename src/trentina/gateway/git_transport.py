"""Git transport: clone, fetch and push to the repositories a profile lists (#453).

A coding agent's ``git`` used to reach its forge through a client-egress
tunnel, which decides a host and nothing else: every repository on that
forge, with a credential the agent holds, and no record of which repository
or branch a push went to. This route carries git's smart HTTP protocol
instead, on the main port::

    /proxy/git/{remote}/{owner}/{repo}[.git]/info/refs?service=git-upload-pack
    /proxy/git/{remote}/{owner}/{repo}[.git]/git-upload-pack
    /proxy/git/{remote}/{owner}/{repo}[.git]/git-receive-pack

What it decides, in order, each one deterministic:

- **who is calling**: the gateway bearer token, as on ``/proxy/llm``. None of the
  caller's headers go upstream; the profile's forge token is injected, so the
  agent never holds one.
- **which repository**: an owner and name the gateway validated, lower-cased,
  matched against that profile's ``fetch`` or ``push`` list, ``deny`` first.
  The upstream URL is built from those parts and the operator's origin.
- **what it may ask**: only the three endpoints, the two services, a
  ``Git-Protocol`` of version 1 or 2, and under v2 only ``ls-refs`` and
  ``fetch``. A request that names a hidden ref namespace is refused.
- **what a push may move**: the command list is read before a byte of the
  pack is forwarded. Every ref must match ``push_refs``; a tag or a delete is
  refused whatever is listed.
- **where it goes**: through the egress guard, to an address that was
  checked. No redirect is followed: a renamed repository would otherwise
  carry the injected token to a repository nobody matched.
- **what is listed back**: refs under a hidden namespace (``refs/pull/`` by
  default) are dropped from ref advertisements and ``ls-refs`` answers,
  unless the profile's grant lists that namespace in ``show_refs``.

What it does not decide is anything inside a pack. The gateway terminates
this connection, so that is a choice and not a limit: a pack is compressed
objects, and no layer reads it in either direction. Nor is a ``want`` for an
object id restricted. That is known gap 29 in ``docs/defense-pipeline.md``.

Since #535 this module is the route's own half, on the perimeter spine
(``transports/perimeter.py``): ``admit`` decides from the request line and
headers, ``deliver`` reads the body by git's own rules and relays the forge's
answer, ``render`` words a refusal for git's user. The caller, the remote and
grant, the slot, the injected credential, the dial and the row are the spine's.

One ``gateway_calls`` row per request, written when it ends or is refused.
"""

from __future__ import annotations

import asyncio
import logging
import zlib
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from starlette.responses import Response

from ..outcomes import Outcome
from ..transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Bearer,
    Grant,
    Instance,
    OperatorOrigin,
    Refusal,
    RefusedError,
    Route,
    Wire,
)
from ..transports.perimeter import InTree
from .destination import MAX_DESTINATION_CHARS
from .git_fetch import Fetch, at_tips, enter_lane, relay_fetch, relay_listing, relay_push
from .git_wire import (
    FLUSH,
    INFO_REFS,
    OPERATION,
    PROTOCOL_HEADER,
    PROTOCOL_V2,
    PROTOCOLS,
    PUSH,
    REASONS,
    RECEIVE_PACK,
    SERVICES,
    Command,
    GitRefusedError,
    PktReader,
    RefFilter,
    RepoPath,
    check_upload_request,
    is_cold_fetch,
    is_promisor_fetch,
    negotiated_sideband,
    parse_command,
    parse_repo_path,
    refuse_ref_update,
    strip_fetch_request,
    wants,
)
from .proxy_utils import PLAIN_TEXT
from .relay import Relayed

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from .profile import GitGrant
    from .relay import Operation

logger = logging.getLogger(__name__)

MAX_COMMAND_BYTES = 65536
"""Longest push command list read, in bytes. It is held in memory until
every ref in it has been decided."""

MAX_COMMANDS = 64
"""Most refs one push may update."""

MAX_NEGOTIATION_BYTES = 8 * 1024 * 1024
"""Largest upload-pack request, inflated. It is read whole because all of it
is text the gateway checks: about 160,000 ``have`` lines."""

_GZIP = "gzip"
_IDENTITY = ("", "identity")
_GZIP_WINDOW = 31
_OK = 200
_PASSED_STATUSES = frozenset({HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND})


#: How long the client or the forge may go quiet before the request is given up.
IDLE_TIMEOUT = 300.0
USER_AGENT = "git/trentina"
REASON_HEADER = "X-Trentina-Reason"
#: The origin key every git instance has: one forge per remote.
ORIGIN = "origin"


def _service(wire: Wire, endpoint: str) -> str:
    """The service one request is for, by its endpoint, method and query.

    ``info/refs`` is a ``GET`` whose query is exactly ``service=`` and one of
    the two services: without it the forge would answer in the "dumb"
    protocol, a file server over the repository. The other two endpoints are
    a ``POST`` with no query at all.

    Raises:
        GitRefusedError: ``method`` (405) or ``service`` (400).
    """
    wanted = "GET" if endpoint == INFO_REFS else "POST"
    if wire.method != wanted:
        raise GitRefusedError(HTTPStatus.METHOD_NOT_ALLOWED, "method")
    query = wire.query
    if endpoint != INFO_REFS:
        if query:
            raise GitRefusedError(HTTPStatus.BAD_REQUEST, "service")
        return endpoint
    service = query.removeprefix("service=")
    if query != f"service={service}" or service not in SERVICES:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "service")
    return service


#: git's refusals: the spine's, each reason git_wire may raise (each raise
#: carries its own status and outcome), and git's own spelling of three of the
#: spine's: an unknown or ungranted remote is ``remote``, and a redirect and a
#: guard refusal keep git's outcome, and a forge that cannot be reached is
#: ``upstream_failed`` as any other failure is.
REFUSALS: Mapping[str, Refusal] = {
    **{reason: Refusal(HTTPStatus.BAD_REQUEST, Outcome.DENIED_GUARD) for reason in REASONS},
    **SPINE_REFUSALS,
    "unknown_upstream": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_ALLOWLIST, wire="remote"),
    "redirect": Refusal(HTTPStatus.BAD_GATEWAY, Outcome.DENIED_GUARD),
    "upstream_unreachable": Refusal(
        HTTPStatus.BAD_GATEWAY, Outcome.BACKEND_ERROR, wire="upstream_failed"
    ),
}


@dataclass(frozen=True)
class GitAdmitted(Admitted):
    """A request whose line and headers passed every rule that reads them."""

    path: RepoPath = field(default_factory=lambda: RepoPath("", "", ""))
    service: str = ""
    protocol: str | None = None
    gzipped: bool = False
    hidden: tuple[bytes, ...] = ()
    #: The grant's ``enforcement`` is ``flag``: this request takes the spec 027
    #: path. False is 6.30.1's pass-through, and nothing below the fork runs.
    judges: bool = False

    @property
    def lists_refs(self) -> bool:
        return self.path.endpoint == INFO_REFS


class GitRoute(Route[GitAdmitted, InTree]):
    """``/proxy/git/<remote>/<owner>/<repo>[.git]/<endpoint>``: git smart HTTP to a listed forge."""

    name = "git"
    #: More than git sends: a method git never uses is answered by this route's
    #: own refusal and recorded, not by the server's 405.
    methods = (
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
        "PROPFIND", "MKCOL", "LOCK", "UNLOCK", "MOVE",
    )  # fmt: skip
    auth = Bearer()
    refusals = REFUSALS
    max_request_bytes = MAX_NEGOTIATION_BYTES
    idle = IDLE_TIMEOUT

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> GitAdmitted:
        """Decide everything a request's line and headers can decide.

        In order: the path; the service; ``Git-Protocol``; the repository
        against the profile's lists; and for a ``POST`` the body's declared
        type and encoding. Once the service is known, a refusal carries the
        operation and the repository for the row, and nothing the caller merely
        claimed. Git gzips a fetch negotiation and never a push, so a
        compressed push is refused: what is checked must be what the forge parses.
        """
        path = parse_repo_path(wire.path, wire.raw_path)
        service = _service(wire, path.endpoint)
        tool, destination = OPERATION[service], path.slug
        try:
            protocols = wire.headers.getlist(PROTOCOL_HEADER)
            if len(protocols) > 1 or (protocols and protocols[0] not in PROTOCOLS):
                raise GitRefusedError(HTTPStatus.BAD_REQUEST, "protocol")
            lists: GitGrant = grant.options["git"]
            if (reason := lists.allows(tool, path.owner, path.repo)) is not None:
                raise GitRefusedError(HTTPStatus.FORBIDDEN, reason, Outcome.DENIED_ALLOWLIST)
            encoding = wire.headers.get("content-encoding", "").strip().lower()
            if path.endpoint != INFO_REFS:
                declared = wire.headers.get("content-type", "").partition(";")[0].strip().lower()
                if declared != f"application/x-{service}-request":
                    raise GitRefusedError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "content_type")
                if encoding not in _IDENTITY and (encoding != _GZIP or service == RECEIVE_PACK):
                    raise GitRefusedError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "encoding")
        except RefusedError as refused:
            raise RefusedError(
                refused.reason,
                status=refused.status,
                outcome=refused.outcome,
                tool=tool,
                destination=destination,
            ) from refused
        return GitAdmitted(
            origin=OperatorOrigin(ORIGIN),
            destination=destination,
            tool=tool,
            path=path,
            service=service,
            protocol=protocols[0] if protocols else None,
            gzipped=encoding == _GZIP,
            hidden=tuple(prefix.encode() for prefix in instance.options["hidden_refs"]),
            judges=lists.judges,
        )

    async def deliver(self, admitted: GitAdmitted, ctx: InTree) -> Response:
        """Read the body by git's rules, send it to the forge, relay its answer.

        Everything in the body that is text is decided before a byte goes
        upstream. Only a ``200`` of the expected type carries a body back. A
        forge's ``403`` or ``404`` is passed on as that status alone and
        anything else is ``502``: the forge's own error text is text nothing
        judged, and is never forwarded.
        """
        # TRUST: a git request from an agent, to a forge that holds its code
        #   untrusted: remote, path, query, headers and body, all agent-chosen
        #   judged-by: git_wire (request), GitGrant (repository, branches), egress (address)
        #   on-failure: fail-closed; refused with a closed reason and audited
        #   owner: gateway/git_transport.py, gateway/git_wire.py
        #   evidence: T3 module docstring; T4 URL and headers built here from validated
        #     parts; T3 spec 027: a fetch's objects and names are judged, a push's pack is not
        op = ctx.op
        kind = "advertisement" if admitted.lists_refs else "result"
        answer_type = f"application/x-{admitted.service}-{kind}"
        headers = {"User-Agent": USER_AGENT, "Accept": answer_type}
        if admitted.protocol is not None:
            headers["Git-Protocol"] = admitted.protocol
        content: bytes | AsyncIterator[bytes] | None = None
        negotiation: Negotiation | None = None
        if not admitted.lists_refs:
            headers["Content-Type"] = f"application/x-{admitted.service}-request"
            if op.tool == PUSH:
                content = await _push(ctx.stream(), op, ctx.grant.options["git"])
            else:
                negotiation = await _negotiation(ctx.stream(), admitted)
                content = negotiation.body
        if negotiation is not None and negotiation.wants:
            # A judged fetch waits for its lane before the forge is asked, and
            # gives it back when the operation finishes, however it ends.
            if negotiation.promisor and at_tips(
                ctx.profile.name, admitted.path.slug, negotiation.wants
            ):
                # A filtered clone, not a lazy fetch: what it wants is a ref tip.
                negotiation = replace(negotiation, promisor=False, cold=True)
            lane = await enter_lane(ctx.profile.name, negotiation.promisor)
            op.upstream.callback(lane.release)
        return await self._answer(admitted, ctx, headers, content, negotiation)

    async def _answer(
        self,
        admitted: GitAdmitted,
        ctx: InTree,
        headers: dict[str, str],
        content: bytes | AsyncIterator[bytes] | None,
        negotiation: Negotiation | None,
    ) -> Response:
        """Send the request to the forge and relay its answer, judged."""
        op = ctx.op
        kind = "advertisement" if admitted.lists_refs else "result"
        answer_type = f"application/x-{admitted.service}-{kind}"
        path = admitted.path
        resp = await ctx.open(
            ctx.wire.method,
            f"{path.owner}/{path.repo}.git/{path.endpoint}",
            query=f"service={admitted.service}" if admitted.lists_refs else "",
            headers=headers,
            content=content,
        )
        if isinstance(content, bytes):
            # Counted once the forge has it: a request the guard refused, or one
            # that never connected, delivered nothing. A streamed push counts
            # itself as it is read.
            op.sent = len(content)
        if resp.status_code != _OK:
            passed = resp.status_code in _PASSED_STATUSES
            raise GitRefusedError(
                HTTPStatus(resp.status_code) if passed else HTTPStatus.BAD_GATEWAY,
                "upstream_status",
                Outcome.TOOL_ERROR if passed else Outcome.BACKEND_ERROR,
            )
        if resp.headers.get("content-type", "").partition(";")[0].strip().lower() != answer_type:
            raise GitRefusedError(HTTPStatus.BAD_GATEWAY, "upstream_content", Outcome.BACKEND_ERROR)
        return Relayed(
            _relayed(admitted, ctx, resp, negotiation),
            op,
            media_type=answer_type,
            headers={"Cache-Control": "no-cache"},
            idle=IDLE_TIMEOUT,
        )

    def render(self, refused: RefusedError) -> Response:
        """A status, one closed reason in ``X-Trentina-Reason``, and a line of
        text git shows its user. A guard refusal names the guard's own reason."""
        if refused.reason == "unauthorized":
            return Response(content="unauthorized\n", status_code=401, media_type=PLAIN_TEXT)
        shown = (
            (refused.detail or refused.reason)
            if refused.reason == "denied_guard"
            else refused.reason
        )
        return Response(
            content=f"refused by Trentina: {shown}\n",
            status_code=refused.status or HTTPStatus.FORBIDDEN,
            media_type=PLAIN_TEXT,
            headers={REASON_HEADER: shown},
        )


async def _body(stream: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """The request body a piece at a time, refused when the client goes quiet.

    Raises:
        GitRefusedError: ``idle`` (408) after ``IDLE_TIMEOUT`` with no piece.
    """
    pieces = stream.__aiter__()
    while True:
        try:
            piece = await asyncio.wait_for(anext(pieces), IDLE_TIMEOUT)
        except StopAsyncIteration:
            return
        except TimeoutError:
            raise GitRefusedError(HTTPStatus.REQUEST_TIMEOUT, "idle") from None
        if piece:
            yield piece


@dataclass(frozen=True)
class Negotiation:
    """An upload-pack request as the forge will read it, and what it asks for."""

    body: bytes
    lists_refs: bool
    wants: list[str]
    promisor: bool
    cold: bool = False

    @property
    def object_format(self) -> str:
        """The repository's object format, by the length of the ids it wants."""
        return "sha256" if any(len(oid) == 64 for oid in self.wants) else "sha1"


def _admit_negotiation(arrived: bytes, admitted: GitAdmitted) -> Negotiation:
    """Inflate, strip and check one upload-pack request.

    ``thin-pack``, ``packfile-uris`` and ``sideband-all`` are taken out
    before it is checked (spec 027), so the forge parses exactly the bytes
    that were: a thin pack's bases, a pack fetched from a URI and progress
    outside the pack section would each be content off the judged path. A
    v0 or v1 fetch that did not ask for ``side-band-64k`` is refused: the
    gateway names what it judged on that band. git always asks.

    Runs in a worker thread: eight megabytes of pkt-lines is too long to
    hold the event loop for. A gzip body is inflated to at most
    ``MAX_NEGOTIATION_BYTES`` and must be one whole gzip member.

    Raises:
        GitRefusedError: ``too_large`` (413) past the cap, before the rest is
            inflated; ``malformed`` (400) for a broken gzip body; and as
            ``check_upload_request``.
    """
    body = arrived
    if admitted.gzipped:
        inflater = zlib.decompressobj(wbits=_GZIP_WINDOW)
        try:
            body = inflater.decompress(arrived, MAX_NEGOTIATION_BYTES + 1)
        except zlib.error:
            raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
        if len(body) > MAX_NEGOTIATION_BYTES or inflater.unconsumed_tail:
            raise GitRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
        if not inflater.eof or inflater.unused_data:
            raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
    if not admitted.judges:
        # 6.30.1: the request is checked and forwarded as it came.
        return Negotiation(
            body, check_upload_request(body, admitted.protocol, admitted.hidden), [], False
        )
    try:
        body = strip_fetch_request(body, admitted.protocol)
    except ValueError:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
    lists_refs = check_upload_request(body, admitted.protocol, admitted.hidden)
    try:
        wanted = [] if lists_refs else wants(body, admitted.protocol)
    except ValueError:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
    if wanted and not negotiated_sideband(body, admitted.protocol):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "sideband")
    promisor = bool(wanted) and is_promisor_fetch(body, admitted.protocol)
    cold = not promisor and bool(wanted) and is_cold_fetch(body, admitted.protocol)
    return Negotiation(body, lists_refs, wanted, promisor, cold)


async def _negotiation(stream: AsyncIterator[bytes], admitted: GitAdmitted) -> Negotiation:
    """An upload-pack request, read whole, stripped and checked.

    The body goes upstream inflated, so the forge parses the bytes that were
    checked and not a second reading of a compressed stream.

    Raises:
        GitRefusedError: as ``_body`` and ``_admit_negotiation``;
            ``too_large`` (413) past the cap.
    """
    buffer = bytearray()
    async for piece in _body(stream):
        buffer += piece
        if len(buffer) > MAX_NEGOTIATION_BYTES:
            raise GitRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
    arrived = bytes(buffer)
    buffer.clear()  # one copy of the body from here on, and its inflation
    return await asyncio.to_thread(_admit_negotiation, arrived, admitted)


async def _command_list(pieces: AsyncIterator[bytes]) -> tuple[list[Command], bytes]:
    """Read a push's commands, up to the flush that ends them.

    Returns:
        The commands, and every byte read so far, to be sent on unchanged
        ahead of the rest of the body. Whatever followed the flush in the
        last piece read is the start of the pack and is in those bytes,
        unparsed.

    Raises:
        GitRefusedError: ``malformed`` (400) when the body is not a command
            list or ends before its flush; ``too_large`` (413) past
            ``MAX_COMMAND_BYTES`` or ``MAX_COMMANDS``.
    """
    reader = PktReader()
    commands: list[Command] = []
    read = bytearray()
    try:
        async for piece in pieces:
            reader.feed(piece)
            read += piece
            while (taken := reader.take()) is not None:
                payload = taken[1]
                if isinstance(payload, int):
                    if payload == FLUSH:
                        return commands, bytes(read)
                    raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
                if (command := parse_command(payload)) is not None:
                    commands.append(command)
                parsed = len(read) - reader.pending
                if parsed > MAX_COMMAND_BYTES or len(commands) > MAX_COMMANDS:
                    raise GitRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
    except ValueError:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
    raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")


async def _counted(op: Operation, head: bytes, rest: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """A push's body for upstream: what was read to decide it, then the rest
    as it arrives, counted. Nothing here looks at the pack."""
    op.sent += len(head)
    yield head
    async for piece in rest:
        op.sent += len(piece)
        yield piece


async def _push(
    stream: AsyncIterator[bytes], op: Operation, grant: GitGrant
) -> bytes | AsyncIterator[bytes]:
    """Decide a push by its command list, before any of it is forwarded.

    A push with no command is git's probe before a large one: a lone flush,
    forwarded as that and nothing more.

    Raises:
        GitRefusedError: as ``_command_list``; ``delete`` or ``tag`` (403, a
            guard); ``ref_not_listed`` (403, the profile's allowlist when the
            ref is a branch); ``malformed`` when bytes follow an empty
            command list.
    """
    pieces = _body(stream)
    commands, head = await _command_list(pieces)
    refs = " ".join(command.ref for command in commands)
    op.destination = f"{op.destination} {refs}".rstrip()[:MAX_DESTINATION_CHARS]
    for command in commands:
        if (reason := refuse_ref_update(command)) is not None:
            raise GitRefusedError(HTTPStatus.FORBIDDEN, reason)
        if not grant.may_move(command.ref):
            raise GitRefusedError(HTTPStatus.FORBIDDEN, "ref_not_listed", Outcome.DENIED_ALLOWLIST)
    if commands:
        return _counted(op, head, pieces)
    # The first byte after the flush is enough to refuse it: nothing more is read.
    if len(head) != len(b"0000") or await anext(pieces, None) is not None:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
    return head


async def _relayed(
    admitted: GitAdmitted,
    ctx: InTree,
    resp: Any,
    negotiation: Negotiation | None,
) -> AsyncIterator[bytes]:
    """The forge's answer for the client, by what was asked (spec 027).

    A ref listing (``info/refs``, or an ``ls-refs`` answer) is buffered,
    rewritten and its names judged; a fetch's pack is judged as it streams;
    a push's report has the forge's words replaced.
    """
    if not admitted.judges:
        listing = None
        if admitted.lists_refs or (negotiation is not None and negotiation.lists_refs):
            listing = RefFilter(admitted.hidden)
        async for piece in _relay(ctx, resp, listing):
            yield piece
        return
    grant: GitGrant = ctx.grant.options["git"]
    source = f"git:{ctx.op.backend.removeprefix('git:')}/{admitted.path.slug}"
    if admitted.lists_refs or (negotiation is not None and negotiation.lists_refs):
        relayed = relay_listing(
            ctx,
            resp,
            protocol=admitted.protocol,
            hidden=admitted.hidden,
            profile=ctx.profile,
            grant=grant,
            source=source,
            slug=admitted.path.slug,
        )
    elif admitted.tool == PUSH or negotiation is None:
        relayed = relay_push(ctx, resp)
    else:
        fetch = Fetch(
            profile=ctx.profile,
            grant=grant,
            source=source,
            slug=admitted.path.slug,
            v2=admitted.protocol == PROTOCOL_V2,
            wants=negotiation.wants,
            object_format=negotiation.object_format,
            cold=negotiation.cold,
        )
        relayed = relay_fetch(ctx, resp, fetch)
    async for piece in relayed:
        yield piece


async def _relay(ctx: InTree, resp: Any, listing: RefFilter | None) -> AsyncIterator[bytes]:
    """The forge's answer for the client, counted as it passes (``enforcement: none``).

    A ref listing goes through ``listing``, which drops hidden refs. Anything
    else is passed on unread: it is a pack, or the side-band stream one
    travels in. A stream that fails part-way simply ends, and git reads a
    truncated listing or pack as the error it is.
    """
    op = ctx.op
    try:
        async for piece in ctx.chunks(resp):
            op.received += len(piece)
            passed = listing.feed(piece) if listing is not None else piece
            if passed:
                yield passed
        if listing is not None:
            listing.finish()
        op.settle(Outcome.OK)
    except ValueError:
        logger.warning("git transport: a ref listing could not be filtered; ended it")
        op.settle(Outcome.BLOCKED_DEFENSE, "advertisement")
    except RefusedError as failed:
        logger.warning("git transport: upstream %s mid-stream", failed.reason)
        op.settle(Outcome.BACKEND_ERROR, failed.reason)
