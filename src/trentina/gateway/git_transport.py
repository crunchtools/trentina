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
  default) are dropped from ref advertisements and ``ls-refs`` answers.

What it does not decide is anything inside a pack. The gateway terminates
this connection, so that is a choice and not a limit: a pack is compressed
objects, and no layer reads it in either direction. Nor is a ``want`` for an
object id restricted. That is known gap 29 in ``docs/defense-pipeline.md``.

One ``gateway_calls`` row per request, written when it ends or is refused.
"""

from __future__ import annotations

import asyncio
import logging
import zlib
from base64 import b64encode
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import httpx
from starlette.requests import ClientDisconnect
from starlette.responses import Response

from .. import logsafe
from ..errors import EgressRefusedError
from ..outcomes import Outcome
from .auth import resolve_profile_by_token
from .destination import MAX_DESTINATION_CHARS, DestinationKind
from .git_wire import (
    FLUSH,
    INFO_REFS,
    OPERATION,
    PROTOCOL_HEADER,
    PROTOCOLS,
    PUSH,
    RECEIVE_PACK,
    SERVICES,
    Command,
    GitRefusedError,
    PktReader,
    RefFilter,
    RepoPath,
    check_upload_request,
    parse_command,
    parse_repo_path,
    refuse_ref_update,
)
from .loader import get_active_config
from .proxy_utils import PLAIN_TEXT
from .relay import MAX_OPERATIONS_PER_PROFILE, Operation, Relayed, Slots
from .upstream import RESOLVER_BUSY, pinned_send

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

    from .profile import GitGrant, GitRemote, Profile

logger = logging.getLogger(__name__)

ROUTE = "/proxy/git/{remote}/{path:path}"
METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "PROPFIND",
    "MKCOL",
    "LOCK",
    "UNLOCK",
    "MOVE",
]
"""Every method the route takes, so that it is this module that refuses one
and writes the row. Only ``GET`` and ``POST`` are ever carried; the rest are
what a "dumb" HTTP push would send."""
BACKEND = "git"

USER_AGENT = "git/trentina"
REASON_HEADER = "X-Trentina-Reason"

IDLE_TIMEOUT = 300.0
"""Seconds any one read or write may take, on either side. There is no limit
on a whole clone or push: a large repository over a slow link is served for
as long as bytes keep moving. A forge that is still counting objects sends
keep-alives well inside this."""

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

_SLOTS = Slots(MAX_OPERATIONS_PER_PROFILE)


@dataclass(frozen=True)
class _Admitted:
    """A request whose line and headers passed every rule that reads them."""

    remote: GitRemote
    grant: GitGrant
    path: RepoPath
    service: str
    protocol: str | None
    gzipped: bool

    @property
    def lists_refs(self) -> bool:
        return self.path.endpoint == INFO_REFS

    @property
    def hidden(self) -> tuple[bytes, ...]:
        return tuple(prefix.encode() for prefix in self.remote.hidden_refs)


def register_git_routes(
    mcp_server: Any, remotes: dict[str, GitRemote], profiles: dict[str, Profile]
) -> None:
    """Wire ``/proxy/git/{remote}/{path}`` onto the FastMCP server, if there is a remote.

    With no ``git_remotes`` at startup there is no route. ``profiles`` is the
    live registry a reload refills in place, and the remotes are read from
    the active config on every request, so once the route exists an operator
    reload applies an edit to ``git_remotes`` as it does one to a profile's
    ``git``.
    """
    if not remotes:
        return

    async def git_endpoint(request: Request) -> Response:
        return await serve(request, profiles)

    mcp_server.custom_route(ROUTE, methods=METHODS)(git_endpoint)
    logger.info("git transport: registered /proxy/git/{remote}/{owner}/{repo}")


async def serve(request: Request, profiles: dict[str, Profile]) -> Response:
    """Answer one git request: resolve the caller, then carry it or refuse it.

    A token that matches no profile gets ``401`` and no audit row. A row
    belongs to a profile, and writing one for a caller nobody knows would let
    anyone who can reach the port fill the audit database.

    A refusal is a status, one closed reason code in ``X-Trentina-Reason``,
    and a line of text git shows its user.
    """
    # TRUST: the bearer token picks the profile, as on /llm
    #   untrusted: every header, the path, the query and the body
    #   judged-by: resolve_profile_by_token (constant-time, every profile)
    #   on-failure: fail-closed; 401 before the remote or path is looked at,
    #     so an unknown caller learns nothing about what is configured
    #   owner: git_transport.serve
    #   evidence: T3 gateway/auth.py; T4 tests/test_git_transport.py
    profile = resolve_profile_by_token(request.headers.get("authorization"), profiles)
    if profile is None:
        logger.warning("git transport: refused a caller whose token matches no profile")
        return Response(content="unauthorized\n", status_code=401, media_type=PLAIN_TEXT)
    op = Operation(profile, backend=BACKEND, destination_kind=DestinationKind.GIT)
    try:
        return await _carry(request, op)
    except GitRefusedError as refusal:
        op.settle(refusal.outcome, refusal.reason)
        logger.info("git transport: refused profile=%s reason=%s", profile.name, refusal.reason)
        await op.finish()
        return Response(
            content=f"refused by Trentina: {refusal.reason}\n",
            status_code=refusal.status,
            media_type=PLAIN_TEXT,
            headers={REASON_HEADER: refusal.reason},
        )
    except (ClientDisconnect, asyncio.CancelledError):
        await op.finish()
        raise
    except Exception as exc:
        logger.error(
            "git transport: failed profile=%s err=%s at %s",
            profile.name,
            logsafe.exc_kind(exc),
            logsafe.exc_where(exc),
        )
        op.settle(Outcome.GATEWAY_ERROR)
        await op.finish()
        raise


def _service(request: Request, endpoint: str) -> str:
    """The service one request is for, by its endpoint, method and query.

    ``info/refs`` is a ``GET`` whose query is exactly ``service=`` and one of
    the two services: without it the forge would answer in the "dumb"
    protocol, a file server over the repository. The other two endpoints are
    a ``POST`` with no query at all.

    Raises:
        GitRefusedError: ``method`` (405) or ``service`` (400).
    """
    wanted = "GET" if endpoint == INFO_REFS else "POST"
    if request.method != wanted:
        raise GitRefusedError(HTTPStatus.METHOD_NOT_ALLOWED, "method")
    query = request.url.query
    if endpoint != INFO_REFS:
        if query:
            raise GitRefusedError(HTTPStatus.BAD_REQUEST, "service")
        return endpoint
    service = query.removeprefix("service=")
    if query != f"service={service}" or service not in SERVICES:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "service")
    return service


def _admit(request: Request, op: Operation) -> _Admitted:
    """Decide everything a request's line and headers can decide.

    In order: the remote and this profile's grant on it; the path; the
    service; ``Git-Protocol``; the repository against the profile's lists;
    and for a ``POST`` the body's declared type and encoding. ``op`` learns
    the backend, the tool and the destination as each is validated, so a
    refusal's audit row carries what was known and nothing the caller merely
    claimed.

    A remote that is not configured and one this profile has no grant for
    are one refusal, so a caller cannot list the remotes other profiles use.
    Git gzips a fetch negotiation and never a push, so a compressed push is
    refused: what is checked must be what the forge parses.

    Raises:
        GitRefusedError: ``remote``, ``repo_denied`` or ``repo_not_listed``
            (403, the profile's allowlist); ``name``, ``path``, ``method``,
            ``service``, ``protocol``, ``content_type`` or ``encoding``.
    """
    name = request.path_params.get("remote", "")
    active = get_active_config()
    remote = active.config.git_remotes.get(name) if active is not None else None
    grant = op.profile.git.get(name)
    if remote is None or grant is None or grant.token is None:
        raise GitRefusedError(HTTPStatus.FORBIDDEN, "remote", Outcome.DENIED_ALLOWLIST)
    op.backend = f"{BACKEND}:{name}"

    path = parse_repo_path(request.path_params.get("path", ""), request.scope.get("raw_path", b""))
    service = _service(request, path.endpoint)
    op.tool, op.destination = OPERATION[service], path.slug

    protocols = request.headers.getlist(PROTOCOL_HEADER)
    if len(protocols) > 1 or (protocols and protocols[0] not in PROTOCOLS):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "protocol")
    if (reason := grant.allows(OPERATION[service], path.owner, path.repo)) is not None:
        raise GitRefusedError(HTTPStatus.FORBIDDEN, reason, Outcome.DENIED_ALLOWLIST)

    encoding = request.headers.get("content-encoding", "").strip().lower()
    if path.endpoint != INFO_REFS:
        declared = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if declared != f"application/x-{service}-request":
            raise GitRefusedError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "content_type")
        if encoding not in _IDENTITY and (encoding != _GZIP or service == RECEIVE_PACK):
            raise GitRefusedError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "encoding")
    return _Admitted(
        remote, grant, path, service, protocols[0] if protocols else None, encoding == _GZIP
    )


async def _body(request: Request) -> AsyncIterator[bytes]:
    """The request body a piece at a time, refused when the client goes quiet.

    Raises:
        GitRefusedError: ``idle`` (408) after ``IDLE_TIMEOUT`` with no piece.
    """
    pieces = request.stream().__aiter__()
    while True:
        try:
            piece = await asyncio.wait_for(anext(pieces), IDLE_TIMEOUT)
        except StopAsyncIteration:
            return
        except TimeoutError:
            raise GitRefusedError(HTTPStatus.REQUEST_TIMEOUT, "idle") from None
        if piece:
            yield piece


def _admit_negotiation(arrived: bytes, admitted: _Admitted) -> tuple[bytes, bool]:
    """Inflate and check one upload-pack request; True when it is an ``ls-refs``.

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
    return body, check_upload_request(body, admitted.protocol, admitted.hidden)


async def _negotiation(request: Request, admitted: _Admitted) -> tuple[bytes, RefFilter | None]:
    """An upload-pack request, read whole and checked; and the filter its
    answer needs when it is an ``ls-refs``.

    The body goes upstream inflated, so the forge parses the bytes that were
    checked and not a second reading of a compressed stream.

    Raises:
        GitRefusedError: as ``_body`` and ``_admit_negotiation``;
            ``too_large`` (413) past the cap.
    """
    buffer = bytearray()
    async for piece in _body(request):
        buffer += piece
        if len(buffer) > MAX_NEGOTIATION_BYTES:
            raise GitRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
    arrived = bytes(buffer)
    buffer.clear()  # one copy of the body from here on, and its inflation
    body, lists_refs = await asyncio.to_thread(_admit_negotiation, arrived, admitted)
    return body, RefFilter(admitted.hidden) if lists_refs else None


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


async def _push(request: Request, op: Operation, grant: GitGrant) -> bytes | AsyncIterator[bytes]:
    """Decide a push by its command list, before any of it is forwarded.

    A push with no command is git's probe before a large one: a lone flush,
    forwarded as that and nothing more.

    Raises:
        GitRefusedError: as ``_command_list``; ``delete`` or ``tag`` (403, a
            guard); ``ref_not_listed`` (403, the profile's allowlist when the
            ref is a branch); ``malformed`` when bytes follow an empty
            command list.
    """
    pieces = _body(request)
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


async def _send(
    op: Operation,
    admitted: _Admitted,
    method: str,
    headers: dict[str, str],
    content: bytes | AsyncIterator[bytes] | None,
) -> httpx.Response:
    """Send one request upstream through the egress guard, pinned to a checked address.

    The URL is built here, from the operator's origin and the validated,
    lower-cased owner and name. The response stays open on ``op.upstream``
    until the operation finishes.

    The guard's ``resolver_busy`` is the gateway's load, as on the tunnel,
    and ``redirect`` is this route's own rule kept by the guard; any other
    refusal of its is a verdict on the upstream: an address that is not
    global, a name that does not resolve, an answer that arrived encoded.

    Raises:
        GitRefusedError: the guard refused the upstream or its answer, the
            forge did not answer in time (504) or the connection failed (502).
    """
    path = admitted.path
    url = f"{admitted.remote.upstream}/{path.owner}/{path.repo}.git/{path.endpoint}"
    if admitted.lists_refs:
        url = f"{url}?service={admitted.service}"
    try:
        return await op.upstream.enter_async_context(
            pinned_send(
                op.profile, method, url, idle=IDLE_TIMEOUT, headers=headers, content=content
            )
        )
    except EgressRefusedError as exc:
        if exc.reason == RESOLVER_BUSY:
            raise GitRefusedError(HTTPStatus.SERVICE_UNAVAILABLE, exc.reason) from None
        if exc.reason == "redirect":
            raise GitRefusedError(HTTPStatus.BAD_GATEWAY, exc.reason) from None
        raise GitRefusedError(HTTPStatus.FORBIDDEN, exc.reason, Outcome.BLOCKED_DEFENSE) from None
    except httpx.TimeoutException:
        raise GitRefusedError(
            HTTPStatus.GATEWAY_TIMEOUT, "upstream_idle", Outcome.BACKEND_ERROR
        ) from None
    except httpx.HTTPError as exc:
        logger.warning("git transport: upstream failed err=%s", logsafe.exc_kind(exc))
        raise GitRefusedError(
            HTTPStatus.BAD_GATEWAY, "upstream_failed", Outcome.BACKEND_ERROR
        ) from None


async def _relay(
    op: Operation, resp: httpx.Response, listing: RefFilter | None
) -> AsyncIterator[bytes]:
    """The forge's answer for the client, counted as it passes.

    A ref listing goes through ``listing``, which drops hidden refs. Anything
    else is passed on unread: it is a pack, or the side-band stream one
    travels in (known gap 29). A stream that fails part-way simply ends, and
    git reads a truncated listing or pack as the error it is.
    """
    try:
        async for piece in resp.aiter_raw():
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
    except httpx.TimeoutException as exc:
        logger.warning("git transport: upstream idle mid-stream err=%s", logsafe.exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR, "upstream_idle")
    except httpx.HTTPError as exc:
        logger.warning("git transport: upstream failed mid-stream err=%s", logsafe.exc_kind(exc))
        op.settle(Outcome.BACKEND_ERROR, "upstream_failed")


async def _carry(request: Request, op: Operation) -> Response:
    """Admit one request, send it upstream and hand back its streamed answer.

    Everything the request line and headers can decide is decided before a
    slot is taken, and everything in the body that is text is decided before
    a byte goes upstream. Only a ``200`` of the expected type carries a body
    back. A forge's ``403`` or ``404`` is passed on as that status alone and
    anything else is ``502``: the forge's own error text is text nothing
    judged, and is never forwarded.

    Raises:
        GitRefusedError: any rule in this module's docstring refused it.
    """
    # TRUST: a git request from an agent, to a forge that holds its code
    #   untrusted: remote, path, query, headers and body, all agent-chosen
    #   judged-by: git_wire (path, service, protocol, command list, ref
    #     requests), GitGrant (repository and branch lists), egress (address)
    #   on-failure: fail-closed; refused with a closed reason and audited
    #   owner: gateway/git_transport.py, gateway/git_wire.py
    #   evidence: T3 this module's docstring; T4 _send builds the URL and this
    #     function every header; T3 known gap 29: a pack is not judged
    admitted = _admit(request, op)
    if not op.take_slot(_SLOTS):
        raise GitRefusedError(HTTPStatus.SERVICE_UNAVAILABLE, "busy")

    kind = "advertisement" if admitted.lists_refs else "result"
    answer_type = f"application/x-{admitted.service}-{kind}"
    token = admitted.grant.token.get_secret_value() if admitted.grant.token is not None else ""
    credential = b64encode(f"{admitted.remote.username}:{token}".encode()).decode("ascii")
    # The token in the form it is sent in is a secret too.
    logsafe.hold(credential, admitted.grant.token_env)
    headers = {
        "Authorization": f"Basic {credential}",
        "User-Agent": USER_AGENT,
        "Accept": answer_type,
    }
    if admitted.protocol is not None:
        headers["Git-Protocol"] = admitted.protocol
    content: bytes | AsyncIterator[bytes] | None = None
    listing = RefFilter(admitted.hidden) if admitted.lists_refs else None
    if not admitted.lists_refs:
        headers["Content-Type"] = f"application/x-{admitted.service}-request"
        if op.tool == PUSH:
            content = await _push(request, op, admitted.grant)
        else:
            content, listing = await _negotiation(request, admitted)

    resp = await _send(op, admitted, request.method, headers, content)
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
        _relay(op, resp, listing),
        op,
        media_type=answer_type,
        headers={"Cache-Control": "no-cache"},
        idle=IDLE_TIMEOUT,
    )
