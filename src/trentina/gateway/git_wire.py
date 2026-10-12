"""Git's smart-HTTP wire format, as far as the gateway reads it (#453).

The git transport terminates the client's HTTP, so everything on the wire
that is deterministic text is something it can read, and what it can read it
owes a verdict on. This module is that reading, with no I/O in it:

- the request path: an owner, a repository and one of three endpoints;
- pkt-lines, the framing every smart-HTTP body opens with;
- a push's command list, which precedes its pack;
- an upload-pack request (a v2 command, or v0 wants and haves);
- a ref advertisement or an ``ls-refs`` answer, with hidden refs dropped.

What it does not read is a pack, in either direction, or the side-band
stream a pack travels in. That is known gap 29.

Every refusal is a ``GitRefusedError`` carrying a status, a reason from
``REASONS`` and an outcome. No reason quotes the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Literal

from ..outcomes import Outcome

if TYPE_CHECKING:
    from collections.abc import Iterator

UPLOAD_PACK = "git-upload-pack"
RECEIVE_PACK = "git-receive-pack"
INFO_REFS = "info/refs"
SERVICES = (UPLOAD_PACK, RECEIVE_PACK)

FETCH: Literal["fetch"] = "fetch"
PUSH: Literal["push"] = "push"
OPERATION: dict[str, Literal["fetch", "push"]] = {UPLOAD_PACK: FETCH, RECEIVE_PACK: PUSH}

PROTOCOL_HEADER = "git-protocol"
PROTOCOL_V2 = "version=2"
PROTOCOLS = frozenset({"version=1", PROTOCOL_V2})
"""Every ``Git-Protocol`` value forwarded. Absent is protocol v0."""

PKT_MAX = 65520
"""Longest pkt-line, its four-byte length included (gitprotocol-common)."""

MAX_LISTED_REF = 255
"""Longest ref name passed on in a listing, in bytes. A name is delivered
unjudged, so it is held to one short token."""

MAX_REQUEST_PACKETS = 200_000
"""Most pkt-lines in one upload-pack request. A ``have`` line is 50 bytes,
so the transport's 8 MiB cap is about 160,000 of them; without a count, the
same 8 MiB of four-byte packets is two million to walk."""

FLUSH, DELIMITER, RESPONSE_END = 0, 1, 2
_PKT_HEADER = 4
_HEX = frozenset(b"0123456789abcdefABCDEF")
_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_OID_RE = re.compile(rb"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_GIT_SUFFIX = ".git"
_BRANCHES = "refs/heads/"
_TAGS = "refs/tags/"
_REFUSED_PUSH_CAPABILITY = "push-options"
_V2_COMMANDS = frozenset({b"ls-refs", b"fetch"})
_REF_ARGUMENTS = frozenset({b"ref-prefix", b"want-ref"})

REASONS = frozenset(
    {
        "remote",
        "name",
        "path",
        "method",
        "service",
        "protocol",
        "content_type",
        "encoding",
        "repo_denied",
        "repo_not_listed",
        "busy",
        "idle",
        "malformed",
        "too_large",
        "command",
        "hidden_ref",
        "ref_not_listed",
        "tag",
        "delete",
        "push_options",
        "redirect",
        "upstream_status",
        "upstream_content",
        "upstream_failed",
        "upstream_idle",
        "advertisement",
    }
)
"""Every ``error_message`` the git transport writes besides the egress
guard's own reason codes. Closed, so the audit never carries the caller's
text there."""


class GitRefusedError(Exception):
    """A git request the gateway will not carry, or will not finish carrying.

    Most refusals are one of this route's own deterministic rules, so the
    outcome defaults to ``denied_guard``. A refusal by the profile's lists,
    by the egress guard or of the forge's answer says so.
    """

    def __init__(
        self, status: HTTPStatus, reason: str, outcome: Outcome = Outcome.DENIED_GUARD
    ) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.outcome = outcome


@dataclass(frozen=True)
class RepoPath:
    """A request path, parsed: lower-case owner and name, and the endpoint."""

    owner: str
    repo: str
    endpoint: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_repo_path(path: str, raw_path: bytes) -> RepoPath:
    """The repository and endpoint ``path`` names, or a refusal.

    The path is ``<owner>/<repo>[.git]/`` and then exactly ``info/refs``,
    ``git-upload-pack`` or ``git-receive-pack``. Owner and name are
    ``[A-Za-z0-9_.-]+`` with no ``..``, and are returned lower-case, the name
    without ``.git``: what is matched against the profile's lists is what the
    upstream URL is built from.

    Args:
        path: the part of the URL path after the remote, percent-decoded as
            the server hands it over.
        raw_path: the whole request path as it arrived. A ``%`` anywhere in
            it is refused: no valid owner, name or endpoint needs encoding,
            so an encoded slash or dot is an attempt to be read two ways.

    Raises:
        GitRefusedError: ``name`` (400) or ``path`` (404).
    """
    if b"%" in raw_path:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "name")
    owner, slash, rest = path.partition("/")
    repo, slash2, endpoint = rest.partition("/")
    if not slash or not slash2 or endpoint not in (INFO_REFS, *SERVICES):
        raise GitRefusedError(HTTPStatus.NOT_FOUND, "path")
    if ".." in path:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "name")
    owner, repo = owner.lower(), repo.lower().removesuffix(_GIT_SUFFIX)
    for name in (owner, repo):
        if not _NAME_RE.fullmatch(name) or name == ".":
            raise GitRefusedError(HTTPStatus.BAD_REQUEST, "name")
    return RepoPath(owner, repo, endpoint)


def _packet_at(held: bytes | bytearray, start: int) -> tuple[bytes, bytes | int] | None:
    """The pkt-line that starts at ``start`` in ``held``, or None when it is
    not all there yet: its bytes on the wire, and its payload (or which
    special packet it is). Reads in place; ``held`` is never copied.

    Raises:
        ValueError: the four bytes at ``start`` are not a pkt-line length.
    """
    if len(held) - start < _PKT_HEADER:
        return None
    header = bytes(held[start : start + _PKT_HEADER])
    if not _HEX.issuperset(header):
        raise ValueError("pkt-line length is not four hex digits")
    length = int(header, 16)
    if length < _PKT_HEADER:
        if length > RESPONSE_END:
            raise ValueError("pkt-line length 3 means nothing")
        return header, length
    if length > PKT_MAX:
        raise ValueError("pkt-line longer than the protocol allows")
    if len(held) - start < length:
        return None
    wire = bytes(held[start : start + length])
    return wire, wire[_PKT_HEADER:]


class PktReader:
    """Pkt-lines out of bytes that arrive in pieces.

    Holds the bytes it was fed and has not yet returned, so a caller that
    takes every whole pkt-line after each ``feed`` holds under ``PKT_MAX``
    plus one piece. Taking a line moves an offset; what was taken is dropped
    at the next ``feed``, so reading a body is linear in its size however
    short its lines are.
    """

    def __init__(self) -> None:
        self._held = bytearray()
        self._at = 0

    def feed(self, arrived: bytes) -> None:
        """Add ``arrived`` to what is held, after dropping every byte ``take``
        has already returned. Part of a pkt-line stays held until a later
        ``feed`` completes it."""
        del self._held[: self._at]
        self._at = 0
        self._held += arrived

    def take(self) -> tuple[bytes, bytes | int] | None:
        """The next whole pkt-line, or None until more bytes arrive.

        Returns:
            Its bytes as they were on the wire, and what it is: the payload
            of a data pkt-line, or ``FLUSH``, ``DELIMITER`` or
            ``RESPONSE_END`` for one of the three special packets.

        Raises:
            ValueError: the next four bytes are not a pkt-line length.
        """
        taken = _packet_at(self._held, self._at)
        if taken is not None:
            self._at += len(taken[0])
        return taken

    @property
    def pending(self) -> int:
        """Bytes fed and not yet returned: part of a pkt-line, or what follows one."""
        return len(self._held) - self._at


def pkt_lines(body: bytes) -> Iterator[bytes | int]:
    """Each pkt-line in ``body``, which must be pkt-lines from end to end.
    Read in place: a body of megabytes is not copied to be walked.

    Raises:
        ValueError: a bad length, or bytes left over that are not a whole pkt-line.
    """
    start = 0
    while (taken := _packet_at(body, start)) is not None:
        start += len(taken[0])
        yield taken[1]
    if start != len(body):
        raise ValueError("bytes after the last whole pkt-line")


@dataclass(frozen=True)
class Command:
    """One ref update a push asks for."""

    old: bytes
    new: bytes
    ref: str

    @property
    def deletes(self) -> bool:
        return not self.new.strip(b"0")


def parse_command(payload: bytes) -> Command | None:
    """One pkt-line of a push's command list, or None for a ``shallow`` line.

    A command is ``<old-oid> <new-oid> <refname>``; the first also carries
    the client's capabilities after a NUL. A client pushing from a shallow
    clone sends ``shallow <oid>`` lines first, which update nothing.

    Raises:
        GitRefusedError: ``malformed`` for anything else, a signed-push
            certificate included; ``push_options`` when the capabilities ask
            for push options, which are instructions to the forge that
            follow the command list and that no rule here reads.
    """
    line, _nul, capabilities = payload.removesuffix(b"\n").partition(b"\0")
    fields = line.split(b" ")
    if fields[0] == b"shallow" and len(fields) == 2 and _OID_RE.fullmatch(fields[1]):
        return None
    if len(fields) != 3 or not all(_OID_RE.fullmatch(oid) for oid in fields[:2]):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
    try:
        ref = fields[2].decode("utf-8")
    except UnicodeDecodeError:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
    if not ref.isprintable() or len(fields[0]) != len(fields[1]):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
    if _REFUSED_PUSH_CAPABILITY in capabilities.decode("utf-8", "replace").split(" "):
        raise GitRefusedError(HTTPStatus.FORBIDDEN, "push_options")
    return Command(fields[0], fields[1], ref)


def refuse_ref_update(command: Command) -> str | None:
    """Why a command is refused whatever the profile lists, or None.

    Returns:
        ``delete`` for an all-zero new object id, ``tag`` for anything under
        ``refs/tags/``, ``ref_not_listed`` for anything else that is not a
        branch. A branch is left for the profile's ``push_refs`` to decide.
    """
    if command.deletes:
        return "delete"
    if command.ref.startswith(_TAGS):
        return "tag"
    return None if command.ref.startswith(_BRANCHES) else "ref_not_listed"


def _names_hidden(name: bytes, hidden: tuple[bytes, ...]) -> bool:
    """True when ``name`` is a hidden namespace or anything under one:
    ``refs/pull`` and ``refs/pull/7/head``, and not ``refs/pulled/x``."""
    return any(name == prefix.removesuffix(b"/") or name.startswith(prefix) for prefix in hidden)


def check_upload_request(body: bytes, protocol: str | None, hidden: tuple[bytes, ...]) -> bool:
    """Admit one whole upload-pack request body; True when it is an ``ls-refs``.

    Under protocol v2 the body is one command, ``ls-refs`` or ``fetch``,
    ending at its flush: a second command behind the first would be answered
    by a forge that reads on, with a listing nothing filtered. Otherwise the
    body is v0 wants and haves and must not open with a command. Either way
    it is pkt-lines from end to end, and it may not ask for a hidden
    namespace by name: a ``ref-prefix`` or a ``want-ref`` that starts with
    one is refused. A ``want`` names an object id, not a ref, and is not
    restricted here.

    Args:
        body: the request body, already inflated.
        protocol: the request's ``Git-Protocol`` value, or None.
        hidden: the remote's hidden ref prefixes.

    Raises:
        GitRefusedError: ``malformed``, ``protocol``, ``command``,
            ``hidden_ref``, or ``too_large`` past ``MAX_REQUEST_PACKETS``.
    """
    v2 = protocol == PROTOCOL_V2
    command: bytes | None = None
    commands = flushes = 0
    last: bytes | int = DELIMITER
    try:
        # One pass and no list, however many packets there are.
        for index, packet in enumerate(pkt_lines(body)):
            last = packet
            if index >= MAX_REQUEST_PACKETS:
                raise GitRefusedError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large")
            if isinstance(packet, int):
                flushes += packet == FLUSH
                continue
            line = packet.removesuffix(b"\n")
            if line.startswith(b"command="):
                commands += 1
                command = line.removeprefix(b"command=") if index == 0 else command
            verb, _space, argument = line.partition(b" ")
            if verb in _REF_ARGUMENTS and _names_hidden(argument, hidden):
                raise GitRefusedError(HTTPStatus.FORBIDDEN, "hidden_ref")
    except ValueError:
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed") from None
    if v2 != (command is not None) or (commands and not v2):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "protocol")
    if v2 and (commands > 1 or command not in _V2_COMMANDS):
        raise GitRefusedError(HTTPStatus.FORBIDDEN, "command")
    if v2 and (flushes != 1 or last != FLUSH):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "malformed")
    return command == b"ls-refs"


class RefFilter:
    """Drops refs that are not to be listed from a ref listing as it streams past.

    A v0 advertisement line is ``<oid> <refname>``, the first with the
    server's capabilities after a NUL; an ``ls-refs`` line is ``<oid>
    <refname>`` and then attributes. In both the name is the second field,
    so one rule reads both. A line is not passed on when its name starts
    with a hidden prefix, or when it is a ref whose name is not one token an
    agent can be handed unjudged: over ``MAX_LISTED_REF`` bytes, or holding
    anything but printable ASCII. Everything else is passed on, byte for byte.

    A ref name is text someone with push access chose, and no layer judges
    it. What bounds it is git's own grammar (no space, no control character)
    and this length, the same single-token rule the Matrix proxy applies to
    identifiers it keeps from a response nothing judged. A name can still be
    words joined by hyphens. That is part of known gap 29.

    Dropping a hidden ref removes its name. It does not stop a client that
    already knows an object id from asking for it.
    """

    def __init__(self, hidden: tuple[bytes, ...]) -> None:
        self._reader = PktReader()
        self._hidden = hidden
        self._ended_on_flush = False
        self.dropped = 0

    def feed(self, arrived: bytes) -> bytes:
        """The bytes to pass on for ``arrived``: whole pkt-lines, hidden ones left out.

        Raises:
            ValueError: the stream is not pkt-lines; the hidden ref is the
                line that carries the server's capabilities, which cannot be
                dropped without rewriting the listing; or a line that is
                kept names a hidden ref as a symref's target.
        """
        self._reader.feed(arrived)
        passed = bytearray()
        while (taken := self._reader.take()) is not None:
            wire, payload = taken
            self._ended_on_flush = payload == FLUSH and isinstance(payload, int)
            if isinstance(payload, bytes) and self._lists_hidden(payload):
                self.dropped += 1
                continue
            passed += wire
        return bytes(passed)

    def _lists_hidden(self, payload: bytes) -> bool:
        fields = payload.split(b" ", 2)
        if len(fields) < 2:
            return False
        name, nul, _capabilities = fields[1].partition(b"\0")
        name = name.removesuffix(b"\n")
        unlistable = (
            len(name) > MAX_LISTED_REF or not name.isascii() or not name.decode().isprintable()
        )
        if any(name.startswith(prefix) for prefix in self._hidden) or (
            unlistable and _OID_RE.fullmatch(fields[0])
        ):
            if nul:
                raise ValueError("a ref that is not listed carries the capabilities")
            return True
        # A kept line can still name one: ``symref-target:refs/pull/7/head``
        # in an ls-refs answer, ``symref=HEAD:refs/pull/7/head`` in a v0
        # capability list. Rewriting those is not this filter's to do.
        if any(b":" + prefix in payload for prefix in self._hidden):
            raise ValueError("a hidden ref is named in an attribute")
        return False

    def finish(self) -> None:
        """Called at the end of the stream.

        Raises:
            ValueError: it ended inside a pkt-line, or on anything but the
                flush packet every listing closes with: a forge that stopped
                short at a line boundary sent an incomplete list, not a
                short one.
        """
        if self._reader.pending or not self._ended_on_flush:
            raise ValueError("listing ended before its flush")
