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
from typing import TYPE_CHECKING, Any, Literal

from ..outcomes import Outcome
from ..transports.base import RefusedError

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
        "sideband",
        "section",
    }
)
"""Every ``error_message`` the git transport writes besides the egress
guard's own reason codes. Closed, so the audit never carries the caller's
text there."""


class GitRefusedError(RefusedError):
    """A git request the gateway will not carry, or will not finish carrying.

    Most refusals are one of this route's own deterministic rules, so the
    outcome defaults to ``denied_guard``. A refusal by the profile's lists,
    by the egress guard or of the forge's answer says so. It is a
    ``RefusedError``, so the perimeter spine answers it like any other.
    """

    def __init__(
        self, status: HTTPStatus, reason: str, outcome: Outcome = Outcome.DENIED_GUARD
    ) -> None:
        super().__init__(reason, status=status, outcome=outcome)


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
    without ``.git`` (one suffix; a name that still ends in it is refused):
    what is matched against the profile's lists is what the upstream URL is
    built from.

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
    # One suffix is taken off and no more. A forge that takes off two would
    # read ``x-srv.git.git`` as ``x-srv`` after a ``deny`` of ``*-srv`` had
    # read it as ``x-srv.git``; no forge lets a repository end in ``.git``.
    if repo.endswith(_GIT_SUFFIX):
        raise GitRefusedError(HTTPStatus.BAD_REQUEST, "name")
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


# Spec 027: the request is rewritten before it is checked, the forge's own
# text is replaced by the gateway's words, and a fetch answer is held to the
# sections git v2 defines. Everything below is pure.

GATEWAY_AGENT = b"agent=git/trentina"
"""The one ``agent=`` value a client is told, whatever the forge runs."""

PACKFILE_HEADER = b"000dpackfile\n"
"""The ``packfile`` section header on the wire, which the gateway forwards
itself when ``FetchResponse`` reports ``section_start``."""

_REQUEST_STRIPPED = frozenset({b"thin-pack", b"sideband-all", b"packfile-uris"})
_ADVERTISED_DROPPED_LINES = frozenset({b"bundle-uri", b"object-info"})
_ADVERTISED_DROPPED_FEATURES = frozenset({b"packfile-uris", b"sideband-all", b"thin-pack"})
_V0_DROPPED_CAPABILITIES = frozenset({b"bundle-uri", b"object-info"}) | _ADVERTISED_DROPPED_FEATURES
_SECTIONS = frozenset({b"acknowledgments", b"shallow-info", b"wanted-refs", b"packfile"})
_SIDEBAND = b"side-band-64k"
_ERR = b"ERR"
_ERR_REWRITTEN = b"ERR refused by forge"
_BAND_DATA, _BAND_PROGRESS, _BAND_ERROR = 1, 2, 3
_BAND_PAYLOAD_MAX = PKT_MAX - _PKT_HEADER - 1
_REFNAME_RE = re.compile(rb"[\x21-\x7e]{1,%d}" % MAX_LISTED_REF)
_ACK_RE = re.compile(rb"ACK [0-9a-f]{40}(?:[0-9a-f]{24})?(?: (?:continue|common|ready))?")
_UNPACK_OK = b"unpack ok"


def _pkt(payload: bytes) -> bytes:
    if len(payload) + _PKT_HEADER > PKT_MAX:
        raise ValueError("pkt-line longer than the protocol allows")
    return b"%04x" % (len(payload) + _PKT_HEADER) + payload


def _wire(packet: bytes | int) -> bytes:
    return b"%04x" % packet if isinstance(packet, int) else _pkt(packet)


def _text(payload: bytes) -> bytes:
    return payload.removesuffix(b"\n")


def _is_ref_line(payload: bytes) -> bool:
    head, _nul, _caps = payload.partition(b"\0")
    oid, space, _rest = head.partition(b" ")
    return bool(space) and _OID_RE.fullmatch(oid) is not None


def is_err(payload: bytes) -> bool:
    """True for an ``ERR <message>`` pkt-line payload."""
    return payload == _ERR or payload.startswith(_ERR + b" ")


def rewrite_err(payload: bytes) -> bytes:
    """``ERR <anything>`` as ``ERR refused by forge``, keeping a trailing
    newline if there was one. Any other payload is returned as it is."""
    if not is_err(payload):
        return payload
    return _ERR_REWRITTEN + (b"\n" if payload.endswith(b"\n") else b"")


# --- the fetch request ------------------------------------------------------


def _fetch_lines(body: bytes) -> list[bytes | int]:
    return list(pkt_lines(body))


def strip_fetch_request(body: bytes, protocol: str | None) -> bytes:
    """The upload-pack request with ``thin-pack``, ``packfile-uris`` and
    ``sideband-all`` taken out, so the forge never sees them.

    Under v2 they are argument or capability lines and the pkt-lines are
    dropped. Under v0 and v1 they are capabilities on the first ``want``
    line, and are removed from it. Every length is recomputed, and every
    other pkt-line is passed on byte for byte.

    Raises:
        ValueError: the body is not pkt-lines end to end.
    """
    v2 = protocol == PROTOCOL_V2
    out = bytearray()
    first_want = True
    for packet in pkt_lines(body):
        if isinstance(packet, int):
            out += _wire(packet)
            continue
        line = _text(packet)
        if v2:
            verb = line.partition(b" ")[0]
            if verb in _REQUEST_STRIPPED:
                continue
        elif first_want and line.startswith(b"want "):
            first_want = False
            fields = line.split(b" ")
            kept = [f for f in fields if f not in _V0_DROPPED_CAPABILITIES]
            kept = [f for f in kept if f.partition(b"=")[0] != b"packfile-uris"]
            if len(kept) != len(fields):
                newline = b"\n" if packet.endswith(b"\n") else b""
                out += _pkt(b" ".join(kept) + newline)
                continue
        out += _pkt(packet)
    return bytes(out)


def _want_fields(body: bytes, protocol: str | None) -> tuple[list[bytes], list[bytes]]:
    """The oids of the ``want`` lines, and the first v0 want line's capabilities."""
    wants: list[bytes] = []
    capabilities: list[bytes] = []
    for packet in pkt_lines(body):
        if isinstance(packet, int):
            continue
        fields = _text(packet).split(b" ")
        if fields[0] != b"want" or len(fields) < 2:
            continue
        if not _OID_RE.fullmatch(fields[1]):
            raise ValueError("a want that is not an object id")
        if not wants and protocol != PROTOCOL_V2:
            capabilities = fields[2:]
        wants.append(fields[1])
    return wants, capabilities


def wants(body: bytes, protocol: str | None) -> list[str]:
    """The hex object ids of the request's ``want`` lines, in order, the v0
    first line's capabilities left off.

    Raises:
        ValueError: not pkt-lines, or a ``want`` that does not carry an object id.
    """
    return [oid.decode() for oid in _want_fields(body, protocol)[0]]


def is_promisor_fetch(body: bytes, protocol: str | None) -> bool:
    """True for a partial clone's lazy fetch: a ``filter`` with explicit
    ``want`` lines and no ``have`` lines.

    git's lazy fetch names the objects it is missing and has nothing to
    negotiate; a clone or a fetch with a filter sends no explicit blob wants
    it could not also send ``have`` for, and a clone has no ``have`` either
    but is told apart by ``filter`` being absent from it when it is full. The
    cheap, conservative rule: filter, at least one want, no have, no deepen.
    """
    wanted, capabilities = _want_fields(body, protocol)
    filtered = protocol != PROTOCOL_V2 and b"filter" in capabilities
    for packet in pkt_lines(body):
        if isinstance(packet, int):
            continue
        verb = _text(packet).partition(b" ")[0]
        if verb in (b"have", b"deepen", b"deepen-since", b"deepen-not"):
            return False
        filtered = filtered or verb == b"filter"
    return filtered and bool(wanted)


def negotiated_sideband(body: bytes, protocol: str | None) -> bool:
    """Whether the response carries its pack in side-band.

    v2 always does. v0 and v1 do when the first ``want`` line asks for
    ``side-band-64k``; a request that does not is refused by the caller
    (``sideband``), as git itself never sends one.
    """
    if protocol == PROTOCOL_V2:
        return True
    return _SIDEBAND in _want_fields(body, protocol)[1]


# --- the advertisement ------------------------------------------------------


def _v0_capabilities(caps: bytes) -> tuple[bytes, list[bytes]]:
    """A v0 capability list, rewritten, and the symref targets it names."""
    kept: list[bytes] = []
    targets: list[bytes] = []
    for cap in caps.split(b" "):
        key, _eq, value = cap.partition(b"=")
        if key == b"agent":
            kept.append(GATEWAY_AGENT)
        elif key == b"session-id" or cap in _V0_DROPPED_CAPABILITIES or key == b"packfile-uris":
            continue
        else:
            kept.append(cap)
            if key == b"symref":
                targets.append(value.partition(b":")[2])
    return b" ".join(kept), targets


def _v2_capability(line: bytes) -> bytes | None:
    """One v2 capability line, rewritten, or None when it is not advertised."""
    key, eq, value = line.partition(b"=")
    if key == b"agent" and eq:
        return GATEWAY_AGENT
    if (
        key == b"session-id"
        or line in _ADVERTISED_DROPPED_LINES
        or key in _ADVERTISED_DROPPED_LINES
    ):
        return None
    if key == b"fetch" and eq:
        features = [f for f in value.split(b" ") if f not in _ADVERTISED_DROPPED_FEATURES]
        return b"fetch=" + b" ".join(features) if features else b"fetch"
    return line


def rewrite_listing(
    body: bytes, protocol: str | None, hidden: tuple[bytes, ...]
) -> tuple[bytes, list[str]]:
    """A whole ref listing, rewritten, and the names in it to be judged.

    Applies ``RefFilter``'s rules (hidden and unlistable refs dropped, a
    symref into a hidden namespace refused), then rewrites what the forge
    says about itself: ``agent=`` becomes ``git/trentina``; ``session-id=``,
    ``bundle-uri`` and ``object-info`` are dropped; ``packfile-uris``,
    ``sideband-all`` and ``thin-pack`` are removed from v2's ``fetch=``
    feature list and from a v0 capability list; an ``ERR`` line is replaced.
    Serves a v0, v1 or v2 ``info/refs`` and a v2 ``ls-refs`` answer alike.

    Returns:
        The listing, and every ref name and symref target on a line that is
        kept, in order and with repeats.

    Raises:
        ValueError: the listing is not pkt-lines to a flush, or ``RefFilter``'s
            own refusals.
    """
    listing = RefFilter(hidden)
    kept = listing.feed(body)
    listing.finish()
    v2 = protocol == PROTOCOL_V2
    out = bytearray()
    names: list[str] = []
    for packet in pkt_lines(kept):
        if isinstance(packet, int):
            out += _wire(packet)
            continue
        if is_err(packet):
            out += _pkt(rewrite_err(packet))
            continue
        newline = b"\n" if packet.endswith(b"\n") else b""
        if _is_ref_line(packet):
            head, nul, caps = _text(packet).partition(b"\0")
            fields = head.split(b" ")
            found = [fields[1]] if fields[1] != b"capabilities^{}" else []
            found += [f.partition(b":")[2] for f in fields[2:] if f.startswith(b"symref-target:")]
            if nul:
                caps, targets = _v0_capabilities(caps)
                found += targets
                head += b"\0" + caps
            names += [n.decode("utf-8", "replace") for n in found]
            out += _pkt(head + newline)
        elif v2 and (line := _v2_capability(_text(packet))) is not None:
            out += _pkt(line + newline)
        elif not v2:
            out += _pkt(packet)
    return bytes(out), names


# --- writers ----------------------------------------------------------------


def sideband_line(band: int, text: str) -> bytes:
    """One side-band pkt-line on ``band`` (1, 2 or 3) carrying gateway-written
    ``text``. Raises ValueError for another band or text past one pkt-line."""
    if band not in (_BAND_DATA, _BAND_PROGRESS, _BAND_ERROR):
        raise ValueError("not a side-band channel")
    encoded = text.encode()
    if len(encoded) > _BAND_PAYLOAD_MAX:
        raise ValueError("side-band text longer than a pkt-line")
    return _pkt(bytes([band]) + encoded)


def progress(text: str) -> bytes:
    """A band 2 line: ``text`` and a newline."""
    return sideband_line(_BAND_PROGRESS, text + "\n")


def refusal(reason: str) -> bytes:
    """A band 3 line: ``refused by Trentina: <reason>``."""
    return sideband_line(_BAND_ERROR, f"refused by Trentina: {reason}")


# --- the fetch response -----------------------------------------------------

Event = tuple[str, Any]
"""``("pass", wire)``, ``("section_start", b"packfile")``, ``("pack", content)``,
``("forge_error", None)`` or ``("end", wire)``."""


def _check_section_line(section: bytes, line: bytes) -> None:
    """A line of a non-pack section is the shape git writes, or a refusal."""
    ok: bool
    if section == b"acknowledgments":
        ok = line in (b"NAK", b"ready") or _ACK_RE.fullmatch(line) is not None
    elif section == b"shallow-info":
        verb, _space, oid = line.partition(b" ")
        ok = verb in (b"shallow", b"unshallow") and _OID_RE.fullmatch(oid) is not None
    else:  # wanted-refs
        oid, _space, name = line.partition(b" ")
        ok = _OID_RE.fullmatch(oid) is not None and _REFNAME_RE.fullmatch(name) is not None
    if not ok:
        raise ValueError("a section line git does not write")


class FetchResponse:
    """The forge's upload-pack answer, read as it streams and held to its grammar.

    ``v2=True``: sections ``acknowledgments``, ``shallow-info``,
    ``wanted-refs`` and ``packfile``, each opened by a line naming it,
    separated by a delimiter and ended by a flush. Anything else (a
    ``packfile-uris`` section included) ends the response with ValueError.
    ``v2=False`` (v0 and v1): ``NAK``, ``ACK`` and ``shallow`` lines, then
    side-band until the flush.

    Inside the pack every pkt-line is side-band: band 1 is pack data, band 2
    (forge progress) is dropped and counted in ``dropped``, band 3 is
    ``("forge_error", None)`` and its text is never kept. An ``ERR`` line is
    passed on rewritten and ends the response.

    Memory held is under one pkt-line plus the piece fed.
    """

    def __init__(self, *, v2: bool) -> None:
        self._reader = PktReader()
        self._v2 = v2
        self._section: bytes | None = None
        self._in_pack = False
        self._shallow_seen = False
        self._shallow_flushed = False
        self._ended = False
        self.dropped = 0

    def feed(self, arrived: bytes) -> list[Event]:
        """The events for the whole pkt-lines ``arrived`` completes.

        Raises:
            ValueError: not pkt-lines, a section or line git does not write,
                a band that is not 1, 2 or 3, or bytes after the end.
        """
        self._reader.feed(arrived)
        events: list[Event] = []
        while (taken := self._reader.take()) is not None:
            if self._ended:
                raise ValueError("bytes after the end of the response")
            self._one(*taken, events)
        return events

    def _one(self, wire: bytes, payload: bytes | int, events: list[Event]) -> None:
        if isinstance(payload, bytes) and is_err(payload):
            events.append(("pass", _pkt(rewrite_err(payload))))
            self._ended = True
        elif self._in_pack:
            self._pack_line(wire, payload, events)
        elif self._v2:
            self._section_line(wire, payload, events)
        else:
            self._v0_line(wire, payload, events)

    def _pack_line(self, wire: bytes, payload: bytes | int, events: list[Event]) -> None:
        if isinstance(payload, int):
            if payload != FLUSH:
                raise ValueError("a delimiter inside the pack")
            events.append(("end", wire))
            self._ended = True
            return
        if not payload:
            raise ValueError("an empty side-band line")
        band, content = payload[0], payload[1:]
        if band == _BAND_DATA:
            if content:
                events.append(("pack", content))
        elif band == _BAND_PROGRESS:
            self.dropped += 1
        elif band == _BAND_ERROR:
            events.append(("forge_error", None))
        else:
            raise ValueError("a side-band channel that is not 1, 2 or 3")

    def _section_line(self, wire: bytes, payload: bytes | int, events: list[Event]) -> None:
        if payload == FLUSH and isinstance(payload, int):
            events.append(("end", wire))
            self._ended = True
        elif isinstance(payload, int):
            if self._section is None:
                raise ValueError("a delimiter where a section should open")
            self._section = None
            events.append(("pass", wire))
        elif self._section is None:
            name = _text(payload)
            if name not in _SECTIONS:
                raise ValueError("a section git does not define for fetch")
            self._section = name
            if name == b"packfile":
                self._in_pack = True
                events.append(("section_start", b"packfile"))
            else:
                events.append(("pass", wire))
        else:
            _check_section_line(self._section, _text(payload))
            events.append(("pass", wire))

    def _v0_line(self, wire: bytes, payload: bytes | int, events: list[Event]) -> None:
        if isinstance(payload, int):
            # One flush closes a ``shallow`` list; the answer goes on after it.
            if payload == FLUSH and self._shallow_seen and not self._shallow_flushed:
                self._shallow_flushed = True
                events.append(("pass", wire))
                return
            raise ValueError("a special packet before the pack")
        if payload and payload[0] in (_BAND_DATA, _BAND_PROGRESS, _BAND_ERROR):
            self._in_pack = True
            self._pack_line(wire, payload, events)
            return
        line = _text(payload)
        verb, _space, oid = line.partition(b" ")
        if verb in (b"shallow", b"unshallow") and _OID_RE.fullmatch(oid):
            self._shallow_seen = True
        elif line != b"NAK" and not _ACK_RE.fullmatch(line):
            raise ValueError("a line before the pack that git does not write")
        events.append(("pass", wire))

    def finish(self) -> None:
        """Called at the end of the stream.

        Raises:
            ValueError: it stopped inside a pkt-line or before the flush.
        """
        if self._reader.pending or not self._ended:
            raise ValueError("response ended before its flush")


# --- the push response ------------------------------------------------------


def _valid_option(line: bytes) -> bool:
    key, _space, value = line.partition(b" ")
    if key == b"forced-update":
        return not value
    if key == b"refname":
        return _REFNAME_RE.fullmatch(value) is not None
    return key in (b"old-oid", b"new-oid") and _OID_RE.fullmatch(value) is not None


def rewrite_push_status(payload: bytes) -> bytes:
    """One report-status line with the forge's words replaced.

    ``unpack ok`` stays; any other ``unpack <reason>`` becomes ``unpack
    error``. ``ok <ref>`` stays. ``ng <ref> <reason>`` becomes ``ng <ref>
    rejected``. A report-status-v2 ``option`` line stays when it is one of
    ``refname``, ``old-oid``, ``new-oid`` or ``forced-update`` in its
    deterministic shape. An ``ERR`` line is replaced as ``rewrite_err`` does.

    Raises:
        ValueError: any other line.
    """
    newline = b"\n" if payload.endswith(b"\n") else b""
    line = _text(payload)
    verb, _space, rest = line.partition(b" ")
    if is_err(payload):
        return rewrite_err(payload)
    if verb == b"unpack" and rest:
        return (_UNPACK_OK if rest == b"ok" else b"unpack error") + newline
    if verb in (b"ok", b"ng"):
        ref = rest.partition(b" ")[0]
        if _REFNAME_RE.fullmatch(ref) is None or (verb == b"ok" and rest != ref):
            raise ValueError("a report-status ref that is not one token")
        return (
            (b"ok " if verb == b"ok" else b"ng ")
            + ref
            + (b"" if verb == b"ok" else b" rejected")
            + newline
        )
    if verb == b"option" and _valid_option(rest):
        return payload
    raise ValueError("a report-status line git does not write")


def _rebanded(report: bytearray, out: bytearray) -> None:
    """Move a rewritten report into ``out`` as band-1 pkt-lines, emptying it."""
    for at in range(0, len(report), _BAND_PAYLOAD_MAX):
        out += _pkt(bytes([_BAND_DATA]) + bytes(report[at : at + _BAND_PAYLOAD_MAX]))
    report.clear()


class PushResponse:
    """A receive-pack answer with every word of the forge's replaced.

    Reads the report-status, in side-band-64k when the answer opens with a
    band byte and plain otherwise. In side-band, band 1 carries the report
    (itself pkt-lines, which may be split across band-1 packets), band 2 is
    dropped and counted in ``dropped``, and band 3 is replaced by the
    gateway's own ``refused by Trentina: forge_error``. Output is the same
    shape, rewritten with ``rewrite_push_status``; a line git does not write
    is a ValueError.
    """

    def __init__(self) -> None:
        self._outer = PktReader()
        self._inner = PktReader()
        self._sideband: bool | None = None
        self._report_done = False
        self._ended = False
        self.dropped = 0

    def feed(self, arrived: bytes) -> bytes:
        """The rewritten bytes for the whole pkt-lines ``arrived`` completes."""
        self._outer.feed(arrived)
        out = bytearray()
        report = bytearray()
        while (taken := self._outer.take()) is not None:
            if self._ended:
                raise ValueError("bytes after the end of the response")
            wire, payload = taken
            if self._sideband is None and isinstance(payload, bytes):
                self._sideband = bool(payload) and payload[0] in (1, 2, 3)
            if not self._sideband:
                self._plain(wire, payload, out)
            else:
                self._banded(wire, payload, out, report)
        _rebanded(report, out)
        return bytes(out)

    def _plain(self, wire: bytes, payload: bytes | int, out: bytearray) -> None:
        if isinstance(payload, int):
            if payload != FLUSH:
                raise ValueError("a delimiter in a push report")
            self._report_done = self._ended = True
            out += wire
        else:
            out += _pkt(rewrite_push_status(payload))

    def _banded(self, wire: bytes, payload: bytes | int, out: bytearray, report: bytearray) -> None:
        if isinstance(payload, int):
            if payload != FLUSH or self._inner.pending or not self._report_done:
                raise ValueError("a push report that did not finish")
            self._ended = True
            # The report read so far goes first: the flush ends the answer.
            _rebanded(report, out)
            out += wire
            return
        if not payload:
            raise ValueError("an empty side-band line")
        band, content = payload[0], payload[1:]
        if band == _BAND_PROGRESS:
            self.dropped += 1
        elif band == _BAND_ERROR:
            _rebanded(report, out)
            out += refusal("forge_error")
        elif band == _BAND_DATA:
            self._report_data(content, report)
        else:
            raise ValueError("a side-band channel that is not 1, 2 or 3")

    def _report_data(self, content: bytes, report: bytearray) -> None:
        self._inner.feed(content)
        while (taken := self._inner.take()) is not None:
            if self._report_done:
                raise ValueError("bytes after the push report")
            inner = taken[1]
            if isinstance(inner, int):
                if inner != FLUSH:
                    raise ValueError("a delimiter in a push report")
                self._report_done = True
                report += taken[0]
            else:
                report += _pkt(rewrite_push_status(inner))

    def finish(self) -> None:
        """Called at the end of the stream; ValueError when the report is incomplete.

        An answer with nothing in it is whole: it is the forge's reply to the
        lone flush git sends to probe before a large push.
        """
        if self._sideband is None and not self._outer.pending:
            return
        if self._outer.pending or not self._ended:
            raise ValueError("push response ended before its flush")
