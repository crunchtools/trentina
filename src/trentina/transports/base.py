"""The transport contract: a Face in and out, a Carrier to the backend.

A transport speaks one wire protocol. It is two halves:

* A ``Face`` turns wire bytes into parsed data on the way in and a result into
  wire bytes on the way out. It parses the REQUEST edge, runs the RESPONSE
  edge, and wraps the result in the protocol's envelope. It spells no refusal
  of its own — ``core.render`` is the one refusal composer — and, as the
  public plugin contract, it constructs no sealed trust type and is handed no
  ``Posture``/``Profile``/``Principal``.
* A ``Carrier`` carries a parsed, outbound request to its destination and
  brings back the reply.

``orchestrator.crossing`` runs the two halves in ONE order it alone knows —
parse (request edge), carry, deliver (response edge), wrap — and that order is
the security property: a transport cannot reorder the steps, so it cannot skip
the gate (Trentina 3.0 plan §A/§C). Everything a half returns is either the
next step's input or an ``Early``: a protocol response already built and
audited, which the crossing returns as-is without running a later step.

This module is the future ``trentina.transports.base`` public surface. In
Phase 4 it carries only the in-tree MCP transport (``transports.mcp``), whose
halves reach the gateway's own collaborators directly; the typed plugin
contract and the line those collaborators sit behind are drawn in Phase 6.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from ..outcomes import Outcome

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from starlette.datastructures import Headers

    from ..modes import Mode


@dataclass(frozen=True)
class Early:
    """A protocol response already built and already audited — returned as-is.

    A face's ``parse``/``deliver`` or a carrier's ``carry`` returns one when the
    crossing must end before its remaining steps: an unknown tool, a refused
    argument, a backend error, a withheld response. ``crossing`` returns
    ``response`` unwrapped and runs no later step, exactly as the hand-rolled
    ``tools/call`` path's early ``return`` did.
    """

    response: Any


class Face(ABC):
    """One protocol's way in and out.

    ``parse`` is the REQUEST edge, ``deliver`` the RESPONSE edge, ``wrap`` the
    success envelope. A face never composes a refusal (``core.render`` owns the
    wording) and, as the public contract, constructs no sealed trust type.
    """

    name: str
    #: The transport contract version this face was written against — the compat
    #: anchor for transport registration. ``registry.register_transport`` refuses
    #: a face whose version this build does not run; the built-in ``mcp`` face is
    #: version 1.
    api_version: int = 1

    @abstractmethod
    async def parse(self, ctx: Any) -> Any:
        """The REQUEST edge: resolve, guard and normalize the call.

        Returns the transport's own parsed-request object (carried next), or an
        ``Early`` when the request is refused before anything is carried.
        """

    @abstractmethod
    async def deliver(self, ctx: Any, parsed: Any, carried: Any) -> Any:
        """The RESPONSE edge: judge and shape what the carrier brought back.

        Returns the result payload for ``wrap``, or an ``Early`` when the
        response is withheld after the backend answered.
        """

    @abstractmethod
    def wrap(self, ctx: Any, result: Any) -> Any:
        """Put a delivered result into the protocol's success envelope."""


class Carrier(ABC):
    """Carry a parsed, outbound request to its destination and bring back the reply."""

    name: str
    #: The transport contract version this carrier was written against; see ``Face``.
    api_version: int = 1

    @abstractmethod
    async def carry(self, ctx: Any, parsed: Any) -> Any:
        """Dispatch the parsed request to its backend.

        Returns what came back, for the response edge to judge, or an ``Early``
        when the carry itself failed (a backend error the agent is told of).
        """


@dataclass(frozen=True)
class Transport:
    """A protocol: its face (in and out) and its carrier (to the backend)."""

    face: Face
    carrier: Carrier


# The perimeter shapes (#535). A ``Transport`` above crosses to an MCP backend;
# the two below carry an agent's own traffic out of its network. A ``Route`` is
# an HTTP path under ``/proxy/<type>/<instance>/``, a ``Listener`` a raw stream
# on a port of its own (CONNECT). Each declares its contract and implements its
# own policy and wire shape; the spine in ``transports/perimeter.py`` owns
# everything they share: who the caller is, the instance and grant, the slot,
# the dial, judging what is sent and what comes back, and the one audit row.


class Audit(Enum):
    """When a route's operation writes its ``gateway_calls`` row.

    ``ALWAYS``: every operation a known caller started. ``ON_FINDING``: only a
    refusal, an upstream failure or a security finding — for a route whose
    clean traffic is a continuous poll (Matrix ``/sync``). Built in only: a
    plugin does not get to silence its clean calls.
    """

    ALWAYS = "always"
    ON_FINDING = "on_finding"


@dataclass(frozen=True)
class Bearer:
    """The caller presents its profile's gateway token.

    ``fallback_headers`` are read, in order, when ``Authorization`` is absent
    (an SDK that sends its key as ``x-api-key`` to a base URL it does not know
    wants Bearer). Every one of them is removed before the route sees the
    request, so a route never holds the caller's token.
    """

    fallback_headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class OperatorOrigin:
    """A destination the operator named: a KEY into the instance's ``origins``.
    A route names which one; the spine resolves it and checks the address."""

    key: str


#: Where ``admit`` says a request goes.
Destination = OperatorOrigin


#: The port an origin is reached on unless the operator names another.
HTTPS_PORT = 443


@dataclass(frozen=True)
class Origin:
    """An https origin the operator configured: a DNS name and a port."""

    host: str
    port: int = HTTPS_PORT


@dataclass(frozen=True)
class Instance:
    """One configured instance of a route type, as a route may read it.

    ``origins`` are what ``admit`` may name by key; ``options`` are the
    instance's own settings for its route. Nothing secret is here.
    """

    name: str
    type: str
    origins: Mapping[str, Origin]
    options: Mapping[str, Any]


@dataclass(frozen=True)
class Grant:
    """What the calling profile may do on one instance.

    ``origins`` are the keys it may reach, ``methods`` the HTTP methods,
    ``enforcement`` what a finding on its request does (``block`` refuses,
    ``flag`` forwards it marked). ``options`` are the route's own grant terms
    (repositories for git, path globs for http). The credential the spine
    injects is not here: a route never holds it.
    """

    origins: frozenset[str]
    methods: frozenset[str]
    enforcement: Mode
    options: Mapping[str, Any]


@dataclass(frozen=True)
class Refusal:
    """What a refusal reason means on one route: its status and audit outcome.

    Reasons are keyed by the spine's canonical names. ``wire`` is this route's
    own spelling of one, used on its refusal and in its audit row, where a
    route spoke a different name before the spine existed (git's ``remote``
    for an unknown instance).
    """

    status: int
    outcome: Outcome
    wire: str | None = None


#: The refusals the spine itself raises, on any route: the caller, the instance,
#: the slot, the dial, and judging what is sent and what comes back. A route's
#: ``refusals`` extends this table with its own, and may re-spell or re-status an
#: entry; a reason the route raises that its table does not hold is a gateway
#: error.
SPINE_REFUSALS: Mapping[str, Refusal] = {
    "unauthorized": Refusal(HTTPStatus.UNAUTHORIZED, Outcome.DENIED_GUARD),
    "unknown_upstream": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_ALLOWLIST),
    "busy": Refusal(HTTPStatus.SERVICE_UNAVAILABLE, Outcome.DENIED_GUARD),
    "too_large": Refusal(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, Outcome.DENIED_GUARD),
    "resolver_busy": Refusal(HTTPStatus.SERVICE_UNAVAILABLE, Outcome.DENIED_GUARD),
    "denied_guard": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "redirect": Refusal(HTTPStatus.BAD_GATEWAY, Outcome.BACKEND_ERROR),
    "upstream_failed": Refusal(HTTPStatus.BAD_GATEWAY, Outcome.BACKEND_ERROR),
    "upstream_idle": Refusal(HTTPStatus.GATEWAY_TIMEOUT, Outcome.BACKEND_ERROR),
    "binary_body": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "credential_in_request": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "flagged": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "not_fully_judged": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "gatekeeper": Refusal(HTTPStatus.FORBIDDEN, Outcome.DENIED_GATEKEEPER),
    "response_flagged": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "response_unjudged": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
    "response_binary": Refusal(HTTPStatus.FORBIDDEN, Outcome.BLOCKED_DEFENSE),
}


class RefusedError(Exception):
    """A refusal, raised by a route's ``admit`` or ``deliver`` or by the spine.

    ``reason`` is one of the route's declared ``refusals``. ``status`` and
    ``outcome`` override that entry where one reason has more than one answer
    (a forge's 403 passed through, against its 500). ``detail`` goes to the
    audit row instead of ``reason`` where a built-in has a more specific fact;
    a plugin's is dropped. ``executed`` says the destination acted before the
    response was withheld (#425). ``tool`` and ``destination`` are what the
    route had established before it refused (the git operation and the
    repository, say), for the audit row; a refusal knows no more than that.
    """

    def __init__(
        self,
        reason: str,
        *,
        status: int | None = None,
        outcome: Outcome | None = None,
        executed: bool = False,
        detail: str | None = None,
        tool: str | None = None,
        destination: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.outcome = outcome
        self.executed = executed
        self.detail = detail
        self.tool = tool
        self.destination = destination


@dataclass(frozen=True)
class Wire:
    """What a route sees of the request: never a Starlette ``Request``, never the body.

    A request object reaches the app and every other route's state; this holds
    the method, the path below the instance (``raw_path`` as it arrived), the
    query and the headers with the caller's credential removed. The body is
    only for ``deliver``, after the route holds a slot.
    """

    method: str
    path: str
    raw_path: bytes
    query: str
    #: Every header as it arrived, repeats kept (``getlist``), less the credential.
    headers: Headers
    peer: str | None


class Body:
    """The request body, read once, never past the route's ``max_request_bytes``."""

    def __init__(self, chunks: AsyncIterator[bytes], cap: int) -> None:
        self._chunks = chunks
        self._cap = cap
        self._read = False

    async def read(self) -> bytes:
        """The whole body, or ``RefusedError("too_large")`` past the cap."""
        if self._read:
            raise RuntimeError("the request body has been read")
        self._read = True
        buffer = bytearray()
        async for chunk in self._chunks:
            buffer.extend(chunk)
            if len(buffer) > self._cap:
                raise RefusedError("too_large")
        return bytes(buffer)


@dataclass(frozen=True)
class Delivered:
    """A response that crossed the spine: judged, scrubbed, ready to hand back.

    ``warning`` is the finding a ``flag`` grant forwards with, or None.
    """

    status: int
    headers: Mapping[str, str]
    content_type: str
    body: bytes
    warning: str | None


class Upstream(ABC):
    """The one way out of a route: a send to the destination ``admit`` named.

    The spine builds it, bound to an origin it resolved and checked. A send
    judges the request before it leaves, injects the profile's credential,
    dials the checked address, then reads and judges the response, and either
    returns it as ``Delivered`` or raises ``RefusedError``. A route sees neither
    the address nor the secret.
    """

    @abstractmethod
    async def send(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        headers: Mapping[str, str],
        content: bytes | None = None,
    ) -> Delivered:
        """Send one request and return the judged response."""


@dataclass(frozen=True)
class Admitted:
    """What ``admit`` decided: where the request goes, and for the audit row
    the operation (``tool``, the method when None) and the ``destination`` (the
    caller's text, recorded and nowhere else). A route subclasses it to carry
    what it parsed on the way."""

    origin: Destination
    destination: str | None = None
    tool: str | None = None


@dataclass
class Context:
    """What ``deliver`` works with: the request, its body, the instance, the
    profile's grant on it and the way out."""

    wire: Wire
    body: Body
    instance: Instance
    grant: Grant
    upstream: Upstream


A = TypeVar("A", bound=Admitted)
C = TypeVar("C", bound=Context, default=Context)


class Route(ABC, Generic[A, C]):
    """An HTTP path, ``/proxy/<name>/<instance>/...``, that carries an agent's request out.

    The class declares its contract; the three methods are the route's own
    policy and wire shape and have no defaults. ``admit`` decides from the
    request line and headers, and the profile's grant, whether the request may
    go and to which origin; the spine then takes a slot. ``deliver`` reads the
    body, sends through the ``Upstream`` it is handed and returns the response.
    ``render`` turns a ``RefusedError`` into this route's own refusal.
    """

    name: str
    methods: tuple[str, ...]
    auth: Bearer
    refusals: Mapping[str, Refusal]
    max_request_bytes: int
    slots: int | None = 8
    audit: Audit = Audit.ALWAYS
    idle: float = 300.0
    api_version: int = 1

    @property
    def path(self) -> str:
        """Where the route is served; the instance is the first segment."""
        return f"/proxy/{self.name}/{{instance}}/{{path:path}}"

    @abstractmethod
    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> A:
        """Admit the request or raise ``RefusedError``."""

    @abstractmethod
    async def deliver(self, admitted: A, ctx: C) -> Any:
        """Carry the admitted request and return the response to send back."""

    @abstractmethod
    def render(self, refused: RefusedError) -> Any:
        """This route's response for a refusal."""


class Listener(ABC):
    """A raw stream on a port of its own (CONNECT). Built in only.

    ``admit`` parses the request head; the spine checks the destination, dials
    it and calls ``relay`` with both ends. ``respond`` is the bytes a refusal
    answers with before the stream opens.
    """

    name: str
    refusals: Mapping[str, Refusal]
    slots: int = 64
    idle: float = 900.0
    api_version: int = 1

    @abstractmethod
    def admit(self, head: bytes, grant: Grant) -> Admitted:
        """Parse the head and name the destination, or raise ``RefusedError``."""

    @abstractmethod
    async def relay(self, client: Any, upstream: Any, op: Any) -> None:
        """Carry the stream between the two ends until either closes."""

    @abstractmethod
    def respond(self, refused: RefusedError) -> bytes:
        """The bytes a refusal answers with."""
