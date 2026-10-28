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
from typing import Any


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
    #: anchor for when transport plugins unlock (3.0.0). Not yet enforced; the
    #: built-in ``mcp`` face is version 1.
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
