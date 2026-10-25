"""The ONE perimeter-call lifecycle (#511 convergence).

Every terminating reverse proxy — ``/egress``, ``/git``, ``/llm`` and the Matrix
proxy — does the same bookkeeping around one request: take one of the profile's
in-flight slots, run, settle an outcome and reason, then ONCE at the end give
the slot back, close any held upstream, and write exactly one ``gateway_calls``
row. This was copied into each route (two near-identical ``_Operation``
dataclasses in ``egress_http`` and ``git_transport``, plus ad-hoc variants in
``llm_proxy`` and the tunnel). Here it is once.

What a route does BETWEEN ``take_slot`` and ``finish`` — how it admits, judges,
injects a credential and delivers — stays in the route. That is where the
security lives, and it differs by protocol on purpose; only the bookkeeping is
shared.
"""

from __future__ import annotations

import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..database import record_gateway_call
from ..logsafe import exc_kind
from ..outcomes import Outcome

if TYPE_CHECKING:
    from .destination import DestinationKind
    from .profile import Profile

logger = logging.getLogger(__name__)

#: The ``backend``/``tool`` stand-in on a row for a request refused before the
#: route knew what it was (an unknown upstream, a token that matched no profile).
NO_OPERATION = "-"

#: In-flight requests one profile may hold on a single terminating route. A
#: route that must allow a subagent fan-out (``/llm``) sets its own higher cap;
#: the tunnel has its own. Never one global number — a shared limit would let
#: one route starve another (the channel #291 closed for resolver slots).
MAX_OPERATIONS_PER_PROFILE = 8


class Slots:
    """One route's per-profile in-flight counter. Each route owns one instance,
    so one route's load never counts against another's cap."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._open: dict[str, int] = {}

    def take(self, name: str) -> bool:
        """Claim a slot for ``name``; False when the profile holds them all."""
        if self._open.get(name, 0) >= self._limit:
            return False
        self._open[name] = self._open.get(name, 0) + 1
        return True

    def give(self, name: str) -> None:
        """Return a slot. A profile with none in flight keeps no entry: names
        come and go with reloads, and this map should not pin them."""
        held = self._open.get(name)
        if not held:
            return
        self._open[name] = held - 1
        if not self._open[name]:
            del self._open[name]


@dataclass
class Operation:
    """One request, from the caller's token to its audit row.

    ``sent`` is what went upstream from the agent and ``received`` what came back
    for it. The outcome starts ``CANCELLED`` and stays that unless something
    decides otherwise: an operation nobody finished is one whose task was
    cancelled or whose client went away. A response relayed on ``upstream`` (an
    ``AsyncExitStack``) is closed exactly once, when the operation finishes.
    """

    profile: Profile
    #: The audit ``backend`` column, e.g. ``egress:<name>`` or ``git:<remote>``.
    #: Set by the route; a default marks a refusal before the route knew it.
    backend: str
    #: The audit ``tool`` column (the method for ``/egress``, fetch/push for git).
    tool: str = NO_OPERATION
    destination: str | None = None
    destination_kind: DestinationKind | None = None
    started: float = field(default_factory=time.monotonic)
    sent: int = 0
    received: int = 0
    outcome: Outcome = Outcome.CANCELLED
    reason: str | None = None
    #: A flag-mode finding carried onto the forwarded call's row, so a flag is
    #: recorded and not only shown to the agent.
    flag_reason: str | None = None
    holds_slot: bool = False
    finished: bool = False
    upstream: AsyncExitStack = field(default_factory=AsyncExitStack)
    _slots: Slots | None = None

    def settle(self, outcome: Outcome, reason: str | None = None) -> None:
        self.outcome, self.reason = outcome, reason

    def take_slot(self, slots: Slots) -> bool:
        """Take one of the profile's slots on ``slots``; ``finish`` gives it back.
        Returns False when the profile holds them all — the route raises its own
        ``busy`` refusal, so the status and reason stay the route's."""
        if not slots.take(self.profile.name):
            return False
        self._slots = slots
        self.holds_slot = True
        return True

    async def finish(self) -> None:
        """Close upstream, give the slot back and write the audit row. Once.

        The destination and tool are the caller's text, stored there and nowhere
        else (#266). Like ``router._audit``, a lost row never fails what it
        records.
        """
        if self.finished:
            return
        self.finished = True
        try:
            await self.upstream.aclose()
        finally:
            if self.holds_slot and self._slots is not None:
                self._slots.give(self.profile.name)
            try:
                record_gateway_call(
                    self.profile.name,
                    self.backend,
                    self.tool,
                    self.outcome.value,
                    int((time.monotonic() - self.started) * 1000),
                    self.reason,
                    bytes_arrived=self.received,
                    bytes_delivered=self.sent,
                    destination=self.destination,
                    destination_kind=(
                        self.destination_kind.value
                        if self.destination and self.destination_kind
                        else None
                    ),
                )
            except Exception as exc:
                logger.warning(
                    "perimeter: audit row lost profile=%s err=%s",
                    self.profile.name,
                    exc_kind(exc),
                )
