"""Actions an operator agent stages and a person approves (#637).

The operator is root on this gateway. Two decisions were still not its own to
make alone — minting a second operator, and believing another gateway's scan
instead of running our own layers — and not because it lacks the authority:
because it is a model, so the question was never "may it?" but "can it be
talked into it?". Until now both were flat refusals, which left the product
with two steps that needed a text editor and a shell. That is the thing
Trentina exists to remove.

Scott's ruling is that they stay human decisions and stop being
manual ones. The agent STAGES the action here; a person opens the approval
page, reads what is about to change, and enters the approval password. Fully
automated for the agent, explicitly consented by a human.

**Why a password and not a link.** The first cut of this handed the agent a
capability URL and let whoever held it approve. That is unsound, and in the
same way the design it replaced was: the agent reads the URL out of its own
tool result, and an operator profile with any code-execution backend can POST
it. The capability has to be something the agent cannot read, so it is a
secret a person holds and the gateway only verifies — never a token this
module gives away. Nothing here is returned to a caller: an agent learns that
something is staged and nothing more.

ONE mechanism, deliberately. The next action with a blast radius like these
gets a ``Kind`` here, not a flow of its own — the same rule that keeps one
egress guard and one driver registry. What does NOT come here is anything
high-volume: a gateway holds hundreds of tool pins and a restart can re-hold
every remote tool at once, so routing those through a human would push people
toward turning pinning off, which is worse than the thing it protects.

Nothing is written to disk. A staged action lives in this process only, so a
restart cancels every one of them. That is the fail-closed direction: a staged
change that outlives the process that proposed it is a change nobody is
watching any more.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

#: How long a staged action stands. Long enough for a person to be fetched,
#: short enough that an abandoned proposal is gone before anyone forgets it was
#: made.
TTL_SECONDS = 900

#: What may be shown on the approval page. Every value a person reads is either
#: authored here or a config name — except a federated peer's stamp and judge,
#: which the PEER chose, and which this bound keeps to a shape. A value that
#: does not match is refused rather than displayed: rendering a peer's text to
#: the person deciding whether to trust that peer is the one place this feature
#: could be turned against its own purpose.
_DISPLAYABLE = re.compile(r"^[A-Za-z0-9 ._:/@+=,'()-]{1,200}$")


class PendingError(ValueError):
    """A staged action could not be created or applied. The message names the
    reason and never the value that failed."""


class Kind(Enum):
    """What may be staged. A closed set: a new one is an edit here.

    The value reaches the approval page and the audit, so it is spelled for a
    person rather than for the code that raises it.
    """

    OPERATOR_SEAT = "operator seat"
    FEDERATION_TRUST = "federation trust"


@dataclass(frozen=True)
class Staged:
    """One action awaiting a person, and what to show them about it.

    ``facts`` is an ordered mapping of label to already-checked display string:
    the page renders it as given (escaped), and nothing else about the action
    reaches a human. ``apply`` is called at most once, after approval.
    """

    kind: Kind
    facts: dict[str, str]
    apply: Callable[[], Awaitable[dict[str, Any]]]
    staged_at: float = field(default_factory=time.time)

    def expired(self, *, now: float | None = None) -> bool:
        return (time.time() if now is None else now) - self.staged_at > TTL_SECONDS


#: At most one outstanding action per kind. Staging a second replaces the
#: first: two pending seat changes would make "approve" ambiguous to the person
#: reading the page, and the newest proposal is the live one.
_staged: dict[Kind, Staged] = {}


def checked_display(value: str, *, what: str) -> str:
    """``value``, proved safe to show a person, or raise.

    Called on anything that did not originate in this gateway, before it is
    staged — not at render time. A refusal has to happen while there is still
    somewhere to report it; a page that silently dropped a field would leave a
    person approving against an incomplete description.
    """
    if not _DISPLAYABLE.match(value):
        raise PendingError(f"{what} is not in a shape that can be shown for approval")
    return value


def stage(
    kind: Kind,
    facts: dict[str, str],
    apply: Callable[[], Awaitable[dict[str, Any]]],
) -> None:
    """Hold ``kind`` for a person's approval.

    Returns nothing, deliberately. There is no handle to hand back: a caller
    that received one would hold part of the capability it is being held away
    from. The caller has already done every check it can make on its own —
    staging is the last step before a human, not a way to defer validation to
    one.
    """
    _staged[kind] = Staged(kind=kind, facts=facts, apply=apply)
    logger.info("approval: staged %s, awaiting a person", kind.value)


def _sweep(now: float) -> None:
    for kind, action in list(_staged.items()):
        if action.expired(now=now):
            del _staged[kind]
            logger.info("approval: %s expired unapproved", kind.value)


def outstanding(*, now: float | None = None) -> dict[Kind, dict[str, str]]:
    """What is awaiting a person, by kind, with the facts to show.

    Read by the approval page AFTER it has verified the password, and by an
    operator tool that reports what it is waiting on. Expired actions are swept
    on the way through, so a page never renders one that approving would
    refuse.
    """
    _sweep(time.time() if now is None else now)
    return {kind: dict(action.facts) for kind, action in _staged.items()}


def kind_named(name: str) -> Kind | None:
    """The ``Kind`` whose value is ``name``, or None.

    The page submits a kind back as a string. A name that is not one of the
    closed set resolves to nothing rather than raising, so a hand-made form
    reaches the same "nothing to approve" answer as a stale one.
    """
    return next((kind for kind in Kind if kind.value == name), None)


async def approve(kind: Kind) -> dict[str, Any]:
    """Apply the staged action of ``kind``, once.

    Removed from the store BEFORE it is applied, so a double submit cannot run
    it twice even if applying is slow — and so a failure does not leave
    something that looks live.
    """
    _sweep(time.time())
    action = _staged.get(kind)
    if action is None:
        raise PendingError("there is nothing of that kind waiting to be approved")
    del _staged[kind]
    logger.info("approval: %s approved by a person", kind.value)
    return await action.apply()


def decline(kind: Kind) -> bool:
    """Drop the staged action of ``kind`` without applying it."""
    _sweep(time.time())
    if _staged.pop(kind, None) is None:
        return False
    logger.info("approval: %s declined", kind.value)
    return True


def clear() -> None:
    """Drop everything staged. For tests, and for a shutdown that wants to say
    so rather than rely on the process ending."""
    _staged.clear()
