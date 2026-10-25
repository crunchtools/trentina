"""The operator-named-origin spine (#511 convergence).

Shared by the terminating reverse proxies (``/egress``, ``/git``, ``/llm``) and
the CONNECT tunnel. These five differ from ``fetch`` in *who chose the
destination*: ``fetch`` hands ``egress.open_guarded`` an agent-chosen URL,
checked per hop, redirects followed, a per-call client, never pooled. Here the
agent supplies only a *path*; the *host* is one the operator named. So the
address is checked ONCE per burst, the connection is pinned to it, no redirect
is followed, and — because the key set is operator config, not agent input —
the check may be cached.

Nothing here judges content. It is the network leg only; the address rule lives
in ``egress.py`` (the ONE egress guard, #260), which this calls.

``checked_target`` lived in ``client_egress.py`` until the convergence moved it
here: the terminating HTTP routes imported it *up* from the tunnel module, an
inverted dependency. The tunnel now imports it from here like everyone else.
"""

from __future__ import annotations

import asyncio
import time
from functools import partial
from typing import TYPE_CHECKING

from ..egress import check_url
from .context import profile_context
from .profile import CLIENT_EGRESS_PORT

if TYPE_CHECKING:
    from ..egress import ResolvedTarget
    from .profile import Profile

RESOLVER_BUSY = "resolver_busy"
"""The egress guard's reason when no resolver slot was free. It is the
gateway's load, not a verdict on the name, so a route answers it as it answers
its own ``busy``: 503, ``denied_guard`` — never a defense block."""

CHECKED_TTL = 5.0
"""Seconds a name's checked addresses answer the same profile's next call
(#449). A client opens a pool of connections to two or three names at once, and
each lookup takes one of the profile's four resolver slots, which never queue:
without this the fifth call of a burst was refused. Safe for an operator-named
origin and not for ``fetch``: the name is one the operator listed, checked
against the list before this is asked, and the caller dials the addresses that
were checked. A refusal is never kept."""

#: In-flight checks, shared by every caller of a name that starts while one runs.
_checking: dict[tuple[str, str], asyncio.Task[ResolvedTarget]] = {}
#: Finished checks, kept for ``CHECKED_TTL``. Nothing sweeps it: a key is a name
#: some profile lists, so there are at most a bounded set per profile, and a
#: stale answer is replaced when its name is next asked for.
_checked: dict[tuple[str, str], tuple[float, ResolvedTarget]] = {}


def forget_checked() -> None:
    """Drop every cached check. Called when the tunnel listener stops."""
    _checked.clear()


def _settle(key: tuple[str, str], task: asyncio.Task[ResolvedTarget]) -> None:
    """Keep a finished check's answer for ``CHECKED_TTL``; drop a refusal."""
    _checking.pop(key, None)
    # Read here so a check nobody waited out is not reported as unretrieved.
    if task.cancelled() or task.exception() is not None:
        _checked.pop(key, None)
        return
    _checked[key] = (time.monotonic() + CHECKED_TTL, task.result())


async def checked_target(profile: Profile, host: str) -> ResolvedTarget:
    """``host``'s checked addresses, from one lookup per burst (#449).

    Calls to one name that start together share the check in flight, and ones
    that start within ``CHECKED_TTL`` of it share its answer. The check is
    shielded: a caller that hangs up does not cancel it for the others. The
    tunnel (#442), the git transport (#453) and the egress route (#511) all ask
    here, for a host the operator named; one profile's burst is one burst,
    whichever way it leaves.

    Raises:
        EgressRefusedError: the egress guard refused the name.
    """
    key = (profile.name, host)
    held = _checked.get(key)
    if held is not None and time.monotonic() < held[0]:
        return held[1]
    task = _checking.get(key)
    if task is None:
        with profile_context(profile):
            task = asyncio.create_task(check_url(f"https://{host}:{CLIENT_EGRESS_PORT}"))
        _checking[key] = task
        task.add_done_callback(partial(_settle, key))
    return await asyncio.shield(task)
