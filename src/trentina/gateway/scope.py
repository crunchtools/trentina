"""Who is calling, and what may they see and act on.

One gateway process serves several agent profiles out of one config file, one
SQLite database and one set of caches. Every admin tool therefore has to answer
the same question before it does anything — *whose is this?* — and four tools
answering it four ways is four chances to get it wrong. This module is the
single answer.

Two rules live here, and nowhere else:

**Standalone is single-tenant.** With no ``ActiveConfig`` registered the process
is the plain MCP server, not the gateway: one operator ran it, there are no
other profiles to insulate from, and the full view is correct. Scoping a
single-tenant server to a profile that does not exist would only break it.

**A live gateway with no bound caller is refused.** The router binds the profile
around every internal dispatch (``router.py``, ``profile_context``), and it is
the only in-tree path that reaches these tools — the unauthenticated ``/mcp``
endpoint is a tombstone. So an unbound caller under a live gateway is not an
operator who skipped a step; it is a path nobody designed, and the honest answer
to "whose is this?" is "unknown", which fails closed.

What scoping does NOT claim: the caches and circuit breakers are keyed by
backend URL, so flushing or resetting a backend a caller legitimately holds is
felt by every other profile that shares it. That is correctness — a stale entry
is stale for everyone — and it discloses nothing. The insulation this module
provides is over what a caller may *name*, *see* and *decide*, not over the cost
of a shared re-probe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..database import is_blocked
from ..errors import BlockedSourceError
from ..modes import BLOCKLIST_REASON, Mode, refusal_body
from .context import get_current_profile
from .errors import ScopeError

if TYPE_CHECKING:
    from .profile import Backend, DefenseConfig, Profile


@dataclass(frozen=True)
class CallerScope:
    """What one caller may reach.

    ``profile`` is always present: a profile behind a live gateway, or the
    operator profile synthesized from the environment standalone (#P7.3).
    """

    profile: Profile
    is_operator: bool

    @property
    def name(self) -> str:
        """The calling profile's name (``standalone`` for the env operator)."""
        return self.profile.name

    @property
    def label(self) -> str:
        """A name for logs and result payloads."""
        return self.profile.name

    @property
    def backends(self) -> dict[str, Backend]:
        """The backends this caller may name."""
        return self.profile.backends


def current_scope() -> CallerScope:
    """The calling profile's scope.

    Reads the bound profile from ``get_current_profile``: a profile behind a
    live gateway, the operator synthesized from the environment standalone, or a
    ``ScopeError`` when a live gateway bound no caller — a path nobody designed,
    which fails closed rather than acting gateway-wide.
    """
    profile = get_current_profile()
    return CallerScope(profile=profile, is_operator=profile.role == "operator")


def require_caller(tool: str) -> CallerScope:
    """The calling scope, or raise with the tool named.

    Raises:
        ScopeError: the gateway is live and no profile is bound to this call.
    """
    try:
        return current_scope()
    except ScopeError:
        raise ScopeError(
            f"{tool}: no calling profile bound — refusing to act gateway-wide"
        ) from None


def require_operator(scope: CallerScope, action: str) -> None:
    """Raise unless this caller holds the operator role.

    Args:
        scope: The caller, from ``require_caller``.
        action: What was refused, phrased for the caller.

    Raises:
        ScopeError: the caller is an agent profile.
    """
    if not scope.is_operator:
        raise ScopeError(f"{action} requires the operator role")


def resolve_backend(scope: CallerScope, name: str) -> tuple[str, Backend]:
    """Resolve a backend NAME within the caller's own profile.

    By exact name, deliberately. Matching a name against cached URLs the way
    this used to means ``gw`` reaches ``gw-work`` and ``gw-personal`` both —
    one careless argument acting on a backend the caller never meant, and
    possibly never held.

    Returns:
        The backend's URL and its config.

    Raises:
        ScopeError: the caller does not hold a backend by that name. The
            message names no other profile's backend, so a miss is not an
            existence oracle for the rest of the gateway.
    """
    backend = scope.backends.get(name)
    if backend is None:
        raise ScopeError(f"backend {name!r} is not in this profile")
    return backend.url, backend


# The scope questions an internal tool (fetch/read/dir/content/search) asks
# before and after it produces a payload: whose blocklist holds the source,
# whose defense policy judges it, and whether the caller is a honeypot. They
# live here, beside the one answer to "whose is this?", rather than in the
# response edge that consumes them.


def blocklisted(source: str, mode: Mode) -> BlockedSourceError:
    """block and flag on a blocklisted source, refused before any bytes arrive.

    Offers redact when the policy allows it, because redact is the mode that
    proceeds on a blocklisted source. The body is constant (#263): it said
    ``since {detected_at}`` until then, which handed a caller another
    profile's timestamp. Nothing in it now depends on anything but the
    caller's own source and mode policy.
    """
    return BlockedSourceError(
        source,
        BLOCKLIST_REASON,
        refusal=refusal_body(BLOCKLIST_REASON, mode, flagged_by="blocklist"),
    )


def _caller() -> tuple[str, bool]:
    """The calling profile's name, and whether it reads the gateway-wide blocklist.

    Operator and standalone read every row; an agent reads its own. A live
    gateway with no bound caller never reaches here — ``current_scope`` raises
    rather than answer "whose is this?" as nobody.
    """
    scope = current_scope()
    return scope.name, scope.is_operator


def _caller_defense() -> DefenseConfig:
    """The calling profile's defense policy."""
    return current_scope().profile.defense


def honeypot_caller() -> str | None:
    """The calling profile's name when it is a honeypot (#357), else None.

    Every place a tool would tell its caller what the layers made of
    something asks this first: a honeypot is told nothing, and what it was
    sent is kept instead.
    """
    profile = current_scope().profile
    return profile.name if profile.honeypot else None


def check_blocklist(source: str, mode: Mode) -> bool:
    """Refuse block and flag on a source the caller's blocklist holds.

    Returns:
        Whether it is blocklisted, for redact, which proceeds and says so.

    Raises:
        BlockedSourceError: block or flag, and the source is on it.
    """
    profile, gateway_wide = _caller()
    blocked = is_blocked(source, profile, gateway_wide=gateway_wide)
    if blocked and mode is not Mode.REDACT:
        raise blocklisted(source, mode)
    return blocked
