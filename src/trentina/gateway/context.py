"""Request context for threading profile information to internal tools.

Uses contextvars to propagate the authenticated profile from the gateway's
tool dispatch layer down to the quarantine system's provider selection. This
allows per-profile API keys and model overrides to work for internal://
tool calls without changing the MCP protocol or tool signatures.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .errors import ScopeError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..modes import ModePolicy
    from ..transforms.policy import PreProcessPolicy
    from .profile import Profile

_current_profile: ContextVar[Profile | None] = ContextVar("current_profile", default=None)
_current_policy: ContextVar[ModePolicy | None] = ContextVar("current_mode_policy", default=None)
_current_preprocess: ContextVar[PreProcessPolicy | None] = ContextVar(
    "current_preprocess_policy", default=None
)


@dataclass(frozen=True)
class PartsOffer:
    """That this call's response may be delivered in parts (#446), and as whose.

    Bound for an internal tool only when the calling profile can call
    ``read_part``: a profile that cannot read part 2 is never handed a part 1.
    ``backend`` and ``tool`` are what the rest is judged, audited and policed
    as; ``label`` and ``reader`` are the names the agent calls them by.
    """

    backend: str
    tool: str
    label: str
    reader: str


_current_parts: ContextVar[PartsOffer | None] = ContextVar("current_parts_offer", default=None)
# What ties an audit row to the rows written beside it (#357): the MCP
# session a request arrived on, as a fingerprint, and one random reference
# per tools/call. Empty outside a gateway request, and for a client that
# sends no session header.
current_session: ContextVar[str] = ContextVar("current_session", default="")
current_call: ContextVar[str] = ContextVar("current_call", default="")
# The real caller behind a federated request (#592, C2): the (peer, sub) an
# primary JWT carried — the primary peer whose key VERIFIED (the actor) and the
# caller it ASSERTS. None for every non-federated request. Set beside
# ``current_session`` from one request's ``request.state`` and read by the audit;
# ``caller_sub`` is peer-chosen and is an audit fact only, never an input to
# scope, role, policy or a guard (cto ruling, #592 C2).
current_caller: ContextVar[tuple[str, str] | None] = ContextVar("current_caller", default=None)


def session_fingerprint(session_id: str) -> str:
    """What ``current_session`` holds for an MCP session id: the id is a
    bearer of the session, so only this reaches the audit."""
    return hashlib.sha256(session_id.encode()).hexdigest()[:16] if session_id else ""


@contextmanager
def profile_context(
    profile: Profile,
    policy: ModePolicy | None = None,
    preprocess: PreProcessPolicy | None = None,
    parts: PartsOffer | None = None,
) -> Iterator[None]:
    """Bind ``profile`` to the current async context for the duration of the block.

    Used by the gateway around internal:// tool dispatch. Restoring the
    previous value on exit is what keeps a profile from leaking into a
    reused async task, including when the tool call raises. ``policy`` is
    the call's mode policy (#193): what a web tool's refusal offers.
    ``preprocess`` is the tool's transform policy (#183), which the tool
    resolves against its own default. ``parts`` is the offer to deliver
    the response in parts (#446); without it the tool answers whole.
    """
    token = _current_profile.set(profile)
    policy_token = _current_policy.set(policy)
    preprocess_token = _current_preprocess.set(preprocess)
    parts_token = _current_parts.set(parts)
    try:
        yield
    finally:
        _current_parts.reset(parts_token)
        _current_preprocess.reset(preprocess_token)
        _current_policy.reset(policy_token)
        _current_profile.reset(token)


def get_current_policy() -> ModePolicy | None:
    """The mode policy the gateway bound for this call, or None standalone."""
    return _current_policy.get()


def get_current_preprocess_policy() -> PreProcessPolicy | None:
    """The transform policy the gateway bound for this call, or None standalone."""
    return _current_preprocess.get()


def get_current_parts() -> PartsOffer | None:
    """The offer to deliver this call's response in parts, or None."""
    return _current_parts.get()


def get_current_profile() -> Profile:
    """The profile bound to the current call.

    Behind a live gateway the router binds one around every internal dispatch.
    With no gateway registered the process is standalone — a single operator
    profile synthesized from the environment (``standalone.standalone_profile``),
    read the same way a bound profile is. A live gateway with nothing bound is a
    path nobody designed, so the honest answer is to refuse (fail closed) rather
    than act gateway-wide.

    Raises:
        ScopeError: a live gateway is registered but no profile is bound to the
            current call — an undesigned path, refused rather than served.
    """
    profile = _current_profile.get()
    if profile is not None:
        return profile
    # Lazy: ``loader`` is mid-import when ``context`` is first reached on some
    # import orders (database → modes → context), so a top-level import cycles.
    from .loader import get_active_config
    from .standalone import environment_operator

    if get_active_config() is None:
        return environment_operator()
    raise ScopeError("no calling profile bound — refusing to act gateway-wide")
