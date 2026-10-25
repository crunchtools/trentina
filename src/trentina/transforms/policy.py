"""Whether a call minifies: one switch, inside the operator's bounds (#183, 0.38.0).

Output is minified by default. ``trentina_preprocess: false`` asks for the
exact text instead, which is what an agent needs before it edits and saves a
document back; ``true`` asks for minification on a tool whose default is
exact. It is a switch, not a menu: 0.37.0 let the agent name processors, and
the one decision an agent actually has is "shorter" or "exact".

The profile sets both bounds, as before:

* ``processors`` is what "minified" runs (default ``[detect]``, which picks
  the minifier by format).
* ``required`` is the FLOOR. Those run on every call, first, and ``false``
  cannot remove them. That is what makes HTML conversion mandatory for a
  profile that considers markup hostile enough.

What the switch can never do is touch ``defend()``. Transformation runs
before the perimeter (``base.py`` invariant 2), so the choice changes what is
scanned only in the sense that it changes what is delivered: the two are
always the same bytes. ``false`` is not unscanned, it is unminified, and
``l1/hidden.py`` still counts what conversion would have removed.

An omitted switch resolves to the tool's default BEFORE anything is checked,
the same rule ``ModePolicy.resolve`` follows, so absence is never a way around
the policy.

Every tool accepts the switch; ``instructions`` says so once per session.
Declaring it in each tool's schema is optional (``selectable``): Claude Code
forwards an undeclared argument, and 376 declarations cost a 376-tool profile ~15 KB.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..errors import TransformNotPermittedError

logger = logging.getLogger(__name__)

PREPROCESS_PARAM = "trentina_preprocess"

_SPELLED = {"true": True, "false": False}


def switch_value(requested: Any) -> Any:
    """``"true"``/``"false"`` as the booleans they spell; anything else unchanged."""
    if isinstance(requested, str):
        return _SPELLED.get(requested.strip().lower(), requested)
    return requested


#: Declines that mean a processor did not do its job, rather than that the
#: payload was not its shape. A REQUIRED processor that reports one refuses
#: the call. ``too_large`` is here because padding a payload past the parse
#: cap must not be a way around a converter the operator pinned.
FAILED_DECLINES = frozenset(
    {"error", "petit_error", "worker_error", "no_api_key", "empty_summary", "too_large"}
)

#: What the internal tools minify with, whatever the profile's processors
#: say: those are tuned for proxied output, and a profile that lists only
#: petit must not silently cost fetch its HTML conversion.
INTERNAL_CHAIN = ("detect",)

#: Whether each internal tool minifies when the switch is omitted. `read`
#: does not: agents edit the files they read.
INTERNAL_DEFAULTS: dict[str, bool] = {
    "fetch_tool": True,
    "content_tool": True,
    "read_tool": False,
}


@dataclass(frozen=True)
class PreProcessPolicy:
    """What a call runs: the floor, plus the chain when minification is on.

    ``chain``: what minification runs, in order; a ``required`` name is
    dropped from it. ``required``: the floor, run first on every call. ``default``:
    whether an omitted switch minifies.
    """

    chain: tuple[str, ...]
    required: tuple[str, ...] = ()
    default: bool = True
    # Whether the tool's schema declares the switch. Every tool accepts it.
    declared: bool = False
    # The profile's size budget: past it, `structured` clips long strings.
    target_bytes: int | None = None

    def __post_init__(self) -> None:
        floor = tuple(dict.fromkeys(self.required))
        object.__setattr__(self, "required", floor)
        chain = tuple(n for n in dict.fromkeys(self.chain) if n not in floor)
        object.__setattr__(self, "chain", chain)

    def minifies(self, requested: Any) -> bool:
        """Whether this call runs the chain.

        ``"true"`` and ``"false"`` count as the booleans: the switch is
        undeclared on most tools, and a client that marshals against the
        declared schema sends an undeclared value as a string (#244).

        Raises:
            TransformNotPermittedError: anything but a bool, its spelling, or None.
        """
        requested = switch_value(requested)
        if requested is None:
            return self.default
        if isinstance(requested, bool):
            return requested
        raise TransformNotPermittedError(["true", "false"])

    def resolve(self, requested: Any) -> tuple[str, ...]:
        """The processors this call runs, in order: required, then the chain.

        Raises:
            TransformNotPermittedError: see ``minifies``.
        """
        return self.required + (self.chain if self.minifies(requested) else ())


def standalone_policy(tool_name: str = "") -> PreProcessPolicy:
    """No gateway: the internal chain, no floor, the tool's own default and the default budget."""
    from ..gateway.profile import DEFAULT_TARGET_BYTES

    return PreProcessPolicy(
        INTERNAL_CHAIN,
        default=INTERNAL_DEFAULTS.get(tool_name, True),
        target_bytes=DEFAULT_TARGET_BYTES,
    )


def current_preprocess_policy(tool_name: str = "") -> PreProcessPolicy:
    """The policy the gateway bound for this call, else the standalone one."""
    from ..gateway.context import get_current_preprocess_policy

    bound = get_current_preprocess_policy()
    return bound if bound is not None else standalone_policy(tool_name)
