"""Tool-allowlist filter for `tools/list` responses.

Applied to the aggregated backend tool list before returning to the consumer.
Tool definitions excluded by the filter never reach the consumer's prompt
context — this is where actual token savings come from versus settings.json
deny lists which keep definitions in context.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from .paging import READ_PART_TOOL

if TYPE_CHECKING:
    from .profile import Backend


def _withheld(name: str, backend: Backend) -> bool:
    """A tool no allowlist may offer, whatever the profile says.

    One entry: a FEDERATED peer's own ``read_part``. The parts of a peer's
    paged response are proxied — ``parts.py`` calls the peer's reader itself,
    with the lead-in, in order, and stops at a flagged part — so offering the
    peer's reader to the agent is a second, unjudged way to the same parts, and
    the peer answers it against its OWN view of who is asking. It is withheld
    from ``tools/list`` and, because the router re-checks this filter before
    dispatch, refused as a direct ``tools/call`` too (#592).
    """
    return backend.federated is not None and name == READ_PART_TOOL


def filter_tools(tools: list[dict[str, Any]], backend: Backend) -> list[dict[str, Any]]:
    """Filter a backend's tool list against the backend's allow/deny patterns.

    A tool is kept iff it is not withheld outright (``_withheld``), its name
    matches any allow pattern AND it does not match any deny pattern. Patterns
    use shell-style globs validated at profile load time (see
    profile.GLOB_PATTERN_RE).

    Args:
        tools: List of MCP tool definitions (each a dict with at least "name").
        backend: Backend config carrying `tools_allow` + `tools_deny` glob lists.

    Returns:
        Filtered tool list. Empty `tools_allow` results in an empty output —
        the default model value is `["*"]` (allow all), so a profile must
        explicitly opt out of that to reach the empty-allow case.
    """
    allow = backend.tools_allow
    deny = backend.tools_deny

    kept: list[dict[str, Any]] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            continue
        if _withheld(name, backend):
            continue
        if not any(fnmatchcase(name, pat) for pat in allow):
            continue
        if deny and any(fnmatchcase(name, pat) for pat in deny):
            continue
        kept.append(tool)
    return kept
