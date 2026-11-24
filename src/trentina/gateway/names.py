"""Short tool names: the simplest name that says what a tool does (0.38.0).

Until 0.38.0 every tool was served as ``<backend>__<tool>``: ``jira__jira_search``,
``cloudflare__list_zones_tool``, ``wp-blog__wordpress_get_post``. The
backend is already in the client's own prefix (``mcp__trentina__``), the
tool repeats it, and ``_tool`` says nothing. On a 376-tool profile the names were 10 KB
before a client prefixed them.

The rule, applied without a model:

1. Drop a trailing ``_tool``.
2. Drop the longest run of leading words that EVERY tool of that backend
   shares (``jira_``, ``wordpress_``, ``gemini_``), and a leading word that
   is the backend's own name, unless one word would be all that is left:
   ``memory_store`` stays, ``jira_get_issue`` becomes ``get_issue``.
3. Where two backends' tools still end up with the same name, prefix each
   with its backend's tag: ``Backend.name_tag``, else the backend name.
   ``work_send_gmail_message`` and ``home_send_gmail_message``, never
   ``send_gmail_message1``, because a number cannot tell an agent which
   account it is about to send from.
4. A backend with ``tool_prefix`` (6.31.0) skips 1-3: every tool is served
   as ``<prefix>_<tool>``, collision or not, so the name alone says where a
   call lands (``work_memory_store``, ``personal_memory_store``). A name it
   replaces is retired: reserved forever, never resolved again.

A name, once issued to a profile, is never reassigned (``database.tool_names``).
A backend added later cannot rename a tool an agent already knows: the
newcomer takes the tag. Everything behind the edge — allowlists, guards,
``preprocess_tools``, the verdict cache, the audit log — keeps using the real
``(backend, tool)``; only ``tools/list`` and ``tools/call`` see short names.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from ..database import (
    issue_tool_names,
    issued_tool_name,
    issued_tool_names,
    retire_tool_names,
    retired_tool_names,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .profile import Backend, Profile


#: How ``<backend>__<tool>`` is spelled, the form served before 0.38.0.
NAMESPACE_SEP = "__"

Pair = tuple[str, str]  # (backend, tool)

logger = logging.getLogger(__name__)

_INVALID = re.compile(r"[^A-Za-z0-9-]+")

# Names issued per profile, read through from the database: a name is never
# reassigned, so this never goes stale, only incomplete.
_issued: dict[str, dict[str, Pair]] = {}


def _clean(name: str) -> str:
    """Letters, digits and hyphens joined by single underscores; never ``__``."""
    return "_".join(part for part in _INVALID.split(name) if part)


def _shared_words(names: list[str]) -> int:
    """How many leading words every name shares, leaving each at least one."""
    split = [n.split("_") for n in names]
    if len(split) < 2:
        return 0
    shared = 0
    for words in zip(*split, strict=False):
        if len(set(words)) != 1 or any(len(s) <= shared + 1 for s in split):
            break
        shared += 1
    return shared


def base_names(backend: str, tools: Iterable[str]) -> dict[str, str]:
    """Each tool's short name within its backend, before any cross-backend collision.

    Two tools of one backend that would share a name keep their full names
    instead: a tag cannot tell them apart.
    """
    cleaned = {t: _clean(t.removesuffix("_tool")) or _clean(t) for t in tools}
    shared = _shared_words(list(cleaned.values()))
    own = set(_clean(backend).replace("-", "_").split("_"))
    short: dict[str, str] = {}
    for tool, name in cleaned.items():
        words = name.split("_")
        # A lone verb (`store`, `delete`) says nothing about what it acts on,
        # so the prefix stays when it is all that would be left.
        drop = shared if len(words) - shared > 1 else 0
        words = words[drop:]
        if len(words) > 2 and words[0] in own:
            words = words[1:]
        short[tool] = "_".join(words)
    counts = Counter(short.values())
    return {t: (s if counts[s] == 1 else _clean(t)) for t, s in short.items()}


def tag_of(name: str, backend: Backend) -> str:
    """The prefix that tells this backend's tools from another's."""
    return backend.name_tag or _clean(name.replace("-", "_"))


def prefixed(
    wanted: list[Pair],
    prefixes: dict[str, str],
    issued: dict[str, Pair],
    retired: set[str],
) -> tuple[dict[str, Pair], dict[str, Pair]]:
    """Names forced by ``tool_prefix``: which to issue, and which to retire.

    A forced name already held by another tool, live or retired, is not
    taken: that tool keeps its name, this one falls back to rules 1-3, and
    the clash is logged by backend for the operator to resolve.

    Returns:
        ``(issue, retire)``: forced names not yet issued, and the names they
        replace.
    """
    by_pair = {pair: name for name, pair in issued.items()}
    issue: dict[str, Pair] = {}
    retire: dict[str, Pair] = {}
    for pair in wanted:
        prefix = prefixes.get(pair[0])
        if prefix is None:
            continue
        name = f"{prefix}_{_clean(pair[1].removesuffix('_tool')) or _clean(pair[1])}"
        if by_pair.get(pair) == name:
            continue
        holder = issued.get(name)
        if (holder is not None and holder != pair) or name in retired:
            logger.warning("tool_prefix name already held; backend=%s keeps its name", pair[0])
            continue
        issue[name] = pair
        if pair in by_pair:
            retire[by_pair[pair]] = pair
    return issue, retire


def assign(
    wanted: list[Pair],
    tags: dict[str, str],
    issued: dict[str, Pair],
    reserved: set[str] | frozenset[str] = frozenset(),
) -> tuple[dict[Pair, str], dict[str, Pair]]:
    """The served name of every wanted tool, and which names are new.

    Args:
        wanted: every (backend, tool) the profile serves now.
        tags: each backend's tag.
        issued: every name issued to this profile before, including names
            of tools it no longer serves: those stay reserved.
        reserved: retired names, never issued again.

    Returns:
        ``(served, new)``: the name per tool, and the names to record.
    """
    by_name = {pair: name for name, pair in issued.items()}
    served = {pair: by_name[pair] for pair in wanted if pair in by_name}
    tools: dict[str, list[str]] = defaultdict(list)
    for backend, tool in wanted:
        tools[backend].append(tool)
    base = {
        (backend, tool): short
        for backend, names in tools.items()
        for tool, short in base_names(backend, names).items()
    }
    clashes = Counter(base.values())
    taken = set(issued) | set(reserved)
    new: dict[str, Pair] = {}
    for pair in wanted:
        if pair in served:
            continue
        name = base[pair]
        if clashes[name] > 1 or name in taken:
            name = f"{tags[pair[0]]}_{name}"
        if name in taken:
            # Only a tag clash lands here. The form every client understood
            # before 0.38.0 still routes, and it is unique by construction.
            name = f"{pair[0]}{NAMESPACE_SEP}{pair[1]}"
        taken.add(name)
        new[name] = pair
        served[pair] = name
    return served, new


def forget_issued_names() -> None:
    """Drop the in-memory copy (for testing); the database keeps every name."""
    _issued.clear()


def _issued_names(profile_name: str) -> dict[str, Pair]:
    names = _issued.get(profile_name)
    if names is None:
        names = _issued[profile_name] = issued_tool_names(profile_name)
    return names


def _apply_prefixes(profile: Profile, pairs: list[Pair]) -> set[str]:
    """Issue every ``tool_prefix`` name and retire what it replaces.

    Returns:
        The profile's retired names, which ``assign`` must never issue.
    """
    prefixes = {b: be.tool_prefix for b, be in profile.backends.items() if be.tool_prefix}
    if not prefixes:
        return set()
    retired = retired_tool_names(profile.name)
    forced, old = prefixed(pairs, prefixes, _issued_names(profile.name), retired)
    if forced:
        # Retire first: the table holds one live name per tool.
        retire_tool_names(profile.name, old)
        issue_tool_names(profile.name, forced)
        _issued[profile.name] = issued_tool_names(profile.name)
    return retired | set(old)


def serve_short_names(profile: Profile, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The aggregate, ``<backend>__<tool>`` names in, served names out.

    Issues and records a name for every tool that has none. Unchanged when
    the profile turns ``short_names`` off.
    """
    if not profile.short_names:
        return tools
    pairs: list[Pair] = [
        (backend, name) for backend, _, name in (t["name"].partition(NAMESPACE_SEP) for t in tools)
    ]
    tags = {b: tag_of(b, backend) for b, backend in profile.backends.items()}
    retired = _apply_prefixes(profile, pairs)
    served, new = assign(pairs, tags, _issued_names(profile.name), retired)
    if new:
        # Recorded, then read back: a row another writer got in first wins,
        # and this list is assigned again around it.
        issue_tool_names(profile.name, new)
        _issued[profile.name] = issued_tool_names(profile.name)
        served, new = assign(pairs, tags, _issued[profile.name], retired)
        issue_tool_names(profile.name, new)
        _issued[profile.name].update(new)
    return [{**tool, "name": served[pair]} for tool, pair in zip(tools, pairs, strict=True)]


def served_name(profile: Profile, backend: str, tool: str) -> str | None:
    """The name tools/list serves ``(backend, tool)`` under, or None if it never has.

    For text the gateway writes that names one of its own tools (#340): an
    agent can only call the name it was served.
    """
    if backend not in profile.backends:
        return None
    if not profile.short_names:
        return f"{backend}{NAMESPACE_SEP}{tool}"
    for name, pair in _issued_names(profile.name).items():
        if pair == (backend, tool):
            return name
    return None


def resolve_name(profile: Profile, name: str) -> Pair | None:
    """The (backend, tool) a served name stands for, or None.

    Only the names tools/list serves: short names, or ``<backend>__<tool>``
    when the profile turns ``short_names`` off. The long form stopped
    resolving under short names in 0.43.0; it was a pre-0.38.0 client's.
    """
    if not profile.short_names:
        backend, sep, tool = name.partition(NAMESPACE_SEP)
        return (backend, tool) if sep and backend in profile.backends else None

    names = _issued_names(profile.name)
    pair = names.get(name)
    if pair is None:
        # Issued by another writer since this one read the table: one row.
        pair = issued_tool_name(profile.name, name)
        if pair is not None:
            names[name] = pair
    return pair
