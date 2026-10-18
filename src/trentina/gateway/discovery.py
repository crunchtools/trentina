"""Tool discovery for clients without their own tool search (#473).

A client that sends every listed schema with every request pays for all of
them on every turn: Kagetora's 361 tools were ~95% of each request. Claude
Code defers MCP tools and searches them itself; a client without that needs
the gateway to list less. ``tool_discovery.mode`` picks how, per profile:

- ``search``: the core tools plus ``find_tools`` and ``call_tool``.
  ``call_tool`` re-enters the router with the real served name, so the call
  meets every rule a direct one does, and the audit row and the gatekeeper
  see the real (backend, tool). Nothing here forwards anything.
- ``dynamic``: the core tools plus ``load_tools``, and whatever this session
  has loaded. Loading pushes ``notifications/tools/list_changed`` to the
  session, so real names reach the client and hooks keyed on them work.

Both read only the served aggregate, which the perimeter has judged: what
``find_tools`` returns is text tools/list would have delivered anyway. A tool
not listed is not forbidden: the allowlist is the policy, and a direct call
by a served name routes as it always did.

Every word of the discovery tools and of the category line in the session
instructions is the gateway's or the operator's (backend and category names
from the profile), never a backend's.
"""

from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from . import paging
from .names import resolve_name
from .tool_search import Entry, ToolIndex

if TYPE_CHECKING:
    from .profile import Profile

FIND_TOOLS = "find_tools"
CALL_TOOL = "call_tool"
LOAD_TOOLS = "load_tools"

# Most tools one session may have loaded: a profile has a few hundred at most.
MAX_LOADED = 1024

# profile name -> (the aggregate it was built from, its index, the tools in it)
_indexes: dict[str, tuple[list[dict[str, Any]], ToolIndex, list[dict[str, Any]]]] = {}
# session fingerprint -> (profile name, served names loaded)
_loaded: dict[str, tuple[str, set[str]]] = {}


def meta_names(profile: Profile) -> frozenset[str]:
    """The discovery tools this profile's mode serves."""
    mode = profile.tool_discovery.mode
    if mode == "search":
        return frozenset({FIND_TOOLS, CALL_TOOL})
    if mode == "dynamic":
        return frozenset({LOAD_TOOLS})
    return frozenset()


def categories(profile: Profile) -> dict[str, list[str]]:
    """Category name to its backends, in profile order."""
    order = dict.fromkeys(profile.category_of(b) for b in profile.backends)
    return {c: [b for b in profile.backends if profile.category_of(b) == c] for c in order}


def instructions(profile: Profile) -> str:
    """The session-instructions sentences for discovery, or ``""``.

    Built from profile configuration only. Said when the mode lists less
    than everything, or when the operator named categories: a client that
    searches by itself reads these instructions before it searches.
    """
    config = profile.tool_discovery
    if config.lists_everything and not config.categories:
        return ""
    groups = "; ".join(
        name if backends == [name] else f"{name} ({', '.join(backends)})"
        for name, backends in categories(profile).items()
    )
    lines = [f"Tool categories: {groups}."] if groups else []
    if config.mode == "search":
        lines.append(
            "Only a few tools are listed. Find others with find_tools and call them with call_tool."
        )
    elif config.mode == "dynamic":
        lines.append("Only a few tools are listed. Add others with load_tools.")
    return " ".join(lines)


def describe(profile: Profile, backend: str, tool: dict[str, Any]) -> dict[str, Any]:
    """``tool`` with its category leading its description, when the profile asks.

    Applied after the perimeter scan, like ``insert_params``: the prefix is
    the operator's word, and the rest is the judged text unchanged.
    """
    if not profile.tool_discovery.describe_backend:
        return tool
    description = str(tool.get("description") or "")
    return {**tool, "description": f"{profile.category_of(backend)}: {description}".rstrip()}


def _definitions(profile: Profile) -> list[dict[str, Any]]:
    config = profile.tool_discovery
    category_schema: dict[str, Any] = {
        "type": "string",
        "enum": list(categories(profile)),
        "description": "Limit to one category",
    }
    found = {
        "name": FIND_TOOLS,
        "description": (
            "Search this gateway's tools by what you want to do. Returns the best "
            "matches with their input schemas; call one with call_tool."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What you want to do, in a few words"},
                "category": category_schema,
                "limit": {"type": "integer", "minimum": 1, "maximum": config.top_k},
            },
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True},
    }
    call = {
        "name": CALL_TOOL,
        "description": (
            "Call a tool that find_tools returned, by its name, with its arguments. "
            "It runs exactly as if it were listed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The tool's name from find_tools"},
                "arguments": {"type": "object", "description": "The tool's arguments"},
            },
            "required": ["name"],
        },
    }
    load = {
        "name": LOAD_TOOLS,
        "description": (
            "Add tools to your tool list: every tool in a category, or the best "
            "matches for what you want to do. Your tool list then changes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": category_schema,
                "query": {"type": "string", "description": "What you want to do, in a few words"},
            },
        },
        "annotations": {"readOnlyHint": True},
    }
    return [t for t in (found, call, load) if t["name"] in meta_names(profile)]


def _core(profile: Profile, name: str) -> bool:
    """Always listed: the operator's core, and ``read_part``, without which a
    part 1 handed to this profile could not be followed (#340)."""
    if any(fnmatchcase(name, pattern) for pattern in profile.tool_discovery.core):
        return True
    resolved = resolve_name(profile, name)
    if resolved is None or resolved[1] != paging.READ_PART_TOOL:
        return False
    backend = profile.backends.get(resolved[0])
    return backend is not None and backend.is_internal


def shape(profile: Profile, aggregate: list[dict[str, Any]], session: str) -> list[dict[str, Any]]:
    """What tools/list serves this session from the profile's aggregate.

    A served tool whose name is a discovery tool's is left out under a mode
    that serves that discovery tool: the name can mean one thing only.
    """
    if profile.tool_discovery.lists_everything:
        return aggregate
    loaded = _loaded_names(profile, session)
    shadowed = meta_names(profile)
    listed = [
        tool
        for tool in aggregate
        if tool["name"] not in shadowed and (_core(profile, tool["name"]) or tool["name"] in loaded)
    ]
    return listed + _definitions(profile)


def _index(
    profile: Profile, aggregate: list[dict[str, Any]]
) -> tuple[ToolIndex, list[dict[str, Any]]]:
    cached = _indexes.get(profile.name)
    if cached is not None and cached[0] is aggregate:
        return cached[1], cached[2]
    shadowed = meta_names(profile)
    tools = [t for t in aggregate if t["name"] not in shadowed]
    entries = []
    for tool in tools:
        backend = (resolve_name(profile, tool["name"]) or ("", ""))[0]
        entries.append(
            Entry(
                name=tool["name"],
                category=profile.category_of(backend) if backend else "",
                backend=backend,
                description=str(tool.get("description") or ""),
            )
        )
    index = ToolIndex(entries)
    _indexes[profile.name] = (aggregate, index, tools)
    return index, tools


def _category_arg(profile: Profile, arguments: dict[str, Any]) -> str | None:
    category = arguments.get("category")
    if category in (None, ""):
        return None
    if not isinstance(category, str) or category not in categories(profile):
        raise ValueError("category is not one of this profile's categories")
    return category


def _query_arg(arguments: dict[str, Any], required: bool) -> str | None:
    query = arguments.get("query")
    if query in (None, "") and not required:
        return None
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    return query


def find(
    profile: Profile, aggregate: list[dict[str, Any]], arguments: dict[str, Any]
) -> dict[str, Any]:
    """``find_tools``: the best matches, each ready to call.

    Raises:
        ValueError: on arguments it cannot read; the router refuses the call.
    """
    query = _query_arg(arguments, required=True)
    category = _category_arg(profile, arguments)
    limit = arguments.get("limit", profile.tool_discovery.top_k)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    limit = min(limit, profile.tool_discovery.top_k)
    index, tools = _index(profile, aggregate)
    hits = [tools[i] for i in index.search(query or "", limit, category)]
    body = {
        "tools": [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "inputSchema": t.get("inputSchema", {}),
            }
            for t in hits
        ],
        "call_with": f'{CALL_TOOL}(name="<name>", arguments={{...}})',
    }
    return _text(body)


def load(
    profile: Profile, aggregate: list[dict[str, Any]], session: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    """``load_tools``: add a category's tools, or a query's matches, to the
    session's list. Returns the result and whether the list grew.

    Raises:
        ValueError: on arguments it cannot read, or a session it cannot name.
    """
    if not session:
        raise ValueError(
            "load_tools needs an MCP session (Mcp-Session-Id). A client without "
            "one can be given tool_discovery.mode: search instead"
        )
    category = _category_arg(profile, arguments)
    query = _query_arg(arguments, required=category is None)
    index, tools = _index(profile, aggregate)
    if query is not None:
        hits = index.search(query, profile.tool_discovery.top_k, category)
        picked = [tools[i]["name"] for i in hits]
    else:
        picked = [
            tools[i]["name"] for i, entry in enumerate(index.entries) if entry.category == category
        ]
    owner, names = _loaded.get(session, (profile.name, set()))
    if owner != profile.name:
        # A fingerprint is one session, and a session one profile; a
        # mismatch is a reload or a collision, and either starts afresh.
        names = set()
    added = []
    for name in picked:
        if name in names:
            continue
        if len(names) >= MAX_LOADED:
            break
        names.add(name)
        added.append(name)
    _loaded[session] = (profile.name, names)
    body = {
        "loaded": added,
        "note": (
            "Your tool list has changed. If your client did not refresh it, list tools again."
        ),
    }
    return _text(body), bool(added)


def _text(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}],
        "isError": False,
    }


def _loaded_names(profile: Profile, session: str) -> set[str]:
    owner, names = _loaded.get(session, ("", set()))
    return names if session and owner == profile.name else set()


def forget_session(fingerprint: str) -> None:
    """Drop what a session loaded, when the session ends."""
    _loaded.pop(fingerprint, None)


def reset() -> None:
    """Drop every index and loaded set (for testing)."""
    _indexes.clear()
    _loaded.clear()
