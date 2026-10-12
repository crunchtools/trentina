"""Where a call went, for the audit row (#266).

The audit said which profile called which tool and how it ended, never where
the call was pointed. After an incident that left 17,600 actions to
reconstruct, "which hosts did it fetch, who did it message" was the one
question the database could not answer.

Three kinds, each stored beside the call in ``gateway_calls``:

- ``fetch``: the URL's host, then ``#`` and ``sha256[:16]`` of the whole URL.
  The host is what fan-out counts; the hash tells two URLs on one host apart
  without keeping a path or query that may carry a token.
- ``search``: ``q#`` and ``sha256[:16]`` of the query. Repeats are visible,
  the words are not.
- ``model``: for an LLM proxy call (#297), the model the agent named,
  truncated. The provider is the row's backend.
- ``param``: for a proxied tool its backend declares in ``destination_params``,
  that argument's value — the channel, recipient, repo or queue — truncated.
- ``tunnel``: for a client-egress tunnel (#442), ``host:port`` as the client
  named it on its CONNECT line. The row's backend is ``egress``.
- ``git``: for the git transport (#453), ``owner/name`` as the gateway
  validated and lower-cased it, then for a push a space and each ref it
  named. The remote is the row's backend, ``git:<remote>``.

The value is caller-chosen, so it lives in the audit database only, which no
tool reads raw. It never goes to the log (#262), and ``quarantine_stats``
shows it only to the agent that chose it; the operator gets its fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .profile import Backend

#: Longest value recorded; a recipient list or channel id fits, an essay does not.
MAX_DESTINATION_CHARS = 256
#: Room left for ``#`` and the hash after a fetch host.
_MAX_HOST_CHARS = MAX_DESTINATION_CHARS - 17

FETCH_TOOL = "fetch_tool"
SEARCH_TOOL = "search_tool"


class DestinationKind(StrEnum):
    """What a destination row counts as. Stored in ``destination_kind``."""

    FETCH = "fetch"
    SEARCH = "search"
    PARAM = "param"
    MODEL = "model"
    TUNNEL = "tunnel"
    GIT = "git"


@dataclass(frozen=True)
class Destination:
    """One call's destination, as the audit row stores it."""

    value: str
    kind: DestinationKind


def fingerprint(text: str) -> str:
    """``sha256[:16]`` of *text*."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _fetch(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return f"{host[:_MAX_HOST_CHARS]}#{fingerprint(url)}"


#: Recipients kept from a list argument; with each capped, the JSON is bounded.
_MAX_ITEMS = 16
#: Recorded in place of a value that is neither a scalar nor a list of them.
NON_SCALAR = "<non-scalar>"

_Scalar = str | int | float | bool


def _param(value: Any) -> str | None:
    """The argument as recorded, built from a bounded slice of it.

    The input is capped BEFORE it is serialized: an agent-sized argument
    must not cost an agent-sized ``json.dumps`` on every call.

    Args:
        value: The declared argument as the agent sent it.

    Returns:
        None for an absent or empty value. A scalar as text, a list's first
        ``_MAX_ITEMS`` scalars as JSON, or ``NON_SCALAR`` for anything else,
        each at most ``MAX_DESTINATION_CHARS`` long.
    """
    if value is None or value == "":
        return None
    if isinstance(value, _Scalar):
        return str(value)[:MAX_DESTINATION_CHARS]
    if isinstance(value, list | tuple) and all(isinstance(v, _Scalar) for v in value[:_MAX_ITEMS]):
        head = [str(v)[:MAX_DESTINATION_CHARS] for v in value[:_MAX_ITEMS]]
        return json.dumps(head)[:MAX_DESTINATION_CHARS]
    return NON_SCALAR


def destination_of(backend: Backend, tool: str, arguments: dict[str, Any]) -> Destination | None:
    """The destination one call names, or None when it names none we record.

    Internal ``fetch_tool`` and ``search_tool`` are recognized by name on the
    internal backend only: a proxied tool that happens to share the name is
    not ours, and is recorded only if its backend declares it.
    """
    if backend.is_internal:
        if tool == FETCH_TOOL and isinstance(url := arguments.get("url"), str):
            return Destination(_fetch(url), DestinationKind.FETCH)
        if tool == SEARCH_TOOL and isinstance(query := arguments.get("query"), str):
            return Destination(f"q#{fingerprint(query)}", DestinationKind.SEARCH)
        return None
    param = backend.destination_params.get(tool)
    if param is None:
        return None
    value = _param(arguments.get(param))
    return Destination(value, DestinationKind.PARAM) if value is not None else None
