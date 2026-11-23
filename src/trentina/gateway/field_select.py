"""Field select: exact values out of a tool result, by path (#915).

A seat that needs a review's ``commit_id`` does not need its body. Until this,
it got both or neither: ``block`` refused the whole review list because one
body was flagged, and ``redact`` asked L3 to copy forty hex digits, which it
garbled or declined. So the seat went round the gateway to the API.

``trentina_select`` names the leaves the call wants, as jq-like paths
(``[].commit_id``, ``[].user.login``, ``head.sha``), and the gateway picks
them out of the RAW result before anything else reads it:

* **Every picked leaf is a structurally safe value** (below): the projection
  is delivered and no layer reads it. There is nothing in it to read. A
  40-digit hex string cannot carry an instruction, and the gateway decides
  that with a regular expression, not a model.
* **Any picked leaf is not**: the projection, and only the projection, takes
  the ordinary path under the call's mode. A flagged body nobody selected
  is not in it, so it cannot refuse it. Free text never passes unjudged.

Safe is decided by the leaf's KEY and checked against its VALUE. Numbers,
booleans and null are safe under any key. A string is safe only under a key
with a type, and only if it matches that type exactly: ``login`` must be a
GitHub login, ``sha`` forty or sixty-four lowercase hex digits, ``*_at`` an
ISO 8601 timestamp, ``state`` one of a closed set of words. A string under any
other key, a ``name`` or ``body`` or ``url``, is free text. So is a typed key
whose value does not match: ``"login": "ignore all previous"`` is judged,
never delivered on its key's say-so.

The one safe type an outsider chooses is a login: a 39-character
hyphenated word, ``ignore-previous-instructions-run-this``, is a real
account name GitHub would register. That is the residual this accepts, and
``docs/field-select.md`` names it.

Paths are a small grammar, not jq: keys, and ``[]`` for every element of a
list. No filters, no indices, no recursion. The projection keeps the
result's shape (jq's ``pick``), so ``[].commit_id`` and ``[].user.login``
come back as one list of ``{"commit_id": …, "user": {"login": …}}`` with the
two values of each review side by side.

Iterative, like ``jsonwalk``: a depth bomb in a backend's JSON is an
attacker's RecursionError.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

#: At most this many paths in one call, each at most this long and this deep.
MAX_PATHS = 32
MAX_PATH_CHARS = 256
MAX_PATH_SEGMENTS = 16

#: What the audit's ``selected`` column says of a select call: every leaf typed
#: and none read, the projection judged, or the result not one JSON document.
UNJUDGED, JUDGED, REFUSED = "unjudged", "judged", "refused"

ITERATE = "[]"
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")

_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# GitHub's own rule: alphanumerics and single hyphens, no leading or trailing
# hyphen, at most 39. An app's account adds "[bot]".
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}(?:\[bot\])?")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)  # [0-9], not \d: \d is every script's digits

_SHA_KEYS = frozenset({"sha", "oid", "commit_id", "original_commit_id", "tree_id"})
_TIMESTAMP_KEYS = frozenset({"date", "timestamp"})


def _words(*words: str) -> frozenset[str]:
    """A closed vocabulary, in GitHub's REST spelling and its GraphQL capitals."""
    return frozenset({*words, *(w.upper() for w in words)})


#: Keys whose value is one of a closed set of words, the union across the
#: objects that use the key (a review's state, a pull request's, a status's).
ENUMS: dict[str, frozenset[str]] = {
    "state": _words(
        "open", "closed", "merged", "approved", "changes_requested", "commented",
        "dismissed", "pending", "success", "failure", "error", "active",
        "inactive", "in_progress", "queued", "waiting", "deleted",
        "disabled_manually", "disabled_inactivity",
    ),
    "conclusion": _words(
        "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
        "action_required", "stale", "startup_failure",
    ),
    "status": _words(
        "queued", "in_progress", "completed", "waiting", "requested", "pending",
        "added", "removed", "modified", "renamed", "copied", "changed", "unchanged",
    ),
    "author_association": _words(
        "collaborator", "contributor", "first_timer", "first_time_contributor",
        "mannequin", "member", "none", "owner",
    ),
    "mergeable_state": _words(
        "behind", "blocked", "clean", "dirty", "draft", "has_hooks", "unknown", "unstable",
    ),
    "state_reason": _words("completed", "not_planned", "reopened", "duplicate"),
    "type": frozenset({"User", "Bot", "Organization"}),
    "side": _words("left", "right"),
    "start_side": _words("left", "right"),
    "subject_type": _words("line", "file"),
}  # fmt: skip


class SelectPathError(ValueError):
    """A path outside the grammar. Says which rule, never echoes the path."""


@dataclass(frozen=True)
class Projection:
    """What ``project`` picked: the JSON to deliver, and whether it may skip the layers."""

    text: str
    leaves: int
    safe: bool


def parse_paths(value: Any) -> tuple[tuple[str, ...], ...]:
    """``trentina_select`` as tuples of segments, each a key or ``ITERATE``.

    Raises:
        SelectPathError: not a non-empty list of strings in the grammar, or
            over the limits.
    """
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise SelectPathError("trentina_select must be a non-empty list of paths")
    if len(value) > MAX_PATHS:
        raise SelectPathError(f"at most {MAX_PATHS} paths")
    paths = []
    for raw in value:
        if not isinstance(raw, str) or not raw or len(raw) > MAX_PATH_CHARS:
            raise SelectPathError(f"each path is a string of 1 to {MAX_PATH_CHARS} characters")
        paths.append(_parse_path(raw))
    return tuple(dict.fromkeys(paths))


def _parse_path(raw: str) -> tuple[str, ...]:
    """``.a[].b`` or ``a[].b`` as ``("a", "[]", "b")``; a key after anything needs a dot."""
    segments: list[str] = []
    pos = 0
    while pos < len(raw):
        if raw.startswith(ITERATE, pos):
            segments.append(ITERATE)
            pos += len(ITERATE)
            continue
        dotted = raw.startswith(".", pos)
        if dotted:
            pos += 1
            if raw.startswith(ITERATE, pos):  # jq's ".[]"
                continue
        match = _KEY.match(raw, pos)
        if match is None or (segments and not dotted):
            raise SelectPathError(
                "a path is keys joined by '.', and '[]' for every element of a list"
            )
        segments.append(match.group())
        pos = match.end()
    if not segments:
        raise SelectPathError("a path names at least one key or '[]'")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise SelectPathError(f"a path has at most {MAX_PATH_SEGMENTS} segments")
    return tuple(segments)


def key_path(path: tuple[str, ...]) -> str:
    """The keys of a parsed path joined by dots, ``[]`` left out: what a guard matches.

    ``labels[].name`` is ``labels.name``. A guard pattern cannot hold a
    bracket (``ParameterConstraint``), and which FIELD is read is the policy;
    which list it sits in is not.
    """
    return ".".join(s for s in path if s != ITERATE)


def document_of(content_blocks: list[Any] | None, structured: Any) -> Any:
    """The result as one JSON value: its ``structuredContent``, else its one text block.

    Raises:
        ValueError: neither is there, or the text is not JSON.
    """
    if isinstance(structured, (dict, list)):
        return structured
    texts = [
        b.get("text")
        for b in content_blocks or ()
        if isinstance(b, dict) and b.get("type") == "text"
    ]
    if len(texts) != 1 or not isinstance(texts[0], str):
        raise ValueError("the result is not one JSON document")
    try:
        return json.loads(texts[0])
    except (ValueError, RecursionError):
        raise ValueError("the result is not JSON") from None


_MISSING = object()


def project(document: Any, paths: tuple[tuple[str, ...], ...]) -> Projection:
    """Pick ``paths`` out of ``document`` and type every leaf picked.

    Raises:
        ValueError: a subtree picked whole is too deep to serialize.
    """
    picked: Any = _MISSING
    for path in paths:
        picked = _merge(picked, _pick(document, path))
    if picked is _MISSING:
        picked = None
    leaves, safe = _leaves(picked)
    try:
        text = json.dumps(picked, ensure_ascii=False, separators=(",", ":"))
    except RecursionError:
        raise ValueError("the selection is nested too deeply") from None
    return Projection(text=text, leaves=leaves, safe=safe)


def _pick(document: Any, path: tuple[str, ...]) -> Any:
    """One path's projection of ``document``, the shape kept; ``_MISSING`` if absent.

    Built bottom up from an explicit stack, so depth is the path's (at most
    ``MAX_PATH_SEGMENTS``) times the lists it crosses, never the document's.
    """
    # Each frame: the node, the segment index, and a slot to fill.
    root: list[Any] = [_MISSING]
    stack: list[tuple[Any, int, list[Any], int]] = [(document, 0, root, 0)]
    while stack:
        node, i, slot, at = stack.pop()
        if i == len(path):
            slot[at] = node
            continue
        segment = path[i]
        if segment == ITERATE:
            if not isinstance(node, list):
                continue
            items: list[Any] = [_MISSING] * len(node)
            slot[at] = items
            for j, item in enumerate(node):
                stack.append((item, i + 1, items, j))
        elif isinstance(node, dict) and segment in node:
            inner: list[Any] = [_MISSING]
            slot[at] = _Keyed(segment, inner)
            stack.append((node[segment], i + 1, inner, 0))
    return _finish(root[0])


@dataclass
class _Keyed:
    """A key picked on the way down, its value filled in later."""

    key: str
    value: list[Any]


def _finish(node: Any) -> Any:
    """``_pick``'s scaffolding as plain JSON, a key whose value was absent dropped."""
    out: list[Any] = [_MISSING]
    stack: list[tuple[Any, list[Any] | dict[str, Any], Any]] = [(node, out, 0)]
    while stack:
        item, parent, at = stack.pop()
        if isinstance(item, _Keyed):
            if item.value[0] is _MISSING:
                continue
            obj: dict[str, Any] = {}
            parent[at] = obj
            stack.append((item.value[0], obj, item.key))
        elif isinstance(item, list) and item and isinstance(parent, (list, dict)):
            # Only a list _pick built holds _MISSING; a picked list is copied as is.
            if any(x is _MISSING or isinstance(x, (_Keyed, list)) for x in item):
                built: list[Any] = [None] * len(item)
                parent[at] = built
                for j, x in enumerate(item):
                    if x is not _MISSING:
                        stack.append((x, built, j))
            else:
                parent[at] = item
        else:
            parent[at] = item
    return out[0]


def _merge(a: Any, b: Any) -> Any:
    """Two projections of one document as one: dicts by key, lists by position."""
    if a is _MISSING or a is None:
        return b
    if b is _MISSING or b is None:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        merged = dict(a)
        for key, value in b.items():
            merged[key] = _merge(merged[key], value) if key in merged else value
        return merged
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [_merge(x, y) for x, y in zip(a, b, strict=True)]
    # Two paths reaching one node: the deeper pick is inside the shallower one.
    return a


def _leaves(picked: Any) -> tuple[int, bool]:
    """How many leaves the projection holds, and whether each is a safe value.

    A dict's keys are leaves too, as ``jsonwalk`` says, but every key here is
    one a path named, matched by ``_KEY``, or one inside a subtree a path
    picked whole; the second kind is checked like any string.
    """
    count, safe = 0, True
    stack: list[tuple[Any, str | None]] = [(picked, None)]
    while stack:
        node, key = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if not (isinstance(k, str) and _KEY.fullmatch(k)):
                    safe = False
                stack.append((v, k))
        elif isinstance(node, list):
            stack.extend((x, key) for x in node)
        else:
            count += 1
            safe = safe and _safe_leaf(key, node)
    return count, safe


def _safe_leaf(key: str | None, value: Any) -> bool:
    """Whether ``value`` under ``key`` is a value no layer needs to read."""
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if not isinstance(value, str) or key is None:
        return False
    if key in _SHA_KEYS or key.endswith("_sha"):
        return _SHA.fullmatch(value) is not None
    if key == "login":
        return _LOGIN.fullmatch(value) is not None
    if key in _TIMESTAMP_KEYS or key.endswith("_at"):
        return _TIMESTAMP.fullmatch(value) is not None
    words = ENUMS.get(key)
    return words is not None and value in words
