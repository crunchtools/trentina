"""Editing ``profiles.yaml`` without destroying it (#633).

The loader reads config with ``yaml.safe_load``, which discards comments,
key order detail and formatting. That is the right trade for reading and the
wrong one for writing: a round trip through it would hand back a file with
every comment its author wrote stripped out. ``profiles.yaml`` is a file a
human maintains, reviews in a diff and keeps in git, so a write has to leave
everything it did not touch exactly as it found it. That is what ruamel's
round-trip mode is for.

This module edits TEXT and nothing else. It does not validate, does not touch
the filesystem, and knows nothing about what a profile means. Validation stays
in ``loader.load_profiles``, which is the one schema authority: the caller
renders a candidate here and then loads it to find out whether it is allowed.

A path is a sequence of KEY NAMES. There is no list indexing on purpose — a
list is replaced whole. Indexing would let a write depend on the current order
of a sequence the operator cannot see in the same call, and ``tools_allow: [a,
b]`` is one decision, not two.
"""

from __future__ import annotations

import io
import re
from typing import Any

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

#: A config key: what appears on the left of a colon in profiles.yaml, which is
#: a profile name, a backend name or a field name. Not a value, and never a
#: path — a segment containing a dot or a slash is refused rather than split.
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: Wide enough that ruamel never re-folds a line it did not have to touch.
#: The default of 80 would rewrap long descriptions and URLs, which shows up
#: as a diff in sections nobody edited.
_WIDTH = 4096

#: Two spaces per level, as every profiles.yaml in the repo is written.
_INDENT = 2


class ConfigPatchError(ValueError):
    """A patch could not be applied. The message names the reason and the key
    that failed, never a value."""


def _yaml() -> YAML:
    """A round-trip parser configured to give back what it was given."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.width = _WIDTH
    # ruamel's default puts a block sequence's dash at its parent key's indent;
    # every profiles.yaml in this repo indents it two further. Matching the
    # house style is what makes an untouched list round-trip byte-for-byte
    # instead of showing up as a whitespace diff in a section nobody edited.
    yaml.indent(mapping=_INDENT, sequence=_INDENT * 2, offset=_INDENT)
    return yaml


def load(text: str) -> Any:
    """Parse ``text``, keeping comments and formatting."""
    try:
        return _yaml().load(text) if text.strip() else CommentedMap()
    except YAMLError:
        # The parser's message quotes the offending line, which is file content
        # and not ours to echo (#262), so the cause is dropped with it.
        raise ConfigPatchError("the file is not valid YAML") from None


def dump(document: Any) -> str:
    """Render ``document`` back to text."""
    stream = io.StringIO()
    _yaml().dump(document, stream)
    return stream.getvalue()


def checked_path(path: tuple[str, ...]) -> tuple[str, ...]:
    if not path:
        raise ConfigPatchError("a path must name at least one key")
    for key in path:
        if not KEY_RE.match(key):
            raise ConfigPatchError(f"{key!r} is not a config key")
    return path


def _walk(document: Any, path: tuple[str, ...]) -> Any:
    """The mapping holding the last key, creating intermediate ones.

    A path through something that is not a mapping is refused rather than
    overwritten: replacing a scalar with a map because a path ran through it
    would silently discard whatever was there.
    """
    node = document
    for key in path[:-1]:
        if not isinstance(node, CommentedMap):
            raise ConfigPatchError(f"{key!r} is not inside a mapping")
        if key not in node:
            node[key] = CommentedMap()
        node = node[key]
    if not isinstance(node, CommentedMap):
        raise ConfigPatchError(f"{path[-1]!r} is not inside a mapping")
    return node


def get_at(text: str, path: tuple[str, ...]) -> Any:
    """The value at ``path``, or raise ``ConfigPatchError`` if it is not there."""
    node = load(text)
    for key in checked_path(path):
        if not isinstance(node, CommentedMap) or key not in node:
            raise ConfigPatchError(f"{key!r} is not set")
        node = node[key]
    return node


def _as_written(value: Any) -> Any:
    """``value``, with any string the READER would not give back quoted.

    ruamel writes YAML 1.2, where ``yes``, ``no``, ``on``, ``off`` and ``1:30``
    are strings. The loader is pyyaml, which reads YAML 1.1, where the first
    four are booleans and the last is 90. Written bare, a string set here comes
    back as something else — a tool named ``no``, a token spelled ``on``, a
    value that happens to look like a clock. Quoting what the reader would
    reinterpret is what makes a write mean the same thing to both parsers.

    Only strings are touched, and only when they would change: a value that
    round-trips bare stays bare, so nothing is noisily quoted.
    """
    if isinstance(value, str):
        try:
            reread = yaml.safe_load(value)
        except yaml.YAMLError:
            return DoubleQuotedScalarString(value)
        return value if reread == value else DoubleQuotedScalarString(value)
    if isinstance(value, dict):
        return {key: _as_written(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_as_written(item) for item in value]
    return value


def set_at(text: str, path: tuple[str, ...], value: Any) -> str:
    """``text`` with ``path`` set to ``value``, everything else untouched."""
    document = load(text)
    holder = _walk(document, checked_path(path))
    holder[path[-1]] = _as_written(value)
    return dump(document)


def unset_at(text: str, path: tuple[str, ...]) -> str:
    """``text`` with ``path`` removed. Removing what is not there is an error,
    so a typo in a path cannot read as a successful no-op."""
    document = load(text)
    holder = _walk(document, checked_path(path))
    if path[-1] not in holder:
        raise ConfigPatchError(f"{path[-1]!r} is not set")
    del holder[path[-1]]
    return dump(document)
