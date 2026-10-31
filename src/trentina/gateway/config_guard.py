"""The rules a config write must satisfy, and nothing else (#633).

Pure functions over a write request, over loaded profiles, and over the value
being written. Keeping them here means each rule is testable on its own, and
the tool that applies them stays a readable sequence of steps rather than a
place where policy hides between two file operations.

Scott's ruling is that the operator is root on the gateway, and it is: it may
rewrite any other profile's backends, guards, defense and credentials. These
rules are not a privilege boundary against a hostile operator — there is no
such boundary, by design. They exist because the operator is an LLM, so the
question is not "may it?" but "can it be talked into it?", and two writes have
consequences out of all proportion to how easily they would slip into a
plausible-looking request: minting a second operator, and accepting another
gateway's security verdict.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from . import config_patch

if TYPE_CHECKING:
    from pydantic import BaseModel

    from .profile import Profile

WRITE_ACTIONS = ("set", "unset", "normalize")

#: The one action that takes no path, because it rewrites the whole document.
RESHAPE_ACTION = "normalize"

#: Accepting another gateway's scan instead of running our own. Not writable
#: through the API at all — see ``trust_stays_human``.
TRUST_FIELD = "trust_verdict"

#: The one field in the whole profile schema that can hold a credential VALUE
#: rather than the name of somewhere to find one. Everything else resolves from
#: the environment or the key store and is ``exclude=True``, so it is never in
#: the file at all — established by walking the schema, not by assumption.
MASKED_FIELD = "api_key"

REDACTED = "[REDACTED]"


class ConfigWriteError(Exception):
    """A refusal, carrying the answer the caller should get.

    The checks are a sequence of ways a request can be wrong, and returning
    from each in place turned one function into ten exits. Raising puts them
    all on one path.
    """

    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(payload.get("error", "refused"))
        self.payload = payload


def check_write_request(
    action: str, keys: tuple[str, ...], expect_hash: str | None, current_hash: str
) -> None:
    """Refuse a write request that is not well formed, before anything is read.

    ``expect_hash`` is required rather than optional, which is the whole reason
    a hand edit and a tool write can share one file: a write carries the hash
    of the version it was composed against, and a file that moved underneath
    refuses it instead of overwriting the other writer. ``get`` returns that
    hash, and so does every successful write, so a sequence of writes needs one
    read at the start and not one per change.
    """
    if action not in WRITE_ACTIONS:
        raise ConfigWriteError({"error": "action is get, set, unset or normalize"})
    if action == RESHAPE_ACTION:
        if keys:
            raise ConfigWriteError(
                {"error": "normalize takes no path: it rewrites the whole file or nothing"}
            )
    elif not keys:
        raise ConfigWriteError({"error": "set and unset need a path"})
    if expect_hash is None:
        raise ConfigWriteError({"error": f"{action} needs expect_hash from a get"})
    if expect_hash != current_hash:
        raise ConfigWriteError(
            {
                "error": "the configuration changed since that hash; read it again",
                "hash": current_hash,
            }
        )


def _annotations(text: str) -> list[str]:
    """Every comment in ``text``, sorted, position discarded.

    Taken from the first ``#`` on each line that has one, so an inline note
    counts as much as a whole-line one — and so does a ``#`` inside a quoted
    value, which is harmless: such a line reads the same on both sides, and
    ``equivalent`` has already proved every value identical, so it can only
    ever match. Position is dropped because a comment legitimately moves with
    the line it is attached to.
    """
    return sorted(line[line.index("#") :].strip() for line in text.splitlines() if "#" in line)


def equivalent(before: str, after: str) -> bool:
    """Whether two config texts mean the same thing AND say the same things.

    The gate on ``normalize``, the one write whose bytes are meant to change.
    Two checks, because either alone passes something a reader would call a
    loss. ``safe_load`` equality proves no value, key or sequence order moved,
    and it is exactly what the loader reads — but it discards every comment, so
    a dump that threw away the file's documentation satisfies it completely.
    Comparing the comments catches that, and catches ruamel dislocating one
    that trails an alias.

    Deliberately not a hash of the text: that is what ``round_trips`` already
    answers, and it answers "no" for every file worth normalizing.
    """
    if yaml.safe_load(before) != yaml.safe_load(after):
        return False
    return _annotations(before) == _annotations(after)


def _dumped(model: BaseModel | None) -> Any:
    return model.model_dump(mode="json") if model is not None else None


def _networks(block: Any) -> list[str] | None:
    """A block's ``source_networks`` as comparable strings.

    These belong to the seat because the peer address is what picks the profile
    on those paths (#330): widening the operator's networks is a way to make
    another caller the operator without touching ``role`` at all.
    """
    if block is None:
        return None
    return sorted(str(net) for net in block.source_networks)


def operator_seat(profiles: dict[str, Profile]) -> dict[str, Any]:
    """Everything that decides WHO the operator is and how a caller becomes one.

    Compared before and after a write. Deliberately not ``llm_keys`` or
    ``defense``: those move which judge the gateway's own calls run on, which is
    a real change but one ``reload_profiles`` already reports as
    ``service_identity_moved`` rather than something to forbid.
    """
    return {
        name: {
            "auth": _dumped(profile.auth),
            "oauth": _dumped(profile.oauth),
            "matrix_networks": _networks(profile.matrix_ingress),
            "egress_networks": _networks(profile.client_egress),
        }
        for name, profile in profiles.items()
        if profile.role == "operator"
    }


def trust_pins(profiles: dict[str, Profile]) -> dict[str, dict[str, str]]:
    """Every federated backend's pinned verdict, by ``<profile>.<backend>``.

    Compared before and after a write, the way ``operator_seat`` is, so what a
    person is asked to approve is the pin that actually resulted from loading
    the candidate — not the mapping the caller sent. A write can reach a pin by
    setting a parent key, and the loaded config is the only place that is
    unambiguous.
    """
    pins: dict[str, dict[str, str]] = {}
    for name, profile in profiles.items():
        for backend_name, backend in profile.backends.items():
            federated = backend.federated
            verdict = federated.trust_verdict if federated is not None else None
            if verdict is not None:
                pins[f"{name}.{backend_name}"] = {
                    "public_key": verdict.public_key,
                    "perimeter_stamp": verdict.perimeter_stamp,
                    "judge": verdict.judge,
                }
    return pins


def _nodes(root: Any) -> Any:
    """Every mapping and list reachable from ``root``, including itself."""
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            stack.extend(node.values())
        elif isinstance(node, list):
            yield node
            stack.extend(node)


def trust_stays_human(action: str, keys: tuple[str, ...], value: Any) -> bool:
    """Whether a write leaves scan-once trust alone — i.e. needs no approval.

    Since #637 a write that does NOT satisfy this is staged for a person rather
    than refused: the decision stays human, and stops being a text editor.

    ``trust_verdict`` makes this gateway serve another gateway's response
    WITHOUT running its own three layers over it. The constitution's Human
    Approval rule governs it: an operator agent may PROPOSE a trust that stops
    a layer running and may not apply one. Not because the operator lacks the
    authority — because the operator is a model, and this is the setting where
    being talked into it costs the most.

    The Trust Allowlist clause is about the allowlist and says a finding's cost
    changes while a layer still runs. That was quoted here as though it forbade
    scan-once, which it does not: federation trust is a different mechanism in
    a different file. What governs it is written down now rather than inferred
    from a neighbour (#637).

    Everything else about federation IS the operator's: minting keys, declaring
    the link, and ``federation.peers``, which decides who may authenticate —
    an access grant like any other, not a decision to believe someone's scan.

    Removing trust only makes this gateway scan more, so ``unset`` is allowed.
    The value is walked rather than the resulting config diffed, because
    carrying a mapping that holds the field is the only way a single-path write
    can reach it.
    """
    if action == "unset":
        return True
    carried = TRUST_FIELD in keys or any(
        TRUST_FIELD in node for node in _nodes(value) if isinstance(node, dict)
    )
    return not carried


def echoes_redaction(value: Any) -> bool:
    """Whether ``value`` carries the placeholder ``get`` hands back.

    ``get`` masks the one inline credential field, so the obvious way to use
    this tool — read a section, change one thing, write the section back —
    would otherwise store the literal ``[REDACTED]`` as a real API key. The
    write is refused instead, because the alternative is a provider call
    failing later with nothing pointing back to here.
    """
    return any(
        isinstance(item, str) and item == REDACTED
        for node in _nodes(value)
        for item in (node.values() if isinstance(node, dict) else node)
    ) or (isinstance(value, str) and value == REDACTED)


def mask_inline_secrets(text: str) -> str:
    """``text`` with every inline credential value replaced by ``REDACTED``.

    ``get`` hands back the file, and the file is where an ``api_key`` given
    directly rather than by env var would sit. An internal tool's result skips
    the transform chain, the judge and the log scrubber, so this is the only
    place it can happen. Text with nothing to hide is returned unchanged rather
    than round-tripped, so the common case is exactly the bytes on disk.
    """
    document = config_patch.load(text)
    masked = False
    for node in _nodes(document):
        if isinstance(node, dict) and isinstance(node.get(MASKED_FIELD), str):
            node[MASKED_FIELD] = REDACTED
            masked = True
    return config_patch.dump(document, like=text) if masked else text
