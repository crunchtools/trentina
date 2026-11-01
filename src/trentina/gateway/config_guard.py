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

import ipaddress
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import yaml

from . import config_patch
from .profile import DefenseConfig

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


def federation_peers(profiles: dict[str, Profile]) -> dict[str, str]:
    """Every federation ingress's peers, by ``<profile>.<peer>`` to public key.

    Compared before and after a write, like ``trust_pins`` and for the same
    reason: a peer can be reached by setting a parent key, and the loaded
    candidate is the only place the resulting grant is unambiguous.

    A peer is what AUTHENTICATES a primary gateway to this one — adding one
    hands another gateway a seat on this ingress, with whatever that profile's
    backends reach. It was deliberately left out of the rules in #633, on the
    ground that it is an access grant rather than a decision to believe
    someone's scan, and that refusing it would make a federation ingress
    impossible to create through the API. The first half of that still holds and
    the second no longer does: since #637 a grant like this is PROPOSED rather
    than refused, so the ingress can still be built by an agent and a person
    still sees who was let in.
    """
    return {
        f"{name}.{peer_name}": peer.public_key
        for name, profile in profiles.items()
        if profile.federation is not None
        for peer_name, peer in profile.federation.peers.items()
    }


#: The mode that delivers what arrived. ``flag`` returns the response byte for
#: byte as it came in, with the verdict attached and nothing withheld, so a
#: profile that can reach it has a perimeter that detects and does not enforce.
UNENFORCED_MODE = "flag"


def _posture_of(defense: DefenseConfig) -> dict[str, Any]:
    """One ``defense`` block as the three fields that decide what it enforces.

    ``modes`` is what the agent may choose per call, ``enforcement`` is what an
    omitted mode resolves to, and ``llm_completion`` is the same decision on a
    streamed completion. The plan named ``modes`` alone; the other two are the
    same question asked of the same block, and a rule that watched the list an
    agent may choose from while leaving the value an omitted choice resolves to
    unguarded would be a gate with the gate's own door open.

    Read off the LOADED model, where ``modes`` is never unset: a validator
    fills it with ``[enforcement]`` and refuses a list that does not contain
    ``enforcement``. So this is the effective set, not the literal file, which
    is the right thing to compare — and it means an edit that moves
    ``enforcement`` alone shows up in both fields. Both rows are true and say
    different things (the set the agent may choose from, and what an omitted
    choice resolves to), so neither is suppressed to make the page tidier.
    """
    return {
        "modes": sorted(defense.modes or []),
        "enforcement": defense.enforcement,
        "llm_completion": defense.llm_completion,
    }


def default_posture() -> dict[str, Any]:
    """What a profile with no ``defense`` block at all enforces.

    Read off the schema rather than written down here, because it is the
    schema's to decide and today it is ``flag`` on both edges — a profile is
    detect-only until someone says otherwise. That is why this is the baseline
    a NEW profile is judged against: treating the default as a downgrade would
    stage an approval for every profile ever created, and an approval page a
    person learns to click through protects nothing.
    """
    return _posture_of(DefenseConfig())


def defense_posture(profiles: dict[str, Profile]) -> dict[str, dict[str, Any]]:
    """What each profile's perimeter still enforces, by profile."""
    return {name: _posture_of(profile.defense) for name, profile in profiles.items()}


def defense_downgraded(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """The profiles whose perimeter would stop enforcing, with both sides.

    Only a downgrade. Dropping ``flag``, or moving an edge off it, makes this
    gateway stricter and applies at once — narrowing never waits for a person,
    which is what keeps the approval page a place where something is being
    granted rather than a dialog in the way of routine work.
    """
    baseline = default_posture()
    downgraded: dict[str, dict[str, Any]] = {}
    for name, now in after.items():
        was = before.get(name, baseline)
        if (
            (UNENFORCED_MODE in now["modes"] and UNENFORCED_MODE not in was["modes"])
            or (now["enforcement"] == UNENFORCED_MODE and was["enforcement"] != UNENFORCED_MODE)
            or (
                now["llm_completion"] == UNENFORCED_MODE
                and was["llm_completion"] != UNENFORCED_MODE
            )
        ):
            downgraded[name] = {"before": was, "after": now}
    return downgraded


#: What ``_origin_only`` yields for a value it cannot reduce to an origin.
#:
#: A value, not an exception: ``egress_grants`` reads the config as it ALREADY
#: IS as well as the candidate, so raising would let one malformed provider on
#: disk refuse every later write, including the one that fixes it. The refusal
#: lives where such a grant is about to reach a person (``tools/config.py``).
#: NUL-prefixed, so it matches no real URL and no displayable string.
UNSHOWABLE_DESTINATION = "\0unshowable"


def _origin_only(value: Any) -> str:
    """``value`` reduced to scheme, host and port, or ``UNSHOWABLE_DESTINATION``.

    For a URL nothing has validated. The approval page is the one place a
    credential must never be rendered, and a destination is identified by its
    origin — userinfo, path, query and fragment identify nothing a person is
    deciding about and are exactly where a secret would be.

    ``urlparse`` defers validating the port until ``.port`` is read, so that
    read is inside the guard too: ``https://x.example:bad`` parses happily and
    then raises while a page is being built.
    """
    try:
        parts = urlparse(str(value))
        if not parts.scheme or not parts.hostname:
            return UNSHOWABLE_DESTINATION
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return UNSHOWABLE_DESTINATION
    return f"{parts.scheme}://{parts.hostname}{port}"


def egress_grants(
    profiles: dict[str, Profile],
    egress_upstreams: dict[str, Any],
    llm_providers: dict[str, Any],
) -> dict[str, str]:
    """Every destination this gateway may carry an agent's traffic to.

    Three settings, one question. Each is a way out of ``--network=none``, and
    the blast radius is larger than trusting a peer's scan: a trusted peer has
    still run three layers over the response, while known gap 26 says nothing
    reads a CONNECT tunnel's bytes at all. Adding a host grants an UNREAD
    channel out.

    Keyed by what is being granted and where, so a write is diffed as a set of
    grants rather than as three differently-shaped blocks. The value is only
    ever an operator-written destination; nothing from an ``llm_providers``
    entry is carried but its origin, because that mapping is ``dict[str, Any]``
    straight from the file and could hold an inline ``api_key``, which must
    never reach a web page.

    A provider that is not ``enabled`` is not a grant and is left out
    ENTIRELY, rather than listed as off. Carrying its state in the value made
    disabling one read as a changed grant and staged it — a withdrawal waiting
    on a person, which is the one thing the narrowing rule forbids. Absence is
    the only spelling of "not granted" that ``widened`` reads correctly.

    Only the DESTINATIONS are here. Who may open a tunnel is the other half of
    a ``client_egress`` grant and lives in ``source_networks_widened``, because
    a network is not comparable as a string: replacing ``10.0.0.0/8`` with
    ``10.9.0.0/24`` changes the key and narrows the grant, and a set difference
    would stage a tightening.

    An ``egress_upstreams`` origin is safe to render because the model has
    already reduced it: its validator refuses userinfo, a port, a path, a query
    and a fragment, and returns ``https://<netloc>``. That is a premise, not an
    assumption — ``tests/test_config_tool.py`` asserts the validator still
    refuses a credential-bearing URL, so loosening it cannot quietly publish
    one to an approval page.

    An ``llm_providers`` origin has NO such model behind it: that section is
    ``dict[str, Any]`` straight from the file, so its ``upstream`` is whatever
    a writer typed and may carry userinfo or a query. It goes through
    ``_origin_only`` rather than being rendered as written.

    A provider is dropped from the grants when it is disabled, so disabling one
    narrows and applies at once — but the route itself binds at startup and
    outlives the write. That is not this rule claiming otherwise: ``reload``
    already reports every ``llm_providers`` change as "restart to apply"
    (``tools/reload.py``), so the operator is told the withdrawal is not live
    yet by the same answer that says the write applied.
    """
    grants: dict[str, str] = {}
    for name, profile in profiles.items():
        if profile.client_egress is not None:
            for host in profile.client_egress.hosts:
                grants[f"client_egress:{name}.{host}"] = f"{host}:443, tunnelled and unread"
    for name, upstream in egress_upstreams.items():
        grants[f"egress_upstreams:{name}"] = str(getattr(upstream, "upstream", upstream))
    for name, provider in llm_providers.items():
        if isinstance(provider, dict) and provider.get("enabled"):
            grants[f"llm_providers:{name}"] = _origin_only(provider.get("upstream"))
    return grants


#: The networks that may open a profile's tunnels, by profile. A
#: ``client_egress`` block's ``source_networks`` decides who may open one,
#: because the peer address is what picks the profile and nothing secret is on
#: the wire (#330).
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Networks = dict[str, list[_Network]]


def client_egress_networks(profiles: dict[str, Profile]) -> _Networks:
    """Who may open each profile's tunnels, by profile.

    An OPERATOR profile is left out, and left to ``operator_seat``, which
    already compares the same field: there, widening the networks makes another
    caller the operator, so it is a seat change rather than an egress grant.
    Counting one unsplittable field in both rules would make the write need two
    approvals with no way to comply.
    """
    return {
        name: list(profile.client_egress.source_networks)
        for name, profile in profiles.items()
        if profile.client_egress is not None and profile.role != "operator"
    }


def source_networks_widened(before: _Networks, after: _Networks) -> dict[str, str]:
    """The networks that would reach addresses they could not reach before.

    Compared as ADDRESS RANGES, not as strings. A profile moving from
    ``10.0.0.0/8`` to ``10.9.0.0/24`` has a new key and a strictly smaller
    grant; a set difference over the written CIDRs reads that as widening and
    stages a tightening, which is the one thing the narrowing rule forbids. A
    network already inside one that was granted is therefore not a grant at
    all.

    ``subnet_of`` raises on a mismatched family, so the families are kept
    apart: an IPv6 range is never contained in an IPv4 one. The prior networks
    are collapsed first, which merges adjacent and nested ranges — there is no
    ``max_length`` on ``source_networks``, so without it a long list would cost
    one containment test per pair on every config write.
    """
    reaching: dict[str, str] = {}
    for name, nets in after.items():
        had_v4, had_v6 = _collapsed(before.get(name, []))
        for net in nets:
            covered = (
                any(net.subnet_of(old) for old in had_v4)
                if isinstance(net, ipaddress.IPv4Network)
                else any(net.subnet_of(old) for old in had_v6)
            )
            if not covered:
                reaching[f"client_egress:{name}.from.{net}"] = (
                    f"clients in {net} may open that profile's tunnels"
                )
    return reaching


def _collapsed(
    networks: list[_Network],
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    """``networks`` merged into the fewest ranges covering the same addresses.

    Returned as two concretely typed lists rather than one keyed by family:
    ``collapse_addresses`` and ``subnet_of`` are both family-specific, so a
    union would have to be re-narrowed at every use.
    """
    v4 = [net for net in networks if isinstance(net, ipaddress.IPv4Network)]
    v6 = [net for net in networks if isinstance(net, ipaddress.IPv6Network)]
    return (
        list(ipaddress.collapse_addresses(v4)) if v4 else [],
        list(ipaddress.collapse_addresses(v6)) if v6 else [],
    )


def widened(before: dict[str, str], after: dict[str, str]) -> dict[str, str]:
    """The grants ``after`` adds or changes, by the same keys both sides use.

    A grant only in ``before`` has been withdrawn, which needs no approval.
    """
    return {where: what for where, what in after.items() if before.get(where) != what}


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
