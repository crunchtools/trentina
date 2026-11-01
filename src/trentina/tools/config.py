"""Reading and writing the gateway's own configuration (#633): operator only.

``docs/operator.md`` describes an Operator agent's loop as "it edits
profiles.yaml, applies the edit with reload_profiles, and reads back what
applied and what needs a restart. None of this needs a shell." Until now the
first clause was not true: nothing in Trentina could edit the file, so the only
way an operator agent did it was with a shell it was not supposed to need.

The file stays the source of truth. It is not a view over a database and it is
not generated: a human maintains it, reviews it in a diff and keeps it in git,
and a hand edit still wins. ``expect_hash`` is what keeps the two writers
honest.

The order below is the point of the module. The candidate is validated by
LOADING it — from a real file, through ``loader.load_profiles``, the one schema
authority — before anything replaces anything, so a refusal has touched
nothing. The previous text is kept before the replace, so even a crash between
the two leaves it recoverable. And the reload is the existing
``reload_profiles``, not a second applier, so there stays one path by which a
profile change reaches the running gateway.

The rules live in ``gateway/config_guard.py``; this module is the sequence.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from ..gateway import approver, config_guard, config_patch, config_store, pending
from ..gateway.audit import _audit
from ..gateway.config_guard import ConfigWriteError
from ..gateway.errors import ProfileConfigError, ScopeError
from ..gateway.llm_proxy import validate_profile_llm_keys
from ..gateway.loader import get_active_config, load_profiles
from ..gateway.scope import require_caller, require_operator
from ..gateway.service import service_context, service_profile
from ..logsafe import exc_kind
from ..outcomes import Outcome
from ..perimeter_db import perimeter_stamp
from .reload import reload_profiles

if TYPE_CHECKING:
    from ..gateway.loader import ActiveConfig, GatewayConfig

logger = logging.getLogger(__name__)

#: One write at a time. Two writes that each validated against the same text
#: would both satisfy their own ``expect_hash``, and the second would land on a
#: file it never read.
_WRITE_LOCK = asyncio.Lock()

_CANDIDATE_PREFIX = ".profiles-candidate-"


def _live_config() -> tuple[ActiveConfig, Path, str]:
    """The running config, the file behind it, and that file's current text."""
    active = get_active_config()
    if active is None:
        raise ConfigWriteError({"error": "no gateway configuration is loaded"})
    live = Path(active.path)
    try:
        return active, live, live.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("config could not read the live file: %s", exc_kind(exc))
        raise ConfigWriteError({"error": "could not read the configuration"}) from exc


def _read_at(text: str, keys: tuple[str, ...]) -> Any:
    """The value at ``keys``, as plain Python.

    Reading is pyyaml's job and writing is ruamel's (``config_patch``). Reading
    here keeps ruamel's round-trip types — comment-carrying maps, quote-
    preserving strings — out of a tool result that has to serialize to JSON.
    """
    node = yaml.safe_load(text)
    try:
        checked = config_patch.checked_path(keys) if keys else ()
    except config_patch.ConfigPatchError as exc:
        raise ConfigWriteError({"error": str(exc)}) from None
    for key in checked:
        if not isinstance(node, dict) or key not in node:
            raise ConfigWriteError({"error": f"{key!r} is not set"})
        node = node[key]
    return node


def _read(keys: tuple[str, ...]) -> dict[str, Any]:
    """A ``get``: the file's hash, and the masked value at ``keys``."""
    _, _, current = _live_config()
    return {
        "hash": config_store.config_hash(current),
        "value": _read_at(config_guard.mask_inline_secrets(current), keys),
    }


def _candidate_loads(live: Path, text: str, providers: dict[str, Any]) -> GatewayConfig:
    """Load ``text`` as a configuration, or refuse. Nothing live is touched.

    Written to a real file beside the live one and loaded by path, because that
    is exactly what ``reload_profiles`` does moments later: validating the way
    the applier reads it leaves no gap between "it validated" and "it loaded".
    The staged file is random-named and 0600 from creation, and is removed
    whatever happens.
    """
    fd, staged_name = tempfile.mkstemp(dir=live.parent, prefix=_CANDIDATE_PREFIX, suffix=".yaml")
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        config = load_profiles(staged)
        validate_profile_llm_keys(providers, config.profiles)
    except ProfileConfigError as exc:
        # Its message names the file it read, which is this temporary one. The
        # operator needs the reason, not our scratch path.
        reason = str(exc).replace(str(staged), str(live))
        raise ConfigWriteError({"error": f"the change does not validate: {reason}"}) from None
    else:
        # The whole config, not just the profiles: the egress grants a person
        # approves live in `egress_upstreams` and `llm_providers`, which are
        # file-level sections rather than per-profile blocks.
        return config
    finally:
        staged.unlink(missing_ok=True)


def _reshaped(current: str, current_hash: str) -> tuple[str, dict[str, int]]:
    """Render a normalization of ``current``, or refuse to.

    The only write that changes bytes nobody asked to change, so it carries its
    own gate rather than the round-trip precondition every other write gets:

    1. The file must NOT already round-trip. On one that does, this would be a
       no-op dressed as a rewrite, and the honest answer is that there is
       nothing to do.
    2. The result must mean the same thing and keep every comment
       (``config_guard.equivalent``). This is the check that makes a deliberate
       reformat reviewable rather than a leap of faith.
    3. The result must round-trip. Without it, normalizing could hand back
       something no better than what it replaced, and the next write would
       refuse for the same reason as before.
    """
    if config_patch.round_trips(current):
        raise ConfigWriteError(
            {
                "error": (
                    "this file already reproduces itself exactly, so there is nothing "
                    "to normalize; set and unset work on it as they are"
                ),
                "hash": current_hash,
            }
        )
    candidate_text, reshaped = config_patch.normalized(current)
    if not config_guard.equivalent(current, candidate_text):
        raise ConfigWriteError(
            {
                "error": (
                    "normalizing this file would change what it says, not just how it "
                    "is written, so nothing was changed. Either a value moved or a "
                    "comment was lost. This needs a person to look at the file"
                ),
                "hash": current_hash,
            }
        )
    if not config_patch.round_trips(candidate_text):
        raise ConfigWriteError(
            {
                "error": (
                    "normalizing this file does not make it reproducible, so nothing "
                    "was changed and a later write would refuse for the same reason. "
                    "This needs a person to look at the file"
                ),
                "hash": current_hash,
            }
        )
    return candidate_text, reshaped


def _fingerprint(pem: str) -> str:
    """A short digest of a public key, for a person to compare by eye.

    The whole PEM on an approval page is a wall of base64 nobody checks; a
    fingerprint is what the other operator can read out loud.
    """
    return f"sha256:{hashlib.sha256(pem.encode('utf-8')).hexdigest()[:16]}"


#: A key absent from one side's seat, told apart from a key that is present
#: and ``None``. ``operator_seat`` emits the same four keys for every profile
#: today, so the two cannot differ — but this loop reads the union of both key
#: sets, which is a promise that they may, and ``dict.get`` alone would show
#: "absent" and "set to nothing" as the same unchanged field.
_MISSING = object()

#: The most one rendered seat field may run to. Every fragment inside it is
#: already held to ``checked_display``'s length, but it is the operator who
#: writes how MANY fragments there are — an OAuth allowlist is a list it
#: controls. Burying the one line that matters under a thousand that do not is
#: a way to get a change approved, so past this the write is refused rather
#: than shown unreadably.
_SEAT_VALUE_CHARS = 2000


def _shown_value(value: Any) -> str:
    """One config field, as something a person can read off a page.

    Each fragment that came out of the file is checked on its own and the
    punctuation between them is ours. Checking the joined line instead would
    refuse a long but perfectly legitimate value — an OAuth allowlist with a
    dozen addresses — for being longer than one displayable string may be.

    Named for what it does rather than for the first page that needed it: the
    defense table renders through it too, and `_seat_value` read as though seat
    formatting were being applied to something else.
    """
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(_shown_value(item) for item in value) if value else "empty"
    if isinstance(value, dict):
        shown = [
            f"{pending.checked_display(str(key), what='an operator seat field')}"
            f"={_shown_value(item)}"
            for key, item in sorted(value.items())
            if item is not None
        ]
        return ", ".join(shown) if shown else "nothing set"
    return pending.checked_display(str(value), what="an operator seat value")


def _seat_shown(value: Any, aspect: str) -> str:
    """One side of a changed aspect, or a refusal if it cannot be read."""
    if value is _MISSING:
        return "absent"
    rendered = _shown_value(value)
    if len(rendered) > _SEAT_VALUE_CHARS:
        raise pending.PendingError(
            f"the operator seat's {aspect} is too long to show for approval; "
            "change it in the file, where a person can read the diff"
        )
    return rendered


def _seat_facts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, str]:
    """What a person needs to see about a seat change.

    Who holds it is not enough, and saying only that was a real hole.
    ``config_guard.operator_seat`` compares how a caller BECOMES the operator
    as well — ``auth``, ``oauth``, and the source networks that pick the
    profile — so a write can swap the credential that makes someone root
    while the seat's name never moves. Rendered as names alone that reaches a
    person as "josui, then josui": a no-op they have no reason to decline.
    It is also the shape that matters most, because moving the seat to a new
    profile is visible and changing the key behind an unchanged name is not.
    QE found it the hard way — told to decline, shown that page, approved.

    So every aspect that differs is named, with its before and its after,
    across the UNION of both sides. A profile entering the seat needs that as
    much as one already in it: "josui, then ops" says the seat moved and
    nothing about how ops becomes root, and an OAuth block admitting an
    address nobody recognises is exactly the payload that line would hide.
    A side not holding the profile at all renders as ``absent``.

    No credential VALUE can arrive here. The two secret-bearing fields in
    these models, ``auth.bearer_token`` and ``oauth.client_secret``, are
    declared ``Field(exclude=True)`` and so are absent from the dump
    ``operator_seat`` compares — asserted in ``tests/test_config_tool.py``,
    because a new secret field without that marker would otherwise reach a
    web page.
    """
    facts = {
        "Holds the operator seat now": pending.checked_display(
            ", ".join(sorted(before)) or "nobody", what="the current operator seat"
        ),
        "Would hold it after this change": pending.checked_display(
            ", ".join(sorted(after)) or "nobody", what="the proposed operator seat"
        ),
    }
    for name in sorted(set(before) | set(after)):
        shown = pending.checked_display(name, what="an operator seat name")
        was, now = before.get(name, {}), after.get(name, {})
        for aspect in sorted(set(was) | set(now)):
            had, has = was.get(aspect, _MISSING), now.get(aspect, _MISSING)
            if had == has:
                continue
            facts[f"{shown}.{aspect} now"] = _seat_shown(had, aspect)
            facts[f"{shown}.{aspect} after this change"] = _seat_shown(has, aspect)
    facts["What this means"] = "Whoever holds the seat is root on this gateway."
    return facts


def _trust_facts(where: str, pin: dict[str, str]) -> dict[str, str]:
    """What a person needs to see about a trust pin.

    The stamp and the judge are the PEER's own strings, so they are held to a
    displayable shape before they reach a page where someone is deciding
    whether to believe that peer.
    """
    return {
        "Backend to trust": pending.checked_display(where, what="the backend name"),
        "Its key": _fingerprint(pin["public_key"]),
        "Its scanner": pending.checked_display(
            pin["perimeter_stamp"], what="the peer's perimeter stamp"
        ),
        "Its judge": pending.checked_display(pin["judge"], what="the peer's judge"),
        "This gateway scans under": perimeter_stamp(),
        "What this means": (
            "Responses from this backend will be served WITHOUT this gateway running "
            "its own three layers over them. It does not pin the peer's own defense "
            "settings - only the scanner and judge above."
        ),
    }


#: The most rows one grant or downgrade proposal may render. Each is already
#: held to ``checked_display``'s length, but it is the operator that decides HOW
#: MANY there are: a write adding one host nobody recognises among forty
#: familiar ones is a way to get it approved. Past this the write is refused and
#: the operator is told to make it in the file, where a person reads a diff.
_MAX_PROPOSAL_ROWS = 24


def _too_many(what: str, rows: int) -> ConfigWriteError:
    return ConfigWriteError(
        {
            "error": (
                f"this write would need a person to approve {rows} {what} at once, which "
                f"is more than an approval page can show readably (the limit is "
                f"{_MAX_PROPOSAL_ROWS}), so nothing was changed. Make a change this large "
                "in the file, where a person can read it as a diff, or propose it in "
                "smaller writes"
            )
        }
    )


def _granted_facts(rendered: dict[str, str], *, naming: str, meaning: str) -> dict[str, str]:
    """One proposal's table: a checked row per grant, then what it means.

    Shared by the peer page and the egress page because they ask the same shape
    of question — here is a set of things being granted, each named and each
    with one value a person can check. ``rendered`` already holds the display
    value, because the two sides render differently: a peer's key becomes a
    fingerprint, an egress destination is the operator's own text and is
    checked. Written once after Gourmand caught the second copy.
    """
    facts = {
        pending.checked_display(where, what=naming): value
        for where, value in sorted(rendered.items())
    }
    facts["What this means"] = meaning
    return facts


def _peer_facts(added: dict[str, str]) -> dict[str, str]:
    """What a person needs to see about peers being admitted to an ingress.

    One proposal for the whole write rather than one per peer, unlike a trust
    pin: a peer list is a list an operator legitimately writes in one go, and
    each entry is the same question asked of a different key. A pin is not —
    each is its own belief about its own scanner and judge.

    The key is shown as a fingerprint, which is the thing the operator at the
    other end can read down a phone. The whole PEM is a wall of base64 nobody
    checks by eye.
    """
    if len(added) > _MAX_PROPOSAL_ROWS:
        raise _too_many("federation peers", len(added))
    return _granted_facts(
        {where: _fingerprint(key) for where, key in added.items()},
        naming="a federation peer name",
        meaning=(
            "Each key above may authenticate to that ingress as that peer, and reach "
            "whatever that profile's backends reach. It does NOT let the peer's own "
            "scan be believed in place of this gateway's - that is a separate approval."
        ),
    )


def _defense_facts(downgraded: dict[str, dict[str, Any]]) -> dict[str, str]:
    """What a person needs to see about a perimeter that stops enforcing.

    Both sides of all three fields, not only the one that moved: an operator
    reading "may now choose flag" needs to know whether the other two edges
    were already there, because a profile already resolving an omitted mode to
    ``flag`` is a different decision from one that was refusing outright.
    """
    # Counted in ROWS, like the other two, rather than in profiles: each
    # profile contributes up to three, so a limit on profiles would let a
    # defense page run to three times the length the limit states. Counted
    # BEFORE rendering, so an oversized proposal is refused without sorting
    # and checking every name it was never going to show.
    changed = [
        (name, order, aspect)
        for name, sides in downgraded.items()
        for order, aspect in enumerate(_DEFENSE_ASPECTS)
        if sides["before"][aspect] != sides["after"][aspect]
    ]
    if len(changed) > _MAX_PROPOSAL_ROWS:
        raise _too_many("changed defense settings", len(changed))
    facts: dict[str, str] = {}
    # By profile, then in the order the fields are declared rather than
    # alphabetically: "what the agent may choose, what an omitted choice
    # resolves to, what a stream gets" is how they read.
    for name, _, aspect in sorted(changed):
        shown = pending.checked_display(name, what="a profile name")
        sides = downgraded[name]
        was, now = sides["before"][aspect], sides["after"][aspect]
        facts[f"{shown}.{aspect}"] = f"{_shown_value(was)}  ->  {_shown_value(now)}"
    facts["What this means"] = (
        "flag delivers exactly the bytes that arrived, with the verdict attached and "
        "nothing withheld. Those profiles will still DETECT an injection and will no "
        "longer refuse one."
    )
    return facts


def _egress_facts(added: dict[str, str]) -> dict[str, str]:
    """What a person needs to see about a new way out of network isolation.

    Three settings in one question, because a person is being asked the same
    thing about each: may this gateway carry an agent's traffic somewhere new.
    ``llm_providers`` binds at startup, so the page says the grant is not live
    yet rather than letting a reader assume the reload applied it.
    """
    if len(added) > _MAX_PROPOSAL_ROWS:
        raise _too_many("egress destinations", len(added))
    unshowable = sorted(
        where
        for where, what_for in added.items()
        if what_for == config_guard.UNSHOWABLE_DESTINATION
    )
    if unshowable:
        # The constitution requires an approval to state what is being changed
        # in values a person can CHECK. A placeholder is not one: it asks
        # someone to grant a route out without telling them where to. Only a
        # grant being proposed is refused — a malformed entry already in the
        # file does not block unrelated writes.
        raise ConfigWriteError(
            {
                "error": (
                    f"these egress grants have no destination a person could check "
                    f"({', '.join(unshowable)}): the upstream is not a URL with a host, "
                    "so nothing was changed. Give each a scheme and a host"
                )
            }
        )
    facts = _granted_facts(
        {
            where: pending.checked_display(what_for, what="an egress destination")
            for where, what_for in added.items()
        },
        naming="an egress grant",
        meaning=(
            "Each is a route out of this gateway's network isolation. No layer reads what "
            "crosses a CONNECT tunnel, so a client_egress host is an UNREAD channel out."
        ),
    )
    if any(where.startswith("llm_providers:") for where in added):
        facts["Not live until a restart"] = (
            "An llm_providers entry binds at startup, so approving this writes the "
            "file and the route does not exist until this gateway is restarted."
        )
    return facts


#: One question for a person: which decision, and the table they read.
_Proposal = tuple[pending.Kind, dict[str, str]]

#: The three fields of a ``defense`` block that decide what it enforces, in the
#: order a person reads them.
_DEFENSE_ASPECTS = ("modes", "enforcement", "llm_completion")


def _seat_proposals(before: GatewayConfig, after: GatewayConfig) -> list[_Proposal]:
    """Who the operator is, and how a caller becomes one."""
    was = config_guard.operator_seat(before.profiles)
    now = config_guard.operator_seat(after.profiles)
    return [] if was == now else [(pending.Kind.OPERATOR_SEAT, _seat_facts(was, now))]


def _trust_proposals(
    before: GatewayConfig, after: GatewayConfig, action: str, keys: tuple[str, ...], value: Any
) -> list[_Proposal]:
    """Believing a peer's scan instead of running our own.

    The one rule that reads the write itself rather than only the loaded
    candidate: ``trust_stays_human`` walks the value, because carrying a mapping
    that holds the field is how a single-path write reaches it. The pins are
    then compared on the candidate, so what a person approves is what LOADING
    produced. One proposal per pin — each is its own belief about its own
    scanner and judge, so they are not collapsible the way a peer list is.
    """
    if config_guard.trust_stays_human(action, keys, value):
        return []
    was = config_guard.trust_pins(before.profiles)
    return [
        (pending.Kind.FEDERATION_TRUST, _trust_facts(where, pin))
        for where, pin in sorted(config_guard.trust_pins(after.profiles).items())
        if was.get(where) != pin
    ]


def _peer_proposals(before: GatewayConfig, after: GatewayConfig) -> list[_Proposal]:
    """Who may authenticate to a federation ingress as a primary gateway."""
    admitted = config_guard.widened(
        config_guard.federation_peers(before.profiles),
        config_guard.federation_peers(after.profiles),
    )
    return [(pending.Kind.FEDERATION_PEERS, _peer_facts(admitted))] if admitted else []


def _defense_proposals(before: GatewayConfig, after: GatewayConfig) -> list[_Proposal]:
    """A profile's perimeter going from enforcing to detect-only."""
    stood_down = config_guard.defense_downgraded(
        config_guard.defense_posture(before.profiles),
        config_guard.defense_posture(after.profiles),
    )
    return [(pending.Kind.DEFENSE_DOWNGRADE, _defense_facts(stood_down))] if stood_down else []


def _egress_proposals(before: GatewayConfig, after: GatewayConfig) -> list[_Proposal]:
    """A new destination this gateway may carry an agent's traffic to."""

    def grants(config: GatewayConfig) -> dict[str, str]:
        return config_guard.egress_grants(
            config.profiles, config.egress_upstreams, config.llm_providers
        )

    # Two comparisons, one question. Destinations diff as strings; who may open
    # a tunnel has to diff as address ranges, or narrowing a CIDR reads as a
    # new grant.
    granted = {
        **config_guard.widened(grants(before), grants(after)),
        **config_guard.source_networks_widened(
            config_guard.client_egress_networks(before.profiles),
            config_guard.client_egress_networks(after.profiles),
        ),
    }
    return [(pending.Kind.EGRESS_GRANT, _egress_facts(granted))] if granted else []


def _needs_approval(
    active: ActiveConfig,
    after: GatewayConfig,
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> _Proposal | None:
    """Whether this write is one a person has to agree to, and what to show them.

    Five of them, and they are not a privilege boundary — the operator is root.
    They exist because the operator is a model, so the question is whether it
    can be talked into a change whose blast radius is out of all proportion to
    how plausible the request would look: minting a second root, believing
    another gateway's scan instead of running our own, admitting a gateway to a
    federation ingress, standing a profile's perimeter down to detect-only, and
    opening a way out of network isolation.

    Every rule but ``trust_stays_human`` is computed on the LOADED candidate
    rather than on the mapping the caller sent, because a write reaches any of
    these by setting a parent key and the loaded config is the only place the
    result is unambiguous. Each is a widening test: a write that only withdraws
    a grant or tightens a perimeter applies at once.
    """
    before = active.config
    proposals = [
        *_seat_proposals(before, after),
        *_trust_proposals(before, after, action, keys, value),
        *_peer_proposals(before, after),
        *_defense_proposals(before, after),
        *_egress_proposals(before, after),
    ]
    if not proposals:
        return None
    if len(proposals) > 1:
        # The constitution requires the approval to state WHAT IS BEING
        # CHANGED. One write can move the seat and pin trust, or pin two
        # backends at once, and a page can only put one decision in front of a
        # person — so the rest would be applied unseen on the back of the one
        # they read. Refuse and make the operator propose them one at a time;
        # that is also the only shape in which "approve" means anything.
        kinds = ", ".join(sorted({kind.value for kind, _ in proposals}))
        raise ConfigWriteError(
            {
                "error": (
                    f"this write needs more than one approval ({kinds}), and a person can "
                    "only be shown one at a time, so nothing was changed. Propose them "
                    "separately: one write per decision."
                )
            }
        )
    return proposals[0]


def _rendered(
    active: ActiveConfig,
    live: Path,
    current: str,
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> tuple[str, dict[str, int], tuple[pending.Kind, dict[str, str]] | None]:
    """Render and validate a candidate, and say whether it needs a person.

    Changes nothing: a refusal here, and a staged action, have both touched the
    file not at all. Every step is blocking — parsing YAML, loading a candidate
    from disk — so it runs in a worker rather than on the event loop, the same
    rule the rest of the gateway follows for L1 and for SQLite.
    """
    current_hash = config_store.config_hash(current)
    reshaped: dict[str, int] = {}
    if action == config_guard.RESHAPE_ACTION:
        candidate_text, reshaped = _reshaped(current, current_hash)
    else:
        if not config_patch.round_trips(current):
            # Writing re-emits the whole document, so on a file the editor cannot
            # reproduce exactly a one-key change also reformats everything else.
            # Refuse rather than hand back an unreviewable diff.
            raise ConfigWriteError(
                {
                    "error": (
                        "this file cannot be edited through the tool without reformatting "
                        "the rest of it, so nothing was changed. Something in it is not "
                        "reproduced exactly on the way out — usually a few lists indented "
                        "differently from the rest of the file, or anchors and aliases, "
                        "which are renumbered when rewritten. Run this tool once with "
                        'action "normalize" and every write after that applies cleanly'
                    ),
                    "hash": current_hash,
                }
            )
        try:
            candidate_text = (
                config_patch.set_at(current, keys, value)
                if action == "set"
                else config_patch.unset_at(current, keys)
            )
        except config_patch.ConfigPatchError as exc:
            raise ConfigWriteError({"error": str(exc)}) from None

    if candidate_text == current:
        raise ConfigWriteError(
            {"error": "that change is already in the configuration", "hash": current_hash}
        )
    if config_guard.echoes_redaction(value):
        raise ConfigWriteError(
            {
                "error": (
                    f"that value contains {config_guard.REDACTED}, which is what a read "
                    "puts in place of a credential — send the real value, or leave the "
                    "field out of the write"
                )
            }
        )
    after = _candidate_loads(live, candidate_text, active.llm_providers)
    return candidate_text, reshaped, _needs_approval(active, after, action, keys, value)


def _commit(live: Path, current: str, candidate_text: str) -> Path:
    """Keep the previous version and put the candidate in its place.

    The only code that replaces the live file, shared by a write that applied
    straight away and one a person approved — so the two cannot drift, and the
    backup is never the thing that got skipped on the less-travelled path.
    """
    # Validating read and wrote a file, so look once more before replacing:
    # nothing else may have moved while this write was being checked.
    if live.read_text(encoding="utf-8") != current:
        raise ConfigWriteError(
            {"error": "the configuration changed while this write was checked; read it again"}
        )
    kept = config_store.back_up(
        current, after_hash=config_store.config_hash(candidate_text), now=time.time()
    )
    config_store.replace_config(live, candidate_text)
    return kept


async def _write(
    active: ActiveConfig,
    live: Path,
    current: str,
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> dict[str, Any]:
    """Apply a change, or stage it for a person: blocking parts off the loop."""
    current_hash = config_store.config_hash(current)
    candidate_text, reshaped, approval = await asyncio.to_thread(
        _rendered, active, live, current, action, keys, value
    )
    if approval is not None:
        kind, facts = approval
        if not approver.configured():
            # No person can approve, so nothing may be staged: the two writes
            # are refused exactly as they were before #637. The absence of an
            # approval password is the absence of the feature.
            raise ConfigWriteError(
                {
                    "error": (
                        f"changing the {kind.value} needs a person to approve it, and this "
                        "gateway has no approval password configured, so nothing can be "
                        "approved and nothing was changed"
                    ),
                    "hash": current_hash,
                }
            )
        pending.stage(
            kind,
            facts,
            lambda: _apply(live, current, candidate_text, current_hash, reshaped, approved=kind),
        )
        logger.info("config: %s needs a person; staged", kind.value)
        return {
            "staged": True,
            "awaiting": kind.value,
            "shown_for_approval": facts,
            "hash": current_hash,
            # Deliberately no link and no handle. Anything returned here is
            # something this caller holds, and the whole point is that it does
            # not hold the approval.
            "note": (
                "Nothing has changed. Ask a person to open "
                f"{pending.PAGE_PATH} on this gateway and approve it with the approval "
                "password. It expires on its own if nobody does."
            ),
        }
    return await _apply(live, current, candidate_text, current_hash, reshaped)


async def _apply(
    live: Path,
    current: str,
    candidate_text: str,
    current_hash: str,
    reshaped: dict[str, int],
    *,
    approved: pending.Kind | None = None,
) -> dict[str, Any]:
    """Replace the file and apply it. The one path, approved or not.

    ``reload_profiles`` applies the WHOLE file only for an operator, and an
    approved action is applied from the approval route, where there is no bound
    caller at all — a person's browser holds no profile. So the apply runs as
    the service identity, which is the operator this gateway already runs its
    own work as. Without it an approval would replace the file and then be
    refused by the reload, restoring it: approved, and silently not applied.
    """
    kept = await asyncio.to_thread(_commit, live, current, candidate_text)
    after_hash = config_store.config_hash(candidate_text)

    with service_context():
        applied = await reload_profiles()
    if applied.get("reloaded") is not True:
        # The file must never be ahead of the running gateway: a later reader —
        # a human, a drift check, the next write's expect_hash — would be told
        # the change is live when it is not. Put back what was there.
        await asyncio.to_thread(config_store.replace_config, live, current)
        logger.warning("config: reload refused the validated change; the file was restored")
        raise ConfigWriteError(
            {"error": "the change validated but the reload refused it", "reload": applied}
        )

    logger.info("config: applied a change and reloaded")
    if approved is not None:
        # An approved change arrives on the approval route, not as a tools/call,
        # so the row every tool call gets does not exist for it — and the two
        # changes that come this way are the highest-blast-radius writes in the
        # product. Audited here rather than nowhere. The direct path is not
        # audited twice: its enclosing tools/call row already says what happened.
        _audit(
            service_profile().name,
            "internal://config",
            "config_tool",
            Outcome.OK,
            0,
            f"approved by a person: {approved.value}",
        )
    answer: dict[str, Any] = {
        "applied": True,
        "hash_before": current_hash,
        "hash_after": after_hash,
        "backup": str(kept),
        "reload": applied,
    }
    if reshaped:
        # What to expect in the file's own git diff, so the rewrite can be
        # checked against a number rather than taken on trust.
        answer["reshaped"] = reshaped
    return answer


async def manage_config(
    action: str,
    path: str | None = None,
    value: Any = None,
    expect_hash: str | None = None,
) -> dict[str, Any]:
    """Read or change the gateway's configuration.

    Args:
        action: ``get``, ``set``, ``unset`` or ``normalize``.
        path: A dotted path of config keys, e.g.
            ``profiles.myagent.backends.lotor.federated.primary_key_name``. For
            ``get`` it may be omitted, which returns the whole file;
            ``normalize`` takes none.
        value: What to set, for ``set``. A scalar, a list or a mapping.
        expect_hash: The ``hash`` a previous ``get`` or write returned.
            Required for every write.
    """
    keys = tuple(path.split(".")) if path else ()
    try:
        require_operator(require_caller("config"), "config")
        if action == "get":
            # Reading the file and parsing it twice is blocking too, so it goes
            # to a worker like the write does.
            return await asyncio.to_thread(_read, keys)
        async with _WRITE_LOCK:
            active, live, current = await asyncio.to_thread(_live_config)
            config_guard.check_write_request(
                action, keys, expect_hash, config_store.config_hash(current)
            )
            return await _write(active, live, current, action, keys, value)
    except ScopeError as exc:
        logger.warning("config refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    except ConfigWriteError as exc:
        return exc.payload
    except config_patch.ConfigPatchError as exc:
        # The live file can be invalid YAML: a person edits it by hand while the
        # gateway runs. A read has to say so rather than raise.
        return {"error": str(exc)}
    except OSError as exc:
        logger.warning("config failed: %s", exc_kind(exc))
        return {"error": "the configuration could not be written"}
