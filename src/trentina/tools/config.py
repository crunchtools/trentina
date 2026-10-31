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
from ..gateway.approval_routes import PATH
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
    from ..gateway.loader import ActiveConfig
    from ..gateway.profile import Profile

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


def _candidate_loads(live: Path, text: str, providers: dict[str, Any]) -> dict[str, Profile]:
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
        return config.profiles
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


def _seat_facts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, str]:
    """What a person needs to see about a seat change: who holds it now, and
    who would. The names come from a file the operator can write, so they go
    through ``checked_display`` like anything else it chose."""
    return {
        "Holds the operator seat now": pending.checked_display(
            ", ".join(sorted(before)) or "nobody", what="the current operator seat"
        ),
        "Would hold it after this change": pending.checked_display(
            ", ".join(sorted(after)) or "nobody", what="the proposed operator seat"
        ),
        "What this means": "Whoever holds the seat is root on this gateway.",
    }


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


def _needs_approval(
    active: ActiveConfig,
    after: dict[str, Profile],
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> tuple[pending.Kind, dict[str, str]] | None:
    """Whether this write is one a person has to agree to, and what to show them.

    Two of them, and they are not a privilege boundary — the operator is root.
    They exist because the operator is a model, so the question is whether it
    can be talked into the two changes whose blast radius is out of all
    proportion to how plausible the request would look: minting a second root,
    and believing another gateway's scan instead of running our own.
    """
    proposals: list[tuple[pending.Kind, dict[str, str]]] = []
    before_seat = config_guard.operator_seat(active.config.profiles)
    after_seat = config_guard.operator_seat(after)
    if before_seat != after_seat:
        proposals.append((pending.Kind.OPERATOR_SEAT, _seat_facts(before_seat, after_seat)))
    if not config_guard.trust_stays_human(action, keys, value):
        before_pins = config_guard.trust_pins(active.config.profiles)
        changed = sorted(
            (where, pin)
            for where, pin in config_guard.trust_pins(after).items()
            if before_pins.get(where) != pin
        )
        proposals.extend(
            (pending.Kind.FEDERATION_TRUST, _trust_facts(where, pin)) for where, pin in changed
        )
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
                f"Nothing has changed. Ask a person to open {PATH} on this gateway and "
                "approve it with the approval password. It expires on its own if nobody "
                "does."
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
