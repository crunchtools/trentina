"""Stats tool — quarantine_stats for session and blocklist information.

Scoped by role, because "stats" over a shared database is the widest of the
admin tools. Unfiltered, the 30-day audit lists every backend and tool any
profile called, with volumes, and a detection's ``source`` is written as
``profile:backend:tool`` — so the recent-detections list hands the reader other
agents' names and the URLs they fetched.

An agent profile therefore gets its own rows and its own effective settings.
The operator gets the gateway. Nobody gets a host filesystem path they cannot
act on: ``classifier_model_path`` is an operator field.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..config import get_config
from ..database import (
    get_blocklist_stats,
    get_compression_stats,
    get_fanout,
    get_gateway_call_stats,
    get_recent_destinations,
    opened_path,
    snapshot_reader,
)
from ..gateway.errors import ScopeError
from ..gateway.scope import CallerScope, require_caller
from ..gateway.service import judge_stamp, service_profile
from ..gateway.surface import TOKEN_NOTE, surface_profiles, surface_report
from ..logsafe import redact_source
from ..outcomes import Outcome
from ..perimeter_db import perimeter_stamp
from ..quarantine.classifier import is_classifier_available, model_info

GATEWAY_AUDIT_LOOKBACK_DAYS = 30

# Shipped inline with the audit block. Without it the columns invite the same
# misreading the outcome taxonomy was built to prevent: "blocked" is the
# defense doing its job, and only "failed" indicates something needs fixing.
COLUMN_MEANINGS = {
    "ok": "Call returned content.",
    "blocked": (
        "Policy stopped the call: defense pipeline block, allowlist denial, "
        "or request guard. Working as designed — a security metric, not an "
        "error rate."
    ),
    "tripped": (
        "A decoy tool was called, or a planted credential was in a call's "
        "arguments. Not an error and not a block: read what that caller was "
        "delivered before it."
    ),
    "failed": (
        "Something broke: tool-reported error, upstream failure, or a gateway "
        "bug. This is the health signal."
    ),
    "unknown": "Row predates the outcome taxonomy.",
}

#: Destinations shown per profile.
RECENT_DESTINATIONS = 20

NOT_BUILT = {"error": "tool list not built yet; it is measured on the first tools/list"}


def _classifier() -> dict[str, Any]:
    """Whether L2 is up, and which model at which threshold (#350).

    The model's id and revision are no host path, so an agent sees them too:
    they say what its L2 verdicts mean.
    """
    available = is_classifier_available()
    model = model_info() if available else None
    return {
        "available": available,
        "model": model.id if model else None,
        "revision": model.revision if model else None,
        "threshold": model.threshold if model else None,
        "window_tokens": model.window if model else None,
    }


def _agent_stats(scope: CallerScope) -> dict[str, Any]:
    """One profile's own numbers, and the settings it actually runs under.

    The defense block is the caller's own ``profile.defense`` rather than the
    process defaults, which is both narrower and more accurate: a profile with
    its own provider, model or thresholds was never described by the globals.
    """
    defense = scope.profile.defense
    return {
        "scope": scope.label,
        "config": {
            "provider": defense.provider,
            "model": defense.model,
            "l2_threshold": defense.l2_threshold,
            "enforcement": defense.enforcement,
            "modes": defense.modes,
        },
        "classifier": _classifier(),
        "blocklist": get_blocklist_stats(profile=scope.name),
        # An agent is not shown its own decoy trips (#357), here or among its
        # destinations: the operator's view below is where they are read.
        "gateway_audit": {
            **get_gateway_call_stats(
                profile=scope.name, days=GATEWAY_AUDIT_LOOKBACK_DAYS, trips=False
            ),
            "column_meanings": {k: v for k, v in COLUMN_MEANINGS.items() if k != "tripped"},
        },
        # Its own, as written: text it chose, shown back to it (#266).
        "destinations": [
            row
            for row in get_recent_destinations(
                scope.name, RECENT_DESTINATIONS, GATEWAY_AUDIT_LOOKBACK_DAYS
            ).get(scope.label, [])
            if row["outcome"] != Outcome.DECOY_TRIPPED.value
        ]
        if scope.name
        else [],
        "surface": (surface_report(scope.name) if scope.name else None) or NOT_BUILT,
        "token_note": TOKEN_NOTE,
    }


async def get_trentina_stats() -> dict[str, Any]:
    """Get trentina session stats, configuration, and blocklist summary.

    Returns:
        The caller's own audit rows, detections and effective defense settings,
        under ``scope: "<profile>"``, with its tool ``surface`` (offered, allowed,
        served) and the response ``delivery`` sizes; or, for an operator, the gateway-wide
        view under ``scope: "gateway"``, including compression savings and the
        classifier's configured path, every profile's recent ``destinations``
        and the ``fanout`` signal (#266). A caller the gateway cannot identify
        gets ``{"scope": "none", "error": ...}`` and no numbers at all.
    """
    try:
        scope = require_caller("quarantine_stats")
    except ScopeError as exc:
        return {"scope": "none", "error": str(exc)}
    # Every number below is a SQLite aggregate over the audit tables, about
    # 2.7 s per million rows; on the loop that stalls every profile, and a
    # denied call is a cheap way to add rows (#295).
    return await asyncio.to_thread(_snapshot, scope, opened_path())


def _snapshot(scope: CallerScope, path: str) -> dict[str, Any]:
    """The caller's view, read on this worker's own connection."""
    with snapshot_reader(path):
        return _agent_stats(scope) if not scope.is_operator else _gateway_stats()


def _gateway_stats() -> dict[str, Any]:
    """The operator's gateway-wide view. Runs in a worker thread."""
    config = get_config()
    return {
        "scope": "gateway",
        # What this gateway scans UNDER, as a federated peer would pin it
        # (#637). Nothing exposed these before, so an operator asked to vet
        # another gateway's scanner had no way to read its own for comparison,
        # and no way to tell a peer what to pin. Both are identities, not
        # secrets: they name a model, a revision, a threshold and a judge.
        "perimeter": {
            "stamp": perimeter_stamp(),
            "judge": judge_stamp(service_profile()),
        },
        "config": {
            "model": config.model,
            "require_l2": config.require_l2,
            "require_l3": config.require_l3,
            "admission_tokens": config.admission_tokens,
            "provider": config.provider,
            "llm_available": config.has_llm,
            "classifier_model": config.classifier_model,
            "classifier_threshold": config.classifier_threshold,
            "classifier_model_path": config.classifier_model_path,
        },
        "classifier": {**_classifier(), "model_path": config.classifier_model_path},
        "blocklist": get_blocklist_stats(),
        "gateway_audit": {
            **get_gateway_call_stats(days=GATEWAY_AUDIT_LOOKBACK_DAYS),
            "column_meanings": COLUMN_MEANINGS,
        },
        # Another agent's text, so fingerprints only: the operator's agent
        # reads this unjudged, and no character allowlist stops
        # SYSTEM:ignore_previous_instructions. One destination has one
        # fingerprint in every profile; the database keeps the value.
        "destinations": {
            name: [{**row, "destination": redact_source(row["destination"])} for row in rows]
            for name, rows in get_recent_destinations(
                None, RECENT_DESTINATIONS, GATEWAY_AUDIT_LOOKBACK_DAYS
            ).items()
        },
        "fanout": get_fanout(),
        "compression": get_compression_stats(),
        "surface": {name: surface_report(name) for name in surface_profiles()},
        "plugins": _plugins(),
        "token_note": TOKEN_NOTE,
    }


def _plugins() -> list[dict[str, Any]]:
    """The installed transform plugins (the ``trentina.transforms.v1`` entry
    points), each by ``dist:name`` and version. Entry-point METADATA only — no
    plugin code is imported or run to report this. Empty in a stock image,
    which ships no plugin."""
    from ..plugins.registry import TRANSFORM_GROUP, discover, installed_version

    return [
        {"ref": ref, "version": installed_version(ref.partition(":")[0])}
        for ref in sorted(discover(TRANSFORM_GROUP))
    ]
