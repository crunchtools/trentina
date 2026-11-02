"""Tool pinning — notice that a backend's tool CHANGED (#469).

``scan_tool_list`` re-judges a changed description, but a rug pull that stays
benign-looking passes it: a new destructive tool behind ``tools_allow: ["*"]``,
a ``destructiveHint`` that flips, a schema that grows a ``url`` parameter. Here
every tool a remote backend lists is hashed whole (canonical JSON of the tool
object, ``_trentina_*`` keys excluded) and compared with the hash an operator
approved. A new or changed tool is HELD: withheld from every profile, an
explicit allowlist and a ``*`` included, until ``tool_pins`` approves it.

Pins belong to the backend (the hash of its URL), not to a profile, and live in
the perimeter store (``perimeter_db.py``), which never expires them. The check
runs on every aggregate build, so a ``list_changed`` re-list is covered. A
tool that vanishes keeps its pin. Nothing a backend wrote reaches a log: a
detection row names the backend, the tool and the changed FIELDS only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from .. import perimeter_db
from ..database import record_detection
from ..logsafe import redact_source
from .profile import same_gateway_endpoint

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .profile import Profile

logger = logging.getLogger(__name__)

BASELINE_SECONDS = 600.0
"""How long after an upgrade a tool seen for the first time is pinned approved."""

FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

BULK_FIELDS = frozenset({"description", "inputSchema"})
"""The only changes ``decide_all`` will release as a batch (6.2.0).

These two are what the gateway's own re-compression moves: a served description
under ``preprocess_tool_descriptions`` is the compressor's output, so anything
that makes the gateway re-compress changes every compressed definition at once
(``docs/tool-pinning.md``). Everything else a backend can change —
``annotations``, ``name``, ``title``, ``outputSchema``, and ``["new"]`` for a
tool with no approved definition at all — is a rug-pull shape, and stays one
deliberate approval at a time. A never-approved tool is exactly what #469 exists
to put in front of a person; it is not batch work however many of them arrive.
"""


def backend_id(url: str) -> str:
    """A backend's identity. Hashed because a URL can carry a token."""
    return hashlib.sha256(url.encode()).hexdigest()


def canonical(tool: dict[str, Any]) -> str:
    """The tool object as sorted, compact JSON, without the gateway's own keys."""
    kept = {k: v for k, v in tool.items() if not k.startswith("_trentina_")}
    return json.dumps(kept, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(canonical_json: str) -> str:
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def _changed_fields(old: dict[str, Any] | None, new: dict[str, Any]) -> list[str]:
    """Which top-level fields differ; ``["new"]`` when there was no approved version."""
    if old is None:
        return ["new"]
    keys = sorted(set(old) | set(new))
    return [k for k in keys if old.get(k) != new.get(k)]


def _loosens_safety(old: dict[str, Any] | None, new: dict[str, Any]) -> bool:
    """True when an annotation moved toward "safe to run": ``readOnlyHint`` to
    true, or ``destructiveHint`` (default true) to false."""
    if old is None:
        return False
    old_ann = old.get("annotations") or {}
    new_ann = new.get("annotations") or {}
    read_only = new_ann.get("readOnlyHint") is True and old_ann.get("readOnlyHint") is not True
    destructive = (
        new_ann.get("destructiveHint") is False and old_ann.get("destructiveHint") is not False
    )
    return read_only or destructive


# The three below take JSON because that is what the hold path has in hand
# (``_report``); ``pending`` parses each row ONCE and calls the parsed forms,
# since it runs over hundreds of rows on the event loop.


def changed_fields(old_json: str | None, new_json: str) -> list[str]:
    """``_changed_fields`` on serialized definitions."""
    old = None if old_json is None else json.loads(old_json)
    return _changed_fields(old, json.loads(new_json))


def loosens_safety(old_json: str | None, new_json: str) -> bool:
    """``_loosens_safety`` on serialized definitions."""
    old = None if old_json is None else json.loads(old_json)
    return _loosens_safety(old, json.loads(new_json))


#: Keys whose own keys are NAMES an author chose, not schema vocabulary. A
#: property may legitimately be called ``description``, and that key is part of
#: the schema's shape where the annotation of the same name is not.
_NAME_MAPS = frozenset({"properties", "patternProperties", "definitions", "$defs"})

#: Keywords whose value is DATA rather than a subschema. They are compared
#: verbatim and never walked: a ``description`` key inside a ``const`` or a
#: ``default`` is part of the value a call must send, not an annotation about
#: it, and stripping it would hide a change to what the schema accepts.
_LITERALS = frozenset({"const", "default", "examples", "enum"})


def _schema_shape(node: Any, *, names: bool = False) -> Any:
    """``node`` with every schema ``description`` ANNOTATION removed.

    ``names`` says the dict being walked is one whose keys are author-chosen
    names, so a key spelled ``description`` there is a property and is kept.
    Its values are subschemas, so the recursion drops back to vocabulary.

    A ``_LITERALS`` keyword's value is data and is kept whole: ``description``
    inside a ``const`` or a ``default`` is part of what a call must send.
    """
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if not names and key == "description" and isinstance(value, str):
                continue
            if not names and key in _LITERALS:
                out[key] = value  # data: compared whole, never walked
                continue
            out[key] = _schema_shape(value, names=not names and key in _NAME_MAPS)
        return out
    if isinstance(node, list):
        return [_schema_shape(item) for item in node]
    return node


def schema_shape_changed(old_json: str | None, new_json: str) -> bool:
    """``_schema_shape_changed`` on serialized definitions."""
    old = None if old_json is None else json.loads(old_json)
    return _schema_shape_changed(old, json.loads(new_json))


def _schema_shape_changed(old: dict[str, Any] | None, new: dict[str, Any]) -> bool:
    """True unless the new ``inputSchema`` is the approved one with its
    descriptions rewritten.

    This is what makes ``inputSchema`` safe to batch. The gateway's own
    compressor rewrites the DESCRIPTIONS inside a schema as well as the tool's
    own (``compress._compressed_properties``), which is why a re-compression
    reports ``description,inputSchema`` on hundreds of tools at once — 278 of
    breetai's 582. Those strings are the ONLY thing it touches, so the test is
    equality once they are taken out: anything else that moved is the backend's
    doing and goes in front of a person.

    It is deliberately not a "did it grow" check. That was the first cut, and
    Gatehouse was right that it let through every change which adds no key —
    a widened ``enum``, a changed ``type``, a relaxed
    ``additionalProperties``, or a ``required`` entry added to one nested
    object that another already had. Comparing what must not change beats
    enumerating the ways it could.
    """
    if old is None:
        return True
    return bool(_schema_shape(old.get("inputSchema")) != _schema_shape(new.get("inputSchema")))


def _baseline_open() -> bool:
    perimeter_db.get_perimeter_db()  # opening the store is what detects the upgrade
    upgraded_at = perimeter_db.pins_upgraded_at
    return upgraded_at is not None and time.monotonic() < upgraded_at + BASELINE_SECONDS


def _report(backend: str, tool: str, old_json: str | None, new_json: str) -> None:
    fields = changed_fields(old_json, new_json)
    loosened = loosens_safety(old_json, new_json)
    logger.warning(
        "gateway: tool pin held backend=%s tool=%s fields=%s",
        backend,
        redact_source(tool),
        ",".join(fields),
    )
    record_detection(
        source_type="tool_pin",
        source=f"{backend}/{tool}",
        domain=None,
        layer1_stats={"changed": fields, "safety_loosened": loosened},
        risk_level="high" if loosened else "medium",
        backend=backend,
        tool=tool,
        direction="ingress",
        blocked=True,
    )


#: A reserved pin key marking that a federated backend's first list was
#: processed (#592, E1b). NUL is not a legal MCP tool name, so this never
#: matches, is served, or is listed as a tool. It is written even when the
#: first list was EMPTY, so a tool the peer adds later is held normally rather
#: than read as another first connect and auto-approved.
FIRST_SEEN_SENTINEL = "\x00first-seen"


def check_tools(
    url: str, backend: str, tools: list[dict[str, Any]], *, federated: bool = False
) -> list[dict[str, Any]]:
    """Pin ``tools`` against ``url``'s approvals; return those not held.

    A FEDERATED backend's first list is auto-approved as a unit (#592, E1b):
    declaring the link accepts the peer's curation — its offered set already
    passed the peer's own pin gate — so a large secondary does not storm the
    operator with hundreds of per-tool approvals. "First" is decided by a
    persisted marker (``FIRST_SEEN_SENTINEL``), not by whether any tool row
    exists, so an empty first list still records the connect and a later-added
    tool is held one at a time. The marker is read once, before the pass writes.

    It is the one place this gateway trusts a tool set it never showed anyone,
    so it is REPORTED (``_report_first_connect``). Holds wrote a log line and a
    detections row and approvals wrote nothing, which left the quieter path the
    one that trusts more: a container brought up without its perimeter volume
    re-approved every peer's whole offered set and said nothing at all.
    """
    bid = backend_id(url)
    first_connect = federated and not perimeter_db.has_pins(bid)
    baseline = _baseline_open() or first_connect
    served = [
        tool
        for tool in tools
        if isinstance(tool.get("name"), str) and _pin_one(bid, backend, tool, baseline)
    ]
    if first_connect:
        perimeter_db.put_pin(
            bid,
            FIRST_SEEN_SENTINEL,
            digest(FIRST_SEEN_SENTINEL),
            perimeter_db.PIN_APPROVED,
            FIRST_SEEN_SENTINEL,
        )
        _report_first_connect(backend, len(served))
    return served


def _report_first_connect(backend: str, count: int) -> None:
    """Say that a federated peer's whole offered set was approved unasked.

    The backend NAME is config and loggable; the tool names are not (#262), so
    the count stands for them and the audit holds the rest. ``blocked=False``:
    nothing was withheld, which is the point of recording it.
    """
    logger.warning(
        "gateway: federated backend=%s first connect — approved its offered set of %d "
        "tool(s) as a unit, unreviewed. Expected when the link is new; if it is not, "
        "the perimeter store was lost or the backend URL changed, and every tool the "
        "peer now offers has just been trusted. Check tool_pins.",
        backend,
        count,
    )
    record_detection(
        source_type="tool_pin",
        source=f"{backend}/{FIRST_SEEN_SENTINEL}",
        domain=None,
        layer1_stats={"first_connect": True, "approved_unreviewed": count},
        risk_level="medium",
        backend=backend,
        tool=FIRST_SEEN_SENTINEL,
        direction="ingress",
        blocked=False,
    )


def migrate_federated_pins(before: dict[str, Profile], after: dict[str, Profile]) -> list[str]:
    """Carry a federated backend's pins across a URL change, naming what moved.

    The other half of making a first connect honest. ``_report_first_connect``
    made the re-trust loud; this stops the common cause of it being a re-trust
    at all. A pin is keyed by a hash of the URL, so an operator normalising a
    trailing slash or adding an explicit ``:443`` presented the peer as new and
    had its whole offered set approved as a unit.

    Only a backend that is federated on BOTH sides is moved. A backend that
    gained or lost its ``federated`` block changed what it IS, not where it
    lives, and its pins are not this function's to carry over.

    And only a URL that still names the SAME ENDPOINT. The first cut of this
    moved pins on any URL change, which Gatehouse caught and which is worse
    than the problem it was fixing: repointing a federated backend at a server
    the writer controls would have inherited the real peer's approvals, with no
    first connect and no review. ``same_gateway_endpoint`` is the narrow
    normalisation — scheme and host case, a default port, a trailing slash —
    and it keeps the path and the query, because two gateways live behind one
    host on different prefixes and a token-in-URL backend carries its
    credential in the query. A genuinely new endpoint gets the first connect it
    should, loudly.
    """
    moved: list[str] = []
    for name, profile in after.items():
        was = before.get(name)
        if was is None:
            continue
        for backend_name, backend in profile.backends.items():
            old = was.backends.get(backend_name)
            if old is None or old.url == backend.url:
                continue
            if backend.federated is None or old.federated is None:
                continue
            if not same_gateway_endpoint(old.url, backend.url):
                continue
            if perimeter_db.move_pins(backend_id(old.url), backend_id(backend.url)):
                moved.append(f"{name}.{backend_name}")
    if moved:
        # Names only: a profile and a backend name are config, the URLs are not
        # (#262), and the point of the line is that no first connect follows.
        logger.warning(
            "gateway: federated backend URL changed for %s — carried its tool pins "
            "across, so this is not a first connect and nothing was re-approved",
            ", ".join(sorted(moved)),
        )
    return moved


def _pin_one(bid: str, backend: str, tool: dict[str, Any], baseline: bool) -> bool:
    """Pin one DEFINITION of one tool; True when it is served.

    One row per definition since 6.1.0, which makes this a lookup rather than a
    reconciliation. The old shape held one row per tool with an approved and a
    pending hash in it, and with tool lists partitioned per credential that
    could not represent two tenants served different definitions: the second
    listing overwrote the first's pending hash, and worse, a re-list matching
    the approved hash CLEARED the other tenant's hold as a "revert", so the two
    builds flapped the pin and wrote a fresh detection row on alternate passes.

    Now: an approved definition is served, a pending or rejected one is held,
    and one never seen is recorded pending and reported. Nothing a tenant lists
    can disturb what another tenant's definition is.
    """
    name = tool["name"]
    body = canonical(tool)
    current = digest(body)
    row = perimeter_db.get_pin(bid, name, current)
    if row is not None:
        return bool(row["state"] == perimeter_db.PIN_APPROVED)
    if baseline:
        perimeter_db.put_pin(bid, name, current, perimeter_db.PIN_APPROVED, body)
        return True
    perimeter_db.put_pin(bid, name, current, perimeter_db.PIN_PENDING, body)
    previous = perimeter_db.last_approved(bid, name)
    _report(backend, name, previous["definition_json"] if previous else None, body)
    return False


def decide(url: str, tool: str, *, approve: bool, definition_hash: str | None = None) -> bool:
    """Approve or reject one held definition. False when nothing is held.

    ``definition_hash`` names WHICH held definition, and is needed only where a
    tool has more than one — two tenants served different bytes. With exactly
    one held definition it is implied, which keeps the one-argument call every
    operator has been making correct. With several and no hash there is no
    single thing "approve this tool" could mean, so it refuses rather than
    guessing; ``tool_pins list`` carries each hash for that case.
    """
    bid = backend_id(url)
    held_hashes = perimeter_db.pending_hashes(bid, tool)
    if definition_hash is None:
        if len(held_hashes) != 1:
            return False
        definition_hash = held_hashes[0]
    elif definition_hash not in held_hashes:
        return False
    state = perimeter_db.PIN_APPROVED if approve else perimeter_db.PIN_REJECTED
    return perimeter_db.set_pin_state(bid, tool, definition_hash, state)


#: The closed reason code the call gate refuses a held tool with (#469), in the
#: JSON-RPC error's ``data.reason``. A federated primary maps it to its own
#: words ("held on the secondary, awaiting approval"); it never relays peer
#: text (#592).
TOOL_HELD_REASON = "tool_held"

#: The closed reason a federated PRIMARY refuses with when its secondary peer
#: answered a call with ``TOOL_HELD_REASON`` (#592, E1c). The primary authors
#: this itself — "held on the secondary, awaiting approval" — from the peer's closed
#: reason code alone, never relaying the peer's ``detail`` text (#262).
TOOL_HELD_SECONDARY_REASON = "tool_held_secondary"


def held(url: str, tool: str) -> bool:
    """Whether a CALL to ``tool`` on ``url`` must be refused by the pin gate (#469).

    True when the tool is not an approved pin: its row is missing (not yet
    pinned — fail closed; warmup pins every listed tool as approved, and a call
    that beats the first list waits one list), is held pending approval, or was
    rejected. False only for a cleanly approved tool. Pinning was a tools/list
    filter and never a call gate, so a tool whose description changed after
    approval (or, under long names, one never approved) was callable unapproved;
    this is the gate that closes that (``transports/mcp`` on a remote backend).
    """
    flags = perimeter_db.pin_hold_flags(backend_id(url), tool)
    return flags is None or flags[0] or flags[1]  # no row = held, fail closed


def pending(url: str) -> list[dict[str, Any]]:
    """What is held under ``url``: tool, its hash, changed fields, rejected.

    A tool can appear more than once since 6.1.0, which is why each entry
    carries ``hash``: that is what ``tool_pins approve`` needs to name one of
    two definitions. Each is diffed against the most recently APPROVED
    definition of that tool, since there may now be several.
    """
    bid = backend_id(url)
    rows = perimeter_db.list_pending_pins(bid)
    # One read for every held tool's approved definition, not one per tool: a
    # backend can hold dozens, and this is what each is diffed against.
    approved = perimeter_db.approved_by_tool(bid, {row["tool"] for row in rows})
    out: list[dict[str, Any]] = []
    # Parsed once per row, not once per comparison: a held set runs to hundreds
    # and this walk happens on the event loop.
    parsed = {tool: json.loads(body) for tool, body in approved.items()}
    for row in rows:
        tool = row["tool"]
        before = parsed.get(tool)
        after = json.loads(row["definition_json"])
        out.append(
            {
                "tool": tool,
                "hash": row["definition_hash"],
                "changed": _changed_fields(before, after),
                "safety_loosened": _loosens_safety(before, after),
                "schema_shape_changed": _schema_shape_changed(before, after),
                "rejected": bool(row["state"] == perimeter_db.PIN_REJECTED),
            }
        )
    return out


def pending_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    """Name a pending SET by its contents, so a batch approval can be bound to it.

    SHA-256 over the sorted ``(tool, hash)`` pairs still held — ``rejected`` rows
    excluded, since a rejection is a standing decision and not the batch's to
    reverse. A count would not do: a re-list that swapped N definitions for N
    others would keep it, and #469's premise is that an approval names a
    DEFINITION. This names a set of them.

    Pure, and the one implementation both ``tool_pins list`` and ``decide_all``
    read, so the digest a caller is shown cannot drift from the one it is held to.
    """
    pairs = sorted((row["tool"], row["hash"]) for row in rows if not row["rejected"])
    body = json.dumps(pairs, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


def unbatchable_reason(rows: Iterable[Mapping[str, Any]]) -> str:
    """Why this held set may not go as a batch, or ``""`` if it may.

    The rule, in one place, so what ``approve_all`` enforces is the same thing
    a listing could explain. Each clause names the tool responsible, because a
    refusal an operator cannot act on is a refusal they will work around.
    """
    for row in rows:
        if outside := sorted(set(row["changed"]) - BULK_FIELDS):
            return (
                f"{row['tool']} changed in {','.join(outside)}, which a batch will not "
                "release; approve or reject it on its own first"
            )
        if row["safety_loosened"]:
            # The hint lives in ``annotations``, which BULK_FIELDS excludes, so
            # this is unreachable today. Kept, and tested with the field rule
            # widened, so widening it later cannot quietly pass one.
            return f"{row['tool']} loosened a safety hint; approve it on its own"
        if row["schema_shape_changed"]:
            return (
                f"{row['tool']} changed its input schema beyond the descriptions the "
                "gateway's own compressor rewrites; approve it on its own"
            )
    return ""


#: A reserved pin key for the detection row a batch approval writes. NUL is not
#: a legal MCP tool name, as with ``FIRST_SEEN_SENTINEL``, so it never matches a
#: tool, is served, or is listed as one.
BULK_SENTINEL = "\x00bulk-approved"


def _report_bulk(backend: str, count: int) -> None:
    """Record that a whole held set was released on one decision.

    The count stands for the tool names, which are not loggable (#262); the
    manifest the tool returns and this detection row's ``layer1_stats`` are
    where an auditor reads which definitions it was.
    """
    logger.warning(
        "gateway: backend=%s batch approval released %d held tool definition(s) on one "
        "decision, each changed only in fields the gateway's own compressor rewrites. "
        "Expected after a migration that re-compressed descriptions; if nothing did, "
        "the set an operator approved was not the set it meant to.",
        backend,
        count,
    )
    record_detection(
        source_type="tool_pin",
        source=f"{backend}/{BULK_SENTINEL}",
        domain=None,
        layer1_stats={"approved_bulk": count},
        risk_level="medium",
        backend=backend,
        tool=BULK_SENTINEL,
        direction="ingress",
        blocked=False,
    )


def decide_all(
    url: str, backend: str, *, set_digest: str | None
) -> tuple[list[dict[str, Any]], str]:
    """Approve every definition the digested set holds. ``([], reason)`` refuses.

    Nothing is approved unless every row qualifies: a batch that released most
    of itself and reported the rest would be read as a success, and the rows it
    skipped are the ones that needed reading.

    The three gates are ``set_digest`` — the bytes ``pending`` showed, so a
    concurrent re-list cannot ride along — ``BULK_FIELDS``, which keeps every
    rug-pull shape on the one-at-a-time path, and ``schema_shape_changed``,
    which keeps ``inputSchema`` in the batch honest: a schema may differ from
    the approved one only in the descriptions the compressor rewrites. The digest is required
    HERE rather than at the tool, so no caller can reach a batch without one.
    """
    if not set_digest:
        return [], "approve_all needs the set_digest that list returned"
    rows = pending(url)
    if pending_digest(rows) != set_digest:
        return [], "the held set changed since it was listed; list it again and re-read it"
    holding = [row for row in rows if not row["rejected"]]
    if not holding:
        return [], "nothing is held under that backend"
    if refused := unbatchable_reason(holding):
        return [], refused
    moved = perimeter_db.set_pin_states(
        backend_id(url),
        [(row["tool"], row["hash"]) for row in holding],
        perimeter_db.PIN_APPROVED,
        was=perimeter_db.PIN_PENDING,
    )
    if moved is None:
        # One transaction, so nothing was written. A set that moved under the
        # write is the digest's case arriving a moment later than it could be
        # checked; the operator lists again rather than being told a partial
        # release succeeded.
        return [], "the held set moved while it was being approved; list it again"
    _report_bulk(backend, moved)
    return [
        {"tool": row["tool"], "hash": row["hash"], "changed": row["changed"]} for row in holding
    ], ""
