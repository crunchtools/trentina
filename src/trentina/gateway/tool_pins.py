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
from typing import Any

from .. import perimeter_db
from ..database import record_detection
from ..logsafe import redact_source

logger = logging.getLogger(__name__)

BASELINE_SECONDS = 600.0
"""How long after an upgrade a tool seen for the first time is pinned approved."""

FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def backend_id(url: str) -> str:
    """A backend's identity. Hashed because a URL can carry a token."""
    return hashlib.sha256(url.encode()).hexdigest()


def canonical(tool: dict[str, Any]) -> str:
    """The tool object as sorted, compact JSON, without the gateway's own keys."""
    kept = {k: v for k, v in tool.items() if not k.startswith("_trentina_")}
    return json.dumps(kept, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(canonical_json: str) -> str:
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def changed_fields(old_json: str | None, new_json: str) -> list[str]:
    """Which top-level fields differ; ``["new"]`` when there was no approved version."""
    if old_json is None:
        return ["new"]
    old, new = json.loads(old_json), json.loads(new_json)
    keys = sorted(set(old) | set(new))
    return [k for k in keys if old.get(k) != new.get(k)]


def loosens_safety(old_json: str | None, new_json: str) -> bool:
    """True when an annotation moved toward "safe to run": ``readOnlyHint`` to
    true, or ``destructiveHint`` (default true) to false."""
    if old_json is None:
        return False
    old = json.loads(old_json).get("annotations") or {}
    new = json.loads(new_json).get("annotations") or {}
    read_only = new.get("readOnlyHint") is True and old.get("readOnlyHint") is not True
    destructive = new.get("destructiveHint") is False and old.get("destructiveHint") is not False
    return read_only or destructive


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


def check_tools(url: str, backend: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pin ``tools`` against ``url``'s approvals; return those not held."""
    bid = backend_id(url)
    baseline = _baseline_open()
    return [
        tool
        for tool in tools
        if isinstance(tool.get("name"), str) and _pin_one(bid, backend, tool, baseline)
    ]


def _pin_one(bid: str, backend: str, tool: dict[str, Any], baseline: bool) -> bool:
    """Pin one tool; True when it is served."""
    name = tool["name"]
    body = canonical(tool)
    current = (digest(body), body)
    row = perimeter_db.get_pin(bid, name)
    if row is None:
        if baseline:
            perimeter_db.put_pin(bid, name, approved=current, pending=None, rejected=False)
            return True
        perimeter_db.put_pin(bid, name, approved=None, pending=current, rejected=False)
        _report(backend, name, None, body)
        return False
    approved = (row["approved_hash"], row["approved_json"]) if row["approved_hash"] else None
    if approved and approved[0] == current[0]:
        if row["pending_hash"]:
            # Reverted to what was approved: the held version is gone.
            perimeter_db.put_pin(bid, name, approved=approved, pending=None, rejected=False)
        return True
    if row["pending_hash"] != current[0]:
        perimeter_db.put_pin(bid, name, approved=approved, pending=current, rejected=False)
        _report(backend, name, approved[1] if approved else None, body)
    return False


def decide(url: str, tool: str, *, approve: bool) -> bool:
    """Approve or reject a held tool. False when nothing is held under that name."""
    bid = backend_id(url)
    row = perimeter_db.get_pin(bid, tool)
    if row is None or not row["pending_hash"]:
        return False
    approved = (row["approved_hash"], row["approved_json"]) if row["approved_hash"] else None
    pending = (row["pending_hash"], row["pending_json"])
    if approve:
        perimeter_db.put_pin(bid, tool, approved=pending, pending=None, rejected=False)
    else:
        perimeter_db.put_pin(bid, tool, approved=approved, pending=pending, rejected=True)
    return True


#: The closed reason code the call gate refuses a held tool with (#469), in the
#: JSON-RPC error's ``data.reason``. A federated downstream maps it to its own
#: words ("held upstream, awaiting approval"); it never relays peer text (#592).
TOOL_HELD_REASON = "tool_held"


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
    """What is held under ``url``: tool, changed fields, whether rejected."""
    out: list[dict[str, Any]] = []
    for row in perimeter_db.list_pending_pins(backend_id(url)):
        out.append(
            {
                "tool": row["tool"],
                "changed": changed_fields(row["approved_json"], row["pending_json"]),
                "safety_loosened": loosens_safety(row["approved_json"], row["pending_json"]),
                "rejected": bool(row["rejected"]),
            }
        )
    return out
