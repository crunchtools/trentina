"""The federated verdict assertion (#592, D1): what an upstream's perimeter
concluded about a response, signed, so a downstream that pins the matching
public key and perimeter stamp can trust the scan instead of re-judging (D2a).

SLSA-VSA shaped: ``{verifier, content_sha256, verdict, perimeter_stamp, ts}``,
signed with the ingress's Ed25519 signing key (``FederationConfig.signing_key``)
and verified with the downstream's pinned public key. This module is PURE — no
I/O, no gateway state, no decision objects: the emission site (``transports/mcp``)
and the trust site (D2a) map to and from it. The signature covers the RFC 8785
canonical form of the assertion, and ``content_sha256`` binds it to the exact
delivered bytes both sides can reproduce (``content_digest``).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .. import audit_chain
from . import edge_key

#: The assertion rides under ``_meta`` beside a federated response, like the
#: paging marker (#592, B2): the MCP SDK drops a root-level reserved key but
#: keeps ``_meta``, so a downstream Trentina reads it while a plain client
#: ignores it.
VSA_KEY = "_trentina_vsa"

#: An assertion older than this is not trusted (clock skew + flight time); the
#: downstream re-judges instead (#592, D2a). Matches the edge JWT's horizon.
MAX_AGE_SECONDS = 300


def content_digest(blocks: list[Any] | None, structured: Any, is_error: bool) -> str:
    """The sha256 of a response's delivered form, computed the same on both sides.

    Over the content blocks as ``_serialize_content_block`` shapes them, the
    structured content, and ``isError`` — the bytes the agent receives, so the
    downstream can bind the signature to exactly what it got. NOT over
    ``_trentina_warning``/``_meta`` (the SDK and the reserved-key strip alter
    those), and NOT over ``DefenseVerdict.read`` (the downstream cannot
    reproduce the unpacked text without reading it, which is the work being
    skipped).
    """
    payload = {"content": blocks or [], "structuredContent": structured, "isError": bool(is_error)}
    return hashlib.sha256(audit_chain.canonical(payload)).hexdigest()


#: The gap/truncation flags a warning carries (warning.py), all closed-set
#: booleans — the part of a verdict a downstream must see to apply its own mode.
_GAP_FLAGS = (
    "l2_unavailable",
    "l3_unavailable",
    "binary_unread",
    "l2_truncated",
    "l3_truncated",
)


def verdict_summary(warning: dict[str, Any] | None, mode: str) -> dict[str, Any]:
    """The closed verdict an assertion carries, from a gateway warning + mode.

    ONE definition shared by the emit side (#592, D1) and the trust side (D2a),
    so the downstream reconstructs exactly what the upstream concluded. Only
    closed-set facts: the flagging layer, the risk level, the gap/truncation
    flags, oversize, and the unread binary kinds — never any free text an L3
    assessment or a backend wrote (``warning.py`` keeps those out of these
    fields; finding types are a closed enum). ``warning`` is None for a clean
    delivered response, which summarises as not-flagged, no gaps.
    """
    w = warning or {}
    return {
        "flagged_by": w.get("flagged_by"),
        "risk_level": w.get("risk_level"),
        "gaps": sorted(flag for flag in _GAP_FLAGS if w.get(flag)),
        "oversize": bool(w.get("oversize")),
        "unread_kinds": sorted(w.get("unread_kinds") or []),
        "mode": mode,
    }


def build_assertion(
    *, verifier: str, content_sha256: str, verdict: dict[str, Any], perimeter_stamp: str, ts: int
) -> dict[str, Any]:
    """The unsigned assertion. ``verdict`` is the closed DefenseVerdict summary
    (flagged_by, risk_level, gaps, oversize, unread, truncated, mode); ``verifier``
    names the signing ingress; ``perimeter_stamp`` is its policy identity."""
    return {
        "verifier": verifier,
        "content_sha256": content_sha256,
        "verdict": verdict,
        "perimeter_stamp": perimeter_stamp,
        "ts": int(ts),
    }


def sign_assertion(assertion: dict[str, Any], signing_key_pem: str) -> dict[str, Any]:
    """Sign ``assertion`` and wrap it as ``{assertion, signature}`` (signature hex).

    The signature is over the RFC 8785 canonical form, so the downstream
    verifies the same bytes regardless of key order or re-serialization.
    """
    key = edge_key.load_private_key(signing_key_pem)
    signature = edge_key.sign(key, audit_chain.canonical(assertion))
    return {"assertion": assertion, "signature": signature.hex()}


def verify_assertion(envelope: Any, public_key_pem: str) -> dict[str, Any] | None:
    """The assertion iff ``envelope`` is a well-formed ``{assertion, signature}``
    whose signature is the pinned key's over the assertion's canonical form, else
    None. Never raises on a malformed envelope or a bad key — a caller that gets
    None re-judges (fail-closed, #592, D2a)."""
    if not isinstance(envelope, dict):
        return None
    assertion = envelope.get("assertion")
    signature = envelope.get("signature")
    if not isinstance(assertion, dict) or not isinstance(signature, str):
        return None
    try:
        raw = bytes.fromhex(signature)
    except ValueError:
        return None
    try:
        key = edge_key.load_public_key(public_key_pem)
        # Canonicalizing an attacker-supplied assertion can raise — RFC 8785 has
        # no form for a non-finite number, and JSON parses NaN/Infinity by
        # default — so it is inside the guard: a malformed assertion fails
        # closed to None, it does not raise into the caller.
        payload = audit_chain.canonical(assertion)
    except (edge_key.EdgeKeyError, ValueError, TypeError):
        return None
    if not edge_key.verify(key, raw, payload):
        return None
    return assertion
