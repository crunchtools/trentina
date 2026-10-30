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
#: downstream re-judges instead (#592, D2a). Wider than the 60 s edge JWT: this
#: must survive the upstream's own tool-call latency plus the return hop, where
#: the edge JWT covers only a single outbound request. Bound to content_sha256,
#: so a replayed assertion only validates the identical bytes it was signed for.
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
    *,
    verifier: str,
    content_sha256: str,
    verdict: dict[str, Any],
    perimeter_stamp: str,
    ts: int,
    judge: str = "",
) -> dict[str, Any]:
    """The unsigned assertion. ``verdict`` is the closed DefenseVerdict summary
    (flagged_by, risk_level, gaps, oversize, unread, truncated, mode); ``verifier``
    names the signing ingress; ``perimeter_stamp`` is its L2 policy identity and
    ``judge`` its L3 one (provider/model/pack) — the stamp does not cover L3, so
    the two are pinned separately downstream."""
    return {
        "verifier": verifier,
        "content_sha256": content_sha256,
        "verdict": verdict,
        "perimeter_stamp": perimeter_stamp,
        "judge": judge,
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


#: Why a federated response was NOT trusted (#592, D2a) — the caller re-judges
#: and maps the reason to a degradation. ``absent``/``bad_signature`` and the
#: rest are a closed set; ``trusted`` is the one success value.
TRUST_REASONS = (
    "absent",
    "bad_signature",
    "hash_mismatch",
    "stamp_mismatch",
    "judge_mismatch",
    "mode_mismatch",
    "stale",
)


def check_trust(
    envelope: Any,
    *,
    public_key: str,
    content_sha256: str,
    perimeter_stamp: str,
    judge: str,
    mode: str,
    now: int,
) -> tuple[dict[str, Any] | None, str]:
    """Decide whether a federated response's assertion may be trusted (#592, D2a).

    Returns ``(assertion, "trusted")`` iff the envelope verifies against the
    pinned ``public_key`` AND binds to the delivered bytes (``content_sha256``),
    the pinned ``perimeter_stamp`` (the peer's L2 model and gates) and ``judge``
    (its L3 provider/model/pack — the stamp does NOT cover L3, so a peer that
    swapped to a weaker judge must be caught here), the resolved ``mode``, and is
    no older than ``MAX_AGE_SECONDS``; otherwise ``(None, reason)`` with a closed
    reason (``TRUST_REASONS``) so the downstream re-judges and audits WHY it did
    not trust. Pure and fail-closed: any shortfall is a re-judge, never a trust.
    """
    if envelope is None:
        return None, "absent"
    assertion = verify_assertion(envelope, public_key)
    if assertion is None:
        return None, "bad_signature"
    verdict = assertion.get("verdict")
    ts = assertion.get("ts")
    fresh = isinstance(ts, int) and not isinstance(ts, bool) and abs(now - ts) <= MAX_AGE_SECONDS
    bindings = (
        (assertion.get("content_sha256") == content_sha256, "hash_mismatch"),
        (assertion.get("perimeter_stamp") == perimeter_stamp, "stamp_mismatch"),
        (assertion.get("judge") == judge, "judge_mismatch"),
        (isinstance(verdict, dict) and verdict.get("mode") == mode, "mode_mismatch"),
        (fresh, "stale"),
    )
    for bound, reason in bindings:
        if not bound:
            return None, reason
    return assertion, "trusted"


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
