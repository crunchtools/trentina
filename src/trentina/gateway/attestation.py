"""A secondary's signed account of its own scanner, on request (#640).

The only thing a secondary signed before this was a response to a real
``tools/call`` (``vsa.py``), so the three values a primary pins to trust it —
its key, its perimeter stamp and its judge — reached the approval page as the
operator agent's claim. ``trentina/attest`` is the one method this adds to the
federation wire: the primary sends a nonce, the secondary signs
``{verifier, perimeter_stamp, judge, nonce, ts}`` with the same key and through
the same canonical form as a verdict assertion, and the primary checks it
against the key the OPERATOR supplied — never a key taken from the link.

A method and not a tool (ruling on #640). The response envelope is emitted only
on the judged remote path, so an internal tool carrying one would be signing a
verdict over bytes no layer read; and a provisioning handshake has no business
going through short names, tool pins and the tool audit. What a peer reaches is
MCP plus this, and this returns only what every signed response already
carries.

An older secondary answers ``-32601``, and so does one that declines to
attest: the two are indistinguishable and that is harmless, because the
fallback is today's as-supplied staging, never trust.

Pure, like ``vsa.py``: no I/O and no gateway state.
"""

from __future__ import annotations

import re
from typing import Any

from . import vsa

#: The method name, on the gateway's own JSON-RPC surface beside ``ping``.
ATTEST_METHOD = "trentina/attest"

#: The challenge. Hex, so it is never text anyone reads, and long enough that
#: a secondary cannot have signed it before it was asked.
NONCE_RE = re.compile(r"^[0-9a-f]{32,128}\Z")

#: Why an attestation was not believed. Closed, so a refusal names the reason
#: and never anything the peer wrote.
REFUSALS = (
    "bad_signature",
    "malformed",
    "nonce_mismatch",
    "verifier_mismatch",
    "stale",
)


def build_attestation(
    *, verifier: str, perimeter_stamp: str, judge: str, nonce: str, ts: int
) -> dict[str, Any]:
    """The unsigned attestation.

    Its key set cannot be mistaken for a verdict assertion's in either
    direction: it has no ``content_sha256`` (so ``vsa.check_trust`` reads it as
    ``hash_mismatch``) and a verdict assertion has no ``nonce``.
    """
    return {
        "verifier": verifier,
        "perimeter_stamp": perimeter_stamp,
        "judge": judge,
        "nonce": nonce,
        "ts": int(ts),
    }


def check_attestation(
    envelope: Any,
    *,
    public_key: str,
    nonce: str,
    verifier: str,
    now: int,
) -> tuple[dict[str, Any] | None, str]:
    """``(assertion, "verified")`` iff ``envelope`` is the pinned key's signature
    over an attestation answering THIS ``nonce``, from the profile that was
    dialled, recent, and carrying a stamp and judge that are strings.
    Otherwise ``(None, reason)`` with a reason from ``REFUSALS``. Never raises.
    """
    assertion = vsa.verify_assertion(envelope, public_key)
    if assertion is None:
        return None, "bad_signature"
    stamp, judge, ts = (assertion.get(k) for k in ("perimeter_stamp", "judge", "ts"))
    checks = (
        (
            isinstance(stamp, str) and bool(stamp) and isinstance(judge, str) and bool(judge),
            "malformed",
        ),
        (assertion.get("nonce") == nonce, "nonce_mismatch"),
        (assertion.get("verifier") == verifier, "verifier_mismatch"),
        (
            isinstance(ts, int)
            and not isinstance(ts, bool)
            and abs(now - ts) <= vsa.MAX_AGE_SECONDS,
            "stale",
        ),
    )
    for holds, reason in checks:
        if not holds:
            return None, reason
    return assertion, "verified"
