"""L3 over a proxied response, where an L3 failure must never become clean.

The router writes one audit row per call; ``classify_exception`` walks
``__cause__`` and maps a BlockedSourceError to Outcome.BLOCKED_DEFENSE
(outcomes.py).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from trentina.errors import BlockedSourceError
from trentina.gateway.errors import BackendCallError
from trentina.gateway.audit import _audit
from trentina.transports.jsonrpc import _err, _ok
from trentina.logsafe import exc_kind, exc_where
from trentina.outcomes import Outcome, classify_exception, refusal_of
from trentina.quarantine.agent import quarantine_detect

log = logging.getLogger(__name__)

L3_UNAVAILABLE = {"reason": "l3_unavailable", "gaps": ["l3"], "alternatives": ["flag"]}


async def judge_l3(content: str, *, source: str, mode: str) -> dict[str, Any]:
    """L3's assessment of ``content``, or a refusal. Never a default verdict.

    # TRUST: L3 call on untrusted content
    #   untrusted: `content` from a remote backend
    #   judged-by: L3 (quarantine_detect)
    #   on-failure: fail-closed; ANY failure of the call (provider error, timeout,
    #     malformed JSON, a bug here) is a refusal with a closed reason code,
    #     audited by the router as blocked_defense
    #   owner: this function; the router owns the audit row
    #   evidence: T1 `except Exception` leaves CancelledError and KeyboardInterrupt
    #     to propagate; T3 outcomes.classify_exception maps BlockedSourceError to
    #     BLOCKED_DEFENSE via __cause__; T3 CLAUDE.md logging rule
    """
    try:
        assessment = await quarantine_detect(content, layer1_context="")
    except Exception as exc:
        log.warning("l3: judge failed for a %s call: %s at %s", mode, exc_kind(exc), exc_where(exc))
        raise BlockedSourceError(
            source, "l3_unavailable", refusal={**L3_UNAVAILABLE, "mode": mode}
        ) from exc
    if assessment.get("l3_unavailable"):
        # No provider configured is a gap, not a clean read (defense._stage_two).
        raise BlockedSourceError(source, "l3_unavailable", refusal={**L3_UNAVAILABLE, "mode": mode})
    return assessment


FLAGGED = {"reason": "flagged", "mode": "block", "flagged_by": "l3", "alternatives": ["redact"]}


async def deliver_blocking(
    profile_name: str, backend_name: str, tool_name: str, text: str, req_id: Any
) -> dict[str, Any]:
    """Block mode: judge a backend result; audit exactly one row on every exit."""
    t0 = time.monotonic()
    try:
        try:
            assessment = await judge_l3(text, source=f"{backend_name}/{tool_name}", mode="block")
        except BlockedSourceError as exc:
            raise BackendCallError("perimeter refused the response") from exc
    except BackendCallError as exc:
        elapsed = int((time.monotonic() - t0) * 1000)
        _audit(profile_name, backend_name, tool_name, classify_exception(exc), elapsed,
               "perimeter refused the response")
        return _err(req_id, -32603, "[TRENTINA] Refused.", refusal_of(exc))

    elapsed = int((time.monotonic() - t0) * 1000)
    if assessment.get("injection_detected"):
        _audit(profile_name, backend_name, tool_name, Outcome.BLOCKED_DEFENSE, elapsed,
               "response blocked by defense")
        return _err(req_id, -32603, "[TRENTINA] Refused.", FLAGGED)
    _audit(profile_name, backend_name, tool_name, Outcome.OK, elapsed)
    return _ok(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
