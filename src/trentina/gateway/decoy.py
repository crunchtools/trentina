"""Decoy tools and planted credentials: alarms with no model behind them (#357).

A ``decoy://`` backend's tools are declared in the profile and answered by
nothing. An agent doing its job has no reason to call one, so a call is
evidence that something else is steering it. A honeytoken is a fake
credential planted where only an attacker's instructions lead; one appearing
in the arguments of any call, to any backend, is the same evidence.

Both checks are deterministic: a tool name, and a planted value found as it
was planted, encoded (base64, hex, percent), reversed or in part
(``token_variants``, #864). Neither reads the content that caused the call.
The audit's ``session`` and ``call_ref`` columns are what lead back to that.

What this does not see: a planted credential the agent paraphrased, split
across calls or encoded some other way (``tests/test_coverage_gaps.py`` holds
that open), and anything an agent does without a tool call through the gateway.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..database import record_capture, record_detection
from ..dbus_interface import emit_detection_event
from ..token_variants import matcher_for
from .context import current_call
from .profile import HONEYTOKEN_REF_RE

if TYPE_CHECKING:
    from .profile import Backend, DecoyTool, Profile

LAYER = "decoy"
"""What a trip's detection row and event are credited to, where a layer's name goes."""


def served_tools(backend: Backend) -> list[dict[str, Any]]:
    """A decoy backend's tool list, in the shape a real backend's arrives in."""
    return [
        {"name": name, "description": decoy.description, "inputSchema": decoy.input_schema}
        for name, decoy in backend.decoys.items()
    ]


def leaked_tokens(profile: Profile, sent: Any) -> list[str]:
    """The ids of the profile's honeytokens found anywhere in ``sent``.

    ``sent`` is a request's whole ``params``, whatever its shape: the check
    runs before the tool name is resolved or the arguments are known to be a
    mapping, because a hijacked agent reaching for a tool it was never given
    is the call most worth an alarm.
    """
    text = json.dumps(sent, ensure_ascii=False, default=str)
    by_value: dict[str, list[str]] = {}
    for token, planted in profile.honeytokens.items():
        if planted.value is not None:
            by_value.setdefault(planted.value.get_secret_value(), []).append(token)
    if not by_value:
        return []
    hits = matcher_for(frozenset(by_value)).found(text)
    return sorted(token for value in hits for token in by_value[value])


def canned_result(profile: Profile, decoy: DecoyTool) -> dict[str, Any]:
    """What a call to ``decoy`` is answered with: its result text, with each
    ``{honeytoken:<id>}`` replaced by that planted value."""

    def planted_value(match: Any) -> str:
        secret = profile.honeytokens[match.group(1)].value
        return secret.get_secret_value() if secret is not None else str(match.group(0))

    text = HONEYTOKEN_REF_RE.sub(planted_value, decoy.result)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _by_id(profile: Profile, sent: Any) -> Any:
    """``sent`` with each planted value in a string or a key replaced by
    ``{honeytoken:<id>}``. Done before serializing: JSON escapes a quote or a
    backslash, and a value holding one would not match its own escaped form."""
    if isinstance(sent, str):
        for token, planted in profile.honeytokens.items():
            if planted.value is not None:
                sent = sent.replace(planted.value.get_secret_value(), f"{{honeytoken:{token}}}")
        return sent
    if isinstance(sent, dict):
        return {_by_id(profile, key): _by_id(profile, value) for key, value in sent.items()}
    if isinstance(sent, list):
        return [_by_id(profile, item) for item in sent]
    return sent


def keep_arguments(profile: Profile, backend: str, tool: str, arguments: Any) -> None:
    """Keep what a honeypot profile sent a decoy tool, beside what it read (#410).

    Whether a trip was the agent's job or an attacker's turns on what was
    asked for, and the audit row keeps the tool's name alone. Honeypot
    profiles only: a decoy on any other profile may be handed real text. A
    name the backend does not declare is no decoy and keeps nothing. A
    planted credential is kept by id, as the audit names it. The row carries
    the trip's ``call_ref`` and ``flagged_by`` of this tripwire, so a search
    for documents no layer flagged never returns it.
    """
    if not profile.honeypot or tool not in profile.backends[backend].decoys:
        return
    record_capture(
        profile.name,
        f"decoy:{backend}:{tool}",
        json.dumps(_by_id(profile, arguments), ensure_ascii=False, default=str),
        {"flagged_by": LAYER},
        current_call.get() or None,
    )


def record_trip(profile: str, backend: str, tool: str, what: str) -> None:
    """A detection row and a live event for a trip. ``what`` is the kind of
    trip and the ids of any planted credentials, never a value.

    Never blocklisted: ``blocked`` keys the blocklist, which refuses a source
    on its next fetch, and a tool is not a source. Called after the audit row
    is written, so a write that fails here loses the detection and not the
    trip: it surfaces as the gateway error it is.
    """
    source = f"{profile}:{backend}:{tool}"
    record_detection(
        source_type="decoy",
        source=source,
        domain=None,
        layer1_stats={},
        risk_level="high",
        profile=profile,
        backend=backend,
        tool=tool,
        direction="request",
        blocked=False,
        verdicts={"flagged_by": LAYER},
        call_ref=current_call.get() or None,
    )
    emit_detection_event(LAYER, source, "high", {"trip": what})
