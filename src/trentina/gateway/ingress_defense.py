"""The perimeter at the MCP proxy ingress — flag mode (plan step 5).

Before this module, proxied tool responses and tool descriptions crossed
into the agent verbatim, and the three-layer pipeline ran only for the web
tools and the alert ingress. These two functions close that gap:

* ``scan_tool_response`` — every ``tools/call`` result from a REMOTE
  backend: text content blocks, resource text, and every string leaf of
  ``structuredContent``, judged as one document. Internal backends are
  deliberately exempt: their tools (fetch_tool and friends) run the
  pipeline at their own ingress — the firewall filters where content
  ENTERS, and scanning the same bytes twice on the way through is cost,
  not defense.

* ``scan_tool_list`` — every tool's name, title, description, inputSchema
  and annotations: the classic MCP tool-poisoning channel. Runs on the
  post-compression text, because compressed descriptions are LLM output
  and it is the OUTPUT that reaches the agent; a description the
  compressor rewrote carries MODEL_OUTPUT provenance and earns
  unconditional L3. This hook sits on the build path for every tools/list,
  so entries replayed from the persisted SQLite caches (written before the
  perimeter existed) are scanned exactly like live ones — the poisoned-
  cache ingress closes structurally rather than by a deploy-time flush.

Enforcement here was hardwired to what is now flag: content is never modified (L1 is a
owner's rule), a flagged payload gets a ``_trentina_warning``
sibling field, and every flag lands in the detections table as
``source_type="tool_response"`` / ``"tool_description"`` — the score
distribution that step 7's calibration needs before anything fails closed.

A content-hash verdict cache keeps the cost sane: ~210 descriptions are
rebuilt on every circuit-breaker flap, and agents re-read the same tickets
all day. Verdicts are cached per (defense-config, content) pair; a cache
hit re-records nothing.

Tool-description verdicts also OUTLIVE the process, in ``perimeter_db`` —
a store of its own, not a table beside the blocklist. Judging them from
cold took over five minutes, which every MCP client reports as a timeout
rather than as a warm-up. Responses stay in memory: unbounded, mostly seen
once, and not what a restart pays for.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from ..core import Decision, Gated, Posture, identity, refusal_from_warning, refusal_of
from ..core.stages import IngressDecision
from ..defense import Provenance
from ..l1.pipeline import run_l1
from ..modes import Mode, ModePolicy
from ..warning import build_warning
from .collect import _read_response, _unread_warning
from .context import current_call
from .modes_policy import effective_mode
from .service import judge_of
from .verdict_cache import _cache_get, _cache_key, _cache_put

if TYPE_CHECKING:
    from ..defense import DefenseVerdict
    from ..l1.hidden import HiddenStats
    from ..l1.pipeline import PipelineResult
    from .profile import DefenseConfig, Profile

logger = logging.getLogger(__name__)

DEFAULT_REDACT_PROMPT = "Extract the information this tool response contains."
"""redact on a proxied response whose call asked no question: a bare ``"redact"``."""


@dataclass(frozen=True)
class ResponseScan:
    """A judged-but-not-yet-disposed proxied response: the hand-off to the gate.

    ``finish_response_scan`` produces this from a ``PreparedResponseScan`` and
    the verdict the orchestrator's ``defend`` call reached; the orchestrator then
    calls ``gate(verdict, posture, …)`` on it and hands the result back to
    ``disposed_response``. The split keeps the ``defend`` and ``gate()`` calls in
    the orchestration layer (Trentina 3.0 Phase 4/7) while the verdict cache, the
    binary-only shortcut and the warning build stay here. ``profile_name`` /
    ``backend_name`` / ``tool_name`` are carried only for the flagged-response
    log line.
    """

    verdict: DefenseVerdict
    posture: Posture
    warning: dict[str, Any] | None
    key: str
    extra_unread: bool
    profile_name: str
    backend_name: str
    tool_name: str


def _binary_only(
    unscannable: dict[str, int], unread: set[str], posture: Posture
) -> IngressDecision:
    """A response with no text at all: only image blocks or blobs, or nothing.

    No layer has anything to read, so there is no verdict to dispose of — the
    gap alone decides. block and redact refuse what an agent could open, flag
    delivers it with the warning (the pre-gate binary-unread gap, #367).
    """
    counts = {k: v for k, v in unscannable.items() if v}
    if not unread:
        return IngressDecision(warning={"unscannable": counts} if counts else None)
    warning = _unread_warning({"unscannable": counts}, unread)
    if posture.mode is Mode.FLAG:
        return IngressDecision(warning=warning)
    warning["blocked"] = True
    return IngressDecision(
        warning=warning,
        blocked=True,
        refusal=refusal_from_warning(warning, posture.mode, posture.policy),
    )


@dataclass(frozen=True)
class PreparedResponseScan:
    """The pre-defend half of the proxied response edge (Trentina 3.0 Phase 7).

    ``prepare_response_scan`` builds this on a cache miss with text to judge:
    the joined document, the precomputed L1, the ``Posture``, the verdict-cache
    key and the exact ``defend`` arguments that depend on the profile (its
    ``defense`` policy and the detection-row ``attribution``). The orchestrator
    runs the one ``defend`` call from it and hands it to ``finish_response_scan``,
    which builds the warning and the ``ResponseScan``. Lifting the ``defend``
    call out of this module is what drops ``gateway/ingress_defense.py`` from
    ``TestDefendOwnership.ALLOWED``.
    """

    document: str
    source: str
    source_type: str
    pipeline: PipelineResult | None
    defense: DefenseConfig
    provenance: Provenance
    domain: str | None
    l3_context: str | None
    posture: Posture
    attribution: dict[str, Any]
    key: str
    unscannable: dict[str, int]
    unread: set[str]
    profile_name: str
    backend_name: str
    tool_name: str


async def prepare_response_scan(
    *,
    profile: Profile,
    backend_name: str,
    tool_name: str,
    content_blocks: list[Any] | None,
    structured_content: Any,
    provenance: Provenance = Provenance.EXTERNAL,
    l3_context: str | None = None,
    mode: Mode | None = None,
    prompt: str | None = None,
    policy: ModePolicy | None = None,
    hidden: HiddenStats | None = None,
    lead_in: str = "",
    source: str | None = None,
    source_type: str = "tool_response",
    domain: str | None = None,
    blocklists: bool = True,
) -> IngressDecision | PreparedResponseScan:
    """Judge one tool response up to — but not including — ``defend`` (Phase 7).

    Returns an ``IngressDecision`` directly for the two no-defend exits (a binary-
    only response, or a verdict-cache hit), else a ``PreparedResponseScan`` the
    orchestrator runs the one ``defend`` call from, hands to
    ``finish_response_scan`` for the warning, then ``gate`` and
    ``disposed_response``. The split moves the ``defend`` call to the
    orchestration layer (so ``ingress_defense`` no longer imports it) while the
    cache, the binary-only shortcut and the warning build stay here (Phase 4/7).

    Judge one tool response and decide its fate under the call's mode.

    flag — deliver intact, warning attached (`blocked=False`).
    block — a flagged or incompletely judged response is refused
        (`blocked=True`); the caller delivers the refusal INSTEAD.
    redact — refused on the same gaps as block; otherwise a verified L3
        extraction guided by ``prompt`` replaces the response (#193). The
        call carries the prompt, which is what a proxied response lacked
        until the mode became a per-call argument.

    ``mode`` None means the profile default. ``policy`` is what a refusal
    offers as alternatives; without one it offers none. ``hidden`` is what
    the ORIGINAL's text blocks hid before pre-processing converted them
    (#229): L1 reports the larger of those and its own count on the
    Markdown, where conversion left none.

    ``lead_in`` is the text that came immediately before this one in a
    response delivered in parts (#340): the end of the previous part, already
    judged and delivered with it. The layers read it in front of this part,
    so an instruction cut by the part boundary is read whole, and it is not
    delivered again. Scanning more than is delivered is the call site's
    decision (``docs/defense-pipeline.md``, "Where the line falls").

    ``source``, ``source_type`` and ``domain`` are given for a later part of
    an internal tool's response (#446): the URL, path or content hash the
    tool judged part 1 as, so a flag is recorded against it and ``block``
    puts it on the caller's blocklist, unless ``blocklists`` is False (an
    allowlisted source). Without them the source is the backend and tool.

    Flags are recorded to the detections table (source_type="tool_response")
    except on a verdict-cache hit.
    """
    texts, unscannable, unread, hidden = await _read_response(
        content_blocks, structured_content, hidden
    )
    joined = "\n".join(texts)
    # Behind its lead-in, when there is any text to lead into.
    joined = lead_in + joined if lead_in and joined.strip() else joined
    mode = effective_mode(profile, mode)
    policy = policy or ModePolicy((mode,), mode)
    posture = identity.posture(mode, policy, prompt=prompt or DEFAULT_REDACT_PROMPT)

    if not joined.strip():
        return _binary_only(unscannable, unread, posture)

    # The briefing is in the key: the same bytes from a backend whose operator
    # briefed L3 differently may be judged differently (#204). So is the
    # profile (#291): a hit answers in milliseconds and a miss in seconds, so
    # a shared key told B which of N objects A had fetched.
    briefing = hashlib.sha256((l3_context or "").encode()).hexdigest()[:16]
    key = _cache_key(
        profile,
        # The source too, when the call names one: a hit records nothing, and
        # the same text from another URL must still reach that URL's row.
        f"response:{profile.name}:{mode.value}:{provenance.value}:{briefing}"
        + (f":{hashlib.sha256(source.encode()).hexdigest()[:16]}" if source else ""),
        joined
        + json.dumps(unscannable, sort_keys=True)
        + (json.dumps(asdict(hidden), sort_keys=True) if hidden is not None else ""),
        judge_of(profile),
    )
    # redact is not served from the cache: its extraction is per prompt, and
    # the extraction's briefing needs the verdict itself, not its warning.
    hit, cached = _cache_get(key) if mode is not Mode.REDACT else (False, None)
    if hit:
        blocked = bool(cached and cached.get("blocked"))
        return IngressDecision(
            warning=cached,
            blocked=blocked,
            refusal=refusal_from_warning(cached, mode, policy) if blocked else None,
        )

    pipeline = None
    if hidden is not None:
        pipeline = await asyncio.to_thread(run_l1, joined)
        # The original's text blocks, or L1's own count, whichever saw more:
        # L1 alone still sees hiding in structuredContent, which no processor
        # rewrites, and the original saw what conversion deleted.
        pipeline.stats.hidden = pipeline.stats.hidden.at_least(hidden)
    return PreparedResponseScan(
        document=joined,
        source=source or f"{profile.name}:{backend_name}:{tool_name}",
        source_type=source_type,
        pipeline=pipeline,
        defense=profile.defense,
        provenance=provenance,
        domain=domain,
        l3_context=l3_context,
        posture=posture,
        attribution={
            "profile": profile.name,
            "backend": backend_name,
            "tool": tool_name,
            "direction": "response",
            "blocked": posture.records_block(blocklists=blocklists),
            "call_ref": current_call.get() or None,
        },
        key=key,
        unscannable=unscannable,
        unread=unread,
        profile_name=profile.name,
        backend_name=backend_name,
        tool_name=tool_name,
    )


def finish_response_scan(prepared: PreparedResponseScan, verdict: DefenseVerdict) -> ResponseScan:
    """Build the warning and the ``ResponseScan`` from a prepared scan and its verdict.

    The post-defend half of the pre-gate response edge: the orchestrator calls
    this right after running the one ``defend`` over the ``PreparedResponseScan``,
    then hands the ``ResponseScan`` to ``gate`` and ``disposed_response``.
    """
    warning = build_warning(verdict, unscannable=prepared.unscannable)
    if prepared.unread:
        warning = _unread_warning(warning, prepared.unread)
    return ResponseScan(
        verdict=verdict,
        posture=prepared.posture,
        warning=warning,
        key=prepared.key,
        extra_unread=bool(prepared.unread),
        profile_name=prepared.profile_name,
        backend_name=prepared.backend_name,
        tool_name=prepared.tool_name,
    )


async def disposed_response(scan: ResponseScan, gated: Gated) -> IngressDecision:
    """Dispose of a judged proxied response — the post-gate half of the edge.

    Takes the ``ResponseScan`` ``scan_response`` produced and the ``Gated`` the
    orchestrator got from ``gate()``, and writes the verdict cache (the one
    writer). It makes no ``gate()`` call: the decision is already made. The gate
    decided the fate once, in core.gate/core.dispose — a flagged or
    incompletely-judged response is refused unless the mode is flag; "could not
    finish judging" is treated exactly like "this is hostile" (the padding
    attack: L2 scans a benign head, an L3 outage answers "clean").
    """
    disposition = gated.disposition
    posture, warning, key = scan.posture, scan.warning, scan.key

    # Consume exactly what the gate produced: it runs (and carries) the
    # extraction iff the DECISION is redact, so the redact response edge is
    # keyed on the decision, not the mode. They coincide on this path today
    # (a proxied response is never allowlisted, so block never downgrades to
    # redact), but keying on the decision is what keeps a future downgrade
    # from delivering the original while its extraction is discarded.
    if disposition.decision is Decision.REDACT or posture.mode is Mode.REDACT:
        return await _redact_response(gated, warning, posture, key)

    blocked = disposition.decision is Decision.REFUSE
    if blocked:
        if warning is None:
            # build_warning() only returns None when nothing was flagged and
            # nothing was unjudgeable -- a REFUSE means one was true, so the
            # invariant broke. Failing loudly beats silently skipping the block
            # under python -O.
            raise RuntimeError(
                "ingress_defense: warning is None while blocking -- invariant violated"
            )
        if disposition.flagged_by is None:
            logger.warning(
                "gateway: refusing incompletely-judged response for profile=%s (%s)",
                scan.profile_name,
                disposition.gaps,
            )
        warning = {**warning, "blocked": True}

    _cache_put(key, warning)
    if warning is not None:
        logger.warning(
            "gateway: tool response flagged profile=%s backend=%s tool=%s "
            "risk=%s flagged_by=%s enforcement=%s blocked=%s",
            scan.profile_name,
            scan.backend_name,
            scan.tool_name,
            warning.get("risk_level"),
            warning.get("flagged_by"),
            posture.mode.value,
            blocked,
        )
    return IngressDecision(
        warning=warning,
        blocked=blocked,
        refusal=refusal_of(disposition, posture) if blocked else None,
    )


async def _redact_response(
    gated: Gated,
    warning: dict[str, Any] | None,
    posture: Posture,
    key: str,
) -> IngressDecision:
    """redact on a proxied response: refuse on gaps, else extract and verify.

    A flag does not refuse redact — that is what redact is for — but a layer
    that could not finish does, exactly as in ``tools/judged.py``. The gate
    already decided which and, when it extracted, carries the result: a REFUSE
    disposition means a blocking gap; ``extraction_refusal`` means redact's own
    turn objected.
    """
    if gated.disposition.decision is Decision.REFUSE:
        blocked_warning = {**(warning or {}), "blocked": True}
        _cache_put(key, blocked_warning)
        return IngressDecision(
            warning=blocked_warning,
            blocked=True,
            refusal=refusal_of(gated.disposition, posture),
        )
    result = gated.extraction
    if result is None:  # a non-REFUSE redact disposition always carries an extraction
        raise RuntimeError("ingress_defense: redact disposition carried no extraction")
    if gated.extraction_refusal is not None:
        # redact's own turn objecting: nothing is suggested (no flag, no gap).
        return IngressDecision(
            warning={**(warning or {}), "blocked": True, "clean_refused_by": result.refused_by},
            blocked=True,
            refusal=refusal_of(gated.extraction_refusal, posture),
        )
    return IngressDecision(
        warning=warning,
        extraction=json.dumps(result.content, ensure_ascii=False),
    )
