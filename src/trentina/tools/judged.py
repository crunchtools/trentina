"""One path from a produced payload to a tool response, for every family and mode.

Until 0.31.0 each family carried its own copy: ``_fetch_judged``,
``_read_judged``, ``_content_judged``, ``_search_judged``, and four separate
``clean_*`` bodies (redact was named clean until 0.35.0). The copies drifted
in exactly the way copies do. redact ran a different pipeline from block and
flag; search built its own recipe,
blocked on a private ``total_l1 >= 3`` rule, and never called L3 at all.

A producer now does only what only it can: fetch the URL, read the file,
list the directory, hash the inline text, run the grounded search — and the
checks that need what it knows (the blocklist, the allowlist, HTTP status
advisories). Everything after the payload exists is here, once.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, assert_never

from ..config import get_config
from ..core import Decision, Gated, Posture, identity, refusal_of
from ..database import is_blocked, record_capture
from ..dbus_interface import emit_request_event
from ..defense import DefenseVerdict, Provenance, defend, layer_verdicts
from ..errors import BlockedSourceError
from ..gateway import paging
from ..gateway.context import current_call, get_current_parts
from ..gateway.scope import current_scope
from ..l1.pipeline import run_l1
from ..modes import BLOCKLIST_REASON, Mode, current_policy, refusal_body
from ..report import Disposition, LayerState, build_report
from ..warning import build_warning

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..core.dispose import Disposition as Disposed
    from ..gateway.profile import DefenseConfig
    from ..l1.pipeline import PipelineResult


PAGED_FAMILIES = frozenset({"fetch", "read", "content"})
"""The families whose payload is one text an agent reads to the end, and so
is delivered in parts when it is too large to judge in one call (#446). A
directory listing and a search answer are not: neither comes near the size."""

READ_NEXT_KEY = "read_next"


def blocklisted(source: str, mode: Mode) -> BlockedSourceError:
    """block and flag on a blocklisted source, refused before any bytes arrive.

    Offers redact when the policy allows it, because redact is the mode that
    proceeds on a blocklisted source. The body is constant (#263): it said
    ``since {detected_at}`` until then, which handed a caller another
    profile's timestamp. Nothing in it now depends on anything but the
    caller's own source and mode policy.
    """
    return BlockedSourceError(
        source,
        BLOCKLIST_REASON,
        refusal=refusal_body(BLOCKLIST_REASON, mode, flagged_by="blocklist"),
    )


def _caller() -> tuple[str | None, bool]:
    """The calling profile's name, and whether it reads the gateway-wide blocklist.

    Operator and standalone read every row; an agent reads its own. A live
    gateway with no bound caller reads nothing and writes a NULL profile,
    which only an operator sees: no path nobody designed can publish to an
    agent's blocklist.
    """
    scope = current_scope()
    if scope is None:
        return None, False
    return scope.name, scope.is_operator


def _caller_defense() -> DefenseConfig | None:
    """The calling profile's defense policy, or None standalone or unbound."""
    scope = current_scope()
    return scope.profile.defense if scope is not None and scope.profile is not None else None


def honeypot_caller() -> str | None:
    """The calling profile's name when it is a honeypot (#357), else None.

    Every place a tool would tell its caller what the layers made of
    something asks this first: a honeypot is told nothing, and what it was
    sent is kept instead.
    """
    scope = current_scope()
    if scope is None or scope.profile is None or not scope.profile.honeypot:
        return None
    return scope.profile.name


def check_blocklist(source: str, mode: Mode) -> bool:
    """Refuse block and flag on a source the caller's blocklist holds.

    Returns:
        Whether it is blocklisted, for redact, which proceeds and says so.

    Raises:
        BlockedSourceError: block or flag, and the source is on it.
    """
    profile, gateway_wide = _caller()
    blocked = is_blocked(source, profile, gateway_wide=gateway_wide)
    if blocked and mode is not Mode.REDACT:
        raise blocklisted(source, mode)
    return blocked


def l1_metadata(pipeline: PipelineResult) -> dict[str, Any]:
    """The ``l1`` section of a response: sizes and the counts that are not zero.

    Nineteen zeros on every clean response cost the agent ~150 tokens and
    told it nothing (0.38.0). The full table is in the D-Bus event.
    """
    return {
        "input_size": pipeline.input_size,
        "output_size": pipeline.output_size,
        "stripped": {k: v for k, v in pipeline.stats.to_flat_dict().items() if v},
    }


class _Call:
    """What one tool call knows, carried through judging and delivery."""

    def __init__(
        self,
        *,
        mode: Mode,
        family: str,
        source: str,
        kind: str,
        ref: str,
        allowlisted: bool,
        asserted: Mapping[str, bool],
    ) -> None:
        self.mode = mode
        self.tool = f"{mode.value}_{family}"
        self.source = source
        self.kind = kind
        self.ref = ref
        self.allowlisted = allowlisted
        # Facts about the SOURCE the warning states whatever the verdict,
        # such as the caller's own blocklist holding it.
        self.asserted = asserted
        self.start = time.time()

    def emit(self, verdict: DefenseVerdict, disposition: Disposition, output_size: int) -> None:
        stats = verdict.pipeline.stats
        classification = verdict.classification
        emit_request_event(
            tool=self.tool,
            source=self.source,
            disposition=disposition.value,
            risk_level=stats.risk_level(),
            l1_detections=stats.total_detections(),
            l1_suspicious=stats.suspicious_detections(),
            l2_label=classification.label if classification else None,
            l2_score=classification.score if classification else None,
            input_size=verdict.pipeline.input_size,
            output_size=output_size,
            stats=stats.to_flat_dict(),
            start_time=self.start,
        )

    def refuse(
        self, verdict: DefenseVerdict, disposition: Disposed, posture: Posture
    ) -> BlockedSourceError:
        """The refusal the core decided, rendered through the one composer.

        ``disposition.offer_alternatives`` is False when the refusal is redact's
        own extraction turn objecting: neither the verdict's flag nor its gaps
        is the reason, and nothing is suggested.
        """
        self.emit(verdict, Disposition.REFUSED, 0)
        return BlockedSourceError(
            self.source,
            disposition.reason or "refused by the defense pipeline",
            refusal=refusal_of(disposition, posture),
        )

    def warning(self, verdict: DefenseVerdict, **more: Any) -> dict[str, Any] | None:
        """``_trentina_warning``, or None when the scan completed and found nothing."""
        forced = {**more, **self.asserted}
        warning = build_warning(verdict, extras={k: v for k, v in forced.items() if v})
        if warning is not None:
            warning["mode"] = self.mode.value
        return warning


@dataclass(frozen=True)
class JudgeScan:
    """An internal tool's produced payload, judged but not yet disposed.

    ``produce_judgement`` builds this (hold, defend); the orchestrator calls
    ``gate`` on it and hands the result to ``dispose_judgement``. The split
    keeps the one ``gate()`` call in the orchestration layer (Trentina 3.0
    Phase 4) while the paging hold, the ``_Call`` accounting and the family
    renderers stay here.
    """

    call: _Call
    verdict: DefenseVerdict
    posture: Posture
    paged: paging.Paged | None
    original: Any
    extras: Mapping[str, Any] | None
    redact_extras: Mapping[str, Any] | None


async def produce_judgement(
    document: str,
    *,
    mode: Mode,
    family: str,
    source: str,
    source_type: str,
    kind: str,
    ref: str,
    prompt: str | None = None,
    allowlisted: bool = False,
    blocklisted: bool = False,
    provenance: Provenance = Provenance.EXTERNAL,
    domain: str | None = None,
    precomputed_l1: PipelineResult | None = None,
    l3_context: str | None = None,
    delivered: Any = None,
    extras: Mapping[str, Any] | None = None,
    redact_extras: Mapping[str, Any] | None = None,
) -> JudgeScan:
    """Judge ``document`` with all three layers — the pre-gate half of the edge.

    Holds an over-large payload (part 1 is judged, the rest held), builds the
    ``_Call`` accounting and the ``Posture``, and runs ``defend``. Returns a
    ``JudgeScan`` for the orchestrator to ``gate`` and hand to
    ``dispose_judgement``; it makes no ``gate()`` call and raises nothing on a
    detection.

    Args:
        document: The payload as produced — what every layer reads.
        mode: block, flag or redact. It decides delivery, never detection.
        family: ``fetch``, ``read``, ``dir``, ``content`` or ``search``.
        prompt: The extraction request, for redact.
        allowlisted: An operator vouched for the source. Its flags still
            stand; block sends a flagged or partially-read payload to redact
            instead of refusing it. An ABSENT layer still refuses.
        blocklisted: Set when redact proceeds on a blocklisted source.
        delivered: What block and flag hand over, when it is not the document
            itself (search delivers L0's text, the sources separately).
        extras: Family fields for block and flag responses.
        redact_extras: Family fields for redact responses. Separate because
            redact must not re-deliver the payload it replaced.
    """
    paged = None
    if delivered is None and family in PAGED_FAMILIES:
        paged = await _hold(
            document,
            mode=mode,
            prompt=prompt,
            provenance=provenance,
            l3_context=l3_context,
            hidden=precomputed_l1.stats.hidden if precomputed_l1 is not None else None,
            source=source,
            source_type=source_type,
            domain=domain,
            blocklists=not allowlisted,
        )
    if paged is not None:
        # Part 1 is what this call judges and delivers; the rest is held.
        document = paged.parts[0].text
        precomputed_l1 = await _part_l1(document, paged.hidden)
        l3_context = "\n".join(
            note for note in (l3_context, paging.part_briefing(paged, 1)) if note
        )
    call = _Call(
        mode=mode,
        family=family,
        source=source,
        kind=kind,
        ref=ref,
        allowlisted=allowlisted,
        asserted={"blocklisted": blocklisted},
    )
    posture = identity.posture(mode, current_policy(), allowlisted=allowlisted, prompt=prompt)
    verdict = await defend(
        document,
        source=source,
        source_type=source_type,
        # The caller's own thresholds and judge, as every gateway path passes
        # them (#407): without it the tools were judged on built-in defaults.
        defense=_caller_defense(),
        provenance=provenance,
        domain=domain,
        # flag delivers a partial scan with a warning, so it pays for the
        # partial scan; block and redact would refuse it. The one definition
        # of the rule lives on Posture.
        stop_on_partial=posture.stop_on_partial,
        precomputed_l1=precomputed_l1,
        l3_context=l3_context,
        # `blocked` feeds the blocklist. Only a block refusal belongs there:
        # a flag row marked blocked made the NEXT flag of the same page raise.
        # `profile` keys the row (#263): only the caller that was refused is
        # refused again.
        attribution={
            "profile": _caller()[0],
            "tool": call.tool,
            "blocked": posture.records_block(blocklists=not allowlisted),
            "call_ref": current_call.get() or None,
        },
    )
    return JudgeScan(
        call=call,
        verdict=verdict,
        posture=posture,
        paged=paged,
        original=document if delivered is None else delivered,
        extras=extras,
        redact_extras=redact_extras,
    )


async def dispose_judgement(scan: JudgeScan, gated: Gated) -> dict[str, Any]:
    """Dispose of a judged internal payload — the post-gate half of the edge.

    The gate disposed of the verdict once (core.gate/core.dispose) and, for a
    redact or a downgraded block, ran turns 2 and 3 and carries their result.
    Delivers, extracts or refuses per that decision; for a paged response, part
    1 is shaped and the rest left held, releasing the hold if part 1 is refused.

    Raises:
        BlockedSourceError: block or redact refused. The message names the
            layer or gap, never the payload.
    """
    call, posture = scan.call, scan.posture
    if scan.paged is None:
        return await _dispose(call, gated, scan.original, posture, scan.extras, scan.redact_extras)
    try:
        response = await _dispose(
            call, gated, scan.original, posture, scan.extras, scan.redact_extras
        )
    except BlockedSourceError:
        # Nothing of it was delivered, so there is no rest to come back for.
        paging.release(scan.paged)
        raise
    return _first_part(scan.paged, gated.verdict, response)


async def _dispose(
    call: _Call,
    gated: Gated,
    original: Any,
    posture: Posture,
    extras: Mapping[str, Any] | None,
    redact_extras: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Deliver, extract from or refuse a judged payload, as the gate decided."""
    verdict = gated.verdict
    disposition = gated.disposition
    match disposition.decision:
        case Decision.DELIVER:
            return _deliver(call, verdict, original, extras)
        case Decision.DELIVER_UNMARKED:
            honeypot = honeypot_caller()
            if honeypot is None:  # invariant: only a honeypot reaches this decision
                return _deliver(call, verdict, original, extras)
            return _deliver_unmarked(call, verdict, original, extras, honeypot)
        case Decision.REDACT:
            return await _redact(
                call, gated, redact_extras, posture, downgraded=disposition.downgraded
            )
        case Decision.REFUSE:
            raise call.refuse(verdict, disposition, posture)
        case _:  # pragma: no cover - exhaustiveness is the point
            assert_never(disposition.decision)


def pageable(tokens: int) -> bool:
    """Whether a payload of ``tokens`` would be delivered in parts to this caller.

    For a tool that would otherwise refuse the size itself (``content``).
    """
    config = get_config()
    return (
        get_current_parts() is not None
        and honeypot_caller() is None
        and config.part_target_tokens > 0
        and config.whole_tokens < tokens <= config.paged_tokens
    )


async def _hold(document: str, **judged_as: Any) -> paging.Paged | None:
    """Cut and hold a payload too large to judge in one call (#446), or None.

    Only behind the gateway, for a profile that can call ``read_part``: the
    router binds the offer (``context.PartsOffer``). Standalone there is no
    store and nothing to read part 2 with, so nothing is cut. A honeypot is
    handed what arrived, whole and unmarked.
    """
    offer = get_current_parts()
    profile = _caller()[0]
    if offer is None or profile is None or honeypot_caller() is not None:
        return None
    # The tokenizer runs over the whole text: off the loop, like L1 (#295).
    parts = await asyncio.to_thread(paging.cut, document)
    if parts is None:
        return None
    return paging.hold(
        paging.Origin(
            profile=profile,
            backend=offer.backend,
            tool=offer.tool,
            label=offer.label,
            is_error=False,
            acted=False,
        ),
        parts,
        **judged_as,
    )


async def _part_l1(text: str, hidden: Any) -> PipelineResult | None:
    """L1 over part 1 with the whole document's hiding counts, as every later
    part is read (``scan_tool_response``); None leaves L1 to ``defend()``."""
    if hidden is None:
        return None
    pipeline = await asyncio.to_thread(run_l1, text)
    pipeline.stats.hidden = pipeline.stats.hidden.at_least(hidden)
    return pipeline


def _first_part(
    paged: paging.Paged, verdict: DefenseVerdict, response: dict[str, Any]
) -> dict[str, Any]:
    """Part 1 in the tool's own shape, led by where the rest is.

    ``_trentina_part`` is what the router writes on every later part, with
    the footer's words under ``read_next``: an internal tool answers in JSON,
    so the instruction rides in the marker and not in a text block.
    """
    offer = get_current_parts()
    if verdict.flagged_by is not None:
        paged.flagged_at, paged.flagged_by = 1, verdict.flagged_by.value
    paged.delivered.add(1)
    marker = paging.marker(paged, 1)
    marker[READ_NEXT_KEY] = paging.footer(
        paged, 1, offer.reader if offer is not None else paging.READ_PART_TOOL
    )
    return {paging.PART_KEY: marker, **response}


def _deliver(
    call: _Call,
    verdict: DefenseVerdict,
    original: Any,
    extras: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """The bytes as they arrived, with the verdict when there is one to give."""
    warning = call.warning(verdict)
    disposition = Disposition.ANNOTATED if warning is not None else Disposition.DELIVERED
    call.emit(verdict, disposition, verdict.pipeline.output_size)
    scan = build_report(
        verdict,
        disposition=disposition,
        kind=call.kind,
        ref=call.ref,
        allowlisted=call.allowlisted,
    )
    l1 = l1_metadata(verdict.pipeline)
    response: dict[str, Any] = {"content": original, "scan": scan, "l1": l1, **(extras or {})}
    if warning is not None:
        response["_trentina_warning"] = warning
    elif (
        not l1["stripped"]
        and not call.allowlisted
        and set(scan["layers"].values()) == {LayerState.COMPLETE.value}
    ):
        # Clean: one line says so. The agent asked for the source, so the
        # origin repeats its own argument, and L1 found nothing to report.
        response["scan"] = {"layers": "complete", "disposition": disposition.value}
        del response["l1"]
    return response


def _deliver_unmarked(
    call: _Call,
    verdict: DefenseVerdict,
    original: Any,
    extras: Mapping[str, Any] | None,
    profile: str,
) -> dict[str, Any]:
    """A honeypot's delivery (#357): the bytes as they arrived, and nothing
    of what the layers made of them.

    Every layer ran and the verdict is kept, beside the content, in the
    capture table. It is not attached: an agent told "this was flagged" is
    not the reader an attack was written for, and what a honeypot measures
    is what that reader does. The capture is written first: content a
    honeypot read and nobody can read back is the one outcome it has no use
    for, so a write that fails fails the call.
    """
    record_capture(
        profile,
        call.source,
        verdict.content,
        layer_verdicts(verdict.flagged_by, verdict.classification, verdict.l3_assessment),
        current_call.get() or None,
    )
    call.emit(verdict, Disposition.DELIVERED, verdict.pipeline.output_size)
    return {"content": original, **(extras or {})}


def _scripted(extras: Mapping[str, Any] | None) -> bool:
    """Whether pre-processing removed script tags: the app-shell shape (#245)."""
    runs = (extras or {}).get("preprocess")
    return isinstance(runs, list) and any(
        isinstance(r, dict) and r.get("script_tags") for r in runs
    )


async def _redact(
    call: _Call,
    gated: Gated,
    redact_extras: Mapping[str, Any] | None,
    posture: Posture,
    *,
    downgraded: bool = False,
) -> dict[str, Any]:
    """Deliver the gate's verified extraction; refuse if its own turn objected."""
    verdict = gated.verdict
    if gated.extraction_refusal is not None:
        # redact's own turn objecting: nothing is suggested (no flag, no gap).
        raise call.refuse(verdict, gated.extraction_refusal, posture)
    result = gated.extraction
    if result is None:  # a non-refused redact disposition always carries an extraction
        raise RuntimeError("judged: redact disposition carried no extraction")
    extraction = result.content
    if "nothing_to_extract" in extraction and _scripted(redact_extras):
        extraction["nothing_to_extract"] += (
            "; the page carried <script> tags, so it likely renders its content "
            "with JavaScript, which fetch does not run"
        )
    # A downgraded block keeps block's response shape: `content` is text.
    content: Any = extraction.get("extracted_text", "") if downgraded else extraction
    warning = call.warning(verdict, downgraded_to_redact=downgraded)
    call.emit(verdict, Disposition.EXTRACTED, len(str(extraction.get("extracted_text", ""))))
    response: dict[str, Any] = {
        "content": content,
        "scan": build_report(
            verdict,
            disposition=Disposition.EXTRACTED,
            kind=call.kind,
            ref=call.ref,
            allowlisted=call.allowlisted,
            extracted_by=get_config().model,
        ),
        "l1": l1_metadata(verdict.pipeline),
        "usage": result.usage,
        **(redact_extras or {}),
    }
    if warning is not None:
        response["_trentina_warning"] = warning
    return response
