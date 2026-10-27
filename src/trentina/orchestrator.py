"""The one crossing: one request, two edges, in an order only this module knows.

Every request Trentina mediates is one crossing with two edges — the request
edge carries what the agent said toward the world, the response edge carries
what the world said back — and both run from here. ``crossing`` sequences a
transport's halves (``transports.base``) in the ONE order that is the security
property: parse the request, carry it, deliver the response, wrap it. A
transport supplies the protocol; it does not get to choose the order, so it
cannot skip the gate (Trentina 3.0 plan §A/§C).

``crossing`` drives the MCP ``tools/call`` path for every profile; the
hand-rolled ``gateway/router.py`` path it replaced is gone. Alongside it this
module owns the response-edge entries that run the gate for the ingresses that
are not yet full transports — ``scan_tool_response`` (proxied), ``judge_response``
(the sealed ``Judged`` stage), ``judge_and_deliver`` (internal tools) and
``judge_egress_response`` (the terminating ``/proxy/http`` route) — so that
``defend()`` and ``core.gate`` are reached from the orchestration layer and the
order no caller may reorder is held here (Trentina 3.0 plan §A/§C).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .core import gate, identity
from .core.dispose import Decision, dispose
from .core.stages import Judged
from .defense import Provenance, defend, defend_json
from .gateway.context import profile_context
from .gateway.ingress_defense import IngressDecision, disposed_response, scan_response
from .gateway.outbound import (
    REASON_CREDENTIAL,
    REASON_FLAGGED,
    REASON_UNJUDGED,
    detect_credentials,
    judge_input,
)
from .logsafe import exc_kind, exc_where, redact_source
from .modes import Mode, ModePolicy, gaps_of
from .quarantine.prompts import RISK_LEVELS
from .transports.base import Early, Transport

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .core.stages import Transformed
    from .defense import DefenseVerdict
    from .gateway.profile import Profile
    from .l1.hidden import HiddenStats
    from .l1.pipeline import PipelineResult


async def crossing(transport: Transport, ctx: Any) -> Any:
    """Run one request across both edges and return the protocol response.

    ``ctx`` is the transport's own per-request context (for MCP: the profile,
    the JSON-RPC id, and the call params). Each step either hands its result to
    the next or short-circuits with an ``Early`` — a response already built and
    audited — which is returned as-is, exactly as the hand-rolled path's early
    ``return`` did.
    """
    face = transport.face

    parsed = await face.parse(ctx)  # REQUEST edge: resolve, guard, normalize
    if isinstance(parsed, Early):
        return parsed.response

    carried = await transport.carrier.carry(ctx, parsed)  # to the backend
    if isinstance(carried, Early):
        return carried.response

    delivered = await face.deliver(ctx, parsed, carried)  # RESPONSE edge: judge, shape
    if isinstance(delivered, Early):
        return delivered.response

    return face.wrap(ctx, delivered)


async def scan_tool_response(
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
) -> IngressDecision:
    """Judge one proxied tool response and decide its fate — the response edge.

    The one place the gate runs on a proxied response: ``scan_response`` does the
    pre-gate work (admission, the verdict cache, L1/L2/L3 via ``defend``, the
    warning), ``gate`` disposes of the verdict and runs redact's extraction, and
    ``disposed_response`` renders the ``IngressDecision`` and writes the cache.
    Holding the order here, not in the gateway, is why ``core.gate`` is imported
    only by the orchestration layer (Trentina 3.0 Phase 4). The two no-gate exits
    (a binary-only response, a cache hit) come straight back from ``scan_response``.
    """
    scanned = await scan_response(
        profile=profile,
        backend_name=backend_name,
        tool_name=tool_name,
        content_blocks=content_blocks,
        structured_content=structured_content,
        provenance=provenance,
        l3_context=l3_context,
        mode=mode,
        prompt=prompt,
        policy=policy,
        hidden=hidden,
        lead_in=lead_in,
        source=source,
        source_type=source_type,
        domain=domain,
        blocklists=blocklists,
    )
    if isinstance(scanned, IngressDecision):
        return scanned
    gated = await gate(scanned.verdict, scanned.posture, extra_unread=scanned.extra_unread)
    return await disposed_response(scanned, gated)


async def judge_response(
    transformed: Transformed,
    *,
    profile: Profile,
    backend_name: str,
    tool_name: str,
    structured_content: Any,
    mode: Mode | None,
    prompt: str | None,
    policy: ModePolicy | None,
    l3_context: str | None,
    hidden: HiddenStats | None,
) -> Judged:
    """Judge a proxied response and bind the verdict to the exact bytes judged.

    The sole constructor of the ``Judged`` stage. It runs the response edge
    (``scan_tool_response`` → the gate) over ``transformed.content_blocks`` and
    returns the stage pairing that decision with the ``Transformed`` it was
    reached over, so holding a ``Judged`` is proof the gate ran on those bytes
    and no others — one of Trentina 3.0's unforgeable trust types, fenced to
    this function by ``tests/test_seal.py``. An internal tool is judged at its
    own ingress and reaches no ``Judged``; only the proxied response edge
    (``transports.mcp._assemble``) builds one, here.

    Args:
        transformed: The response after the pre-perimeter transform chain. Its
            ``content_blocks`` are what the layers read and what is delivered,
            and its ``provenance`` is carried into the scan; the returned
            ``Judged`` holds this exact stage by reference.
        profile: The calling profile, whose ``defense`` settings the scan runs under.
        backend_name: The backend the response came from, for the detection row.
        tool_name: The tool that produced the response, for the detection row.
        structured_content: The response's ``structuredContent`` (or None),
            judged alongside the text blocks.
        mode: The resolved delivery mode (block, flag or redact), or None to
            resolve the profile default. It decides delivery, never detection.
        prompt: The extraction request for ``redact``; ignored in other modes.
        policy: The mode policy whose ``alternatives`` a refusal offers, or None
            for the single-mode default at the call site.
        l3_context: The L3 briefing for this response (the backend's briefing,
            or a paging part's), or None.
        hidden: Hiding counts carried from the transform (``HiddenStats``), so
            L1 sees what a converter removed, or None.

    Returns:
        The ``Judged`` stage pairing ``transformed`` with the gate's
        ``IngressDecision`` — deliver, redact or block — for the caller to render.
    """
    decision = await scan_tool_response(
        profile=profile,
        backend_name=backend_name,
        tool_name=tool_name,
        content_blocks=transformed.content_blocks,
        structured_content=structured_content,
        provenance=transformed.provenance,
        mode=mode,
        prompt=prompt,
        policy=policy,
        l3_context=l3_context,
        hidden=hidden,
    )
    return Judged(transformed=transformed, decision=decision)


@dataclass(frozen=True)
class ResponseJudgement:
    """A terminating response-edge verdict reduced to what the face renders.

    For an ingress that answers with one buffered reply (the ``/proxy/http``
    egress route), not the staged ``tools/call`` path. ``refuse`` is the gate's
    decision — ``dispose()`` concluded REFUSE, so ``block`` must withhold — while
    ``flagged``/``unjudged``/``risk`` are the facts the face needs to word its own
    deny marker (block) or warning header (flag). The face spells the wire; the
    decision is made here.
    """

    refuse: bool
    flagged: bool
    unjudged: bool
    risk: str


async def judge_egress_response(
    document: str,
    *,
    profile: Profile,
    source: str,
    domain: str,
    blocking: bool,
    deadline: float,
) -> ResponseJudgement:
    """Judge a terminating egress HTTP response — the response edge for /proxy/http.

    Runs L1/L2/L3 over the response (its headers, and its body when text) and
    disposes of the verdict under ``block`` or ``flag``. Deadline- and
    exception-bounded: a hung or failed scan is treated as unjudged, so ``block``
    withholds and ``flag`` warns, never fails open. The ``defend()`` call and the
    ``dispose()`` decision live here, not at the route, so the gate is reached
    from the orchestration layer; the route reads the ``ResponseJudgement`` and
    raises its own refusal or sets its own warning header.

    Args:
        document: The response as text the layers read — headers always, the
            body when it is text.
        profile: The calling profile, whose ``defense`` settings the scan runs under.
        source: The detection row's source (the destination, or the upstream host).
        domain: The upstream host, for blocklist scoping.
        blocking: True under ``block`` (a flag or blocking gap withholds), False
            under ``flag`` (the response forwards with a warning).
        deadline: Seconds the scan may take before it counts as unjudged.

    Returns:
        A ``ResponseJudgement``: ``refuse`` (block must withhold), and the
        ``flagged``/``unjudged``/``risk`` facts the route words its wire from.
    """
    mode = Mode.BLOCK if blocking else Mode.FLAG
    posture = identity.posture(mode, ModePolicy((mode,), mode))
    try:
        with profile_context(profile):
            async with asyncio.timeout(deadline):
                verdict = await defend(
                    document,
                    source=source,
                    source_type="egress_response",
                    defense=profile.defense,
                    provenance=Provenance.EXTERNAL,
                    stop_on_partial=posture.stop_on_partial,
                    domain=domain,
                )
    except Exception as exc:  # TimeoutError too: no verdict was reached
        logger.error(
            "egress: response scan failed profile=%s: %s at %s",
            profile.name,
            exc_kind(exc),
            exc_where(exc),
        )
        # Fail closed: no verdict is an unjudged response. block withholds it,
        # flag warns — the same the route did when it owned the scan.
        return ResponseJudgement(refuse=blocking, flagged=False, unjudged=True, risk="unknown")
    # The one gate policy decides whether to refuse — ``dispose()``, never a
    # second copy here — so the response edge cannot drift from it. The route
    # then words its own deny marker (block) or warning header (flag) from the
    # facts below, because egress's wire is not ``core.render``'s.
    refuse = dispose(verdict, posture).decision is Decision.REFUSE
    return ResponseJudgement(
        refuse=refuse,
        flagged=verdict.flagged,
        unjudged=gaps_of(verdict).blocking(),
        risk=verdict.risk_level,
    )


@dataclass(frozen=True)
class OutboundVerdict:
    """What judging an agent's OUTBOUND request concluded (the request edge).

    Carries no wire shape: the caller (``/proxy/llm`` or the egress route) turns
    it into its own JSON deny marker or warning header. ``refused`` is the gate's
    decision for this mode, decided here so no caller re-derives ``flag or gap``;
    ``kinds``/``flagged``/``gaps``/``risk`` are the facts the caller words its
    marker or warning from.
    """

    refused: bool = False
    kinds: list[str] = field(default_factory=list)
    flagged: bool = False
    flagged_by: str | None = None
    unjudged: bool = True
    # A ``modes.Gaps`` name, not a reason code: this is what a deny marker's
    # `gaps` field carries. l3_unavailable is the default while no verdict ran.
    gaps: list[str] = field(default_factory=lambda: ["l3_unavailable"])
    risk: str = "unknown"

    @property
    def reason(self) -> str | None:
        """The refusal reason code, by precedence credential > flagged > gap."""
        if self.kinds:
            return REASON_CREDENTIAL
        if self.flagged:
            return REASON_FLAGGED
        if self.unjudged:
            return REASON_UNJUDGED
        return None

    @property
    def warning(self) -> str | None:
        """The flag-mode annotation: a finding, never a gap list."""
        if self.kinds:
            return "credential"
        if self.flagged:
            return self.risk
        if self.unjudged:
            return "unjudged"
        return None


async def judge_outbound(
    document: str,
    *,
    source: str,
    source_type: str,
    backend: str,
    profile: Profile,
    mode: Mode,
    deadline: float,
) -> OutboundVerdict:
    """Judge an agent's outbound request — the request edge for /proxy/llm and egress.

    Scans ``document`` for credential shapes and judges a credential-redacted copy
    through L1/L2/L3 (the layer contract: the credential detector adds a signal,
    it never switches a layer off). Deadline- and exception-bounded: a hung or
    failed judge counts as unjudged, so ``block`` refuses and ``flag`` forwards
    with a warning, never fails open.

    ``refused`` is decided here, not at the caller: under ``block`` a credential,
    a flag or a blocking gap refuses before anything is sent. The layer part goes
    through ``refusal_reason`` — the one rule ``dispose()`` delegates to — rather
    than a hand-rolled ``flag or gap``, so this path cannot drift from the gate.
    It does not call ``dispose()`` itself: the request edge can never allowlist or
    redact (block/flag only, so dispose's other branches are dead), the credential
    dimension sits outside ``dispose()``'s model, and routing it through
    ``dispose()`` would couple its gap derivation to the response edge's in one
    crossing. The ORIGINAL request is what each caller forwards upstream.

    Args:
        document: The request as text the layers read.
        source: The detection row's source.
        source_type: The detection row's source type.
        backend: The row's backend column (``llm:<provider>``, ``http:<name>``).
        profile: The calling profile, whose ``defense`` settings the scan runs under.
        mode: The caller's resolved mode (``block`` or ``flag``).
        deadline: Seconds the scan may take before it counts as unjudged.

    Returns:
        An ``OutboundVerdict``: ``refused`` (the caller withholds), plus the
        ``kinds``/``flagged``/``gaps``/``risk`` facts it words its marker from.
    """
    from .defense import defend  # heavy; deferred, and the REQUEST-edge test seam
    from .modes import gaps_of, refusal_reason  # resolved here so a test's gaps_of patch is seen

    kinds = detect_credentials(document)
    flagged, unjudged, flagged_by, risk = False, True, None, "unknown"
    gaps = ["l3_unavailable"]
    # The partial-scan and blocklist rules live in Posture, so this path fails
    # closed for any future mode exactly as the tools do. Was `mode is Mode.BLOCK`
    # here -- a fail-open for a later non-BLOCK mode, masked only because redact is
    # not an enforcement mode on this path.
    posture = identity.posture(mode, ModePolicy((mode,), mode))
    layer_refuses = False
    try:
        with profile_context(profile):
            async with asyncio.timeout(deadline):
                verdict = await defend(
                    judge_input(document),
                    source=source,
                    source_type=source_type,
                    defense=profile.defense,
                    provenance=Provenance.MODEL_OUTPUT,
                    stop_on_partial=posture.stop_on_partial,
                    attribution={
                        "direction": "request",
                        "blocked": posture.records_block(),
                        "profile": profile.name,
                        "backend": backend,
                    },
                )
        flagged = verdict.flagged
        flagged_by = verdict.flagged_by.value if verdict.flagged_by else None
        g = gaps_of(verdict)
        unjudged = g.blocking()
        gaps = g.names()
        risk = verdict.risk_level
        layer_refuses = refusal_reason(flagged_by, g) is not None
    except Exception as exc:  # TimeoutError too: no verdict was reached
        logger.error(  # backend is server-configured (#262-safe); the message may carry the request
            "outbound: request scan failed backend=%s source_type=%s: %s at %s",
            backend,
            source_type,
            exc_kind(exc),
            exc_where(exc),
        )
        layer_refuses = True  # no verdict is an unjudged request: block refuses it
    # block refuses a credential, a flag or a blocking gap; flag forwards with a
    # warning and consults `warning` instead. The credential dimension is
    # outbound-only, OR'd onto the shared layer rule.
    refused = mode is Mode.BLOCK and (bool(kinds) or layer_refuses)
    return OutboundVerdict(
        refused=refused,
        kinds=kinds,
        flagged=flagged,
        flagged_by=flagged_by,
        unjudged=unjudged,
        gaps=gaps,
        risk=risk,
    )


@dataclass(frozen=True)
class LlmCompletionJudgement:
    """An assembled LLM completion reduced to what the proxy records or withholds.

    The ``/proxy/llm`` response edge. In flag mode (the default) the completion
    has already streamed, so these facts are RECORDED only; a block profile
    buffers and withholds on ``flagged`` OR ``unjudged`` (a scan that did not
    complete — timeout, failure, or over the cap — fails closed). ``risk``/
    ``flagged_by`` are the closed-set facts the detection row and the deny marker
    carry.
    """

    flagged: bool
    unjudged: bool
    risk: str
    flagged_by: str | None


async def judge_llm_completion(
    text: str,
    *,
    profile: Profile,
    provider_name: str,
    deadline: float,
) -> LlmCompletionJudgement:
    """Judge an assembled LLM completion — the /proxy/llm response edge.

    Runs L1/L2/L3 over the completion as ``MODEL_OUTPUT``, deadline- and
    exception-bounded. In flag mode it runs AFTER the stream ends, outside the
    request's context, so a hung judge must not leave an unbounded task; the
    finding is recorded only, since a stream cannot be retracted. In block mode
    the caller buffers the completion first and withholds on ``flagged`` or
    ``unjudged``. A timeout, a failed scan or a failed deferred import is logged
    and reported as ``unjudged`` with no flag — fail closed, so block withholds
    and flag simply records nothing. The ``defend()`` call lives here, on the
    response edge.

    Args:
        text: The assembled completion as text the layers read.
        profile: The calling profile, whose ``defense`` settings the scan runs under.
        provider_name: The upstream provider (server-configured; the row's backend).
        deadline: Seconds the scan may take before a timeout counts as unjudged.

    Returns:
        An ``LlmCompletionJudgement``: ``flagged``/``unjudged`` and the
        ``risk``/``flagged_by`` facts the proxy records or withholds from.
    """
    try:
        # Deferred INSIDE the try: the import is heavy, is the completion-scan
        # test seam, and — like the original inline scan — an import failure is
        # caught here rather than left to fail the background task unhandled.
        from .defense import defend

        with profile_context(profile):
            async with asyncio.timeout(deadline):
                verdict = await defend(
                    text,
                    source=f"llm:{profile.name}:{provider_name}",
                    source_type="llm_completion",
                    defense=profile.defense,
                    provenance=Provenance.MODEL_OUTPUT,
                )
        # Inside the try: a malformed verdict's gap derivation fails closed
        # (unjudged) rather than propagating out of the background task.
        unjudged = gaps_of(verdict).blocking()
    except TimeoutError:
        # The scan outran the deadline. In flag mode the response already
        # streamed, so this is recorded and dropped; in block it withholds.
        logger.warning(
            "llm: post-hoc completion scan timed out profile=%s provider=%s",
            profile.name,
            provider_name,
        )
        return LlmCompletionJudgement(flagged=False, unjudged=True, risk="unknown", flagged_by=None)
    except Exception as exc:
        logger.error(  # the message may carry the completion (#262)
            "llm: post-hoc completion scan failed profile=%s provider=%s: %s at %s",
            profile.name,
            provider_name,
            exc_kind(exc),
            exc_where(exc),
        )
        return LlmCompletionJudgement(flagged=False, unjudged=True, risk="unknown", flagged_by=None)
    return LlmCompletionJudgement(
        flagged=verdict.flagged,
        unjudged=unjudged,
        risk=verdict.risk_level,
        flagged_by=verdict.flagged_by.value if verdict.flagged_by else None,
    )


@dataclass(frozen=True)
class MatrixJudgement:
    """A non-JSON Matrix /sync response reduced to what the proxy renders.

    The matrix proxy's disposition is its own: withhold applies to an UNJUDGED
    response (a coverage gap), while a FLAGGED event is always forwarded with a
    warning, never withheld — withholding a flagged message would break the room.
    So this is a fact-extractor, not a ``dispose()`` decision: the proxy reads
    these facts and applies its own withhold/annotate wire. ``risk`` is a closed
    ``RISK_LEVELS`` name, never L3 prose.
    """

    flagged: bool
    unjudged: bool
    risk: str


async def judge_matrix_response(
    document: str,
    *,
    profile: Profile,
    source: str,
    stop_on_partial: bool,
    deadline: float,
) -> MatrixJudgement:
    """Judge a non-JSON Matrix /sync response — the text/media response edge.

    Runs L1/L2/L3 over the response (plain text, or an image's base64 the unpack
    stage reads by OCR). Deadline- and exception-bounded: a hung or failed scan
    is treated as unjudged (``flagged`` False, ``unjudged`` True), so the proxy
    withholds under ``withhold`` and warns under ``annotate``, never fails open.
    The ``defend()`` call and the fact extraction live here, on the response edge;
    the proxy keeps its own withhold/annotate wire and warning header.

    Args:
        document: The response as text the layers read (an image as its base64).
        profile: The calling profile, whose ``defense`` settings the scan runs under.
        source: The detection row's source (``matrix:<profile>:<path>``).
        stop_on_partial: Whether a partial scan short-circuits (withhold refuses a
            partial scan at admission; annotate keeps the head scan it forwards).
        deadline: Seconds the scan may take before it counts as unjudged.

    Returns:
        A ``MatrixJudgement``: ``flagged``/``unjudged``/``risk``, the facts the
        proxy words its warning or withholding from.
    """
    try:
        async with asyncio.timeout(deadline):
            verdict = await defend(
                document,
                source=source,
                source_type="matrix_sync",
                defense=profile.defense,
                stop_on_partial=stop_on_partial,
            )
        flagged = verdict.flagged
        unjudged = gaps_of(verdict).blocking()
        # A closed set, never L3 prose.
        risk = verdict.risk_level if verdict.risk_level in RISK_LEVELS else "unknown"
    except Exception as exc:  # TimeoutError too: either way no verdict was reached
        logger.error(  # the message may carry the payload (#262); source is hashed
            "matrix: text response scan failed profile=%s source=%s: %s at %s",
            profile.name,
            redact_source(source),
            exc_kind(exc),
            exc_where(exc),
        )
        # Fail closed: no verdict is an unjudged response (withhold withholds it,
        # annotate forwards with a warning) -- never the silent clean of a swallow.
        return MatrixJudgement(flagged=False, unjudged=True, risk="unknown")
    return MatrixJudgement(flagged=flagged, unjudged=unjudged, risk=risk)


@dataclass(frozen=True)
class MatrixTextFallbackJudgement:
    """An unparseable Matrix /sync response reduced to the proxy's degraded facts.

    The recursive JSON parse failed, so there is no object to attach a warning
    to: the proxy can neither withhold nor annotate, only record. This is a
    fact-extractor; the proxy forwards regardless and words its own
    flagged-but-forwarded log from these facts. ``risk`` is the verdict's own
    risk level, carried through for that log.
    """

    flagged: bool
    risk: str


async def judge_matrix_text_fallback(
    body: bytes,
    *,
    profile: Profile,
    source: str,
) -> MatrixTextFallbackJudgement:
    """Judge unparseable Matrix /sync bytes as plain text — the degraded edge.

    The recursive JSON parse failed, so there is no annotation channel. A failed
    or flagged scan cannot be withheld (withholding breaks the room) and is only
    recorded; failing closed on an exception means ``flagged`` False here
    precisely because there is nothing to withhold, so the proxy forwards and
    logs rather than reproducing the silent clean the old recursive-parse
    fail-open produced. The ``defend()`` call lives here; the proxy keeps its
    own flagged-but-forwarded log.
    """
    try:
        verdict = await defend(
            body.decode("utf-8", errors="replace"),
            source=source,
            source_type="matrix_sync",
            defense=profile.defense,
        )
    except Exception as exc:
        logger.error(  # the message may carry the payload (#262); source is hashed
            "matrix: text-fallback scan failed source=%s: %s at %s",
            redact_source(source),
            exc_kind(exc),
            exc_where(exc),
        )
        return MatrixTextFallbackJudgement(flagged=False, risk="unknown")
    return MatrixTextFallbackJudgement(flagged=verdict.flagged, risk=verdict.risk_level)


async def judge_matrix_bridge_event(
    scanned: dict[str, Any],
    *,
    profile: Profile,
    source: str,
    direction: str,
    blocked: bool,
) -> DefenseVerdict:
    """Judge one bridged Matrix event — the appservice response edge.

    Runs L1 ∥ L2 → L3 over the event's scanned fields as one JSON document
    (``defend_json``) under the profile's service identity, and hands the
    verdict back. Bidirectional: ``direction`` is ``inbound`` or ``outbound``
    and ``blocked`` the profile's enforcement, both carried onto the detection
    row's attribution exactly as the bridge recorded them. The ``defend_json``
    call lives here; the bridge renders its own warning (``build_warning``) and
    refusal (``_refusal``) from the verdict, and delivers over the appservice.
    """
    with profile_context(profile):
        result = await defend_json(
            scanned,
            source=source,
            source_type="matrix_bridge",
            defense=profile.defense,
            record=True,
            attribution={
                "profile": profile.name,
                "direction": direction,
                "blocked": blocked,
            },
        )
    return result.verdict


async def judge_and_deliver(
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
) -> dict[str, Any]:
    """Judge an internal tool's produced ``document`` and deliver it — the edge.

    The one place the gate runs on an internal tool's output: ``produce_judgement``
    does the pre-gate work (hold, the ``_Call`` accounting, ``defend``), ``gate``
    disposes of the verdict and runs redact's extraction, and ``dispose_judgement``
    renders the tool-result dict (raising ``BlockedSourceError`` on a refusal).
    Holding the order here is why ``core.gate`` is imported only by the
    orchestration layer (Trentina 3.0 Phase 4); the tools ``fetch``/``read``/
    ``dir``/``content``/``search`` call this, not the gateway internals.

    Raises:
        BlockedSourceError: block or redact refused. The message names the
            layer or gap, never the payload.
    """
    # Imported here, not at module scope: tools/__init__ imports gateway.router
    # (via tools.cache), and the orchestrator is imported during router's own
    # load — a module-level import would close that cycle. By call time both are
    # fully loaded.
    from .tools.judged import dispose_judgement, produce_judgement

    scan = await produce_judgement(
        document,
        mode=mode,
        family=family,
        source=source,
        source_type=source_type,
        kind=kind,
        ref=ref,
        prompt=prompt,
        allowlisted=allowlisted,
        blocklisted=blocklisted,
        provenance=provenance,
        domain=domain,
        precomputed_l1=precomputed_l1,
        l3_context=l3_context,
        delivered=delivered,
        extras=extras,
        redact_extras=redact_extras,
    )
    gated = await gate(scan.verdict, scan.posture)
    return await dispose_judgement(scan, gated)
