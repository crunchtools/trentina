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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .core import gate, identity
from .core.dispose import Decision, dispose
from .core.stages import Judged
from .defense import Provenance, defend
from .gateway.context import profile_context
from .gateway.ingress_defense import IngressDecision, disposed_response, scan_response
from .logsafe import exc_kind, exc_where
from .modes import Mode, ModePolicy, gaps_of
from .transports.base import Early, Transport

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .core.stages import Transformed
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
