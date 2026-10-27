"""The one crossing: one request, two edges, in an order only this module knows.

Every request Trentina mediates is one crossing with two edges — the request
edge carries what the agent said toward the world, the response edge carries
what the world said back — and both run from here. ``crossing`` sequences a
transport's halves (``transports.base``) in the ONE order that is the security
property: parse the request, carry it, deliver the response, wrap it. A
transport supplies the protocol; it does not get to choose the order, so it
cannot skip the gate (Trentina 3.0 plan §A/§C).

Phase 4 state: ``crossing`` drives the MCP ``tools/call`` path for a profile
flagged ``orchestrated``, composing the gateway's existing collaborators
through ``transports.mcp`` so its output is byte-identical to the hand-rolled
``gateway/router.py`` path it will replace. The ``edge()`` Part mechanism (the
one home for paging and streaming), the stage types it produces, and the
``Posture`` it carries arrive in the later Phase 4 PRs as logic moves off the
router and into here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .core import gate
from .defense import Provenance
from .gateway.ingress_defense import IngressDecision, disposed_response, scan_response
from .transports.base import Early, Transport

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .gateway.profile import Profile
    from .l1.hidden import HiddenStats
    from .l1.pipeline import PipelineResult
    from .modes import Mode, ModePolicy


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
