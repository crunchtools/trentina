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
    from .gateway.profile import Profile
    from .l1.hidden import HiddenStats
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
