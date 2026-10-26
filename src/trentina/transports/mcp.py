"""The MCP transport: a server face and a client carrier for ``tools/call``.

This is the in-tree first transport (Trentina 3.0 Phase 4). Its halves do not
reimplement the ``tools/call`` path — they COMPOSE the gateway's existing
collaborators in ``gateway/router.py`` in the same order, so a crossing driven
through them produces a byte-identical JSON-RPC response to the hand-rolled
``router._tools_call``. That is the point of the first PR: prove the
Face/Carrier seam carries the live path unchanged, under a per-profile flag,
before any logic moves off the router and into the orchestrator.

The mapping to ``router._tools_call`` is one-to-one:

* ``McpServerFace.parse``   — resolve the target, re-check the allowlist, answer
  a decoy or ``read_part`` here, resolve the mode and preprocess switch,
  normalize the arguments, and run the argument guards. The REQUEST edge.
* ``McpClientCarrier.carry`` — ``router._dispatch`` (remote backend or internal
  tool), with the backend-error refusal.
* ``McpServerFace.deliver`` — the response guards, then the RESPONSE edge as
  stages (``_assemble``: Arrived → Transformed → Judged → disposed), with the
  one audit row written by the shared ``router._finish_delivery``.
* ``McpServerFace.wrap``    — the JSON-RPC success envelope.

``_assemble`` reproduces ``router._assemble_call_result`` as the stage pipeline
(``core.stages``), composing the same collaborators in the same order so the
delivered bytes are byte-identical; the paged branch still delegates to
``router._hold_paged`` / ``_deliver_part`` until a later PR collapses the two
paging holds into one Part mechanism.

Because the coupling to the router's private helpers lives HERE and nowhere
else, later Phase 4 PRs absorb those helpers into the orchestrator by editing
this file and deleting the router copies, not by touching every call site.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

# ``router`` holds the private ``tools/call`` helpers this transport composes;
# the shared collaborators are imported from their own modules (mypy does not
# re-export a name through an importer). This is the one place the orchestrator
# couples to the gateway's internals, so the later cutover edits only this file.
from ..core.stages import Arrived, Judged, Transformed
from ..defense import Provenance
from ..errors import ModeNotPermittedError, TransformNotPermittedError
from ..gateway import paging, router
from ..gateway.destination import Destination, destination_of
from ..gateway.errors import BackendCallError
from ..gateway.filter import filter_tools
from ..gateway.guards import check_response_guards
from ..gateway.ingress_defense import scan_tool_response
from ..gateway.modes_policy import policy_for, resolve_call, resolve_preprocess
from ..gateway.transform import transform_response
from ..outcomes import Outcome, classify_exception
from ..reserved import REFUSAL_KEY, WARNING_KEY
from .base import Carrier, Early, Face, Transport

if TYPE_CHECKING:
    from ..gateway.args import Normalized
    from ..gateway.profile import Backend, Profile
    from ..gateway.transform import TransformOutcome
    from ..modes import Mode, ModePolicy
    from ..transforms.policy import PreProcessPolicy


@dataclass(frozen=True)
class McpCrossing:
    """One ``tools/call`` request's context: who, which JSON-RPC id, what params.

    Built by ``router._route_tools_call`` for an ``orchestrated`` profile and
    handed to ``crossing``. ``params`` has already been checked to be a mapping
    and is not a discovery/``call_tool`` meta name (those are answered before
    the crossing), so it is exactly what ``router._tools_call`` receives.
    """

    profile: Profile
    req_id: Any
    params: dict[str, Any]


@dataclass(frozen=True)
class McpParsed:
    """A resolved, guarded, normalized ``tools/call`` ready to carry.

    Everything ``_dispatch`` and ``_deliver`` need, resolved once on the
    request edge: the routed backend and tool, the forwarded arguments, the
    resolved mode policy / mode / extraction prompt, the preprocess policy and
    switch, the normalization record, and where the call was pointed.
    """

    backend_name: str
    tool_name: str
    backend: Backend
    forwarded: dict[str, Any]
    policy: ModePolicy
    mode: Mode
    prompt: str | None
    preprocess: PreProcessPolicy
    requested: Any
    minify: bool | None
    normalized: Normalized
    dest: Destination | None


@dataclass(frozen=True)
class McpCarried:
    """What the carrier brought back: the raw backend result and its start time.

    ``t0`` is set the instant before the dispatch (as in ``router._tools_call``)
    so the response edge's audit row measures the same wall clock the
    hand-rolled path did.
    """

    call_result: Any
    t0: float


class McpServerFace(Face):
    """The MCP server side: parse the request, deliver the response, wrap it."""

    name = "mcp_server"

    async def _route(
        self, ctx: McpCrossing
    ) -> tuple[str, str, Backend, dict[str, Any], Destination | None] | Early:
        """Resolve the served name to a backend tool, re-check the allowlist, and
        answer the two calls no backend serves (a decoy, ``read_part``).

        Returns ``(backend_name, tool_name, backend, arguments, dest)`` with
        ``arguments`` narrowed to a mapping, or an ``Early`` for an unknown tool,
        an allowlist denial, non-object arguments, or a call answered here.
        """
        profile, req_id, params = ctx.profile, ctx.req_id, ctx.params
        served_name = params.get("name", "")
        # Only an absent or null ``arguments`` defaults; a falsy ``[]`` stays malformed.
        arguments = {} if params.get("arguments") is None else params["arguments"]

        target = router._resolve_target(profile, served_name)
        if target is None:
            return Early(router._unknown_tool(profile, req_id, served_name))
        backend_name, tool_name, backend = target

        # From the arguments as sent, so a call refused below still records
        # where it was pointed (#266).
        dest = (
            destination_of(backend, tool_name, arguments) if isinstance(arguments, dict) else None
        )

        if not filter_tools([{"name": tool_name}], backend):
            message = f"Tool {tool_name!r} not permitted on backend {backend_name!r}"
            router._audit(
                profile.name,
                backend_name,
                tool_name,
                Outcome.DENIED_ALLOWLIST,
                0,
                message,
                destination=dest,
            )
            return Early(router._err(req_id, router.JSONRPC_INVALID_PARAMS, message))

        if not isinstance(arguments, dict):
            message = "arguments must be an object"
            router._audit(profile.name, backend_name, tool_name, Outcome.DENIED_GUARD, 0, message)
            return Early(router._err(req_id, router.JSONRPC_INVALID_PARAMS, message))

        if backend.is_decoy or (backend.is_internal and tool_name == paging.READ_PART_TOOL):
            answer = await router._answered_here(profile, req_id, served_name, target, arguments)
            return Early(answer)

        return backend_name, tool_name, backend, arguments, dest

    async def parse(self, ctx: McpCrossing) -> McpParsed | Early:
        """The REQUEST edge — ``router._tools_call`` up to the dispatch.

        Returns an ``McpParsed`` ready to carry, or an ``Early`` carrying the
        already-audited refusal for every way the request is turned away:
        unknown tool, allowlist, non-object arguments, a decoy / ``read_part``
        answered here, a bad mode or preprocess switch, or a guarded argument.
        """
        profile, req_id = ctx.profile, ctx.req_id

        routed = await self._route(ctx)
        if isinstance(routed, Early):
            return routed
        backend_name, tool_name, backend, arguments, dest = routed

        # The mode resolves BEFORE any guard reads it: an omitted mode becomes
        # the default and is checked as that, never skipped as absent.
        try:
            policy, mode, prompt, forwarded = resolve_call(profile, backend, tool_name, arguments)
            preprocess, requested, minify = resolve_preprocess(
                profile, backend, tool_name, arguments
            )
        except (ModeNotPermittedError, TransformNotPermittedError) as exc:
            router._audit(
                profile.name,
                backend_name,
                tool_name,
                Outcome.DENIED_GUARD,
                0,
                str(exc),
                destination=dest,
            )
            return Early(router._err(req_id, router.JSONRPC_INVALID_PARAMS, str(exc)))

        # Before the guards, so they judge exactly what is forwarded.
        normalized = router._normalize_arguments(
            profile, backend, backend_name, tool_name, forwarded
        )
        forwarded = normalized.arguments

        refused = await router._refuse_call(
            profile, backend, backend_name, tool_name, forwarded, mode, prompt, normalized, dest
        )
        if refused is not None:
            outcome, message, recorded = refused
            router._audit(
                profile.name,
                backend_name,
                tool_name,
                outcome,
                0,
                recorded,
                normalized=normalized.dropped or None,
                destination=dest,
            )
            return Early(router._err(req_id, router.JSONRPC_INVALID_PARAMS, message))

        return McpParsed(
            backend_name=backend_name,
            tool_name=tool_name,
            backend=backend,
            forwarded=forwarded,
            policy=policy,
            mode=mode,
            prompt=prompt,
            preprocess=preprocess,
            requested=requested,
            minify=minify,
            normalized=normalized,
            dest=dest,
        )

    async def deliver(
        self, ctx: McpCrossing, parsed: McpParsed, carried: McpCarried
    ) -> dict[str, Any] | Early:
        """The RESPONSE edge — response guards, then the staged assembly.

        Returns the result mapping for ``wrap`` (the delivered result, or the
        ``executed, response withheld`` body a write tool gets when its response
        is guarded off), or an ``Early`` when a read tool's response is refused.

        The assembly is reproduced here as the stage pipeline ``_assemble``
        (Arrived → Transformed → Judged → the disposed ``Assembled``), composing
        the same collaborators ``router._assemble_call_result`` does, in the same
        order, so the delivered bytes match. The one audit row and the session
        mark are written by the shared ``router._finish_delivery`` — the same
        function the hand-rolled path uses — so the row is written exactly once.
        """
        profile, req_id = ctx.profile, ctx.req_id
        call_result = carried.call_result

        # Response guards run on the RAW result, before reduction and the scan.
        duration_ms = int((time.monotonic() - carried.t0) * 1000)
        response_err = check_response_guards(
            parsed.tool_name, call_result.content, call_result.structured_content, parsed.backend
        )
        if response_err:
            router._audit(
                profile.name,
                parsed.backend_name,
                parsed.tool_name,
                Outcome.DENIED_RESPONSE_GUARD,
                duration_ms,
                response_err,
                destination=parsed.dest,
            )
            if not router._may_have_acted(parsed.backend, parsed.tool_name):
                return Early(router._err(req_id, router.JSONRPC_INVALID_PARAMS, response_err))
            withheld = {REFUSAL_KEY: {"reason": response_err, "mode": parsed.mode.value}}
            return router._executed(withheld, call_result.is_error)

        t0 = carried.t0
        try:
            assembled = await self._assemble(ctx, parsed, carried)
        except Exception as exc:
            router._audit_assembly_failure(
                profile.name, parsed.backend_name, parsed.tool_name, t0, exc, parsed.dest
            )
            raise
        return await router._finish_delivery(
            profile,
            parsed.backend,
            parsed.backend_name,
            parsed.tool_name,
            call_result,
            t0,
            assembled,
            normalized=parsed.normalized.dropped,
            destination=parsed.dest,
        )

    async def _assemble(
        self, ctx: McpCrossing, parsed: McpParsed, carried: McpCarried
    ) -> router.Assembled:
        """The response edge as stages — ``router._assemble_call_result`` reproduced.

        Arrived (strip the gateway's reserved keys) → Transformed (the
        pre-perimeter transform chain) → Judged (``scan_tool_response``) → the
        disposed ``Assembled``. The same collaborators in the same order; the
        paged branch still delegates to ``router._hold_paged`` / ``_deliver_part``
        (collapsed into the one Part mechanism in a later PR). An internal tool
        runs the pipeline at its own ingress, so it is neither transformed nor
        scanned here and has no ``Transformed.reduced`` and no ``Judged`` stage.
        """
        profile = ctx.profile
        backend, backend_name, tool_name = parsed.backend, parsed.backend_name, parsed.tool_name
        call_result = carried.call_result
        mode, prompt, policy, minify = parsed.mode, parsed.prompt, parsed.policy, parsed.minify

        ok = Outcome.TOOL_ERROR if call_result.is_error else Outcome.OK
        content_blocks, structured, stripped = await asyncio.to_thread(
            router._arrived, backend, call_result
        )
        arrived = Arrived(
            content_blocks=content_blocks,
            structured=structured,
            stripped=stripped,
            # ``bool`` as the paging hold reads it; the result keeps the raw flag.
            is_error=bool(call_result.is_error),
            # The backend has answered, so a tool that may write has written (#425).
            acted=router._may_have_acted(backend, tool_name),
        )

        # Transform BEFORE the perimeter, never after: the scan reads the
        # transformed artifact and that artifact is delivered, so nothing a
        # processor dropped is judged or delivered.
        provenance = Provenance.EXTERNAL
        reduced: TransformOutcome | None = None
        content_blocks = arrived.content_blocks
        if not backend.is_internal:
            reduced = await transform_response(
                profile=profile,
                backend=backend,
                backend_name=backend_name,
                tool_name=tool_name,
                content_blocks=content_blocks,
                minify=minify,
            )
            if reduced.failed is not None:
                failed = router._preprocess_refusal(reduced.failed, mode)
                return router.Assembled(
                    router._executed(failed, call_result.is_error) if arrived.acted else failed,
                    Outcome.BLOCKED_DEFENSE,
                    reduced.failed,
                    stripped=stripped,
                )
            content_blocks = reduced.content_blocks
            provenance = reduced.provenance
            # Too large to judge in one call (#340): cut once, from the
            # transformed text, so what is cut is what would have been delivered.
            paged = await router._hold_paged(
                profile,
                backend,
                backend_name,
                tool_name,
                content_blocks,
                arrived.structured,
                mode=mode,
                prompt=prompt,
                provenance=provenance,
                l3_context=router._l3_context(backend, reduced),
                hidden=reduced.hidden,
                is_error=arrived.is_error,
                acted=arrived.acted,
            )
            if paged is not None:
                first = await router._deliver_part(
                    profile,
                    paged,
                    1,
                    mode=paged.mode,
                    prompt=prompt,
                    policy=policy or policy_for(profile, backend, tool_name),
                )
                first.stripped = stripped
                return first
        transformed = Transformed(
            arrived=arrived, content_blocks=content_blocks, provenance=provenance, reduced=reduced
        )

        result: dict[str, Any] = {
            "content": transformed.content_blocks,
            "isError": call_result.is_error,
        }
        if arrived.structured is not None:
            result["structuredContent"] = arrived.structured

        gateway_warning: dict[str, Any] | None = None
        if not backend.is_internal:
            judged = Judged(
                transformed=transformed,
                decision=await scan_tool_response(
                    profile=profile,
                    backend_name=backend_name,
                    tool_name=tool_name,
                    content_blocks=transformed.content_blocks,
                    structured_content=arrived.structured,
                    provenance=transformed.provenance,
                    mode=mode,
                    prompt=prompt,
                    policy=policy,
                    l3_context=router._l3_context(backend, reduced)
                    if reduced is not None
                    else backend.l3_briefing,
                    hidden=reduced.hidden if reduced is not None else None,
                ),
            )
            gateway_warning = judged.decision.warning
            if judged.decision.blocked:
                # The content never reaches the agent; the warning does. Audited
                # as a defense block so a misfiring threshold shows in the
                # outcome column, not only in an agent's confusion.
                risk = judged.decision.warning.get("risk_level") if judged.decision.warning else "?"
                blocked = router._blocked_result(judged.decision)
                return router.Assembled(
                    router._executed(blocked, call_result.is_error) if arrived.acted else blocked,
                    Outcome.BLOCKED_DEFENSE,
                    f"response blocked by defense (risk={risk})",
                    warning=gateway_warning,
                    stripped=stripped,
                )
            if judged.decision.extraction is not None:
                # redact: the verified extraction REPLACES the response, and
                # structuredContent goes with it — redact never re-delivers what
                # it replaced.
                result = {
                    "content": [{"type": "text", "text": judged.decision.extraction}],
                    "isError": call_result.is_error,
                }
                if judged.decision.warning is not None:
                    result[WARNING_KEY] = judged.decision.warning
                return router.Assembled(result, ok, warning=gateway_warning, stripped=stripped)
            router._attach_warning(result, judged.decision.warning)

        return router.Assembled(result, ok, warning=gateway_warning, stripped=stripped)

    def wrap(self, ctx: McpCrossing, result: dict[str, Any]) -> dict[str, Any]:
        """The JSON-RPC success envelope."""
        return router._ok(ctx.req_id, result)


class McpClientCarrier(Carrier):
    """The MCP client side: dispatch the call to its backend or internal tool."""

    name = "mcp_client"

    async def carry(self, ctx: McpCrossing, parsed: McpParsed) -> McpCarried | Early:
        """Forward the call — ``router._dispatch`` — with the backend-error refusal.

        ``t0`` is taken the instant before the dispatch, exactly as
        ``router._tools_call`` does, and travels on the ``McpCarried`` so the
        response edge's audit measures one wall clock.
        """
        profile, req_id = ctx.profile, ctx.req_id
        t0 = time.monotonic()
        try:
            call_result = await router._dispatch(
                profile,
                parsed.backend,
                parsed.backend_name,
                parsed.tool_name,
                parsed.forwarded,
                policy=parsed.policy,
                mode=parsed.mode,
                prompt=parsed.prompt,
                preprocess=parsed.preprocess,
                requested=parsed.requested,
            )
        except BackendCallError as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            outcome = classify_exception(exc)
            router._audit(
                profile.name,
                parsed.backend_name,
                parsed.tool_name,
                outcome,
                duration_ms,
                str(exc),
                destination=parsed.dest,
            )
            return Early(
                router._failed_call(
                    req_id,
                    exc,
                    router._may_have_acted(parsed.backend, parsed.tool_name),
                    parsed.mode,
                    parsed.policy,
                )
            )
        return McpCarried(call_result=call_result, t0=t0)


#: The one MCP transport, wired into ``router._route_tools_call`` for a profile
#: flagged ``orchestrated``. Stateless, so one instance is shared.
mcp_transport = Transport(face=McpServerFace(), carrier=McpClientCarrier())
