"""The MCP transport and the gateway's JSON-RPC surface.

Trentina 3.0's one in-tree transport. ``route_jsonrpc`` dispatches a profile's
JSON-RPC (``initialize`` / ``ping`` / ``tools/list`` / ``tools/call``), and a
``tools/call`` runs through ``orchestrator.crossing`` driving this module's
``McpServerFace`` + ``McpClientCarrier``:

* ``McpServerFace.parse``   — resolve the target, re-check the allowlist, answer
  a decoy or ``read_part`` here, resolve the mode and preprocess switch,
  normalize the arguments, and run the argument guards. The REQUEST edge.
* ``McpClientCarrier.carry`` — ``_dispatch`` (remote backend or internal
  tool), with the backend-error refusal.
* ``McpServerFace.deliver`` — the response guards, then the RESPONSE edge as
  stages (``_assemble``: Arrived → Transformed → Judged → disposed), with the
  one audit row written by ``_finish_delivery``.
* ``McpServerFace.wrap``    — the JSON-RPC success envelope.

``_assemble`` runs the response edge over ``core.stages``; the paged branch
delegates to ``parts._hold_paged`` / ``parts._deliver_part`` until a later PR
collapses the two paging holds into one Part mechanism. The hand-rolled
``gateway/router.py`` that owned this path was deleted in PR3b (Trentina 3.0
Phase 7); the ``tools/list`` aggregate it held is in ``gateway/aggregate.py``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

# This transport owns the gateway's ``tools/call`` path; its collaborators are
# imported from their own gateway modules. This is the one place the transport
# layer couples to the gateway's internals.
from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_HANDSHAKE_VERSION,
)

from .. import __version__
from ..core.stages import Arrived, Assembled, IngressDecision, Transformed
from ..defense import Provenance
from ..errors import ModeNotPermittedError, TransformNotPermittedError
from ..gateway import (
    aggregate,
    audit,
    discovery,
    gatekeeper,
    paging,
    parts,
    request_edge,
    results,
    session_marks,
    tool_pins,
    vsa,
)
from ..gateway.backend import call_backend_tool, loggable_tool
from ..gateway.context import PartsOffer, current_call, current_session, profile_context
from ..gateway.decoy import leaked_tokens
from ..gateway.destination import Destination, destination_of
from ..gateway.errors import BackendCallError
from ..gateway.filter import filter_tools
from ..gateway.guards import _response_text as _response_guard_text
from ..gateway.guards import check_response_guards
from ..gateway.internal import call_internal_tool
from ..gateway.internal_edge import READ_NEXT_KEY
from ..gateway.modes_policy import (
    MODE_PARAM,
    effective_mode,
    mode_instructions,
    policy_for,
    resolve_call,
    resolve_preprocess,
)
from ..gateway.names import NAMESPACE_SEP, served_name
from ..gateway.parts import _part_reader
from ..gateway.service import judge_of
from ..gateway.sessions import session_registry
from ..gateway.surface import held_total, wire_bytes, wire_digest
from ..gateway.transform import transform_response
from ..logsafe import exc_kind, redact_source
from ..modes import refusal_body
from ..orchestrator import crossing, judge_response
from ..outcomes import Outcome, classify_exception
from ..perimeter_db import perimeter_stamp
from ..quarantine.packs import pack_for
from ..reserved import PINS_KEY, REFUSAL_KEY, WARNING_KEY, with_stripped
from ..transforms.policy import PREPROCESS_PARAM
from .base import Carrier, Early, Face, Transport
from .jsonrpc import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    _err,
    _ok,
    _refused,
    _response_guard_refusal,
)

if TYPE_CHECKING:
    from ..gateway.args import Normalized
    from ..gateway.backend import BackendCall
    from ..gateway.profile import Backend, Profile
    from ..gateway.transform import TransformOutcome
    from ..modes import Mode, ModePolicy
    from ..transforms.policy import PreProcessPolicy

logger = logging.getLogger(__name__)


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


def _result_document(call_result: Any) -> str:
    """The raw result as one text blob for the semantic response guard.

    The same text the literal response guard read (every text block joined, and
    an embedded ``resource``'s ``text``), plus each resource's OTHER delivered
    fields (``uri``, ``mimeType``) and the structured content, every piece
    serialized — so the judge sees everything the agent would receive, not only
    the joined text. ``_response_text`` reads only a resource's ``text``, but
    the agent is handed the whole resource dict; a backend could hide
    policy-restricted data (a credential in a resource ``uri``) in a field that
    extractor drops, so those fields are judged too. Empty when the result
    carries nothing to judge.
    """
    parts: list[str] = []
    text = _response_guard_text(call_result.content)
    if text:
        parts.append(text)
    for block in call_result.content or []:
        if not isinstance(block, dict) or block.get("type") != "resource":
            continue
        resource = block.get("resource")
        if not isinstance(resource, dict):
            continue
        # Everything delivered except the ``text`` already joined above — the
        # ``uri`` and ``mimeType`` the agent also sees. ``_has_uninspectable_content``
        # has already refused any resource carrying a binary ``blob``.
        meta = {k: v for k, v in resource.items() if k != "text"}
        if meta:
            parts.append(json.dumps(meta, sort_keys=True, ensure_ascii=False, default=str))
    structured = call_result.structured_content
    if structured is not None:
        parts.append(json.dumps(structured, sort_keys=True, ensure_ascii=False, default=str))
    return "\n".join(parts)


def _has_uninspectable_content(call_result: Any) -> bool:
    """True when any content block carries something the judge cannot read as text.

    The judge reads only text — a ``text`` block whose ``text`` is a string, or
    a ``resource`` block that is a text resource we can read whole. Every other
    block (an image, audio, a binary resource ``blob``, a ``resource_link``, an
    unknown type, a non-dict shape, or a ``text``/``resource`` block too
    malformed to read) is content the operator's policy cannot be checked
    against, so a guarded response holding any is failed closed — refused —
    rather than judged on the text around it. An allowlist, not a denylist: a
    block we do not explicitly read as text fails closed, so neither a new MCP
    block type nor a malformed block can open a hole here.
    """
    for block in call_result.content or []:
        if not isinstance(block, dict):
            return True
        kind = block.get("type")
        if kind == "text":
            # Inspectable only when the text is actually a string: a missing or
            # non-string ``text`` extracts to nothing, which would reach the
            # judge as an empty document and pass the policy unchecked.
            if isinstance(block.get("text"), str):
                continue
            return True
        if kind == "resource":
            resource = block.get("resource")
            # A text resource we can read whole: a dict, a string ``text``, and
            # no binary ``blob``. Its ``uri``/``mimeType`` are judged by
            # ``_result_document``; a ``blob`` is binary the judge cannot read.
            if (
                isinstance(resource, dict)
                and isinstance(resource.get("text"), str)
                and "blob" not in resource
            ):
                continue
            return True
        return True
    return False


def _federated_continuation(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    call_result: BackendCall,
    result: dict[str, Any],
    *,
    mode: Mode,
    prompt: str | None,
    provenance: Provenance,
    reduced: TransformOutcome | None,
    arrived: Arrived,
) -> dict[str, Any]:
    """Hold a federated peer's remaining parts and mark the delivered part 1 (#592, B2).

    A federated peer delivered part 1 (judged by the caller) and holds the rest
    under its own handle, named in ``call_result.meta._trentina_part``. Hold a
    proxy under that handle and attach OUR continuation marker to ``result``, so
    the agent's ``read_part`` forwards to the peer rather than the rest being
    orphaned. Part 1 was under ``whole_tokens``, so it was never re-paged — no
    double paging. Returns ``result`` unchanged when the response is not a
    federated peer's paged part, or when this profile cannot read a part 2.
    """
    if backend.federated is None:
        return result
    upstream = paging.federated_upstream(backend_name, call_result.meta)
    reader = _part_reader(profile)
    if upstream is None or reader is None:
        return result
    paged = paging.hold_federated(
        paging.Origin(
            profile=profile.name,
            backend=backend_name,
            tool=tool_name,
            label=served_name(profile, backend_name, tool_name) or tool_name,
            is_error=arrived.is_error,
            acted=arrived.acted,
        ),
        upstream,
        mode=effective_mode(profile, mode),
        prompt=prompt,
        provenance=provenance,
        l3_context=results._l3_context(backend, reduced)
        if reduced is not None
        else backend.l3_briefing,
        hidden=reduced.hidden if reduced is not None else None,
    )
    if paged is None:
        return result
    paged.delivered.add(1)
    marker = paging.marker(paged, 1)
    marker[READ_NEXT_KEY] = paging.footer(paged, 1, reader)
    return paging.with_part_marker(result, marker, reader=reader)


#: The untrusted reasons worth a log line (#592, D2a): the rest — absent, a
#: hash/mode mismatch, a stale assertion — re-judge quietly.
_LOGGED_UNTRUSTED = frozenset({"bad_signature", "stamp_mismatch"})
#: (profile, backend, stamp) a stamp-mismatch was already warned for: a changed
#: upstream stamp warns once, not on every call. A log-dedup; dropped and
#: re-warned once if it ever grows past this many distinct stamps.
_WARNED_STAMPS_MAX = 4096
_warned_stamps: set[tuple[str, str, str]] = set()


def _log_untrusted(profile: Profile, backend_name: str, reason: str, stamp: str) -> None:
    """Note why a federated response was NOT trusted and will be re-judged (#592).

    A bad signature (a peer whose key does not verify) and a stamp mismatch (the
    upstream changed its policy and the operator has not re-pinned) are logged;
    a stamp mismatch once per (profile, backend, stamp). Everything else is the
    quiet common case. The backend name is config, not caller-chosen, so it is
    loggable; the peer's own text never is.
    """
    if reason not in _LOGGED_UNTRUSTED:
        return
    key = (profile.name, backend_name, stamp)
    if reason == "stamp_mismatch":
        if key in _warned_stamps:
            return
        # A log-dedup, not state anything reads: if it grows past a sane bound
        # (many distinct stamps over a long uptime) drop it and re-warn once,
        # rather than leak memory.
        if len(_warned_stamps) >= _WARNED_STAMPS_MAX:
            _warned_stamps.clear()
        _warned_stamps.add(key)
    logger.info(
        "gateway: federated verdict not trusted profile=%s backend=%s reason=%s",
        profile.name, backend_name, reason,
    )


def _deliver_trusted(
    arrived: Arrived,
    call_result: BackendCall,
    verdict: dict[str, Any],
    *,
    mode: Mode,
    policy: ModePolicy | None,
    stripped: int,
    ok: Outcome,
) -> Assembled:
    """Deliver a response on the peer's TRUSTED verdict, the layers not re-run
    (#592, D2a). Clean → delivered; flagged under block → refused as a defense
    block would; flagged under flag → delivered with a DOWNSTREAM-authored
    warning built from the verdict's closed fields (never the peer's text). The
    transform is skipped too, so nothing unjudged is reshaped before delivery."""
    flagged_by = verdict.get("flagged_by")
    warning = {k: v for k, v in verdict.items() if k != "mode"} if flagged_by else None
    result: dict[str, Any] = {"content": arrived.content_blocks, "isError": arrived.is_error}
    if arrived.structured is not None:
        result["structuredContent"] = arrived.structured
    if flagged_by and mode.value == "block":
        refusal = refusal_body(f"flagged by {flagged_by}", mode, flagged_by=str(flagged_by),
                               policy=policy)
        blocked = results._blocked_result(IngressDecision(warning=warning, blocked=True,
                                                          refusal=refusal))
        return Assembled(
            results._executed(blocked, call_result.is_error) if arrived.acted else blocked,
            Outcome.BLOCKED_DEFENSE,
            f"trusted federated verdict: flagged by {flagged_by}",
            warning=warning,
            stripped=stripped,
        )
    results._attach_warning(result, warning)
    return Assembled(result, ok, warning=warning, stripped=stripped)


def _federated_hold_refusal(
    backend: Backend, call_result: BackendCall, *, stripped: int
) -> Assembled | None:
    """A federated peer refused the call with its pin CALL GATE (#592, E1c).

    The upstream's gate (#469) returns ``tool_held`` as a result-shaped refusal;
    its root ``_trentina_refusal`` does not survive the SDK, so the peer mirrors
    the closed reason into ``_meta`` (``_mirror_refusal_meta``). Read it BEFORE
    the transform — otherwise the peer's "[TRENTINA] Refused" text is judged as
    content and relayed. Match the reason by its exact closed code, never the
    ``detail``, and author our OWN refusal so the agent reads downstream words.
    Only a federated backend; a non-federated one never sets ``backend.federated``.
    """
    if backend.federated is None:
        return None
    meta = call_result.meta if isinstance(call_result.meta, dict) else None
    refusal = meta.get(REFUSAL_KEY) if meta else None
    if not isinstance(refusal, dict) or refusal.get("reason") != tool_pins.TOOL_HELD_REASON:
        return None
    result = {
        "content": [
            {
                "type": "text",
                "text": (
                    "[TRENTINA] Refused (tool_held_upstream). The tool is held pending "
                    "operator approval on the upstream gateway."
                ),
            }
        ],
        "isError": False,
        REFUSAL_KEY: {
            "reason": tool_pins.TOOL_HELD_UPSTREAM_REASON,
            "detail": "held upstream, awaiting approval",
            "alternatives": [],
        },
    }
    return Assembled(result, Outcome.DENIED_GUARD, stripped=stripped)


def _federated_early(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    arrived: Arrived,
    call_result: BackendCall,
    *,
    mode: Mode,
    policy: ModePolicy,
    stripped: int,
    ok: Outcome,
) -> Assembled | None:
    """The two federated response-edge early exits, checked before the transform
    (#592): the peer's pin-gate ``tool_held`` refusal mapped to our own words
    (E1c), then the peer's trusted signed verdict (D2a). None when neither
    applies and the local pipeline must run."""
    held = _federated_hold_refusal(backend, call_result, stripped=stripped)
    if held is not None:
        return held
    return _federated_trust(
        profile, backend, backend_name, arrived, call_result,
        mode=mode, policy=policy, stripped=stripped, ok=ok,
    )


def _federated_trust(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    arrived: Arrived,
    call_result: BackendCall,
    *,
    mode: Mode,
    policy: ModePolicy | None,
    stripped: int,
    ok: Outcome,
) -> Assembled | None:
    """Trust a federated peer's signed verdict and SKIP the downstream's L1/L2/L3
    (#592, D2a), or None to re-judge locally (fail-closed).

    Only for a federated backend whose ``trust_verdict`` pins the upstream's key
    and perimeter stamp. The assertion (in ``call_result.meta`` — B2's channel)
    must verify against that key, bind to the delivered bytes and the pinned
    stamp, match the resolved mode and be fresh; any shortfall re-judges, with
    the reason logged by kind. A trusted response skips the transform too:
    transformed bytes nobody judged are what the layer contract forbids.
    """
    federated = backend.federated
    if federated is None or federated.trust_verdict is None:
        return None
    tv = federated.trust_verdict
    envelope = call_result.meta.get(vsa.VSA_KEY) if isinstance(call_result.meta, dict) else None
    resolved = effective_mode(profile, mode)
    assertion, reason = vsa.check_trust(
        envelope,
        public_key=tv.public_key,
        content_sha256=vsa.content_digest(
            arrived.content_blocks, arrived.structured, arrived.is_error
        ),
        perimeter_stamp=tv.perimeter_stamp,
        judge=tv.judge,
        mode=resolved.value,
        now=int(time.time()),
    )
    if assertion is None:
        _log_untrusted(profile, backend_name, reason, tv.perimeter_stamp)
        return None
    verdict = assertion["verdict"]
    # An INCOMPLETE upstream judgment is never trust-delivered (#592): a gap, an
    # oversize refusal or unread binary means the upstream could not fully read
    # the content, and whether that is acceptable is THIS downstream's policy
    # (TRENTINA_REQUIRE_L2/L3, the mode's handling of gaps) — which the trust
    # path does not consult. Re-judge locally so the downstream's own policy
    # decides, instead of delivering clean on the peer's weaker gap handling.
    if verdict.get("gaps") or verdict.get("oversize") or verdict.get("unread_kinds"):
        _log_untrusted(profile, backend_name, "incomplete_verdict", tv.perimeter_stamp)
        return None
    return _deliver_trusted(
        arrived, call_result, verdict,
        mode=resolved, policy=policy, stripped=stripped, ok=ok,
    )


def _judge_stamp(profile: Profile) -> str:
    """The L3 judge identity this profile scans under (#592, D2a): its
    ``provider/model`` and L3 prompt-pack stamp — the same (provider, model) and
    pack the verdict cache keys on. The ``perimeter_stamp`` covers L2 and the
    version but not L3, so a federated verdict pins this separately."""
    judge = judge_of(profile)
    pack = pack_for(judge, profile.defense.l3_prompt_pack)
    return f"{judge[0]}/{judge[1]}/{pack.stamp}"


def _federated_vsa(
    profile: Profile,
    result: dict[str, Any],
    *,
    blocks: list[Any] | None,
    structured: Any,
    is_error: bool,
    warning: dict[str, Any] | None,
    mode: Mode,
) -> dict[str, Any]:
    """Attach the ingress's signed verdict assertion to a delivered federated
    response (#592, D1), when this profile is a federation ingress with a
    signing key.

    The assertion binds the signature to the delivered bytes (``content_digest``
    over the blocks, structured content and ``isError``, never the warning or
    ``_meta``) and to the perimeter stamp, so a downstream that pins the public
    key and the stamp can trust the scan instead of re-judging (D2a). Emitted
    only here, on the clean-or-flagged DELIVERED path where the layers ran —
    never on a blocked or redacted response, which returned earlier, and never
    for an internal tool, which is judged at its own ingress. Returns ``result``
    unchanged for a profile that is not a signing federation ingress.
    """
    federation = profile.federation
    if federation is None or federation.signing_key is None:
        return result
    assertion = vsa.build_assertion(
        verifier=profile.name,
        content_sha256=vsa.content_digest(blocks, structured, is_error),
        verdict=vsa.verdict_summary(warning, mode.value),
        perimeter_stamp=perimeter_stamp(),
        judge=_judge_stamp(profile),
        ts=int(time.time()),
    )
    envelope = vsa.sign_assertion(assertion, federation.signing_key.get_secret_value())
    meta = {**(result.get("_meta") or {}), vsa.VSA_KEY: envelope}
    return {**result, "_meta": meta}


def _mirror_refusal_meta(profile: Profile, response: dict[str, Any]) -> dict[str, Any]:
    """Mirror a refusal's closed reason into the result ``_meta`` for a federation
    ingress caller (#592, E1c).

    A policy refusal carries its reason in a root ``_trentina_refusal``, which a
    federated downstream's MCP SDK drops in transit (``_meta`` survives). Copy
    ONLY the closed reason code, never the ``detail`` text (#262), so the
    downstream can author its own "held upstream" wording. A clean result has no
    root refusal and is returned unchanged; no-op off a federation ingress.
    """
    result = response.get("result")
    if not isinstance(result, dict):
        return response
    refusal = result.get(REFUSAL_KEY)
    if not isinstance(refusal, dict) or "reason" not in refusal:
        return response
    if profile.federation is None:
        return response
    result["_meta"] = {**(result.get("_meta") or {}), REFUSAL_KEY: {"reason": refusal["reason"]}}
    return response


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

        target = request_edge._resolve_target(profile, served_name)
        if target is None:
            return Early(request_edge._unknown_tool(profile, req_id, served_name))
        backend_name, tool_name, backend = target

        # From the arguments as sent, so a call refused below still records
        # where it was pointed (#266).
        dest = (
            destination_of(backend, tool_name, arguments) if isinstance(arguments, dict) else None
        )

        if not filter_tools([{"name": tool_name}], backend):
            message = f"Tool {tool_name!r} not permitted on backend {backend_name!r}"
            audit._audit(
                profile.name,
                backend_name,
                tool_name,
                Outcome.DENIED_ALLOWLIST,
                0,
                message,
                destination=dest,
            )
            return Early(_err(req_id, JSONRPC_INVALID_PARAMS, message))

        # The pinning CALL GATE (#469): pinning was only ever a tools/list
        # filter, so a remote tool whose description changed after approval (or,
        # under long names, one never approved) was still callable unapproved.
        # A held remote tool is refused here, fail-closed, before the backend is
        # reached; internal and decoy skip, as the list filter does.
        if backend.is_remote and tool_pins.held(backend.url, tool_name):
            message = f"Tool {tool_name!r} is held pending operator approval"
            audit._audit(
                profile.name,
                backend_name,
                tool_name,
                Outcome.DENIED_GUARD,
                0,
                message,
                destination=dest,
            )
            # A policy refusal, delivered as an ordinary result (not a JSON-RPC
            # error), carrying the closed tool_held reason a federated downstream
            # maps to its own words (#592, E1c).
            return Early(
                _refused(
                    req_id,
                    {
                        "reason": tool_pins.TOOL_HELD_REASON,
                        "detail": message,
                        "alternatives": [],
                    },
                )
            )

        if not isinstance(arguments, dict):
            message = "arguments must be an object"
            audit._audit(profile.name, backend_name, tool_name, Outcome.DENIED_GUARD, 0, message)
            return Early(_err(req_id, JSONRPC_INVALID_PARAMS, message))

        if backend.is_decoy or (backend.is_internal and tool_name == paging.READ_PART_TOOL):
            answer = await request_edge._answered_here(
                profile, req_id, served_name, target, arguments
            )
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
            audit._audit(
                profile.name,
                backend_name,
                tool_name,
                Outcome.DENIED_GUARD,
                0,
                str(exc),
                destination=dest,
            )
            return Early(
                _refused(
                    req_id,
                    {"reason": Outcome.DENIED_GUARD.value, "detail": str(exc), "alternatives": []},
                )
            )

        # Before the guards, so they judge exactly what is forwarded.
        normalized = request_edge._normalize_arguments(
            profile, backend, backend_name, tool_name, forwarded
        )
        forwarded = normalized.arguments

        refused = await request_edge._refuse_call(
            profile, backend, backend_name, tool_name, forwarded, mode, prompt, normalized, dest
        )
        if refused is not None:
            outcome, message, recorded = refused
            audit._audit(
                profile.name,
                backend_name,
                tool_name,
                outcome,
                0,
                recorded,
                normalized=normalized.dropped or None,
                destination=dest,
            )
            return Early(
                _refused(req_id, {"reason": outcome.value, "detail": message, "alternatives": []})
            )

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
        mark are written by the shared ``_finish_delivery`` — the same
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
            audit._audit(
                profile.name,
                parsed.backend_name,
                parsed.tool_name,
                Outcome.DENIED_RESPONSE_GUARD,
                duration_ms,
                response_err,
                destination=parsed.dest,
            )
            if not results._may_have_acted(parsed.backend, parsed.tool_name):
                return Early(_response_guard_refusal(req_id, response_err, parsed.mode))
            withheld = {REFUSAL_KEY: {"reason": response_err, "mode": parsed.mode.value}}
            return results._executed(withheld, call_result.is_error)

        # The semantic response guard: the judge reads the operator's policy
        # against the raw result the literal guard saw, before the perimeter
        # (#456) — purely the policy judge; the perimeter scans next in
        # ``_assemble``. The before-perimeter order is load-bearing: a refused
        # response is never delivered (so the layer contract holds), and
        # scanning first would risk redact mode delivering a redaction of a
        # response the policy withholds. Guarded tools only; unguarded cost nothing.
        guards = profile.semantic_response_guards
        if guards is not None and guards.guards(parsed.backend_name, parsed.tool_name):
            uninspectable = _has_uninspectable_content(call_result)
            document = "" if uninspectable else _result_document(call_result)
            gated = await gatekeeper.judge_response(
                profile,
                parsed.backend,
                parsed.backend_name,
                parsed.tool_name,
                document,
                dest=None,
                uninspectable=uninspectable,
            )
            if gated is not None:
                audit._audit(
                    profile.name,
                    parsed.backend_name,
                    parsed.tool_name,
                    Outcome.DENIED_RESPONSE_GATEKEEPER,
                    duration_ms,
                    gated.audit,
                    destination=parsed.dest,
                )
                if not results._may_have_acted(parsed.backend, parsed.tool_name):
                    return Early(_response_guard_refusal(req_id, gated.message, parsed.mode))
                withheld = {REFUSAL_KEY: {"reason": gated.message, "mode": parsed.mode.value}}
                return results._executed(withheld, call_result.is_error)

        t0 = carried.t0
        try:
            assembled = await self._assemble(ctx, parsed, carried)
        except Exception as exc:
            audit._audit_assembly_failure(
                profile.name, parsed.backend_name, parsed.tool_name, t0, exc, parsed.dest
            )
            raise
        return await _finish_delivery(
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
    ) -> Assembled:
        """The response edge as stages — ``router._assemble_call_result`` reproduced.

        Arrived (strip the gateway's reserved keys) → Transformed (the
        pre-perimeter transform chain) → Judged (``judge_response``) → the
        disposed ``Assembled``. The same collaborators in the same order; the
        paged branch still delegates to ``parts._hold_paged`` / ``_deliver_part``
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
            results._arrived, backend, call_result
        )
        arrived = Arrived(
            content_blocks=content_blocks,
            structured=structured,
            stripped=stripped,
            # ``bool`` as the paging hold reads it; the result keeps the raw flag.
            is_error=bool(call_result.is_error),
            # The backend has answered, so a tool that may write has written (#425).
            acted=results._may_have_acted(backend, tool_name),
        )

        # Before the transform, two federated early exits (#592): a peer's pin
        # call gate refusal mapped to our own "held upstream" words (E1c), and a
        # peer's trusted signed verdict served without re-judging (D2a). Both
        # fail-closed — anything else falls through to the full local pipeline.
        early = _federated_early(
            profile, backend, backend_name, arrived, call_result,
            mode=mode, policy=policy, stripped=stripped, ok=ok,
        )
        if early is not None:
            return early

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
                failed = results._preprocess_refusal(reduced.failed, mode)
                return Assembled(
                    results._executed(failed, call_result.is_error) if arrived.acted else failed,
                    Outcome.BLOCKED_DEFENSE,
                    reduced.failed,
                    stripped=stripped,
                )
            content_blocks = reduced.content_blocks
            provenance = reduced.provenance
            # Too large to judge in one call (#340): cut once, from the
            # transformed text, so what is cut is what would have been delivered.
            paged = await parts._hold_paged(
                profile,
                backend,
                backend_name,
                tool_name,
                content_blocks,
                arrived.structured,
                mode=mode,
                prompt=prompt,
                provenance=provenance,
                l3_context=results._l3_context(backend, reduced),
                hidden=reduced.hidden,
                is_error=arrived.is_error,
                acted=arrived.acted,
            )
            if paged is not None:
                first = await parts._deliver_part(
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
            judged = await judge_response(
                transformed,
                profile=profile,
                backend_name=backend_name,
                tool_name=tool_name,
                structured_content=arrived.structured,
                mode=mode,
                prompt=prompt,
                policy=policy,
                l3_context=results._l3_context(backend, reduced)
                if reduced is not None
                else backend.l3_briefing,
                hidden=reduced.hidden if reduced is not None else None,
            )
            gateway_warning = judged.decision.warning
            if judged.decision.blocked:
                # The content never reaches the agent; the warning does. Audited
                # as a defense block so a misfiring threshold shows in the
                # outcome column, not only in an agent's confusion.
                risk = judged.decision.warning.get("risk_level") if judged.decision.warning else "?"
                blocked = results._blocked_result(judged.decision)
                return Assembled(
                    results._executed(blocked, call_result.is_error) if arrived.acted else blocked,
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
                return Assembled(result, ok, warning=gateway_warning, stripped=stripped)
            results._attach_warning(result, judged.decision.warning)
            # The upstream vouches for this delivered response (#592, D1): a
            # signed verdict beside it a downstream can trust instead of
            # re-judging. Only here — the layers ran, nothing was blocked or
            # redacted — and only for a signing federation ingress.
            result = _federated_vsa(
                profile,
                result,
                blocks=transformed.content_blocks,
                structured=arrived.structured,
                is_error=call_result.is_error,
                warning=gateway_warning,
                mode=effective_mode(profile, mode),
            )

        result = _federated_continuation(
            profile,
            backend,
            backend_name,
            tool_name,
            call_result,
            result,
            mode=mode,
            prompt=prompt,
            provenance=provenance,
            reduced=reduced,
            arrived=arrived,
        )
        return Assembled(result, ok, warning=gateway_warning, stripped=stripped)

    def wrap(self, ctx: McpCrossing, result: dict[str, Any]) -> dict[str, Any]:
        """The JSON-RPC success envelope."""
        return _ok(ctx.req_id, result)


class McpClientCarrier(Carrier):
    """The MCP client side: dispatch the call to its backend or internal tool."""

    name = "mcp_client"

    async def carry(self, ctx: McpCrossing, parsed: McpParsed) -> McpCarried | Early:
        """Forward the call — ``_dispatch`` — with the backend-error refusal.

        ``t0`` is taken the instant before the dispatch, exactly as
        ``router._tools_call`` does, and travels on the ``McpCarried`` so the
        response edge's audit measures one wall clock.
        """
        profile, req_id = ctx.profile, ctx.req_id
        t0 = time.monotonic()
        try:
            call_result = await _dispatch(
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
            audit._audit(
                profile.name,
                parsed.backend_name,
                parsed.tool_name,
                outcome,
                duration_ms,
                str(exc),
                destination=parsed.dest,
            )
            return Early(
                results._failed_call(
                    req_id,
                    exc,
                    results._may_have_acted(parsed.backend, parsed.tool_name),
                    parsed.mode,
                    parsed.policy,
                )
            )
        return McpCarried(call_result=call_result, t0=t0)


async def _dispatch(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    forwarded: dict[str, Any],
    *,
    policy: ModePolicy,
    mode: Mode,
    prompt: str | None,
    preprocess: PreProcessPolicy | None = None,
    requested: Any = None,
) -> Any:
    """Forward the call: in-process for internal://, streamable-http otherwise."""
    if backend.is_decoy:
        # ``request_edge._decoy_call`` answers every one. Reaching here is a bug, and a
        # bug must not become a request to a URL that is not one.
        raise BackendCallError(f"backend {backend_name!r} has nothing to call")
    if not backend.is_internal:
        return await call_backend_tool(backend_name, backend, tool_name, forwarded)

    # The internal tools judge their own ingress, so they get the RESOLVED
    # mode; the bound policy is what their refusals offer as alternatives.
    # The transform request goes through as asked: its default depends on
    # what arrives, so the tool resolves it under the bound policy.
    # A profile that can read part 2 may be handed a part 1 (#446).
    reader = _part_reader(profile)
    parts = (
        PartsOffer(
            backend_name,
            tool_name,
            served_name(profile, backend_name, tool_name) or tool_name,
            reader,
        )
        if reader is not None
        else None
    )
    with profile_context(profile, policy, preprocess, parts):
        return await call_internal_tool(
            tool_name,
            forwarded,
            modal_arguments={
                MODE_PARAM: {"redact": prompt} if mode.value == "redact" and prompt else mode.value,
                PREPROCESS_PARAM: requested,
            },
        )


async def _finish_delivery(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    call_result: Any,
    t0: float,
    assembled: Assembled,
    *,
    normalized: dict[str, str] | None = None,
    destination: Destination | None = None,
) -> dict[str, Any]:
    """Finish an assembled result: the session mark, the warning, the one row.

    The half of delivery below the orchestrator's response edge
    (``transports.mcp.McpServerFace._assemble``): it hands the ``Assembled`` here
    and the audit row is written exactly once, by this one function.
    """
    session_marks._mark_session(assembled, None if not backend.is_internal else call_result)
    if normalized or assembled.stripped:
        # REPLACED, never merged into what the result carries (#265): built
        # from the perimeter's own verdict and the gateway's own notes only.
        warning = with_stripped(assembled.warning, assembled.stripped) or {}
        if normalized:
            warning = {**warning, "normalized": normalized}
        assembled.result[WARNING_KEY] = warning
    if assembled.stripped:
        logger.info(
            "gateway: profile=%s %s/%s stripped %d reserved key(s) from the response",
            profile.name,
            backend_name,
            loggable_tool(backend.url, tool_name),
            assembled.stripped,
        )
    # An internal tool minifies inside itself, so what arrived here is
    # already the delivered form: its arrived size stays NULL, not equal.
    arrived = (
        None
        if backend.is_internal
        else await asyncio.to_thread(
            wire_bytes,
            {"content": call_result.content, "structuredContent": call_result.structured_content},
        )
    )
    delivered, digest = await asyncio.to_thread(wire_digest, assembled.result)
    audit._audit(
        profile.name,
        backend_name,
        tool_name,
        assembled.outcome,
        int((time.monotonic() - t0) * 1000),
        assembled.error,
        bytes_arrived=arrived,
        bytes_delivered=delivered,
        normalized=normalized or None,
        destination=destination,
        content_digest=digest,
    )
    return assembled.result


# The revision answered when a client asks for one we do not recognize. Kept
# at the SDK's own handshake ceiling rather than a literal, so trentina tracks
# the protocol registry instead of drifting behind it.
PROTOCOL_VERSION = LATEST_HANDSHAKE_VERSION

# JSON-RPC reserved error codes and the pure wire-shape builders (_ok/_err/
# _refused/_response_guard_refusal) now live in ``transports/jsonrpc.py`` and are
# imported above, so both the router and the MCP transport share one copy.


def _negotiate_protocol_version(requested: Any) -> str:
    """Answer an ``initialize`` with the revision the client asked for.

    Trentina previously replied with one hardcoded revision no matter what was
    asked, which pinned every consumer to the gateway's era and made the
    gateway the ceiling for its own fleet. Every backend measured in issue #107
    already behaves the way this does: honour the client's request when it is a
    revision we know, otherwise counter-offer our ceiling and let the client
    decide whether it can live with that.

    The known set comes from the SDK's protocol registry rather than a local
    literal, so trentina picks up new revisions when it picks up a new SDK.

    Note the gateway's surface is tools-only and hand-rolled (it does not use
    fastmcp for gateway traffic), so agreeing to a revision costs nothing
    beyond the tool methods, which are stable across every revision listed.
    """
    if isinstance(requested, str) and requested in HANDSHAKE_PROTOCOL_VERSIONS:
        return requested
    return PROTOCOL_VERSION


async def route_jsonrpc(profile: Profile, request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one JSON-RPC request against a profile.

    The response is always a JSON-RPC 2.0 body. HTTP status is 200 for any
    well-formed JSON-RPC, including error responses — the caller never
    promotes a JSON-RPC error to an HTTP non-200.

    Args:
        profile: The authenticated profile (auth was checked before dispatch).
        request: Parsed JSON-RPC 2.0 request body.

    Returns:
        JSON-RPC 2.0 response body.

    Raises:
        Exception: only what ``_route_tools_call`` re-raises after auditing
            it as a gateway_error; the caller answers it with a 500.
    """
    method = request.get("method", "")
    req_id = request.get("id")
    # Only an absent (or null) params defaults: `[]` or `0` is a malformed
    # call, and `or {}` would have quietly made it a well-formed one.
    params = request.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict) and method != "tools/call":
        # tools/call answers this itself, so the refusal is audited (#293).
        return _err(req_id, JSONRPC_INVALID_PARAMS, "params must be an object")

    if method == "initialize":
        # The mode explanation is said here once, not on every tool (#198).
        naming = (
            "Where two servers offer a tool of the same name, a server tag prefixes it."
            if profile.short_names
            else f"Tool names are namespaced as <backend>{NAMESPACE_SEP}<tool>."
        )
        instructions = " ".join(
            part
            for part in (
                f"trentina gateway, profile={profile.name}.",
                naming,
                discovery.instructions(profile),
                mode_instructions(profile),
            )
            if part
        ).rstrip()
        return _ok(
            req_id,
            {
                "protocolVersion": _negotiate_protocol_version(params.get("protocolVersion")),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {
                    "name": f"trentina-gateway:{profile.name}",
                    "version": __version__,
                },
                "instructions": instructions,
            },
        )

    if method == "ping":
        return _ok(req_id, {})

    if method == "notifications/initialized":
        return _ok(req_id, {})

    if method == "tools/list":
        return await _route_tools_list(profile, req_id)

    if method == "tools/call":
        # Everything this call judges runs on the caller's own provider and
        # key (RT #1505): unbound, L3 fell through to the global provider.
        with profile_context(profile):
            return await _route_tools_call(profile, req_id, params)

    return _err(req_id, JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}")


async def _route_tools_list(profile: Profile, req_id: Any) -> dict[str, Any]:
    """Aggregate tools/list across the profile's backends, filtered and namespaced.

    Checks the per-profile cache first. On miss, coalesces concurrent callers
    for the same profile onto a single fan-out (single-flight).
    """
    aggregated = aggregate._profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await aggregate.ensure_profile_build(profile)
    result: dict[str, Any] = {"tools": discovery.shape(profile, aggregated, current_session.get())}
    # Tell a federated downstream how many tools this ingress is holding, so it
    # can report "N held upstream" without ever seeing their names (#592, E1c).
    # A hint in ``_meta`` (the SDK-safe channel), scoped to this caller's slice.
    if profile.federation is not None:
        result["_meta"] = {PINS_KEY: {"held": held_total(profile.name)}}
    return _ok(req_id, result)


async def _route_tools_call(profile: Profile, req_id: Any, params: Any) -> dict[str, Any]:
    """The ``tools/call`` edge, with one audit row guaranteed for every call (#293).

    Rejects a leaked-token probe and a non-mapping params, answers a discovery
    meta name, then hands the resolved call to ``_crossing_call`` (the
    orchestrator). Every path inside writes its own row. An exception that
    escapes them all is ours, so it is recorded as gateway_error before it
    propagates to the HTTP edge's 500: a probe that crashes the router is the
    probe the audit most needs to see.
    """
    # Text held for a caller who never came back does not outlive its hold.
    paging.expire()
    token = audit._call_audited.set(False)
    # Random, not the JSON-RPC id: that one is the caller's to choose.
    call = current_call.set(secrets.token_hex(8))
    t0 = time.monotonic()
    try:
        # First, on the request as sent: the params may not be a mapping and
        # the name may resolve to nothing, and it is still the alarm (#357).
        leaked = leaked_tokens(profile, params)
        if leaked:
            return request_edge._leaked(profile, req_id, params, leaked)
        if not isinstance(params, dict):
            audit._audit(profile.name, "", "", Outcome.DENIED_GUARD, 0, "params must be an object")
            # nosemgrep: trentina-return-before-audit -- row written on the preceding line
            return _err(req_id, JSONRPC_INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if isinstance(name, str) and name in discovery.meta_names(profile):
            arguments = params.get("arguments")
            return await _discovery_call(
                profile, req_id, name, {} if arguments is None else arguments
            )
        return await _crossing_call(profile, req_id, params)
    except Exception as exc:
        if not audit._call_audited.get():
            audit._audit(
                profile.name,
                "",
                redact_source(params.get("name") if isinstance(params, dict) else None),
                Outcome.GATEWAY_ERROR,
                int((time.monotonic() - t0) * 1000),
                f"unhandled: {exc_kind(exc)}",
            )
        raise
    except asyncio.CancelledError:
        # A BaseException: the task was cancelled mid-scan (#439), by a hang-up or a
        # shutdown. Re-raised, so the cancellation still propagates.
        if not audit._call_audited.get():
            audit._audit(
                profile.name,
                "",
                redact_source(params.get("name") if isinstance(params, dict) else None),
                Outcome.CANCELLED,
                int((time.monotonic() - t0) * 1000),
            )
        raise
    finally:
        current_call.reset(call)
        audit._call_audited.reset(token)


async def _crossing_call(profile: Profile, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    """Run one resolved ``tools/call`` through the orchestrator (Trentina 3.0).

    The one call path: ``orchestrator.crossing`` drives the MCP ``Face`` /
    ``Carrier`` (``transports.mcp``), which resolves the target, re-checks the
    allowlist, answers a decoy or ``read_part``, resolves the mode and
    preprocess switch, normalizes and guards the arguments, dispatches, and
    judges and shapes the response — writing the one audit row through
    ``transports.mcp._finish_delivery``. Reached from the ``tools/call`` route and from
    ``call_tool``'s re-entry; ``params`` is already a mapping and not a
    discovery meta name by the time it arrives.
    """
    crossed: dict[str, Any] = await crossing(mcp_transport, McpCrossing(profile, req_id, params))
    return _mirror_refusal_meta(profile, crossed)


async def _discovery_call(
    profile: Profile, req_id: Any, name: str, arguments: Any
) -> dict[str, Any]:
    """Answer a discovery tool (#473): ``call_tool`` by routing the tool it
    names, ``find_tools`` and ``load_tools`` from the served aggregate.

    ``call_tool`` writes no row of its own: the call it carries writes the
    one row, under the real (backend, tool), through every rule a direct
    call meets. A discovery tool cannot be called through it.
    """
    if not isinstance(arguments, dict):
        message = "arguments must be an object"
        audit._audit(profile.name, "", name, Outcome.DENIED_GUARD, 0, message)
        return _err(req_id, JSONRPC_INVALID_PARAMS, message)
    if name == discovery.CALL_TOOL:
        inner = arguments.get("name", "")
        if not isinstance(inner, str) or inner in discovery.meta_names(profile):
            return request_edge._unknown_tool(profile, req_id, inner)
        return await _crossing_call(
            profile, req_id, {"name": inner, "arguments": arguments.get("arguments")}
        )
    t0 = time.monotonic()
    aggregated = aggregate._profile_tools_cache.get(profile.name)
    if aggregated is None:
        aggregated = await aggregate.ensure_profile_build(profile)
    session = current_session.get()
    try:
        if name == discovery.FIND_TOOLS:
            result = discovery.find(profile, aggregated, arguments)
        else:
            result, grew = discovery.load(profile, aggregated, session, arguments)
            if not session_registry.holds(profile.name, session):
                # It ended while the aggregate was built, after its own
                # forget_session ran: nothing else would drop this set.
                discovery.forget_session(session)
            elif grew:
                await session_registry.notify_session(profile.name, session)
    except ValueError as exc:
        # The messages are ours and quote nothing the caller sent.
        audit._audit(profile.name, "", name, Outcome.DENIED_GUARD, 0, str(exc))
        return _err(req_id, JSONRPC_INVALID_PARAMS, str(exc))
    audit._audit(
        profile.name,
        "",
        name,
        Outcome.OK,
        int((time.monotonic() - t0) * 1000),
        bytes_delivered=wire_bytes(result),
    )
    return _ok(req_id, result)


#: The one MCP transport, wired into ``router._route_tools_call`` for a profile
#: flagged ``orchestrated``. Stateless, so one instance is shared.
mcp_transport = Transport(face=McpServerFace(), carrier=McpClientCarrier())
