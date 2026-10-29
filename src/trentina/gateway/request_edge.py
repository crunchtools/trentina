"""The request edge of a crossing: what a ``tools/call`` meets before its backend.

Resolving the served name to its (backend, tool), normalizing and refusing the
forwarded arguments, and the answers no backend gives — a honeytoken probe
(#357), a decoy tool's canned reply (#357), a name this profile never held
(#269), and ``read_part`` (#340). Both ``gateway/router.py`` and
``transports/mcp.py`` run these on the request edge, so they live here rather
than inside the router the transport is replacing. Part of PR3a (Trentina 3.0
Phase 7): make the transport self-contained so the hand-rolled router can be
retired.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..errors import ModeNotPermittedError, TransformNotPermittedError
from ..logsafe import redact_source
from ..outcomes import Outcome
from ..transports.jsonrpc import JSONRPC_INVALID_PARAMS, _err, _ok, _refused
from . import audit, discovery
from .args import Normalized, normalize_arguments
from .backend import cached_tool_read_only, cached_tool_schema, loggable_tool
from .decoy import canned_result, keep_arguments, leaked_tokens, record_trip
from .destination import Destination, destination_of
from .filter import filter_tools
from .gatekeeper import judge_call
from .guards import check_request_guards
from .modes_policy import MODE_PARAM, PROMPT_PARAM, resolve_call, resolve_preprocess
from .names import resolve_name
from .parts import _read_part
from .surface import wire_digest

if TYPE_CHECKING:
    from ..modes import Mode
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)


def _resolve_target(profile: Profile, served_name: object) -> tuple[str, str, Backend] | None:
    """The (backend name, tool, backend) a served name routes to in this profile."""
    if not isinstance(served_name, str):
        return None
    resolved = resolve_name(profile, served_name)
    if resolved is None or not resolved[1]:
        return None
    backend_name, tool_name = resolved
    # None for an issued short name whose backend has since left the profile.
    backend = profile.backends.get(backend_name)
    return (backend_name, tool_name, backend) if backend is not None else None


def _normalize_arguments(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    forwarded: dict[str, Any],
) -> Normalized:
    """Normalize arguments against the backend's schema before a remote call (``args.py``).

    Internal tools are ours and already read an empty value as unset.
    """
    if backend.is_internal:
        return Normalized(forwarded)
    normalized = normalize_arguments(
        forwarded,
        cached_tool_schema(backend.url, tool_name),
        read_only=cached_tool_read_only(backend.url, tool_name),
    )
    if normalized.dropped:
        # How many and why, never which: a name is the caller's (#262).
        logger.info(
            "gateway: profile=%s %s/%s normalized %d arg(s): %s",
            profile.name,
            backend_name,
            loggable_tool(backend.url, tool_name),
            len(normalized.dropped),
            ",".join(sorted(set(normalized.dropped.values()))),
        )
    return normalized


async def _refuse_call(
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    forwarded: dict[str, Any],
    mode: Mode,
    prompt: str | None,
    normalized: Normalized,
    dest: Destination | None,
) -> tuple[Outcome, str, str] | None:
    """Every refusal of a call's arguments: outcome, what the agent is told, what is audited.

    The guards and the schema first; semantic request guards last (#456), so the
    cheap and certain rules have spoken before a model is asked anything.
    """
    refused = _refuse_arguments(
        backend,
        tool_name,
        {**forwarded, MODE_PARAM: mode.value, PROMPT_PARAM: prompt},
        normalized,
    )
    if refused is not None:
        outcome, message = refused
        return outcome, message, message
    gated = await judge_call(profile, backend, backend_name, tool_name, forwarded, dest)
    if gated is not None:
        return Outcome.DENIED_GATEKEEPER, gated.message, gated.audit
    return None


def _refuse_arguments(
    backend: Backend, tool_name: str, judged: dict[str, Any], normalized: Normalized
) -> tuple[Outcome, str] | None:
    """The request guards' refusal, else the schema's, else None.

    Guards first, so a probe a guard refuses still audits as one. A required
    argument that fails its schema would be refused by the backend too;
    answering here spares the round trip, and the breaker never sees a call
    the backend never received. An optional one is refused because the call
    without it is not the call that was asked for (#335).
    """
    guard_err = check_request_guards(tool_name, judged, backend)
    if guard_err:
        return Outcome.DENIED_GUARD, guard_err
    if normalized.invalid_required:
        return Outcome.TOOL_ERROR, "Invalid required arguments: " + "; ".join(
            f"{name} {reason}" for name, reason in normalized.invalid_required.items()
        )
    if normalized.invalid_optional:
        return Outcome.TOOL_ERROR, (
            "Invalid optional arguments: "
            + "; ".join(f"{name} {reason}" for name, reason in normalized.invalid_optional.items())
            + ". Correct or omit them: this tool is not marked read-only, so the call"
            " was not forwarded without them."
        )
    return None


def _tripped(
    profile: str,
    backend_name: str,
    tool_name: str,
    req_id: Any,
    what: str,
    result: dict[str, Any] | None,
    dest: Destination | None,
) -> dict[str, Any]:
    """Record a decoy trip (#357) and answer it with ``result``, or with a
    refusal that says nothing of why when there is none.

    ``what`` goes in the audit row: the kind of trip and the ids of any
    planted credentials, never a value.
    """
    audit._audit(
        profile,
        backend_name,
        tool_name,
        Outcome.DECOY_TRIPPED,
        0,
        what,
        destination=dest,
        content_digest=wire_digest(result)[1] if result is not None else None,
    )
    record_trip(profile, backend_name, tool_name, what)
    if result is None:
        return _err(req_id, JSONRPC_INVALID_PARAMS, "Invalid arguments")
    return _ok(req_id, result)


def _decoy_call(
    profile: Profile,
    req_id: Any,
    served_name: object,
    target: tuple[str, str, Backend],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Answer a call to a decoy backend, as a real backend's tool would be
    answered wherever a caller could tell the difference.

    A decoy backend serves the tools it declares and no other, so a name it
    does not declare is as unknown as one on no backend at all. A declared
    one refuses a mode or a transform request that a real tool would
    refuse, in the same words, and is a trip either way: asking for a mode
    that does not exist must not be a way to map the tripwires.
    """
    backend_name, tool_name, backend = target
    decoy = backend.decoys.get(tool_name)
    if decoy is None:
        return _unknown_tool(profile, req_id, served_name)
    try:
        resolve_call(profile, backend, tool_name, arguments)
        resolve_preprocess(profile, backend, tool_name, arguments)
    except (ModeNotPermittedError, TransformNotPermittedError) as exc:
        audit._audit(profile.name, backend_name, tool_name, Outcome.DECOY_TRIPPED, 0, str(exc))
        record_trip(profile.name, backend_name, tool_name, "decoy tool")
        # Word for word what a real tool's refusal of the same mode says.
        return _refused(
            req_id, {"reason": Outcome.DENIED_GUARD.value, "detail": str(exc), "alternatives": []}
        )
    answer = canned_result(profile, decoy)
    return _tripped(profile.name, backend_name, tool_name, req_id, "decoy tool", answer, None)


async def _answered_here(
    profile: Profile,
    req_id: Any,
    served_name: object,
    target: tuple[str, str, Backend],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """The two calls no backend answers: a decoy's, and ``read_part``'s (#340).

    A part is a proxied response's, judged and audited as that response is,
    so it is served from here and never by the internal server.
    """
    backend_name, tool_name, backend = target
    if not backend.is_decoy:
        return await _read_part(profile, req_id, backend_name, arguments)
    response = _decoy_call(profile, req_id, served_name, target, arguments)
    # After the audit row, as the detection is: a write that fails here
    # loses what was asked for and not the trip.
    keep_arguments(profile, backend_name, tool_name, arguments)
    return response


def _leaked(profile: Profile, req_id: Any, params: Any, leaked: list[str]) -> dict[str, Any]:
    """Answer a request that carries a planted credential, whatever else is
    wrong with it.

    A tool the profile does not hold, a name that resolves to nothing, and
    params or arguments that are not a mapping are each refused anyway; with a
    honeytoken in them they are the alarm, not a denial. Sent to a decoy tool
    the caller does hold, it gets the decoy's canned answer, so that what the
    caller does next is recorded too.
    """
    what = f"honeytoken {', '.join(leaked)}"
    served_name, arguments = _reached_for(profile, params)
    target = _resolve_target(profile, served_name)
    if target is None:
        return _tripped(profile.name, "", redact_source(served_name), req_id, what, None, None)
    backend_name, tool_name, backend = target
    dest: Destination | None = None
    answer: dict[str, Any] | None = None
    if isinstance(arguments, dict):
        dest = destination_of(backend, tool_name, arguments)
        if dest is not None and leaked_tokens(profile, dest.value):
            dest = None  # the audit names a planted credential by id, here as everywhere
        decoy = backend.decoys.get(tool_name)
        if decoy is not None and filter_tools([{"name": tool_name}], backend):
            answer = canned_result(profile, decoy)
    response = _tripped(
        profile.name,
        backend_name,
        tool_name,
        req_id,
        f"decoy tool, {what}" if answer is not None else what,
        answer,
        dest,
    )
    if answer is not None:
        keep_arguments(profile, backend_name, tool_name, arguments)
    return response


def _reached_for(profile: Profile, params: Any) -> tuple[Any, Any]:
    """The name and arguments a request reached for: through ``call_tool``,
    the tool it names (#473)."""
    sent = params if isinstance(params, dict) else {}
    name, arguments = sent.get("name", ""), sent.get("arguments")
    if name == discovery.CALL_TOOL and name in discovery.meta_names(profile):
        inner = arguments if isinstance(arguments, dict) else {}
        return inner.get("name", ""), inner.get("arguments")
    return name, arguments


def _unknown_tool(profile: Profile, req_id: Any, served_name: object) -> dict[str, Any]:
    """Refuse a name this profile was never served, and audit it (#269, #293).

    One answer for every way a name fails to resolve — never issued, a long
    form naming a backend outside the profile, an issued name whose backend
    has since left it — so the refusal says nothing about which. The name is
    the caller's, so the row carries its fingerprint, not its text.
    """
    audit._audit(
        profile.name,
        "",
        redact_source(served_name),
        Outcome.DENIED_ALLOWLIST,
        0,
        "unknown tool",
    )
    return _err(req_id, JSONRPC_INVALID_PARAMS, f"Unknown tool {served_name!r}")
