"""Result envelopes and refusal wording a crossing delivers.

The pieces of a ``tools/call`` answer that are pure functions of the arrived
result and the profile's policy: the refusal wording, the acted-vs-refused
rewording (#425), the block and preprocess refusals, L3's briefing line, and
the arrival stripping that keeps a remote backend from writing the gateway's
reserved keys (#265). Both ``gateway/router.py`` and ``transports/mcp.py``
build an answer out of these, so they live here rather than inside the router
the transport is replacing. Part of PR3a (Trentina 3.0 Phase 7): make the
transport self-contained so the hand-rolled router can be retired.
"""

from __future__ import annotations

import functools
import json
from typing import TYPE_CHECKING, Any

from ..reserved import REFUSAL_KEY, strip_content_blocks, strip_reserved
from .backend import cached_tool_read_only
from .modes_policy import MODE_PARAM

if TYPE_CHECKING:
    from ..modes import Mode
    from .profile import Backend
    from .transform import TransformOutcome

_CANONICAL = functools.partial(json.dumps, sort_keys=True, ensure_ascii=False)


def _spelled_modes(alternatives: list[str]) -> str:
    """The modes a refusal offers, as the arguments an agent would send."""
    return " or ".join(
        f'{MODE_PARAM}={{"redact": "<what you need>"}}' if m == "redact" else f"{MODE_PARAM}={m}"
        for m in alternatives
    )


def _refusal_text(refusal: dict[str, Any]) -> str:
    """One line an agent reads even when a client strips the structured field."""
    spelled = _spelled_modes(refusal.get("alternatives") or [])
    tail = (
        f"Your policy allows retrying with {spelled}."
        if spelled
        else "No other mode is available under your policy."
    )
    advisory = refusal.get("security_advisory")
    if isinstance(advisory, dict) and advisory.get("do_not"):
        # A fetch advisory's instruction is the point of it (#293): a client
        # that drops error.data must still read it.
        tail = f"{tail} {advisory['do_not']}"
    return f"[TRENTINA] Refused ({refusal.get('reason', 'defense')}). {tail}"


def _may_have_acted(backend: Backend, tool_name: str) -> bool:
    """Whether a call the backend answered may have changed something (#425).

    The backend's own ``readOnlyHint`` is the only thing that says it did not,
    as in ``args.py``: an unannotated tool may write. The internal tools read.
    """
    return not backend.is_internal and not cached_tool_read_only(backend.url, tool_name)


def _executed(refused: dict[str, Any], backend_error: bool | None) -> dict[str, Any]:
    """*refused*, reworded for a call that may already have acted (#425).

    A refusal reads as a failed call, and an agent repeats a failed call: a
    blocked confirmation of a sent mail sent the mail twice. What is withheld
    here is the response, never the action, so the result says the call ran
    and is an error only when the backend said so. *backend_error* is its
    ``isError``, or None when the response was never read that far.

    The refusal keeps its alternatives for a tool that only reads and never
    said so; the text names the condition, since another mode is another call.
    """
    refusal = {**(refused.get(REFUSAL_KEY) or {"reason": "defense"}), "executed": True}
    ran = {
        False: "The call was executed and the backend reported no error.",
        True: "The call reached the backend, which reported an error;"
        " whether it took effect is not known.",
        None: "The call reached the backend and may have taken effect.",
    }[backend_error]
    spelled = _spelled_modes(refusal.get("alternatives") or [])
    retry = f" If it only reads, your policy allows retrying with {spelled}." if spelled else ""
    text = (
        f"[TRENTINA] {ran} Its response was withheld ({refusal['reason']}) and nothing"
        " from it was delivered. This tool is not marked read-only: do not repeat the"
        f" call to see the response, because a call that acts would act again.{retry}"
    )
    return {
        **refused,
        "content": [{"type": "text", "text": text}],
        "isError": backend_error is not False,
        REFUSAL_KEY: refusal,
    }


def _blocked_result(decision: Any) -> dict[str, Any]:
    """The refusal delivered in place of a response the perimeter blocked."""
    refused: dict[str, Any] = {
        "content": [
            {
                "type": "text",
                "text": (
                    _refusal_text(decision.refusal)
                    if decision.refusal
                    else "[TRENTINA] This tool response was blocked by the defense pipeline."
                )
                + " Details are in _trentina_warning; the original content was not delivered.",
            }
        ],
        "isError": False,  # a refusal is an answer, not an error: see _refused
        "_trentina_warning": decision.warning,
    }
    if decision.refusal:
        refused["_trentina_refusal"] = decision.refusal
    return refused


def _preprocess_refusal(failed: str, mode: Mode | None) -> dict[str, Any]:
    """A required processor did not run: nothing is delivered in its place.

    Same shape as a defense block. No mode would help, so no alternatives.
    """
    return {
        "content": [
            {
                "type": "text",
                "text": f"[TRENTINA] Refused: {failed}. The original content was not delivered.",
            }
        ],
        "isError": False,  # a refusal is an answer, not an error: see _refused
        "_trentina_refusal": {
            "reason": "preprocess_failed",
            "mode": mode.value if mode else None,
            "alternatives": [],
        },
    }


def _l3_context(backend: Backend, reduced: TransformOutcome) -> str | None:
    """The operator's word on what this backend returns (#204), then invariant 3.

    The transform sidecar travels to L3's briefing too. "This is the 3% that
    survived reduction" is context a judge should have, and so is "the
    conversion removed elements hidden from a human reader" (#229).
    """
    notes = [backend.l3_briefing, reduced.briefing]
    sidecar = reduced.sidecar
    if sidecar:
        notes.append(
            f"This artifact was transformed by trentina transforms "
            f"({sidecar['bytes_in']} -> {sidecar['bytes_out']} "
            f"bytes); where it shrank, it is a sample of a larger payload."
        )
    return "\n".join(n for n in notes if n) or None


def _strip_backend_result(
    content_blocks: list[Any] | None, structured: dict[str, Any] | None
) -> tuple[list[Any], dict[str, Any] | None, int]:
    """A remote result without the gateway's reserved keys (``reserved.py``, #265).

    Content blocks are copied; ``structuredContent`` is stripped in place,
    since the serializer built it for this call alone.
    """
    blocks, count = strip_content_blocks(content_blocks)
    if structured is not None:
        count += strip_reserved(structured)
    return blocks, structured, count


def _drop_duplicate_structured(structured: Any, content_blocks: list[Any] | None) -> Any:
    """``structuredContent``, or None when it is the one text block again, as data.

    FastMCP sends a tool's return value twice, as text and as structured
    content, and the agent reads both: every result costs double (0.38.0).
    The copy is dropped only when it says nothing the text does not, and
    before the transform and the scan, so the perimeter judges what is
    delivered. Response guards already ran on the result as it arrived.

    Compared as canonical JSON, not with ``==``: Python's ``True == 1`` would
    let a structured ``true`` stand in for a textual ``1``.
    """
    blocks = content_blocks or []
    text = blocks[0].get("text") if len(blocks) == 1 and isinstance(blocks[0], dict) else None
    if structured is None or not isinstance(text, str) or blocks[0].get("type") != "text":
        return structured
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        # Not JSON, so the only copy it can be is the string itself; a str
        # never compares equal to a number or a bool.
        return None if structured == {"result": text} else structured
    copies = {_CANONICAL(c) for c in ({"result": text}, parsed, {"result": parsed})}
    return None if _CANONICAL(structured) in copies else structured


def _arrived(backend: Backend, call_result: Any) -> tuple[list[Any] | None, Any, int]:
    """Content, structured content and the reserved-key count, ready for the perimeter.

    Stripped before the scan and before the gateway adds anything (#265): a
    remote backend does not get to write the gateway's markers. An internal
    tool's markers ARE the gateway's, so its result is left alone.
    """
    blocks: list[Any] | None = call_result.content
    structured: Any = call_result.structured_content
    stripped = 0
    if not backend.is_internal:
        blocks, structured, stripped = _strip_backend_result(blocks, structured)
    return blocks, _drop_duplicate_structured(structured, blocks), stripped
