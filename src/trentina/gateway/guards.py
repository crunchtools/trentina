"""Guards — deterministic allow/deny checks on what crosses the gateway.

Two symmetric applications of one evaluator:

- **Literal request guards** inspect the *arguments* of a ``tools/call``, after
  the tool-name allowlist and before the backend is contacted.
- **Literal response guards** inspect the backend's *result*, after the call
  returns and before anything is reduced, scanned or relayed to the agent.

Both express the same constraint — a value must match at least one ``allow``
pattern and must not match any ``deny`` pattern, the same semantics as
tools_allow/tools_deny — and both fail closed on the whole call rather than
editing what passes. A missing value is not checked, on either side.

Response guards exist because request-side matching cannot see what a semantic
tool returns. An agent asking a memory backend for "my employer's roadmap"
sends no matchable token; the restricted material arrives in the response. The
guard is a literal content filter, so a paraphrase defeats it — it is egress
policy for known terms, not a classifier.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .profile import Backend, ParameterConstraint

CONTENT_FIELD = "content"
"""Reserved response-guard field naming the result's concatenated text.

A tool result has no named parameters, so response guards address either a key
of ``structuredContent`` or this one reserved name, which matches every text
block joined together. It is always present — a result with no text is the
empty string, so ``deny: ["*"]`` blocks that too.
"""


def evaluate_constraint(value: str, constraint: ParameterConstraint) -> str | None:
    """Judge one string against one allow/deny constraint.

    Returns ``None`` when the value passes, or a terse reason phrase that the
    caller prefixes with what it was checking. The phrase never includes the
    value: guard configuration is not something a rejected caller gets to read
    back.
    """
    if not any(fnmatchcase(value, pat) for pat in constraint.allow):
        return "value not in allow list"
    if constraint.deny and any(fnmatchcase(value, pat) for pat in constraint.deny):
        return "value matches deny pattern"
    return None


def check_request_guards(
    tool_name: str,
    arguments: dict[str, Any],
    backend: Backend,
) -> str | None:
    """Validate tool arguments against the backend's request guards.

    Args:
        tool_name: The un-namespaced tool name (e.g. ``send_gmail_message``).
        arguments: The arguments dict from the JSON-RPC ``tools/call`` params.
        backend: Backend config carrying ``literal_request_guards``.

    Returns:
        ``None`` if all checks pass, or a terse error message on the first
        violation. Error messages never include the rejected value.
    """
    tool_guards = backend.literal_request_guards.get(tool_name)
    if not tool_guards:
        return None

    for param_name, constraint in tool_guards.items():
        value = arguments.get(param_name)
        if value is None:
            continue

        reason = evaluate_constraint(str(value), constraint)
        if reason:
            return f"Parameter {param_name!r} {reason}"

    return None


def check_response_guards(
    tool_name: str,
    content_blocks: list[Any] | None,
    structured_content: Any,
    backend: Backend,
) -> str | None:
    """Validate a tool result against the backend's response guards.

    Args:
        tool_name: The un-namespaced tool name.
        content_blocks: The result's content blocks, as returned by the backend.
        structured_content: The result's ``structuredContent``, if any.
        backend: Backend config carrying ``literal_response_guards``.

    Returns:
        ``None`` if all checks pass, or a terse error message on the first
        violation. Error messages name the field, never the matched content —
        an agent that could read back what tripped the guard could binary-search
        the material the guard exists to withhold.
    """
    tool_guards = backend.literal_response_guards.get(tool_name)
    if not tool_guards:
        return None

    joined: str | None = None

    for field, constraint in tool_guards.items():
        if field == CONTENT_FIELD:
            if joined is None:
                joined = _response_text(content_blocks)
            value: Any = joined
        elif isinstance(structured_content, dict):
            value = structured_content.get(field)
        else:
            value = None

        if value is None:
            continue

        reason = evaluate_constraint(str(value), constraint)
        if reason:
            return f"Response field {field!r} {reason}"

    return None


def _response_text(content_blocks: list[Any] | None) -> str:
    """Every text string in a result's content blocks, newline-joined.

    Mirrors the defense pipeline's own reading of a result (see
    ``collect._collect_block``): ``text`` blocks and the text form of
    an embedded ``resource``. Image and blob blocks carry no string to match,
    so a guard cannot speak about them — ``deny: ["*"]`` on a result that is
    purely binary still blocks, because the joined text is the empty string
    and ``*`` matches it.
    """
    texts: list[str] = []
    for block in content_blocks or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                texts.append(text)
        elif block.get("type") == "resource":
            resource = block.get("resource")
            if isinstance(resource, dict) and isinstance(resource.get("text"), str):
                texts.append(resource["text"])
    return "\n".join(texts)
