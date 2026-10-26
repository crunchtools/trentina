"""The internal tools' pre-processing: minify unless asked not to, before judging.

The gateway's ``transform_response`` never sees these tools — the router
skips it for internal backends, because they judge at their own ingress — so
the same decision has to happen here, on the producer path. It runs before
``judge_and_deliver`` and everything after judges and delivers its output:
what is scanned is what is delivered.

One failure rule, the same as the proxied path (0.38.0). The operator's
floor (``required``) FAILS CLOSED: a floor that breaks refuses the call,
because delivering something else in its place would be a silent
substitution. Minification FAILS OPEN: a minifier that breaks costs the
agent tokens, not content, so the unminified text is judged and delivered.

What conversion deleted reaches nobody, but a page that hid text from its
reader has shown its intent. So L1's hiding stage counts the ORIGINAL, the
way ``dir`` merges its shadow counts, and L3 is told how many elements went.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..channels import Channel
from ..defense import Provenance
from ..errors import TransformFailedError
from ..l1.hidden import detect_hidden_markup
from ..l1.pipeline import PipelineResult, run_l1
from ..transforms import (
    Applied,
    Cost,
    Failed,
    TransformContext,
    TransformRecord,
    run_transforms,
)
from ..transforms.detect import document_hidden, hiding_briefing, hiding_removed
from ..transforms.policy import current_preprocess_policy

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class Prepared:
    """What a tool judges and delivers, and what pre-processing did to it."""

    content: str  # judged and delivered, byte for byte
    extras: dict[str, Any] = field(default_factory=dict)  # the result's `preprocess` list
    pipeline: PipelineResult | None = None  # L1 with the original's hiding counts
    briefing: str | None = None  # L3 context: what conversion removed
    provenance: Provenance = Provenance.EXTERNAL  # MODEL_OUTPUT after a METERED rewrite


def _l1_with_original_hiding(converted: str, original: str, office: int) -> PipelineResult:
    """L1 over what is delivered, with the hiding counts of what arrived.

    ``office`` is the hidden lines stage 1 dropped from office files (#368):
    they are counted there, since the original holds them as base64.
    """
    pipeline = run_l1(converted)
    _, pipeline.stats.hidden = detect_hidden_markup(original)
    pipeline.stats.hidden.elements += office
    return pipeline


async def _floor(
    processors: Sequence[Any], content: str, ctx: TransformContext
) -> tuple[list[TransformRecord], str]:
    """The required processors, each fed the previous applied output.

    Raises instead of passing through: a floor transform that raises or returns
    ``Failed`` refuses the call, because delivering the original in place of a
    pinned converter would be a silent substitution. Returns the records and
    the threaded content."""
    records: list[TransformRecord] = []
    current = content
    for processor in processors:
        try:
            result = await processor.run(current, ctx)
        except Exception as exc:
            raise TransformFailedError(processor.name, type(exc).__name__) from exc
        if isinstance(result, Failed):
            raise TransformFailedError(processor.name, result.reason)
        records.append(TransformRecord.of(processor.name, processor.cost, current, result))
        if isinstance(result, Applied):
            current = result.content
    return records, current


async def prepare(
    content: str,
    *,
    requested: Any,
    tool: str,
    source: str,
    content_type: str | None = None,
) -> Prepared:
    """Resolve the call's switch under the bound policy and run what it selects.

    Args:
        content: the payload as it arrived.
        requested: the agent's ``trentina_preprocess``, or None.
        tool: the internal tool's name, for its default when unbound.
        source: the URL, path or hash, for the processors' context.
        content_type: what the payload's server declared; ``detect`` takes
            a declared HTML page as HTML without sniffing.

    Returns:
        ``Prepared``: the content every layer judges and the agent receives,
        plus what the tool attaches to the result, L1's run and L3's briefing
        when markup was converted, and the provenance.

    Raises:
        TransformNotPermittedError: the switch is not a bool, None, or the
            deprecated list form.
        TransformFailedError: a REQUIRED processor raised or returned
            ``Failed`` — it tried and could not finish its job.
    """
    from ..gateway.drivers import build_transforms
    from ..gateway.profile import ProcessorChainConfig

    policy = current_preprocess_policy(tool)
    names = policy.resolve(requested)
    processors = build_transforms(
        ProcessorChainConfig.model_validate({"processors": list(names)}), channel=Channel.TOOL
    )
    floor = len(policy.required)
    ctx = TransformContext(
        source=source, target_bytes=policy.target_bytes, content_type=content_type
    )
    results, current = await _floor(processors[:floor], content, ctx)
    if processors[floor:]:
        outcome = await run_transforms(
            current, processors=processors[floor:], strategy="chain", ctx=ctx
        )
        results.extend(outcome.results)
        current = outcome.content
    applied = [r for r in results if r.applied]
    if not applied:
        return Prepared(content)

    final = current
    prepared = Prepared(
        final,
        extras={
            "preprocess": [
                {
                    "name": r.name,
                    "bytes_in": r.bytes_in,
                    "bytes_out": r.bytes_out,
                    **{k: v for k, v in r.details.items() if v != 0},
                }
                for r in applied
            ]
        },
    )
    if any(r.cost is Cost.METERED for r in applied):
        # A model rewrote the payload: the perimeter owes it unconditional L3.
        prepared.provenance = Provenance.MODEL_OUTPUT

    removed = hiding_removed(applied)
    if removed is not None:
        prepared.pipeline = await asyncio.to_thread(
            _l1_with_original_hiding, final, content, document_hidden(applied)
        )
        prepared.briefing = hiding_briefing(removed)
    return prepared
