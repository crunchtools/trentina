"""The gate: dispose plus the redact extraction it may trigger, in isolation.

``core.dispose`` is tested exhaustively in ``test_dispose``; this isolates what
``core.gate`` adds — running turns 2 and 3 for a redact decision and carrying
their result (or the one redact-refusal) — including that a non-redact decision
never reaches the L3 provider.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from trentina.core import Decision, gate
from trentina.core.dispose import _POSTURE_SEAL, DEFAULT_REDACT_PROMPT, Posture
from trentina.defense import DefenseVerdict, Layer
from trentina.l1.pipeline import PipelineResult, PipelineStats
from trentina.modes import Mode, ModePolicy
from trentina.quarantine.agent import CleanResult
from trentina.quarantine.classifier import ClassifierResult

pytestmark = pytest.mark.asyncio

POLICY = ModePolicy((Mode.BLOCK, Mode.FLAG, Mode.REDACT), Mode.BLOCK)
_GATE = "trentina.core.gate"


def _verdict(
    *, text: str = "the window is Tuesday", flagged_by: Layer | None = None, judged: bool = True
) -> DefenseVerdict:
    pipeline = PipelineResult(
        content=text, stats=PipelineStats(), input_size=len(text), output_size=len(text)
    )
    return DefenseVerdict(
        content=text,
        read=text,
        pipeline=pipeline,
        classification=(
            ClassifierResult(label="BENIGN", score=0.01, latency_ms=1.0) if judged else None
        ),
        l3_assessment={"injection_detected": flagged_by is Layer.L3} if judged else None,
        risk_level="low",
        flagged_by=flagged_by,
    )


def _posture(mode: Mode, *, allowlisted: bool = False, prompt: str | None = None) -> Posture:
    return Posture(
        mode=mode, policy=POLICY, allowlisted=allowlisted, prompt=prompt, _seal=_POSTURE_SEAL
    )


class TestNonRedactNeverExtracts:
    async def test_flag_delivers_without_calling_l3(self) -> None:
        extract = AsyncMock()
        with patch(f"{_GATE}.quarantine_redact", extract):
            gated = await gate(_verdict(flagged_by=Layer.L2), _posture(Mode.FLAG))
        assert gated.disposition.decision is Decision.DELIVER
        assert gated.extraction is None and gated.extraction_refusal is None
        extract.assert_not_called()

    async def test_block_refusal_does_not_extract(self) -> None:
        extract = AsyncMock()
        with patch(f"{_GATE}.quarantine_redact", extract):
            gated = await gate(_verdict(flagged_by=Layer.L2), _posture(Mode.BLOCK))
        assert gated.disposition.decision is Decision.REFUSE
        assert gated.extraction is None
        extract.assert_not_called()


class TestRedactExtracts:
    async def test_successful_extraction_is_carried(self) -> None:
        result = CleanResult(content={"extracted_text": "Tuesday"}, usage={"tokens": 3})
        with patch(f"{_GATE}.quarantine_redact", AsyncMock(return_value=result)) as extract:
            gated = await gate(_verdict(), _posture(Mode.REDACT, prompt="when is the window"))
        assert gated.disposition.decision is Decision.REDACT
        assert gated.extraction is result
        assert gated.extraction_refusal is None
        # The judged text and the call's own prompt reach turn 2.
        assert extract.call_args.args[0] == "the window is Tuesday"
        assert extract.call_args.args[1] == "when is the window"

    async def test_default_prompt_when_the_call_carries_none(self) -> None:
        result = CleanResult(content={"extracted_text": "x"})
        with patch(f"{_GATE}.quarantine_redact", AsyncMock(return_value=result)) as extract:
            await gate(_verdict(), _posture(Mode.REDACT))
        assert extract.call_args.args[1] == DEFAULT_REDACT_PROMPT

    async def test_downgraded_block_extracts(self) -> None:
        # An allowlisted block with a flag but no gap downgrades to redact, so the
        # gate must run the extraction even though the mode is not redact.
        result = CleanResult(content={"extracted_text": "y"})
        with patch(f"{_GATE}.quarantine_redact", AsyncMock(return_value=result)) as extract:
            gated = await gate(
                _verdict(flagged_by=Layer.L2), _posture(Mode.BLOCK, allowlisted=True)
            )
        assert gated.disposition.decision is Decision.REDACT
        assert gated.disposition.downgraded is True
        assert gated.extraction is result
        extract.assert_awaited_once()


class TestExtractionRefusal:
    async def test_refused_extraction_builds_the_one_refusal(self) -> None:
        result = CleanResult(refused_by="t3_flagged")
        with patch(f"{_GATE}.quarantine_redact", AsyncMock(return_value=result)):
            gated = await gate(_verdict(), _posture(Mode.REDACT))
        assert gated.disposition.decision is Decision.REDACT  # the decision still stands
        assert gated.extraction is result  # the raw result, for its refused_by
        refusal = gated.extraction_refusal
        assert refusal is not None
        assert refusal.decision is Decision.REFUSE
        assert refusal.reason == "redact refused: t3_flagged"
        assert refusal.offer_alternatives is False
