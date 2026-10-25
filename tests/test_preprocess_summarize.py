"""Tests for the METERED summarize pre-processor (#82).

The worker call itself is mocked — quarantine_generate's own discipline
(no-tools request shape, canary, schema) is covered by the agent tests.
What these pin is the processor's contract: when it declines, when it
applies, that a failed or compromised worker means the ORIGINAL continues
to the perimeter, and that its output arrives as model output.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from trentina.defense import Provenance
from trentina.errors import QuarantineAgentError
from trentina.transforms import (
    SummarizeProcessor,
    TransformContext,
    run_transforms,
)

pytestmark = pytest.mark.asyncio

_S = "trentina.transforms.summarize"

BIG_PAYLOAD = (
    "An operational log line that resists petit because every sentence differs in words. " * 200
)


def _patch_worker(**kwargs: Any) -> Any:
    return patch(f"{_S}.quarantine_generate", new_callable=AsyncMock, **kwargs)


class TestSummarizeProcessor:
    async def test_summarizes_large_payload(self) -> None:
        with (
            _patch_worker(
                return_value={
                    "summary": "200 repetitions of one operational line.",
                    "usage": {"input_tokens": 4000, "output_tokens": 12},
                }
            ) as worker,
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = True
            result = await SummarizeProcessor().run(
                BIG_PAYLOAD, TransformContext(source="jira:SEC-1")
            )
        assert result.applied
        assert result.content == "200 repetitions of one operational line."
        assert result.details["input_tokens"] == 4000
        # The worker was told where the content came from.
        assert "jira:SEC-1" in worker.call_args.kwargs["user_prompt"]

    async def test_small_payload_declines_without_spending(self) -> None:
        with _patch_worker() as worker:
            result = await SummarizeProcessor().run("tiny", TransformContext())
        assert not result.applied
        assert result.details["declined"] == "too_small"
        worker.assert_not_called()

    async def test_no_api_key_declines(self) -> None:
        with (
            _patch_worker() as worker,
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = False
            result = await SummarizeProcessor().run(BIG_PAYLOAD, TransformContext())
        assert not result.applied
        assert result.details["declined"] == "no_api_key"
        worker.assert_not_called()

    async def test_worker_failure_keeps_the_original(self) -> None:
        """A canary leak raises QuarantineAgentError inside the call — the
        compromised worker's output is never used, and the original payload
        continues to the perimeter unreduced."""
        with (
            _patch_worker(side_effect=QuarantineAgentError("canary leaked")),
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = True
            result = await SummarizeProcessor().run(BIG_PAYLOAD, TransformContext())
        assert not result.applied
        assert result.content == BIG_PAYLOAD
        assert result.details["declined"] == "worker_error"

    async def test_non_reducing_summary_declines(self) -> None:
        with (
            _patch_worker(return_value={"summary": BIG_PAYLOAD}),
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = True
            result = await SummarizeProcessor().run(BIG_PAYLOAD, TransformContext())
        assert not result.applied
        assert result.content == BIG_PAYLOAD
        assert result.details["declined"] == "no_reduction"

    async def test_empty_summary_declines(self) -> None:
        with (
            _patch_worker(return_value={"summary": "   "}),
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = True
            result = await SummarizeProcessor().run(BIG_PAYLOAD, TransformContext())
        assert not result.applied
        assert result.details["declined"] == "empty_summary"

    async def test_summary_arrives_as_model_output(self) -> None:
        """The laundering defense, end to end at the composition level."""
        with (
            _patch_worker(return_value={"summary": "a compact summary"}),
            patch(f"{_S}.llm_available") as cfg,
        ):
            cfg.return_value = True
            outcome = await run_transforms(
                BIG_PAYLOAD,
                processors=[SummarizeProcessor()],
                strategy="chain",
            )
        assert outcome.content == "a compact summary"
        assert outcome.metered_used
        assert outcome.provenance() is Provenance.MODEL_OUTPUT
        briefing = outcome.describe_for_l3()
        assert briefing is not None and "LLM-generated" in briefing
