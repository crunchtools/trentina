"""Tests for search tools (spec 005)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from trentina.errors import BlockedSourceError, QuarantineAgentError
from trentina.quarantine.classifier import ClassifierResult
from trentina.tools.search import (
    block_search,
    flag_search,
    redact_search,
)

from .mode_harness import layers


def _mock_gemini_grounding_response(
    text: str = "RHEL 10 introduced bootc for image-based deployments.",
    sources: list[dict[str, str]] | None = None,
    supports: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a mock Gemini REST API response with grounding metadata."""
    if sources is None:
        sources = [
            {
                "web": {
                    "uri": "https://docs.redhat.com/bootc",
                    "title": "Getting Started with bootc",
                }
            },
            {
                "web": {
                    "uri": "https://crunchtools.com/bootc/",
                    "title": "Image mode for RHEL",
                }
            },
        ]
    if supports is None:
        supports = [
            {
                "segment": {"startIndex": 0, "endIndex": 50, "text": text[:50]},
                "groundingChunkIndices": [0],
                "confidenceScores": [0.92],
            }
        ]

    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}]},
                "groundingMetadata": {
                    "groundingChunks": sources,
                    "groundingSupports": supports,
                },
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 320,
            "candidatesTokenCount": 580,
        },
    }


class TestSearchThroughTheOneJudgingPath:
    """Search is a producer like any other (#187). The per-family mode matrix
    lives in test_mode_parity / test_mode_gaps; these are search's own edges."""

    @pytest.mark.parametrize("mode", ["block", "flag", "redact"])
    async def test_an_l0_failure_raises_in_every_mode(self, env: Path, mode: str) -> None:
        """redact_search used to return {"error": ...} instead.

        A provider failure is the provider breaking, not the defense working
        (#293): it raises as one, with none of the provider's text (#292).
        """
        with layers(env) as fakes:
            fakes.search_grounded.side_effect = QuarantineAgentError(
                "HTTP 503 from http://ollama.internal:11434", status_code=503
            )
            call = {
                "block": lambda: block_search("q"),
                "flag": lambda: flag_search("q"),
                "redact": lambda: redact_search("q", "Summarize."),
            }[mode]
            with pytest.raises(QuarantineAgentError) as failed:
                await call()
        assert not isinstance(failed.value, BlockedSourceError)
        assert str(failed.value) == "Q-Agent error: search provider unavailable"
        assert failed.value.status_code == 503
        assert failed.value.__cause__ is None

    @pytest.mark.parametrize("mode", ["block", "flag", "redact"])
    async def test_an_l0_canary_leak_refuses_in_every_mode(self, env: Path, mode: str) -> None:
        from trentina.errors import SearchCanaryLeakedError

        with layers(env) as fakes:
            fakes.search_grounded.side_effect = SearchCanaryLeakedError()
            call = {
                "block": lambda: block_search("q"),
                "flag": lambda: flag_search("q"),
                "redact": lambda: redact_search("q", "Summarize."),
            }[mode]
            with pytest.raises(BlockedSourceError) as refused:
                await call()
        assert refused.value.refusal == {
            "reason": "L0 canary leaked",
            "mode": mode,
            "flagged_by": "l0",
            "alternatives": [],
        }

    async def test_l0_output_is_recorded_as_model_output(self, env: Path) -> None:
        with (
            layers(
                env,
                classification=ClassifierResult(
                    label="MALICIOUS",
                    score=0.9,
                    latency_ms=1.0,
                ),
            ),
            patch("trentina.defense.record_detection") as record,
        ):
            await flag_search("q")
        assert record.call_args.kwargs["provenance"] == "model_output"

    async def test_block_and_flag_deliver_l0_text_and_sources(self, env: Path) -> None:
        with layers(env) as fakes:
            result = await block_search("q")
        assert result["content"] == fakes.payload
        assert result["sources"] == [{"uri": "https://example.com/a", "title": "A"}]
        assert result["query"] == "q"

    async def test_redact_delivers_the_extraction_and_sources_not_the_answer(
        self, env: Path
    ) -> None:
        with layers(env) as fakes:
            result = await redact_search("q", "Summarize.")
        assert result["content"]["extracted_text"] != fakes.payload
        assert result["sources"][0]["uri"] == "https://example.com/a"
        assert "text" not in result
