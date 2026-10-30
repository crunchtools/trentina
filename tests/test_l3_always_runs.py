"""The mandate: L1, L2 and L3 run on every input the gateway scans.

This file exists because the property is easy to lose by accident. It was
lost once already — not by anyone deciding to skip L3, but by a cost-control
threshold that looked like configuration and behaved like an off switch. A
gate that only fires on suspicious content is invisible in every test written
with suspicious content, which is most of them.

So these tests are deliberately boring. They feed the pipeline the most
innocuous input imaginable and assert the judge was called anyway. The day
someone adds a "cheap path" for clean traffic, this file is what says no.

The one thing that may stop L3 is L3 being unable to run. That is a degraded
state, and it must be visible as one rather than silently reading as clean.
"""

from __future__ import annotations

import inspect
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

import pytest

from trentina.defense import (
    Layer,
    Provenance,
    defend,
)
from trentina.gateway.profile import DefenseConfig
from trentina.quarantine.classifier import ClassifierResult

pytestmark = pytest.mark.usefixtures("standalone_l3")

_D = "trentina.defense"

BENIGN_ZERO = ClassifierResult(label="BENIGN", score=0.0, latency_ms=1.0)
BENIGN_MID = ClassifierResult(label="BENIGN", score=0.5, latency_ms=1.0)
MALICIOUS = ClassifierResult(label="MALICIOUS", score=0.95, latency_ms=1.0)

INNOCUOUS = "The quarterly maintenance window is Tuesday at 02:00 UTC."


def _patches(
    stack: ExitStack,
    *,
    classification: ClassifierResult | None = BENIGN_ZERO,
    detection: dict[str, Any] | None = None,
    has_llm: bool = True,
) -> dict[str, Any]:
    def p(name: str, **kw: Any) -> Any:
        return stack.enter_context(patch(f"{_D}.{name}", **kw))

    mocks = {
        "classify_async": p("classify_async", return_value=classification),
        "quarantine_detect": p(
            "quarantine_detect",
            return_value=detection or {"injection_detected": False},
        ),
        "record_detection": p("record_detection"),
        "emit_detection_event": p("emit_detection_event"),
    }
    cfg = p("get_config")
    cfg.return_value.has_llm = has_llm
    cfg.return_value.admission_tokens = 32_768
    mocks["get_config"] = cfg
    return mocks


async def _defend(**kw: Any) -> Any:
    stack_kw = {k: kw.pop(k) for k in ("classification", "detection", "has_llm") if k in kw}
    with ExitStack() as stack:
        mocks = _patches(stack, **stack_kw)
        verdict = await defend(
            kw.pop("content", INNOCUOUS),
            source=kw.pop("source", "https://example.com"),
            source_type=kw.pop("source_type", "url"),
            **kw,
        )
        return verdict, mocks


class TestL3RunsOnCleanTraffic:
    """The case that never ran before. Every one of these used to skip L3."""

    async def test_clean_content_clean_l2_still_reaches_l3(self) -> None:
        _, mocks = await _defend()
        mocks["quarantine_detect"].assert_called_once()

    @pytest.mark.parametrize("score", [0.0, 0.01, 0.1, 0.29, 0.3, 0.5, 0.69])
    async def test_every_l2_score_below_the_old_threshold_reaches_l3(self, score: float) -> None:
        """0.7 was the old escalation point. Nothing below it reached L3."""
        cls = ClassifierResult(label="BENIGN", score=score, latency_ms=1.0)
        _, mocks = await _defend(classification=cls, defense=DefenseConfig())
        mocks["quarantine_detect"].assert_called_once()

    async def test_the_flagged_but_unjudged_band(self) -> None:
        """The sharpest case: L2 flags at 0.3, escalation needed 0.7.

        Content scoring 0.5 was flagged as suspicious by L2 and then never
        shown to the layer that could tell an attack from a CVE ticket
        discussing one. That band is the reason this file exists.
        """
        _, mocks = await _defend(
            classification=BENIGN_MID,
            defense=DefenseConfig(l2_threshold=0.3),
        )
        mocks["quarantine_detect"].assert_called_once()

    async def test_no_l1_detections_still_reaches_l3(self) -> None:
        verdict, mocks = await _defend(content="Nothing hostile here at all.")
        assert verdict.pipeline.stats.total_detections() == 0
        mocks["quarantine_detect"].assert_called_once()


class TestThresholdCannotSuppressL3:
    """`l3_threshold` no longer exists, so nothing can be set to suppress L3.

    Until 0.29.0 the key was accepted and ignored, and these tests had to
    prove the ignoring actually happened for every value including 1.0 —
    which under the old gate meant "effectively never". The key is now
    rejected at load, so the guarantee is structural rather than tested.
    """

    def test_the_key_is_rejected_rather_than_ignored(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            DefenseConfig(l3_threshold=1.0)

    def test_no_caller_can_switch_l3_off(self) -> None:
        """``l3_gate`` let a caller skip detection until 0.31.0, and search
        used it to skip L3 entirely. No parameter of defend() may do that."""
        params = set(inspect.signature(defend).parameters)
        assert params == {
            "content",
            "source",
            "source_type",
            "defense",
            "provenance",
            "domain",
            "stop_on_partial",
            "record",
            "l3_context",
            "precomputed_l1",
            "attribution",
        }, (
            "a new parameter here may be a new way to skip L3 — if one is "
            "added, it needs a test in this file saying why it is allowed to"
        )


class TestL3RunsRegardlessOfOtherLayers:
    async def test_runs_when_l2_is_unavailable(self) -> None:
        """No classifier result at all must not mean 'nothing to judge'."""
        _, mocks = await _defend(classification=None)
        mocks["quarantine_detect"].assert_called_once()

    async def test_runs_when_l2_says_malicious(self) -> None:
        _, mocks = await _defend(classification=MALICIOUS)
        mocks["quarantine_detect"].assert_called_once()

    async def test_runs_on_model_output(self) -> None:
        _, mocks = await _defend(provenance=Provenance.MODEL_OUTPUT)
        mocks["quarantine_detect"].assert_called_once()

    async def test_stop_on_partial_does_not_skip_l3(self) -> None:
        _, mocks = await _defend(stop_on_partial=True)
        mocks["quarantine_detect"].assert_called_once()

    async def test_l3_flag_stands(self) -> None:
        verdict, _ = await _defend(
            detection={"injection_detected": True, "risk_level": "high"},
        )
        assert verdict.flagged_by is Layer.L3


class TestTheOnlyPermittedSkips:
    """Two, both named, both visible. Any third is a regression."""

    async def test_no_provider_skips_but_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unable to run is a DEGRADED state, never a clean one.

        No key anywhere: the synthesized standalone operator resolves no
        provider, so L3 cannot run (``standalone_l3``'s key is removed here).
        """
        import trentina.config as _config_mod

        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("TRENTINA_MODEL_PROVIDER", raising=False)
        _config_mod._config = None
        verdict, mocks = await _defend(has_llm=False, defense=None)
        mocks["quarantine_detect"].assert_not_called()
        assert verdict.l3_assessment is not None, (
            "a skipped L3 must leave evidence; None here would read as 'ran and found nothing'"
        )
        assert verdict.l3_assessment.get("l3_unavailable") is True

    async def test_a_configured_provider_opens_the_gate_without_gemini_key(
        self,
    ) -> None:
        """A profile bringing its own provider is not 'no provider'."""
        _, mocks = await _defend(has_llm=False, defense=DefenseConfig(provider="ollama"))
        mocks["quarantine_detect"].assert_called_once()

    async def test_every_mode_detects(self) -> None:
        """This asserted the OPPOSITE until 0.31.0: that ``advise()`` — the
        clean_* path — skipped detection, and it called that a design. It
        was the hole #187 closes. redact now detects first, then extracts and
        verifies; see tests/test_mode_parity.py for every family and mode."""
        import trentina.defense as defense_mod

        assert not hasattr(defense_mod, "advise")


class TestDeprecatedKeyIsRejected:
    async def test_a_profile_setting_l3_threshold_fails_to_load(
        self,
        tmp_path: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Announced as ignored since 0.12.0, removed in 0.29.0.

        ``extra="forbid"`` now refuses it, which is the point: a key that
        silently stopped mattering is worse than one that fails loudly, and
        an operator who still sets it is reasoning about a gate that has not
        existed for seventeen minor releases.
        """
        from trentina.gateway.errors import ProfileConfigError
        from trentina.gateway.loader import load_profiles

        monkeypatch.setenv("TEST_TOK", "x")
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            "profiles:\n"
            "  agent2:\n"
            "    auth:\n"
            "      bearer_token_env: TEST_TOK\n"
            "    defense:\n"
            "      l3_threshold: 0.7\n"
            "    backends: {}\n",
            encoding="utf-8",
        )
        with pytest.raises((ProfileConfigError, ValueError)):
            load_profiles(cfg)
