"""The one disposition decision, tested exhaustively in isolation.

``core.dispose`` is pure, so every mode crossed with every verdict shape is a
table here rather than an integration test. This is the behaviour the nine
rewired ingress sites must preserve; if one of them drifts again, it drifts away
from this table.
"""

from __future__ import annotations

from trentina.core import Decision, Posture, dispose, refusal_of
from trentina.core.dispose import DEFAULT_REDACT_PROMPT
from trentina.defense import DefenseVerdict, Layer
from trentina.l1.pipeline import PipelineResult, PipelineStats
from trentina.modes import Mode, ModePolicy
from trentina.quarantine.classifier import ClassifierResult

POLICY = ModePolicy((Mode.BLOCK, Mode.FLAG, Mode.REDACT), Mode.BLOCK)


def _verdict(
    *,
    text: str = "some content",
    flagged_by: Layer | None = None,
    judged: bool = True,
    l3_truncated: bool = False,
    oversize: tuple[int, int] | None = None,
    unread: tuple[str, ...] = (),
) -> DefenseVerdict:
    """A verdict with its gaps under control.

    ``judged=True`` means both scanning layers produced a verdict (no absent
    layer); ``judged=False`` leaves L2/L3 unavailable, the ABSENT-layer gap.
    """
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
        l3_truncated=l3_truncated,
        oversize=oversize,
        unread=unread,
    )


def _posture(mode: Mode, *, allowlisted: bool = False, honeypot: bool = False) -> Posture:
    return Posture(mode=mode, policy=POLICY, allowlisted=allowlisted, honeypot=honeypot)


class TestFlagAlwaysDelivers:
    def test_clean(self) -> None:
        assert dispose(_verdict(), _posture(Mode.FLAG)).decision is Decision.DELIVER

    def test_flagged(self) -> None:
        d = dispose(_verdict(flagged_by=Layer.L2), _posture(Mode.FLAG))
        assert d.decision is Decision.DELIVER

    def test_absent_layers(self) -> None:
        d = dispose(_verdict(judged=False), _posture(Mode.FLAG))
        assert d.decision is Decision.DELIVER

    def test_honeypot_delivers_unmarked(self) -> None:
        d = dispose(_verdict(flagged_by=Layer.L2), _posture(Mode.FLAG, honeypot=True))
        assert d.decision is Decision.DELIVER_UNMARKED


class TestBlock:
    def test_clean_delivers(self) -> None:
        assert dispose(_verdict(), _posture(Mode.BLOCK)).decision is Decision.DELIVER

    def test_flagged_refuses(self) -> None:
        d = dispose(_verdict(flagged_by=Layer.L2), _posture(Mode.BLOCK))
        assert d.decision is Decision.REFUSE
        assert d.flagged_by == "L2"
        assert d.reason and "L2" in d.reason

    def test_partial_gap_refuses_when_not_allowlisted(self) -> None:
        d = dispose(_verdict(l3_truncated=True), _posture(Mode.BLOCK))
        assert d.decision is Decision.REFUSE

    def test_partial_gap_downgrades_to_redact_when_allowlisted(self) -> None:
        d = dispose(_verdict(l3_truncated=True), _posture(Mode.BLOCK, allowlisted=True))
        assert d.decision is Decision.REDACT
        assert d.downgraded is True
        assert d.prompt == DEFAULT_REDACT_PROMPT

    def test_flagged_no_gap_downgrades_to_redact_when_allowlisted(self) -> None:
        # A flagged verdict with no gaps on an allowlisted source: block sends
        # it to redact rather than refusing, keeping the flag details.
        d = dispose(_verdict(flagged_by=Layer.L2), _posture(Mode.BLOCK, allowlisted=True))
        assert d.decision is Decision.REDACT
        assert d.downgraded is True
        assert d.flagged_by == "L2"
        assert d.prompt == DEFAULT_REDACT_PROMPT

    def test_absent_layer_refuses_even_when_allowlisted(self) -> None:
        # An absent layer is not a partial read; the allowlist cannot excuse it.
        d = dispose(_verdict(judged=False), _posture(Mode.BLOCK, allowlisted=True))
        assert d.decision is Decision.REFUSE

    def test_oversize_refuses(self) -> None:
        d = dispose(_verdict(oversize=(100, 50)), _posture(Mode.BLOCK))
        assert d.decision is Decision.REFUSE

    def test_extra_unread_refuses_clean_text(self) -> None:
        # Text judged clean, but the delivery also holds binary no layer read.
        d = dispose(_verdict(), _posture(Mode.BLOCK), extra_unread=True)
        assert d.decision is Decision.REFUSE
        assert d.gaps is not None and d.gaps.binary_unread is True


class TestRedact:
    def test_clean_extracts(self) -> None:
        d = dispose(_verdict(), _posture(Mode.REDACT))
        assert d.decision is Decision.REDACT
        assert d.prompt == DEFAULT_REDACT_PROMPT

    def test_carries_prompt(self) -> None:
        p = Posture(mode=Mode.REDACT, policy=POLICY, prompt="just the title")
        assert dispose(_verdict(), p).prompt == "just the title"

    def test_flagged_but_no_gap_extracts(self) -> None:
        # redact's whole point: a flag does not refuse it, a gap does.
        d = dispose(_verdict(flagged_by=Layer.L3), _posture(Mode.REDACT))
        assert d.decision is Decision.REDACT

    def test_partial_gap_refuses(self) -> None:
        d = dispose(_verdict(l3_truncated=True), _posture(Mode.REDACT))
        assert d.decision is Decision.REFUSE


class TestPostureDerivations:
    def test_stop_on_partial_is_not_flag(self) -> None:
        assert _posture(Mode.FLAG).stop_on_partial is False
        assert _posture(Mode.BLOCK).stop_on_partial is True
        assert _posture(Mode.REDACT).stop_on_partial is True

    def test_records_block_only_for_block(self) -> None:
        assert _posture(Mode.BLOCK).records_block() is True
        assert _posture(Mode.FLAG).records_block() is False
        assert _posture(Mode.REDACT).records_block() is False

    def test_records_block_false_when_not_blocklisting(self) -> None:
        assert _posture(Mode.BLOCK).records_block(blocklists=False) is False


class TestRender:
    def test_refuse_body_names_mode_and_reason(self) -> None:
        d = dispose(_verdict(flagged_by=Layer.L2), _posture(Mode.BLOCK))
        body = refusal_of(d, _posture(Mode.BLOCK))
        assert body["mode"] == "block"
        assert body["flagged_by"] == "L2"
        assert Mode.REDACT.value in body["alternatives"]
        assert Mode.FLAG.value not in body["alternatives"]  # flagged never offers flag

    def test_offer_alternatives_false_empties_them(self) -> None:
        from trentina.core.dispose import Disposition

        d = Disposition(Decision.REFUSE, reason="redact refused: x", offer_alternatives=False)
        assert refusal_of(d, _posture(Mode.REDACT))["alternatives"] == []
