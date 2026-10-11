"""Bounds on Layer 2 scanning.

Regression cover for the 2026-08-22 incident: block_fetch pulled an 855 KB
PDF, decoded the binary as text, and handed ~462k tokens to classify().  The
unbounded sliding-window loop turned that into ~1,800 ONNX inference passes
that pegged every core for roughly 90 minutes and wedged the event loop.
"""

from __future__ import annotations

import importlib
import itertools
import os
import re
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from trentina.errors import UnscannableContentError
from trentina.quarantine.classifier import (
    WINDOW_CONTENT_TOKENS,
    WINDOW_SPECIAL_TOKENS,
    WINDOW_STRIDE,
    WINDOW_TOKENS,
    ModelInfo,
    classifier_status,
    classify,
    classify_async,
    count_tokens,
    estimate_tokens,
    head,
)

_C = "trentina.quarantine.classifier"

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_TOKENS = 32_768

# Imported, not restated. These were local copies that silently agreed with
# the implementation until someone changed one of them; the pass-count
# assertions below are only meaningful if they track the real geometry.
WINDOW = WINDOW_TOKENS
STRIDE = WINDOW_STRIDE


@contextmanager
def mocked_model(token_count: int, max_tokens: int = MAX_TOKENS) -> Iterator[MagicMock]:
    """Patch in a tokenizer/session pair that reports ``token_count`` tokens."""
    import numpy as np

    full_ids = list(range(token_count))

    def tokenize(_text: str, **kwargs: object) -> dict[str, list[int]]:
        """Mirror the real tokenizer: padded calls return one window."""
        if kwargs.get("padding") == "max_length":
            return {"input_ids": list(range(WINDOW)), "attention_mask": [1] * WINDOW}
        return {"input_ids": full_ids, "attention_mask": [1] * token_count}

    tokenizer = MagicMock(side_effect=tokenize)
    tokenizer.decode.return_value = "decoded segment"
    # Match DebertaV2Tokenizer, which is what Prompt Guard 2 ships with.
    tokenizer.cls_token_id = 1
    tokenizer.sep_token_id = 2
    tokenizer.pad_token_id = 0
    tokenizer.num_special_tokens_to_add.return_value = 2

    session = MagicMock()
    session.run.return_value = [np.array([[5.0, -5.0, -5.0]])]

    config = MagicMock()
    config.classifier_max_tokens = max_tokens
    # Config.admission_tokens, as the real property derives it (#225).
    config.admission_tokens = max_tokens if max_tokens > 0 else 1_000_000
    config.classifier_threshold = 0.5

    with (
        patch("trentina.quarantine.classifier._tokenizer", tokenizer),
        patch("trentina.quarantine.classifier._session", session),
        patch("trentina.quarantine.classifier._loaded", True),
        patch(
            "trentina.quarantine.classifier._model",
            ModelInfo(id="three-class", revision="", threshold=0.5, malicious=(1, 2)),
        ),
        patch("trentina.quarantine.classifier._load_attempted", True),
        patch(
            "trentina.quarantine.classifier.get_config",
            return_value=config,
        ),
    ):
        yield session


class TestSegmentCap:
    """The segment loop must be bounded by the admission cap."""

    def test_oversized_input_is_truncated(self) -> None:
        """A PDF-sized token count is capped instead of scanned in full.

        Unbounded this was ~1,800 inference passes; capped it is ~128.
        """
        with mocked_model(token_count=462_000) as session:
            result = classify("x" * 855_551)

        assert result is not None
        assert result.truncated is True
        assert result.tokens == 462_000

        expected_max = MAX_TOKENS // STRIDE + 1
        assert session.run.call_count <= expected_max
        assert session.run.call_count < 200

    def test_normal_content_is_not_truncated(self) -> None:
        """Content within the cap keeps a full scan and no truncated flag."""
        with mocked_model(token_count=4_000) as session:
            result = classify("a normal article")

        assert result is not None
        assert result.truncated is False
        assert result.tokens == 4_000
        assert session.run.call_count == pytest.approx(4_000 // STRIDE, abs=2)

    def test_a_long_article_fits_under_the_default_cap(self) -> None:
        """100k chars of prose, roughly 28k tokens, is admitted and read whole."""
        with mocked_model(token_count=28_000):
            result = classify("prose")

        assert result is not None
        assert result.truncated is False

    def test_cap_disabled_when_zero(self) -> None:
        """CLASSIFIER_MAX_TOKENS=0 removes L2's budget; L3's context still bounds it."""
        with mocked_model(token_count=2_000, max_tokens=0):
            result = classify("x")

        assert result is not None
        assert result.truncated is False


class TestFailClosed:
    """A caller that refuses a partial scan anyway (block, redact) bails early.

    Whether a partial scan is refused is the mode's decision (modes.py); the
    classifier's part is not to spend inference on a verdict nobody will use.
    """

    @pytest.mark.asyncio
    async def test_truncated_raises_when_asked_to(self) -> None:
        with (
            mocked_model(token_count=462_000),
            pytest.raises(UnscannableContentError) as exc,
        ):
            await classify_async(
                "x" * 855_551,
                fail_on_truncate=True,
                source="https://example.com/big.pdf",
            )

        assert "462000" in str(exc.value)
        assert "example.com/big.pdf" in str(exc.value)

    @pytest.mark.asyncio
    async def test_bails_before_running_any_inference(self) -> None:
        """The verdict is known at the token count; scanning first is wasted CPU.

        Letting the ~128 capped passes run before raising gave an attacker a
        cheap way to burn ~112s of CPU per request.
        """
        with (
            mocked_model(token_count=462_000) as session,
            pytest.raises(UnscannableContentError),
        ):
            await classify_async("x", fail_on_truncate=True, source="https://evil.test/big")

        assert session.run.call_count == 0

    @pytest.mark.asyncio
    async def test_flag_path_scans_and_marks_truncated(self) -> None:
        """flag delivers a partial scan with a warning, so it pays for one."""
        with mocked_model(token_count=462_000) as session:
            result = await classify_async("x" * 855_551)

        assert session.run.call_count > 0
        assert result is not None
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_within_cap_passes(self) -> None:
        with mocked_model(token_count=4_000):
            result = await classify_async("normal", fail_on_truncate=True)

        assert result is not None
        assert result.truncated is False


class TestAsyncOffload:
    """classify_async must not run inference on the event loop."""

    @pytest.mark.asyncio
    async def test_runs_on_a_worker_thread(self) -> None:
        loop_thread = threading.get_ident()
        seen: list[int] = []

        def record(_text: str, **_kw: object) -> None:
            seen.append(threading.get_ident())

        with patch(
            "trentina.quarantine.classifier.classify",
            side_effect=record,
        ):
            await classify_async("anything")

        assert seen and seen[0] != loop_thread


class TestClassifierStatus:
    """Health probes must not trigger the lazy model load."""

    def test_status_does_not_load(self) -> None:
        with patch("trentina.quarantine.classifier.is_classifier_available") as loader:
            status = classifier_status()

        loader.assert_not_called()
        assert status in {"loaded", "not-loaded", "failed"}


class TestTelemetryDisabled:
    """onnxruntime telemetry must be off before the library is imported.

    With it live, importing onnxruntime reads /etc/machine-id and
    /proc/cpuinfo, writes /tmp/mat-debug-1.log and creates a session file
    at /tmp/.ses — none of which belongs in a container built to handle
    untrusted content.
    """

    def test_env_var_set_at_import(self) -> None:
        from trentina.quarantine.classifier import TELEMETRY_ENV

        assert os.environ[TELEMETRY_ENV] == "1"

    def test_operator_can_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """setdefault, not assignment — an explicit opt-in must survive."""
        import trentina.quarantine.classifier as mod

        monkeypatch.setenv(mod.TELEMETRY_ENV, "0")
        importlib.reload(mod)
        assert os.environ[mod.TELEMETRY_ENV] == "0"


class TestWindowGeometry:
    """The sliding window must still overlap, and not by more than it needs.

    Overlap is what stops an injection that straddles a window boundary from
    being split across two segments and judged benign in both. It was set to
    256 tokens -- a 50% overlap, which ran the model over every token twice
    and made a /sync scan cost ~47 s of duplicate work on host01. Cutting it
    is a real speedup and a real risk if taken too far, so pin both ends.
    """

    # Stated against CONTENT, not the raw window: the special tokens take two
    # of the 512 slots, so a window carries 510 tokens of input. Measuring the
    # band against WINDOW_TOKENS reports 64 while the code delivers 62 -- the
    # exact drift between a constant and the implementation this file exists
    # to prevent.
    GUARD_BAND = WINDOW_CONTENT_TOKENS - WINDOW_STRIDE

    def test_content_tokens_account_for_the_special_tokens(self) -> None:
        """The geometry constants and the wrapping must agree."""
        assert WINDOW_CONTENT_TOKENS == WINDOW_TOKENS - WINDOW_SPECIAL_TOKENS

    def test_windows_overlap_at_all(self) -> None:
        """stride >= window means adjacent windows touch but never overlap."""
        assert WINDOW_STRIDE < WINDOW_CONTENT_TOKENS

    def test_guard_band_covers_a_canonical_injection(self) -> None:
        """Canonical injections run 10-30 tokens; keep comfortable headroom.

        Below ~64 the margin stops being a margin, and the failure is silent:
        a split phrase simply scores benign in both halves.
        """
        assert self.GUARD_BAND >= 64

    def test_guard_band_is_not_a_second_full_pass(self) -> None:
        """Overlap above half the window is pure duplicated inference."""
        assert self.GUARD_BAND <= WINDOW_CONTENT_TOKENS // 2

    def test_every_short_span_lands_intact_in_some_window(self) -> None:
        """The property the guard band exists to provide.

        For any starting position, a GUARD_BAND-length run of tokens must sit
        wholly inside at least one segment -- otherwise there is a phrase of
        that length the classifier only ever sees in pieces.
        """
        total = 4_096
        segments = [
            (start, min(start + WINDOW_CONTENT_TOKENS, total))
            for start in range(0, total, WINDOW_STRIDE)
        ]

        for pos in range(total - self.GUARD_BAND):
            span_end = pos + self.GUARD_BAND
            assert any(
                seg_start <= pos and span_end <= seg_end for seg_start, seg_end in segments
            ), f"a {self.GUARD_BAND}-token span at {pos} is split across every window"


class TestPadSegment:
    """Model input is built from token IDs instead of a decode/re-encode round trip."""

    def _tokenizer(self) -> MagicMock:
        tok = MagicMock()
        tok.cls_token_id = 1
        tok.sep_token_id = 2
        tok.pad_token_id = 0
        tok.num_special_tokens_to_add.return_value = 2
        return tok

    def test_a_short_segment_keeps_its_natural_length(self) -> None:
        """No padding. The graph's sequence axis is dynamic and batch is 1,
        so there is nothing to line the row up against — and padding made a
        15-token input cost a full 512-token pass (791 ms vs 52 ms) for a
        byte-identical score."""
        from trentina.quarantine import classifier as mod

        with patch.object(mod, "_tokenizer", self._tokenizer()):
            ids, mask = mod._pad_segment([7, 8, 9], 8)

        assert ids == [1, 7, 8, 9, 2]
        assert mask == [1, 1, 1, 1, 1]
        assert 0 not in ids, "a pad token here means we are paying for zeros"

    def test_no_pad_token_is_ever_emitted(self) -> None:
        """The property, not the example: whatever the segment length, the
        mask is all ones, so every position the model reads is real input."""
        from trentina.quarantine import classifier as mod

        with patch.object(mod, "_tokenizer", self._tokenizer()):
            for n in (0, 1, 3, 100, 509, 510, 511):
                ids, mask = mod._pad_segment(list(range(10, 10 + n)), 512)
                assert mask == [1] * len(ids)
                assert len(ids) == min(n + 2, 512)

    def test_full_window_needs_no_padding(self) -> None:
        from trentina.quarantine import classifier as mod

        with patch.object(mod, "_tokenizer", self._tokenizer()):
            ids, mask = mod._pad_segment(list(range(10, 520)), 512)

        assert len(ids) == 512
        assert ids[0] == 1
        assert ids[-1] == 2
        assert mask == [1] * 512

    def test_oversized_segment_is_clipped_not_overflowed(self) -> None:
        """A caller passing too many IDs must not produce a 514-wide tensor."""
        from trentina.quarantine import classifier as mod

        with patch.object(mod, "_tokenizer", self._tokenizer()):
            ids, mask = mod._pad_segment(list(range(600)), 512)

        assert len(ids) == 512
        assert len(mask) == 512

    def test_segment_loop_never_exceeds_the_window(self) -> None:
        """Every tensor handed to ONNX is exactly max_length wide."""
        import numpy as np

        widths: list[int] = []
        masks: list[int] = []

        def record(_names: object, inputs: dict[str, object]) -> list[object]:
            widths.append(len(inputs["input_ids"][0]))
            masks.append(len(inputs["attention_mask"][0]))
            return [np.array([[5.0, -5.0, -5.0]])]

        with mocked_model(token_count=4_000) as session:
            session.run.side_effect = record
            classify("x")

        assert widths, "no segments were classified"
        assert max(widths) <= WINDOW, "a segment wider than the context window"
        assert widths == masks, "mask must cover exactly the ids given"
        # Full windows are exactly WINDOW wide; only the LAST one is short,
        # because the input rarely divides evenly by the stride. It is no
        # longer padded up to WINDOW -- that was the common case paying for
        # zeros.
        assert set(widths[:-1]) in ({WINDOW}, set()), widths
        assert widths[-1] <= WINDOW


@contextmanager
def word_tokenizer(*, fast: bool = True) -> Iterator[None]:
    """One token per whitespace-separated word, with offsets when ``fast``."""

    def tokenize(text: str, **kwargs: Any) -> dict[str, Any]:
        spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
        if kwargs.get("return_offsets_mapping"):
            if not fast:
                raise NotImplementedError("slow tokenizer")
            return {"input_ids": list(range(len(spans))), "offset_mapping": spans}
        return {"input_ids": [i + 10 for i in range(len(spans))]}

    tokenizer = MagicMock(side_effect=tokenize)
    tokenizer.decode.side_effect = lambda ids: " ".join(f"w{i - 10}" for i in ids)
    with (
        patch("trentina.quarantine.classifier._tokenizer", tokenizer),
        patch("trentina.quarantine.classifier._loaded", True),
        patch(
            "trentina.quarantine.classifier._model",
            ModelInfo(id="three-class", revision="", threshold=0.5, malicious=(1, 2)),
        ),
    ):
        yield


class TestAdmissionHelpers:
    """#225: the count admission decides on, and the head flag hands L3."""

    def test_count_is_in_l2_tokens(self) -> None:
        with word_tokenizer():
            assert count_tokens("one two three") == 3

    def test_head_cuts_at_the_token_boundary(self) -> None:
        with word_tokenizer():
            assert head("w0 w1  w2 w3", 3) == "w0 w1  w2"
            assert head("w0 w1", 5) == "w0 w1"

    def test_a_slow_tokenizer_decodes_the_same_prefix(self) -> None:
        with word_tokenizer(fast=False):
            assert head("w0 w1 w2 w3", 2) == "w0 w1"

    def test_without_the_model_the_estimate_stands_in(self) -> None:
        with patch(f"{_C}.is_classifier_available", return_value=False):
            assert count_tokens("x" * 10) is None
            assert head("x" * 100, 10) == "x" * 10
            assert head("你好世界", 7) == "你好"

    def test_the_estimate_never_undercounts_a_script(self) -> None:
        """Bytes, not characters: two CJK characters are six bytes."""
        assert estimate_tokens("你好") == 6
        assert estimate_tokens("ab") == 2


class TestSingleWindowEdge:
    """A window holds WINDOW_CONTENT_TOKENS of content, not WINDOW_TOKENS (#298)."""

    @pytest.mark.parametrize("extra", [1, WINDOW_SPECIAL_TOKENS])
    def test_the_last_tokens_of_a_full_window_are_read(self, extra: int) -> None:
        """511 and 512 tokens used to take the one-window path and lose 1-2."""
        token_count = WINDOW_CONTENT_TOKENS + extra
        seen: list[int] = []

        import numpy as np

        def record(_names: object, inputs: dict[str, Any]) -> list[object]:
            seen.extend(int(i) for i in inputs["input_ids"][0])
            return [np.array([[5.0, -5.0, -5.0]])]

        def tokenize(_text: str, **kwargs: Any) -> dict[str, list[int]]:
            """Truncate like the real tokenizer does when asked to."""
            ids = list(range(token_count))
            if kwargs.get("truncation") and kwargs.get("max_length"):
                ids = [1, *ids[: int(kwargs["max_length"]) - WINDOW_SPECIAL_TOKENS], 2]
            return {"input_ids": ids, "attention_mask": [1] * len(ids)}

        with mocked_model(token_count=token_count) as session:
            patch_tokenizer = patch(f"{_C}._tokenizer.side_effect", tokenize)
            session.run.side_effect = record
            with patch_tokenizer:
                result = classify("x")

        assert result is not None
        assert result.truncated is False
        assert set(range(token_count)) <= set(seen), "content tokens were never scanned"

    def test_empty_text_still_gets_one_pass(self) -> None:
        with mocked_model(token_count=0) as session:
            result = classify("")
        assert result is not None
        assert session.run.call_count == 1


class TestWindowIsTheModels:
    """``classify()`` scans in the loaded model's window, not a constant (#438)."""

    @pytest.mark.parametrize(
        ("window", "guard", "tokens"),
        [(128, 16, 1_000), (1_024, 64, 4_000), (WINDOW_TOKENS, 64, 4_000), (256, 0, 1_016)],
    )
    def test_passes_and_overlap_follow_the_manifest(
        self, window: int, guard: int, tokens: int
    ) -> None:
        content = window - WINDOW_SPECIAL_TOKENS
        stride = content - guard
        model = ModelInfo(
            id="m", revision="", threshold=0.5, malicious=(1, 2), window=window, guard=guard
        )
        with (
            mocked_model(token_count=tokens) as session,
            patch("trentina.quarantine.classifier._model", model),
        ):
            classify("x")

        ids = [list(call.args[1]["input_ids"][0]) for call in session.run.call_args_list]
        assert all(len(seg) <= window for seg in ids)
        assert len(ids[0]) == window
        # Content only: strip the CLS and SEP the window is wrapped in.
        spans = [seg[1:-1] for seg in ids]
        assert [span[0] for span in spans] == list(range(0, spans[-1][0] + 1, stride))
        assert spans[-1][-1] == tokens - 1
        for before, after in itertools.pairwise(spans):
            assert before[-1] - after[0] + 1 == guard
