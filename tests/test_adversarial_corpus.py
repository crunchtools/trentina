"""Integrity tests for the Layer 3 adversarial corpus.

These tests make NO API calls. They prove two things about
``corpora/internal.py``:

1. The corpus is well-formed (unique ids, valid risk levels, coherent
   attack/benign split).
2. Each case reaches the layer it claims to. Semantic attacks must survive
   Layer 1 (deterministic detection) untouched — otherwise they would never
   reach the Q-Agent and the provider benchmark would be measuring nothing.
   Structural attacks and the quoted-attack trap must be stripped by Layer 1,
   as annotated.

The Layer 2 assertions run only when the Prompt Guard model is available
(it lives at ``/models`` in the deployed container, not in local/CI checkouts).

If Layer 1 or Layer 2 ever changes such that a case's annotation no longer
holds, the corresponding test fails loudly — which is the signal to re-annotate
the case (e.g. move a now-caught attack down a layer), not to paper over it.
"""

from __future__ import annotations

import json

import pytest

from corpora.internal import (
    ATTACKS,
    BENIGN,
    CORPUS,
    RISK_ORDER,
    Case,
)
from trentina.l1.pipeline import run_l1
from trentina.preprocess import (
    EmailProcessor,
    PetitProcessor,
    PreProcessContext,
    StructuredProcessor,
    run_preprocessors,
)
from trentina.quarantine.classifier import (
    classify,
    is_classifier_available,
)

_has_classifier = is_classifier_available()


class TestCorpusWellFormed:
    """Structural invariants of the corpus itself."""

    def test_nonempty(self) -> None:
        assert CORPUS, "corpus is empty"
        assert ATTACKS, "no attack cases"
        assert BENIGN, "no benign cases"

    def test_ids_unique(self) -> None:
        ids = [c.id for c in CORPUS]
        dupes = {i for i in ids if ids.count(i) > 1}
        assert not dupes, f"duplicate case ids: {sorted(dupes)}"

    @pytest.mark.parametrize("case", ATTACKS, ids=[c.id for c in ATTACKS])
    def test_attacks_have_valid_min_risk(self, case: Case) -> None:
        assert case.min_risk in RISK_ORDER, (
            f"{case.id}: min_risk {case.min_risk!r} not one of {sorted(RISK_ORDER)}"
        )
        assert RISK_ORDER[case.min_risk] >= RISK_ORDER["medium"], (
            f"{case.id}: attacks should require at least medium risk"
        )

    @pytest.mark.parametrize("case", BENIGN, ids=[c.id for c in BENIGN])
    def test_benign_have_no_min_risk(self, case: Case) -> None:
        assert case.min_risk == "", f"{case.id}: benign case should not set min_risk"

    def test_category_coverage(self) -> None:
        """The corpus must exercise the semantic attack families we care about."""
        required = {
            "authority_social",
            "exfil_action",
            "role_reassignment",
            "fake_config",
            "indirect_second_order",
            "tool_invocation",
            "conditional_trigger",
            "context_confusion",
            "detector_meta",
            "obfuscation_semantic",
            "memory_poison",
        }
        present = {c.category for c in CORPUS}
        missing = required - present
        assert not missing, f"corpus missing attack families: {sorted(missing)}"


class TestLayer1Boundary:
    """Each case reaches Layer 1's output in the state it claims to."""

    @pytest.mark.parametrize("case", CORPUS, ids=[c.id for c in CORPUS])
    def test_l1_annotation_holds(self, case: Case) -> None:
        count = sum(run_l1(case.payload).stats.to_flat_dict().values())
        if case.bypasses_l1:
            assert count == 0, (
                f"{case.id}: expected to bypass Layer 1, but L1 made {count} "
                f"detection(s). This attack no longer reaches L3 intact — "
                f"re-annotate bypasses_l1=False or adjust the payload."
            )
        else:
            assert count > 0, (
                f"{case.id}: expected Layer 1 to strip this, but it made 0 "
                f"detections. Re-annotate bypasses_l1=True."
            )

    def test_semantic_attacks_are_genuinely_semantic(self) -> None:
        """The headline claim: most attacks pass Layer 1 clean.

        If this ratio collapses, the corpus has drifted toward structural
        payloads that L1 already handles and the L3 benchmark loses its point.
        """
        semantic = [c for c in ATTACKS if c.bypasses_l1]
        assert len(semantic) >= 0.7 * len(ATTACKS), (
            f"only {len(semantic)}/{len(ATTACKS)} attacks bypass L1 — corpus is drifting structural"
        )


@pytest.mark.skipif(not _has_classifier, reason="Prompt Guard model not available")
class TestLayer2Boundary:
    """Where annotated deterministically, Layer 2 agrees with the corpus."""

    @pytest.mark.parametrize(
        "case",
        [c for c in CORPUS if c.bypasses_l2 is not None],
        ids=[c.id for c in CORPUS if c.bypasses_l2 is not None],
    )
    def test_l2_annotation_holds(self, case: Case) -> None:
        result = classify(case.payload)
        assert result is not None
        expected = "BENIGN" if case.bypasses_l2 else "MALICIOUS"
        assert result.label == expected, (
            f"{case.id}: L2 returned {result.label} (score={result.score:.4f}), "
            f"expected {expected}. If Prompt Guard changed, re-annotate this case."
        )


@pytest.mark.asyncio
class TestPreProcessorsDoNotSuppressAttacks:
    """Reduction must not delete the thing the perimeter exists to catch.

    This replaces an ARGUMENT with a MEASUREMENT, and that is the whole point
    of the file.

    Until 0.22.0, `preprocess/petit.py` pinned `driver="RawEntry"` and passed
    its own stopword list, under a rule stated as "normalize only tokens that
    cannot carry meaning to a model — never words". The rule was never a test.
    It lived as prose in a docstring, and the docstring's own justification did
    not hold: it argued that keeping a payload distinct meant it "reaches the
    perimeter scan", while the next paragraph established that a payload which
    collides into a group is DELETED — and a deleted line reaches nobody, the
    scanner included.

    So the rule was not preventing smuggling. What it prevented was an attack
    being quietly dropped before anyone judged or recorded it. That is worth
    keeping, and it is measurable, which prose is not.

    Each case is buried in three carriers that look like real tool output —
    repetitive syslog, a JSON array of near-identical records, a quoted mail
    thread — and run through the production chain. The assertion is that the
    payload is still there afterwards.

    A case that legitimately does not survive becomes
    `survives_preprocessing=False` with a reason in `notes`. That is a visible
    edit to the corpus, not a skip, because "we measured this and accepted it"
    and "nobody noticed" must not look the same.
    """

    @staticmethod
    def _syslog_carrier(payload: str) -> str:
        """200 lines of boilerplate with the payload at a fixed position.

        Fixed, not random: an incident has to be reproducible from the corpus
        alone, and a flaky position would make a failure impossible to chase.
        """
        lines = [
            f"Sep 13 04:{i % 60:02d}:00 host01 sshd[{1000 + i}]: "
            f"Accepted publickey for svc from 10.0.0.{i % 250} port {2000 + i}"
            for i in range(200)
        ]
        lines.insert(137, f"Sep 13 04:59:59 host01 app[9999]: {payload}")
        return "\n".join(lines)

    @staticmethod
    def _json_carrier(payload: str) -> str:
        records = [
            {"id": i, "status": "ok", "message": "sync completed", "retries": 0} for i in range(40)
        ]
        records[23]["message"] = payload
        return json.dumps(records, indent=2)

    @staticmethod
    def _mail_carrier(payload: str) -> str:
        thread = []
        for depth in range(8):
            quote = "> " * depth
            thread.append(f"{quote}On Mon, someone wrote:")
            thread.append(f"{quote}Thanks, that works for me.")
            thread.append(f"{quote}")
        thread.append(payload)
        thread.append("-- ")
        thread.append("Sent from my phone")
        return "\n".join(thread)

    @pytest.mark.parametrize(
        "case",
        [c for c in CORPUS if c.expect_injection and c.survives_preprocessing],
        ids=lambda c: c.id,
    )
    @pytest.mark.parametrize("carrier", ["syslog", "json", "mail"])
    async def test_the_payload_survives_reduction(self, case: Case, carrier: str) -> None:
        build = {
            "syslog": self._syslog_carrier,
            "json": self._json_carrier,
            "mail": self._mail_carrier,
        }[carrier]
        # The longest single line, not the whole payload: a carrier reflows
        # multi-line text, so asserting on all of it would fail for reasons
        # that have nothing to do with suppression.
        needle = max(case.payload.splitlines(), key=len).strip()
        document = build(case.payload)

        # Escaping is not suppression, and the two are easy to confuse. The
        # JSON carrier is built with ensure_ascii=True, so an em-dash lands as
        # \u2014; the structured reducer re-serializes with ensure_ascii=False
        # and emits the literal character. Both spell the same payload, so
        # accept either rather than fail a case that in fact survived.
        forms = {needle, json.dumps(needle)[1:-1]}
        assert any(f in document for f in forms), "carrier lost the payload before reduction"

        # The order the shipped default uses (_DEFAULT_PROCESSORS), not an
        # arbitrary one: petit first would turn a JSON array into loose text
        # and the structured reducer would then decline on its own input.
        outcome = await run_preprocessors(
            document,
            processors=[StructuredProcessor(), EmailProcessor(), PetitProcessor()],
            strategy="chain",
            ctx=PreProcessContext(source="test", target_bytes=20_000),
        )

        assert any(f in outcome.content for f in forms), (
            f"{case.id!r} was suppressed by reduction in the {carrier} "
            f"carrier. The agent never sees it, which is safe — but the "
            f"perimeter never judged it and the blocklist never recorded it. "
            f"Either tighten the driver in petit, or set "
            f"survives_preprocessing=False on this case with a written reason."
        )

    def test_every_case_still_claims_to_survive(self) -> None:
        """The exception list is empty, and a change to it should be loud."""
        excepted = [c.id for c in CORPUS if not c.survives_preprocessing]
        assert excepted == [], (
            f"cases now excepted from suppression testing: {excepted}. That "
            f"may be correct, but it is a perimeter coverage decision and "
            f"belongs in a release note, not in a corpus field nobody reads."
        )
