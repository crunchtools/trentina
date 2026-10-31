"""garak's encodings against L2 and against the pipeline: measured, never gated (#423).

The obfuscation gate (``l2_obfuscation.py``) holds a model to six
transforms. garak's ``encoding`` probes are a wider list
(``corpora/garak_encodings.py``), and this scores the model on each of them
without failing anything: the numbers decide which transform could join the
gate and which is a known gap (docs/defense-pipeline.md).

Two questions are asked of every text, attack and benign alike:

* **L2 alone.** Does the model call the text malicious as it arrived? This
  is the gate's question.
* **L1 + unpack + L2.** Would ``defend()`` flag it with no L3: the unpack
  stage builds what the layers read, L1 and L2 each read that once, and
  ``defense._decide`` merges them. No judge is called and no key is needed.

Benign text goes through the same transforms because a detection count
alone cannot tell reading from recoil. A model that flags every base32 blob
detects every base32 attack and has read none of them; the benign column is
what shows it. The six gate transforms are scored the same way for that
reason, though this changes nothing about the gate.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_encodings.py
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.benign_ops import BENIGN
from corpora.garak_encodings import ENCODINGS, carries
from corpora.internal import CORPUS
from trentina.defense import _decide
from trentina.l1.pipeline import run_l1
from trentina.quarantine.classifier import classify, is_classifier_available, model_info
from trentina.quarantine.obfuscation import TRANSFORMS
from trentina.unpack.scan import unpack

PLAIN = "plain"
ATTACKS = "attacks"
SETS: dict[str, tuple[str, ...]] = {
    ATTACKS: tuple(c.payload for c in CORPUS if c.expect_injection),
    "internal benign": tuple(c.payload for c in CORPUS if not c.expect_injection),
    "forum replies": tuple(c.payload for c in BENIGN if c.category == "forum_reply"),
}
"""What is scored. The benign sets are reported apart: the internal ones are
prose written to look like an attack, the forum replies are ordinary."""

ROWS = {PLAIN: str, **TRANSFORMS, **ENCODINGS}
"""Every transform scored, the gate's six ahead of garak's."""


@dataclass(frozen=True)
class Reading:
    """What the layers made of one text.

    Attributes:
        score: L2's score for the text as it arrived.
        l2: Whether that is malicious at the model's threshold.
        decoded: Whether the unpack stage changed what the layers read.
        l1: Suspicious detections L1 counted in what it read.
        flagged: Whether L1, unpack and L2 together flag it: ``defend()``
            with no L3.
    """

    score: float
    l2: bool
    decoded: bool
    l1: int
    flagged: bool


def read(text: str) -> Reading:
    """Score ``text`` alone and as the pipeline reads it."""
    if not text.strip():
        return Reading(0.0, False, False, 0, False)  # defend() scans no empty text
    alone = classify(text)
    if alone is None:
        raise RuntimeError("the L2 model stopped answering")
    view = unpack(text)
    pipeline = run_l1(view.text)
    pipeline.stats.unpacked = view.stats
    seen = alone if view.text is text else classify(view.text)
    if seen is None:
        raise RuntimeError("the L2 model stopped answering")
    flagged_by, _, _ = _decide(
        pipeline=pipeline,
        classification=seen if seen.label == "MALICIOUS" else None,
        l3_assessment=None,
    )
    return Reading(
        score=alone.score,
        l2=alone.label == "MALICIOUS",
        decoded=view.text is not text,
        l1=pipeline.stats.suspicious_detections(),
        flagged=flagged_by is not None,
    )


def measure() -> dict[str, dict[str, list[Reading]]]:
    """A reading for every text of every set under every transform.

    A Latin-only encoder (Braille, Morse) is scored only over the texts it can
    carry (``carries``), the same scoping the gate test applies, so a payload
    garak drops at encode time is not counted as a loss here either."""
    return {
        name: {
            group: [read(change(text)) for text in texts if carries(name, text)]
            for group, texts in SETS.items()
        }
        for name, change in ROWS.items()
    }


def report(readings: dict[str, dict[str, list[Reading]]]) -> str:
    """One row a transform: attacks detected, then benign flagged, each by L2
    alone and by the pipeline."""
    benign = [group for group in SETS if group != ATTACKS]
    head = ["transform", "attacks, L2 alone", "attacks, pipeline", "L1 counts", "unpack decodes"]
    for group in benign:
        head += [f"{group}, L2 alone", f"{group}, pipeline"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for name, groups in readings.items():
        attacks = groups[ATTACKS]
        cells = [
            name,
            f"{sum(r.l2 for r in attacks)}/{len(attacks)}",
            f"{sum(r.flagged for r in attacks)}/{len(attacks)}",
            str(sum(r.l1 > 0 for r in attacks)),
            str(sum(r.decoded for r in attacks)),
        ]
        for group in benign:
            of = len(groups[group])
            cells += [
                f"{sum(r.l2 for r in groups[group])}/{of}",
                f"{sum(r.flagged for r in groups[group])}/{of}",
            ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--json", type=Path, help="write every reading here")
    args = parser.parse_args(argv)
    model = model_info() if is_classifier_available() else None
    if model is None:
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2

    readings = measure()
    sizes = ", ".join(f"{len(texts)} {group}" for group, texts in SETS.items())
    print(f"{model.id} at {model.threshold:g}; {sizes}\n")
    print(report(readings))
    if args.json:
        scores = {
            name: {group: [asdict(r) for r in column] for group, column in groups.items()}
            for name, groups in readings.items()
        }
        args.json.write_text(json.dumps({"model": model.id, "readings": scores}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
