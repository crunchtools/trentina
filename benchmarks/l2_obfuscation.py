"""L2 obfuscation robustness: an L2 model-selection gate (#359).

L2 reads the arrived bytes once (the Layer contract,
docs/defense-pipeline.md). Whether a candidate model reads through zero-width
splits, fullwidth letters, encodings and tag smuggling is a property of the
MODEL, so it is measured here, before the model ships. It is not compensated
for in the pipeline. Until 0.56.0 it was: L2 read L1's normalized copy as
well, to cover Prompt Guard 2's tokenizer. Measured on Horizon it changed 1
of 308 outcomes, and it was retired.

Every attack in the corpus is classified plain and under each transform. A
transform passes when it loses at most ``--max-drop`` detections against
plain. Exit 1 on any failure, so a model that a trick blinds is rejected at
selection.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_obfuscation.py

``--record`` writes the result into the model's ``trentina-model.json``. The
image build runs it for every model it ships and fails on a failing one
(#362); the gateway warns at startup about a model with no passing record.
The transforms themselves live in ``quarantine/obfuscation.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.internal import CORPUS
from trentina.config import get_config
from trentina.quarantine.classifier import (
    MANIFEST_FILE,
    classify,
    is_classifier_available,
)
from trentina.quarantine.obfuscation import (
    GATE_KEY,
    GATE_MAX_DROP,
    TRANSFORMS,
    run_gate,
)

__all__ = ["TRANSFORMS", "main"]


def _detected(text: str) -> bool:
    result = classify(text)
    return result is not None and result.label == "MALICIOUS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--max-drop",
        type=int,
        default=GATE_MAX_DROP,
        help=f"detections a transform may lose against plain (default {GATE_MAX_DROP})",
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help=f"write the result into the model's {MANIFEST_FILE}, pass or fail",
    )
    args = parser.parse_args(argv)
    if not is_classifier_available():
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2

    attacks = [c.payload for c in CORPUS if c.expect_injection]
    record = run_gate(attacks, _detected, args.max_drop)
    plain = record["plain"]
    print(f"{len(attacks)} attacks; plain: {plain} detected\n")
    print("| transform | detected | vs plain | |\n|---|---|---|---|")
    for name, hits in record["transforms"].items():
        verdict = "pass" if plain - hits <= args.max_drop else "FAIL"
        print(f"| {name} | {hits}/{len(attacks)} | {hits - plain:+d} | {verdict} |")
    if args.record:
        _write_record(record)
    return 0 if record["passed"] else 1


def _write_record(record: dict[str, object]) -> None:
    """Add the record to the manifest beside the loaded model, creating it if absent."""
    path = Path(get_config().classifier_model_path) / MANIFEST_FILE
    manifest = json.loads(path.read_text()) if path.is_file() else {}
    manifest[GATE_KEY] = record
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"\nrecorded in {path}")


if __name__ == "__main__":
    sys.exit(main())
