"""Measure the outbound credential detector before it gates a request (#511).

The request paths (`/llm`, and the egress route) refuse or flag on
`trentina.credential_shapes`. A detector that fires on benign traffic blocks an
agent's real work, so it is measured the way L2's benign gate is: recall on an
ATTACK set and a false-positive rate on a BENIGN set, reported as two numbers,
never one.

    uv run python benchmarks/credential_shapes.py          # report
    uv run python benchmarks/credential_shapes.py --max-fp 0.02   # gate

The corpus is `corpora/credential_shapes.py`: invented requests, fixed seed.
The agent-egress-bench corpus (#507) is HELD OUT and never read here. No model
and no key — the detector is deterministic regex.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dataclasses import dataclass

from corpora.credential_shapes import ATTACKS, BENIGN, KNOWN_GAPS
from trentina.credential_shapes import kinds


@dataclass
class Score:
    attacks: int
    benign: int
    missed: list[str]
    missing_kind: list[str]
    false_positives: list[tuple[str, list[str]]]

    @property
    def recall(self) -> float:
        return (self.attacks - len(self.missed)) / self.attacks if self.attacks else 1.0

    @property
    def fp_rate(self) -> float:
        return len(self.false_positives) / self.benign if self.benign else 0.0


def _score() -> Score:
    missed: list[str] = []
    missing_kind: list[str] = []
    for case in ATTACKS:
        found = set(kinds(case.text))
        if not found:
            missed.append(case.id)
        elif not set(case.expect) <= found:
            missing_kind.append(case.id)
    false_positives = [
        (case.id, sorted(k.value for k in found)) for case in BENIGN if (found := kinds(case.text))
    ]
    return Score(len(ATTACKS), len(BENIGN), missed, missing_kind, false_positives)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-fp",
        type=float,
        default=None,
        help="Fail if the benign false-positive rate exceeds this fraction (e.g. 0.02).",
    )
    args = parser.parse_args()

    s = _score()
    missed, missing_kind, false_positives = s.missed, s.missing_kind, s.false_positives
    recall, fp_rate = s.recall, s.fp_rate

    print(f"attacks:        {len(ATTACKS)}")
    print(f"  recall:       {recall:.1%}  ({len(ATTACKS) - len(missed)}/{len(ATTACKS)})")
    if missed:
        print(f"  MISSED:       {', '.join(missed)}")
    if missing_kind:
        print(f"  missing kind: {', '.join(missing_kind)}")
    print(f"benign:         {len(BENIGN)}")
    print(f"  fp rate:      {fp_rate:.1%}  ({len(false_positives)}/{len(BENIGN)})")
    for case_id, found in false_positives:
        print(f"  FALSE POS:    {case_id} -> {', '.join(found)}")
    if KNOWN_GAPS:
        print(f"known gaps (scored, not gated): {', '.join(KNOWN_GAPS)}")

    by_kind: Counter[str] = Counter()
    for case in ATTACKS:
        for kind in case.expect:
            by_kind[kind.value] += 1
    print("attack kinds:   " + ", ".join(f"{k}={n}" for k, n in sorted(by_kind.items())))

    failed = False
    if missed or missing_kind:
        print("FAIL: an attack case was missed or mislabelled")
        failed = True
    if args.max_fp is not None and fp_rate > args.max_fp:
        print(f"FAIL: fp rate {fp_rate:.1%} over the {args.max_fp:.1%} limit")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
