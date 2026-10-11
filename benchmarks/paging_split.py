"""L2 on an attack that a part boundary cuts in two (#340).

A response too large to judge in one call is delivered in parts
(``gateway/paging.py``), and a part is judged with the last
``GUARD_TOKENS`` tokens of the part before it in front. This measures what
that lead-in is worth to L2. Each corpus attack is set in benign text and
the text is cut inside the attack, a quarter, half and three quarters of the
way through it. The two sides are scored as paging would hand them over: the
first part, and the second part with and without its lead-in. An attack is
caught when either part is flagged.

Only attacks L2 flags uncut, in the same benign text, are counted: what is
measured is what the cut loses, not what L2 misses anyway. L3 is not run.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/paging_split.py --text <file>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.internal import ATTACKS
from trentina.quarantine import classifier

CONTEXT_TOKENS = 400
"""Benign tokens on each side of the attack: most of a window."""

FRACTIONS = (0.25, 0.5, 0.75)
"""How far through the attack's tokens the part boundary falls."""


def split(tokens: list[int], fraction: float) -> int:
    """The token index a boundary ``fraction`` of the way through falls at,
    never at either end: a cut there is not inside the attack."""
    return min(max(round(len(tokens) * fraction), 1), max(len(tokens) - 1, 1))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--text", required=True, help="A long benign text file.")
    p.add_argument("--skip", type=int, default=1_500, help="Leading tokens to drop.")
    args = p.parse_args()

    model = classifier.model_info() if classifier.is_classifier_available() else None
    if model is None:
        print("no L2 model: set CLASSIFIER_MODEL_PATH", file=sys.stderr)
        return 1
    tokenizer = classifier._tokenizer
    benign = classifier._encode(Path(args.text).read_text(errors="replace"))[args.skip :]
    if len(benign) < 2 * CONTEXT_TOKENS:
        print("--text is too short", file=sys.stderr)
        return 1
    before, after = benign[:CONTEXT_TOKENS], benign[CONTEXT_TOKENS : 2 * CONTEXT_TOKENS]

    def flagged(tokens: list[int]) -> bool:
        result = classifier.classify(str(tokenizer.decode(tokens)))
        return result is not None and result.label == "MALICIOUS"

    if flagged(before) or flagged(after):
        print("the benign text is itself flagged; pick another --skip", file=sys.stderr)
        return 1

    counted = 0
    without = dict.fromkeys(FRACTIONS, 0)
    led = dict.fromkeys(FRACTIONS, 0)
    for case in ATTACKS:
        attack = classifier._encode("\n\n" + case.payload + "\n\n")
        if not flagged(before + attack + after):
            continue
        counted += 1
        for fraction in FRACTIONS:
            at = split(attack, fraction)
            first, second = before + attack[:at], attack[at:] + after
            first_flagged = flagged(first)
            without[fraction] += first_flagged or flagged(second)
            led[fraction] += first_flagged or flagged(first[-classifier.GUARD_TOKENS :] + second)

    print(
        f"{model.id}@{model.revision[:12]} threshold {model.threshold}: "
        f"{counted} of {len(ATTACKS)} attacks flagged uncut"
    )
    print("| cut at | caught, no lead-in | caught, with lead-in |")
    print("|---|---|---|")
    for fraction in FRACTIONS:
        print(
            f"| {fraction:.0%} | {without[fraction]} of {counted} | {led[fraction]} of {counted} |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
