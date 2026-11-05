"""Record or check the perimeter golden oracle (#535 R1).

    uv run python scripts/record_golden.py --check    # the fixtures still hold
    uv run python scripts/record_golden.py --record   # re-record (pre-spine only)

The fixtures under ``tests/golden/fixtures`` are the contract the spine is held
to, so they are recorded from the code BEFORE it. Recording on a tree that has
the spine would turn whatever the spine does into the contract, so ``--record``
refuses once ``transports/perimeter.py`` exists. Recording runs through pytest,
in this process,
so it sees exactly the isolation the check does.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPINE = ROOT / "src" / "trentina" / "transports" / "perimeter.py"
TEST = "tests/test_perimeter_golden.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="assert the fixtures hold")
    mode.add_argument("--record", action="store_true", help="re-record every fixture")
    args = parser.parse_args()

    if args.record:
        if SPINE.exists():
            print(
                f"refusing to record: {SPINE.relative_to(ROOT)} exists, so this tree has the "
                "spine; the oracle is recorded from the code before it",
                file=sys.stderr,
            )
            return 2
        for old in (ROOT / "tests" / "golden" / "fixtures").glob("*.json"):
            old.unlink()
        sys.path.insert(0, str(ROOT))
        from tests import perimeter_golden

        perimeter_golden.RECORDING = True
        # One process: the flag above must be the one the cases read.
        return int(pytest.main([TEST, "-q", "-p", "no:cacheprovider", "-n", "0"]))
    return int(pytest.main([TEST, "-q", "-p", "no:cacheprovider"]))


if __name__ == "__main__":
    raise SystemExit(main())
