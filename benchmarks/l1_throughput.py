"""How fast L1 reads text nobody attacked, with and without the literal gate.

The directive stage was three quarters of L1's time: every exact pattern ran
on every line, up to five times a line, and a line that matches nothing is
the slow case because nothing short-circuits. ``directives.matches_exact``
now runs a pattern only when a literal it needs is in the string (#709). The
ROT13 and backwards asks have since moved to the unpack stage's letter
reader (#744), which asks the same patterns, so the gate is switched there
too. This reports the stage, the unpack stage and the whole of L1, gated and
ungated, on the same haystack.

    uv run python benchmarks/l1_throughput.py            # docs/
    uv run python benchmarks/l1_throughput.py docs src   # any files or directories

No model and no key: L1 only.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from trentina.l1 import directives
from trentina.l1.pipeline import run_l1
from trentina.unpack import letters
from trentina.unpack.scan import unpack

_TEXT = {".md", ".py", ".txt", ".yaml", ".yml", ".toml", ".json", ".html", ".log"}


def _haystack(paths: list[str]) -> str:
    parts: list[str] = []
    for raw in paths:
        root = Path(raw)
        members = sorted(root.rglob("*")) if root.is_dir() else [root]
        parts += [p.read_text(errors="replace") for p in members if p.suffix in _TEXT]
    return "\n".join(parts)


def _best(run: Callable[[], object], rounds: int) -> float:
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        run()
        times.append(time.perf_counter() - start)
    return min(times)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", default=[str(_REPO_ROOT / "docs")])
    parser.add_argument("--rounds", type=int, default=3, help="best of this many (default 3)")
    args = parser.parse_args(argv)

    text = _haystack(args.paths)
    megabytes = len(text.encode()) / 1e6
    print(f"{megabytes * 1000:.0f} KB, {text.count(chr(10)) + 1} lines, best of {args.rounds}")

    gated = directives.matches_exact
    timings: dict[str, tuple[float, float, float]] = {}
    for label, match in (("ungated", directives._matches_every_pattern), ("gated", gated)):
        directives.matches_exact = letters.matches_exact = match
        try:
            stage = _best(lambda: directives.strip_directives(text), args.rounds)
            unpacked = _best(lambda: unpack(text), args.rounds)
            whole = _best(lambda: run_l1(text), args.rounds)
        finally:
            directives.matches_exact = letters.matches_exact = gated
        timings[label] = (stage, unpacked, whole)
        print(
            f"{label:8} directives {stage * 1000:6.0f} ms {megabytes / stage:5.1f} MB/s"
            f"   unpack {unpacked * 1000:6.0f} ms   run_l1 {whole * 1000:6.0f} ms"
        )
    (s0, u0, w0), (s1, u1, w1) = timings["ungated"], timings["gated"]
    print(f"speed-up  directives {s0 / s1:.2f}x   unpack {u0 / u1:.2f}x   run_l1 {w0 / w1:.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
