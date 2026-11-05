"""L1 throughput: the directive stage and the whole screen (#709).

Builds a haystack from ``docs/**/*.md`` and times ``strip_directives`` and
``run_l1`` over it. Run: ``uv run python benchmarks/l1_throughput.py``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from trentina.l1.directives import strip_directives
from trentina.l1.pipeline import run_l1


def _haystack() -> str:
    root = Path(__file__).resolve().parent.parent / "docs"
    return "\n".join(p.read_text(errors="replace") for p in sorted(root.rglob("*.md")))


def _best(fn: Callable[[str], object], text: str, repeats: int = 3) -> float:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn(text)
        times.append(time.perf_counter() - start)
    return min(times)


def main() -> None:
    text = _haystack()
    mb = len(text.encode()) / 1e6
    for name, fn in (("strip_directives", strip_directives), ("run_l1", run_l1)):
        seconds = _best(fn, text)
        print(f"{name:18} {seconds * 1000:8.1f} ms  {mb / seconds:6.2f} MB/s")


if __name__ == "__main__":
    main()
