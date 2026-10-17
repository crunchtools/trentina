"""Selection accuracy of ``find_tools`` (#473).

For every query in ``corpora/tool_search.py``: the rank of the tool that does
the job among ``find_tools``' results over the corpus catalog. Reported:
recall at 1, 3 and ``top_k``, and mean reciprocal rank, for all queries and
for the held-out ones apart (the ones never used to tune the ranker). With
``--misses``, each query whose tool is not first, with what was.

    uv run python benchmarks/tool_search.py [--top-k 8] [--misses]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.tool_search import CATALOG, CATEGORIES, QUERIES, Query
from trentina.gateway.profile import TOP_K_DEFAULT
from trentina.gateway.tool_search import Entry, ToolIndex


def build_index() -> ToolIndex:
    """The catalog as ``discovery._index`` would build it."""
    category = {b: name for name, backends in CATEGORIES.items() for b in backends}
    return ToolIndex(
        [
            Entry(t.name, category.get(t.backend, t.backend), t.backend, t.description)
            for t in CATALOG
        ]
    )


def ranks(index: ToolIndex, queries: list[Query], top_k: int) -> list[int | None]:
    """The 1-based rank of each query's expected tool, or None past ``top_k``."""
    names = [e.name for e in index.entries]
    found: list[int | None] = []
    for query in queries:
        hits = [names[i] for i in index.search(query.text, top_k)]
        found.append(hits.index(query.expected) + 1 if query.expected in hits else None)
    return found


def summary(found: list[int | None], top_k: int) -> dict[str, float]:
    n = len(found) or 1
    return {
        "queries": len(found),
        "recall@1": sum(1 for r in found if r == 1) / n,
        "recall@3": sum(1 for r in found if r is not None and r <= 3) / n,
        f"recall@{top_k}": sum(1 for r in found if r is not None) / n,
        "mrr": sum(1 / r for r in found if r is not None) / n,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top-k", type=int, default=TOP_K_DEFAULT)
    parser.add_argument("--misses", action="store_true")
    args = parser.parse_args()
    index = build_index()
    found = ranks(index, QUERIES, args.top_k)
    print(f"catalog: {len(CATALOG)} tools in {len(CATEGORIES)} categories")
    for label, keep in (("all", lambda _q: True), ("held-out", lambda q: q.held_out)):
        picked = [r for q, r in zip(QUERIES, found, strict=True) if keep(q)]
        row = summary(picked, args.top_k)
        print(
            label.ljust(9),
            "  ".join(
                f"{k}={v:.3f}" if isinstance(v, float) else f"{k}={v}" for k, v in row.items()
            ),
        )
    if args.misses:
        names = [e.name for e in index.entries]
        for query, rank in zip(QUERIES, found, strict=True):
            if rank != 1:
                top = [names[i] for i in index.search(query.text, 3)]
                print(f"  rank={rank} {query.text!r} want={query.expected} got={top}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
