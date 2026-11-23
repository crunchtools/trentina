"""What a cold clone costs the git transport's judge (spec 027 phase 1).

Reads a repository's whole history as one pack (``git pack-objects --all``)
through the reader child the gateway runs (``unpack.git_pack_worker``, never
in this process: ``--pack`` may be anyone's) and cuts every object into the units
``git_judge`` would judge, with the same keyed chunking, the same dedup by
key and the same tip rule, and reports: objects by kind, unique units and
their tokens, how many L3 groups of ``GROUP_TOKENS`` that makes, the tip
files judged whole, bytes per token, and how long reading the pack took.
With ``--l2`` it also runs L2 over every unit (``CLASSIFIER_MODEL_PATH``
must point at a model) and reports the score histogram the suspicious mark
is set from, and how many units it flags.

No L3 is called: its count and its tokens are what the bill is read from.

    uv run python benchmarks/git_judge_cost.py --repo <path> [--l2] [--json out.json]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from trentina.config import get_config
from trentina.gateway import git_judge
from trentina.gateway.git_chunks import TOKEN_BYTES, chunk_blob, estimate_tokens
from trentina.gateway.git_fetch import _header, _Reading
from trentina.unpack import child
from trentina.unpack.git_pack import (
    DEFAULT_LIMITS,
    OBJ_BLOB,
    OBJ_COMMIT,
    OBJ_TAG,
    OBJ_TREE,
    PackObject,
    commit_tree,
    is_binary,
    render_text,
    tree_entries,
)

_KEY = b"benchmark-chunk-key-0123456789ab"


def _pack(repo: Path) -> tuple[bytes, str, str]:
    """The repository's whole history as one pack, its object format and HEAD."""
    fmt = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--show-object-format"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    pack = subprocess.run(
        ["git", "-C", str(repo), "pack-objects", "--all", "--stdout", "--delta-base-offset"],
        input=b"",
        capture_output=True,
        check=True,
    ).stdout
    return pack, fmt, head


def _read(pack: bytes, fmt: str) -> list[PackObject]:
    """The pack's objects, read by the reader child under the gateway's limits."""
    with tempfile.TemporaryDirectory() as spool:
        reading = _Reading(fmt, len(pack), DEFAULT_LIMITS.max_inflated, 3600, spool)
        out = subprocess.run(
            reading.argv(), input=pack, capture_output=True, env=child.environment(), check=True
        ).stdout
    objects, i = [], 0
    while True:
        eol = out.index(b"\n", i)
        words = out[i:eol].decode("ascii", "replace").split()
        if words == ["end"]:
            return objects
        if words[:1] == ["refused"]:
            raise SystemExit(f"the reader refused the pack: {words[1:]}")
        kind, oid, offset, length, over = _header(words, DEFAULT_LIMITS.max_inflated)
        i = eol + 1
        if over:
            continue
        objects.append(PackObject(oid=oid, kind=kind, content=out[i : i + length], offset=offset))
        i += length


def _units(objects: list, head: str, oid_len: int) -> tuple[dict[str, str], Counter, int]:
    """Unique units by key, objects by kind, and tip files judged whole."""
    units: dict[str, str] = {}
    kinds: Counter = Counter()
    trees: dict[str, list] = {}
    commit_trees: dict[str, str] = {}
    small: dict[str, bytes] = {}
    whole = get_config().whole_tokens
    for obj in objects:
        kinds[obj.kind] += 1
        if obj.kind in (OBJ_COMMIT, OBJ_TAG):
            text, _enc = render_text(obj.content)
            if obj.kind == OBJ_COMMIT and (tree := commit_tree(obj.content)):
                commit_trees[obj.oid] = tree
            for c in chunk_blob(text.encode(), _KEY):
                units[c.key()] = c.lead_in + c.text
        elif obj.kind == OBJ_TREE:
            entries = tree_entries(obj.content, oid_len=oid_len)
            trees[obj.oid] = entries
            for _mode, name, _oid in entries:
                units[f"name:{name}"] = name
        elif obj.kind == OBJ_BLOB:
            if is_binary(obj.content):
                kinds["blob_binary"] += 1
                continue
            if len(obj.content) <= whole * TOKEN_BYTES:
                small[obj.oid] = obj.content
            for c in chunk_blob(obj.content, _KEY):
                units[c.key()] = c.lead_in + c.text
    tips, roots = set(), [commit_trees.get(head, "")]
    while roots:
        for mode, _name, oid in trees.get(roots.pop(), ()):
            if mode.startswith("40"):
                roots.append(oid)
            elif oid in small:
                tips.add(oid)
    return units, kinds, len(tips)


def _groups(tokens: list[int]) -> int:
    groups, held = 0, 0
    for t in tokens:
        if held and held + t > git_judge.GROUP_TOKENS:
            groups, held = groups + 1, 0
        held += t
    return groups + (1 if held else 0)


async def _l2(texts: list[str]) -> tuple[Counter, int, float]:
    from trentina.quarantine import classifier

    if not classifier.is_classifier_available():
        raise SystemExit("--l2 needs CLASSIFIER_MODEL_PATH pointing at a model")
    scores: Counter = Counter()
    flagged = 0
    started = time.monotonic()
    for text in texts:
        result = await classifier.classify_async(text, source="benchmark")
        if result is None:
            continue
        scores[round(result.score, 1)] += 1
        flagged += result.label == "MALICIOUS"
    return scores, flagged, time.monotonic() - started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=_REPO_ROOT)
    parser.add_argument(
        "--pack",
        type=Path,
        help="a pack already made (git pack-objects --all --stdout), for a host without git;"
        " with --head and --format",
    )
    parser.add_argument("--head", help="the tip commit, with --pack")
    parser.add_argument("--format", default="sha1", help="the object format, with --pack")
    parser.add_argument("--l2", action="store_true", help="run L2 over the units")
    parser.add_argument(
        "--sample", type=int, default=0, help="L2 over this many units drawn at random (seed 0)"
    )
    parser.add_argument("--json", type=Path, help="write the report here too")
    args = parser.parse_args()

    if args.pack:
        pack, fmt, head = args.pack.read_bytes(), args.format, args.head
    else:
        pack, fmt, head = _pack(args.repo)
    started = time.monotonic()
    objects = _read(pack, fmt)
    read_seconds = time.monotonic() - started
    units, kinds, tips = _units(objects, head, 32 if fmt == "sha256" else 20)
    tokens = [estimate_tokens(text) for text in units.values()]
    unit_bytes = sum(len(text.encode()) for text in units.values())
    report: dict = {
        "pack_bytes": len(pack),
        "read_seconds": round(read_seconds, 2),
        "objects": dict(kinds),
        "unique_units": len(units),
        "unit_bytes": unit_bytes,
        "unit_tokens": sum(tokens),
        "l3_groups_if_all_clean": _groups(tokens),
        "tip_files_whole": tips,
        "bytes_per_token_estimate": TOKEN_BYTES,
    }
    if args.l2:
        texts = list(units.values())
        if args.sample:
            texts = random.Random(0).sample(texts, min(args.sample, len(texts)))
        scores, flagged, seconds = asyncio.run(_l2(texts))
        report["l2_units"] = len(texts)
        report["l2"] = {
            "seconds": round(seconds, 1),
            "ms_per_token": round(
                seconds * 1000 / max(sum(estimate_tokens(t) for t in texts), 1), 3
            ),
            "flagged": flagged,
            "flag_rate": round(flagged / max(len(texts), 1), 5),
            "score_histogram": {str(k): v for k, v in sorted(scores.items())},
        }
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
