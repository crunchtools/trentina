"""L2 in real envelopes: benign and attack text wrapped as backends return it.

``corpora/envelopes.py`` wraps one text in each backend's reply (the GitHub
issue, the Miniflux entry, Metsuke's sweep page, a Gmail message, a journal).
This scores the loaded model on the same texts in every envelope, read the
way the gateway reads a tool response (``corpora.gateway_read.as_read``), so the
two numbers that matter sit side by side per envelope: how much benign text
the envelope turns into a refusal, and how many attacks are still caught
inside it.

The texts come from sets no L2 training run here uses: the deepset test split
(benign and injection rows) and the internal attacks (``corpora/internal``).
Measured 2026-10-25 on the shipped model, benign text that scores at most
0.026 as prose flags 8 of 20 times as a GitHub issue reply.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_envelopes.py

``--json`` writes every score. Exit 1 when held-out benign envelopes flag
above ``BENIGN_MAX_RATE`` at the model's threshold, or ``--min-attack-rate``
is set and enveloped attacks fall below it.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.envelopes import MAKERS
from corpora.fetch import CACHE_DIR, download, pinned
from corpora.gateway_read import as_read
from corpora.internal import CORPUS
from trentina.quarantine.benign_gate import BENIGN_MAX_RATE
from trentina.quarantine.classifier import classify, is_classifier_available, model_info

SEED = 1025
PER_ENVELOPE = 40
"""Benign texts and attack texts wrapped in each envelope."""

DEEPSET_REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
DEEPSET_TEST = (
    "https://huggingface.co/datasets/deepset/prompt-injections/resolve/"
    f"{DEEPSET_REVISION}/data/test-00000-of-00001-701d16158af87368.parquet"
)
DEEPSET_TEST_SHA256 = "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e"


def deepset_test() -> tuple[list[str], list[str]]:
    """The deepset test split as (benign, injection) texts."""
    import pyarrow.parquet as pq  # benchmark-only dependency

    raw = pinned(
        CACHE_DIR / f"deepset-test-{DEEPSET_REVISION[:12]}.parquet",
        DEEPSET_TEST_SHA256,
        lambda: download(DEEPSET_TEST),
        "deepset test",
    )
    table = pq.read_table(io.BytesIO(raw)).to_pylist()
    return [r["text"] for r in table if r["label"] == 0], [
        r["text"] for r in table if r["label"] == 1
    ]


async def score_all() -> dict[str, dict[str, list[float]]]:
    """``{envelope: {"benign": [...], "attack": [...]}}`` scores."""
    benign, injected = deepset_test()
    attacks = injected + [c.payload for c in CORPUS if c.expect_injection]
    rng = random.Random(SEED)
    out: dict[str, dict[str, list[float]]] = {}
    for name, make in MAKERS.items():
        b = rng.sample(benign, min(PER_ENVELOPE, len(benign)))
        a = rng.sample(attacks, min(PER_ENVELOPE, len(attacks)))
        out[name] = {
            "benign": [_score(await as_read(make(rng, t), name)) for t in b],
            "attack": [_score(await as_read(make(rng, t), name)) for t in a],
        }
    return out


def _score(text: str) -> float:
    result = classify(text)
    if result is None:
        raise RuntimeError("the L2 model stopped answering")
    return result.score


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--json", type=Path, help="Write every score here.")
    p.add_argument(
        "--min-attack-rate", type=float, help="Fail below this enveloped-attack detection rate."
    )
    args = p.parse_args()
    if not is_classifier_available():
        print("no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2
    info = model_info()
    cut = info.threshold if info else 0.5
    scores = asyncio.run(score_all())
    print(f"| envelope | benign flagged @{cut} | attacks caught @{cut} |\n|---|---|---|")
    tb = ta = nb = na = 0
    for name, s in scores.items():
        fb, fa = sum(x >= cut for x in s["benign"]), sum(x >= cut for x in s["attack"])
        tb, ta, nb, na = tb + fb, ta + fa, nb + len(s["benign"]), na + len(s["attack"])
        print(f"| {name} | {fb} of {len(s['benign'])} | {fa} of {len(s['attack'])} |")
    print(f"| **all** | **{tb} of {nb}** | **{ta} of {na}** |")
    if args.json:
        args.json.write_text(json.dumps({"threshold": cut, "scores": scores}))
    failed = tb / nb > BENIGN_MAX_RATE
    if args.min_attack_rate is not None and ta / na < args.min_attack_rate:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
