"""Build the L2 fine-tuning set: benign and attack text, plain and in envelopes.

The shipped model learned that a JSON tool reply is where attacks live: its
training mixes injections planted in tool responses with benign prose, and
no benign tool reply. This set gives it the missing half without teaching the
opposite mistake. Every envelope in ``corpora/envelopes.py`` wraps benign
text AND attack text, so the label depends on what is said, never on the
wrapper; and the plain rows (the same sources, unwrapped) are replayed so it
keeps what it already reads well.

Sources are pinned third-party sets the model card already lists, all
permissive, and none of the sets Trentina measures on: the deepset and
jackhhao splits, the internal corpus, ``benign_ops``'s held-out split and
every planted set stay out, so the gates still mean what they meant.
``benign_ops``'s tuning split (one case in four, the split a threshold is
chosen on) goes in as an anchor: logs, unit status and source code are shapes
no public set has, and without them the model drifts off what the shipped one
reads well there (run 40202667628: 4 to 41 of 221 benign_ops cases flagged).
Each row is rendered the way the gateway renders a tool reply
(``corpora.gateway_read.as_read``).

    uv run python scripts/l2_train_data.py --out build/l2-train

Writes ``train.jsonl`` and ``val.jsonl`` (``{"text", "label", "shape", "distill"}``,
and ``at`` on an attack) and
``sources.json`` naming every pinned file it read.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.benign_ops import BENIGN, in_tuning
from corpora.envelopes import MAKERS
from corpora.gateway_read import as_read

SEED = 20261025
VAL_ONE_IN = 10
"""One source text in ten is validation. The split is by text, before any
row is built, so no text reaches both sides in another envelope or plain."""

MIN_CHARS = 20
"""Shorter source texts are dropped: a fragment says nothing."""
MAX_CHARS = 4000
"""Longer source texts are dropped: past this a text alone outgrows the
512-token window the model trains on."""

PER_ENVELOPE = 120
"""Benign rows per envelope; each has an attack twin, and half as many attacks
arrive alone, so an envelope holds 300 rows as it did before the twins."""
REPLAY = 1000
ANCHOR_REPEATS = 8
"""Times each ``benign_ops`` tuning case appears in training: about 85 cases,
so the anchor weighs about as much as one envelope's benign rows times five."""

SOURCES: tuple[dict[str, Any], ...] = (
    {
        "repo": "rgeada/tool-response-injections",
        "revision": "39050de797f2694f0d72e1086003154de1919379",
        "file": "tool_response_injections_train.csv",
        "text": "text",
        "label": lambda v: v == "injection",
    },
    {
        "repo": "3nesdeniz/agentic-prompt-injection-5k",
        "revision": "e658d94dcafc133e3a4483f9f9aa13507f3848c4",
        "file": "data/train.parquet",
        "text": "text",
        "label": lambda v: int(v) == 1,
    },
    {
        "repo": "neuralchemy/Prompt-injection-dataset",
        "revision": "7d70432dfcf47a821612cbf9d34e9d9e3ad20e75",
        "file": "core/train-00000-of-00001.parquet",
        "text": "text",
        "label": lambda v: int(v) == 1,
    },
    {
        "repo": "S-Labs/prompt-injection-dataset",
        "revision": "002a9dd18514abd021869823d6b0429b38606d99",
        "file": "data/train.csv",
        "text": "text",
        "label": lambda v: int(v) == 1,
    },
    {
        "repo": "hendzh/PromptShield",
        "revision": "a5234cb1f5cdb256600cab64b8c961195b5e8404",
        "file": "train.json",
        "text": "prompt",
        "label": lambda v: int(v) == 1,
    },
    {
        "repo": "microsoft/llmail-inject-challenge",
        "revision": "1063bdf01ec8762b812d5e06ee768a06faa5a6f7",
        "file": "data/emails_for_fp_tests.json",
        "emails": True,
    },
)

SECURITY_WORDS = re.compile(
    r"secur|attack|exploit|vulnerab|inject|malware|phish|password|credential|"
    r"prompt|jailbreak|classifier|firewall|breach|CVE-|patch|token|auth",
    re.IGNORECASE,
)
"""Benign text that talks about attacks is what the shipped model refuses in
an envelope (gap 31), so it is oversampled into the envelopes."""


def _email_rows(path: Path) -> list[tuple[str, bool]]:
    """llmail's benign emails: a list of "Subject of the email: <s>.   Body: <b>"."""
    rows = []
    for item in json.loads(path.read_text()):
        subject, _, body = str(item).removeprefix("Subject of the email: ").partition("Body: ")
        rows.append((f"{subject.strip().rstrip('.')}\n{body.strip()}", False))
    return rows


def _table_rows(src: dict[str, Any], path: Path) -> list[tuple[str, bool]]:
    """A labelled table's ``(text, is_attack)`` rows."""
    import pandas as pd

    readers = {".parquet": pd.read_parquet, ".csv": pd.read_csv, ".json": pd.read_json}
    frame = readers[path.suffix](path)
    return [
        (str(t), bool(src["label"](lab)))
        for t, lab in zip(frame[src["text"]], frame["label"], strict=True)
        if isinstance(t, str) and MIN_CHARS <= len(t) <= MAX_CHARS
    ]


def load_sources(cache: Path) -> tuple[list[str], list[str], list[dict[str, str]]]:
    """Deduplicated (benign, attack) texts and the provenance of each file."""
    from huggingface_hub import hf_hub_download

    benign: dict[str, None] = {}
    attack: dict[str, None] = {}
    provenance = []
    for src in SOURCES:
        path = Path(
            hf_hub_download(
                src["repo"],
                src["file"],
                revision=src["revision"],
                repo_type="dataset",
                cache_dir=cache,
            )
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        provenance.append(
            {
                "repo": src["repo"],
                "revision": src["revision"],
                "file": src["file"],
                "sha256": digest,
            }
        )
        rows = _email_rows(path) if src.get("emails") else _table_rows(src, path)
        for text, is_attack in rows:
            (attack if is_attack else benign).setdefault(text.strip(), None)
    overlap = benign.keys() & attack.keys()
    for text in overlap:  # a text labelled both ways teaches nothing
        benign.pop(text)
        attack.pop(text)
    return list(benign), list(attack), provenance


_SAFE_RUN = re.compile(r"[A-Za-z0-9 ,.:;!?()'-]{24,}")
"""A stretch of an attack that any envelope's escaping leaves as written."""


def attack_at(attack: str, rendered: str) -> int:
    """Where ``attack`` begins in ``rendered``, by its first stretch that survives
    JSON escaping; -1 when none can be found (the row is then dropped in training)."""
    for run in _SAFE_RUN.finditer(attack):
        at = rendered.find(run.group(0))
        if at >= 0:
            return max(0, at - run.start())
    return -1


def plant(rng: random.Random, text: str, attack: str) -> str:
    """``text`` with ``attack`` inserted at one of its line or sentence breaks."""
    breaks = [0, len(text)] + [m.end() for m in re.finditer(r"[.!?]\s+|\n", text)]
    at = rng.choice(breaks)
    return f"{text[:at].rstrip()}\n{attack}\n{text[at:].lstrip()}".strip()


async def _enveloped(
    shape: str, make: Any, seed: int, text: str, attack: str | None
) -> dict[str, Any]:
    """One row: ``text`` (an attack, or planted with ``attack``) in ``shape``'s envelope."""
    rendered = await as_read(make(random.Random(seed), text), shape)
    if attack is None:
        return {"text": rendered, "label": 0, "shape": shape, "distill": False}
    at = attack_at(attack, rendered)
    return {"text": rendered, "label": 1, "shape": shape, "at": at, "distill": False}


async def build(
    benign: list[str], attack: list[str], per_envelope: int, replay: int
) -> list[dict[str, Any]]:
    """Rows: every envelope around benign text and its attack twin, attacks
    alone, and plain replay.

    The twin is the benign row's envelope, built from the same seed, with an
    attack planted in its text: the pair differs only in what is said, so
    neither the wrapper nor where a text came from can carry the label
    (counterfactual pairs, Kaushik et al. 2020). Enveloped rows train on
    their labels; plain rows (``distill``) also train toward the base model's
    own score, so it keeps what it already reads well.
    """
    rng = random.Random(SEED)
    security = [t for t in benign if SECURITY_WORDS.search(t)]
    rows: list[dict[str, Any]] = []
    for shape, make in MAKERS.items():
        for i in range(per_envelope):
            pool = security if security and i % 2 == 0 else benign
            text, planted, seed = rng.choice(pool), rng.choice(attack), rng.getrandbits(64)
            rows.append(await _enveloped(shape, make, seed, text, None))
            rows.append(await _enveloped(shape, make, seed, plant(rng, text, planted), planted))
        for _ in range(per_envelope // 2):
            text = rng.choice(attack)
            rows.append(await _enveloped(shape, make, rng.getrandbits(64), text, text))
    rows += [
        {"text": t, "label": 0, "shape": "plain", "distill": True}
        for t in rng.sample(benign, min(replay, len(benign)))
    ]
    rows += [
        {"text": t, "label": 1, "shape": "plain", "at": 0, "distill": True}
        for t in rng.sample(attack, min(replay, len(attack)))
    ]
    rng.shuffle(rows)
    return rows


async def anchors() -> list[dict[str, Any]]:
    """``benign_ops``'s tuning split, ``ANCHOR_REPEATS`` times; never its held-out cases."""
    rows = []
    for case in BENIGN:
        if in_tuning(case.id):
            text = await as_read(case.payload, case.category)
            row = {"text": text, "label": 0, "shape": "ops", "distill": True}
            rows += [row] * ANCHOR_REPEATS
    return rows


def _in_val(text: str) -> bool:
    return int(hashlib.sha256(text.encode()).hexdigest(), 16) % VAL_ONE_IN == 0


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--cache", type=Path, default=Path("build/hf-cache"))
    p.add_argument(
        "--per-envelope",
        type=int,
        default=PER_ENVELOPE,
        help="Benign rows, and attack rows, per envelope.",
    )
    p.add_argument(
        "--replay", type=int, default=REPLAY, help="Plain benign rows, and plain attack rows."
    )
    args = p.parse_args()
    benign, attack, provenance = load_sources(args.cache)
    split = {
        name: (
            [t for t in benign if _in_val(t) == held],
            [t for t in attack if _in_val(t) == held],
        )
        for name, held in (("train", False), ("val", True))
    }
    train = asyncio.run(build(*split["train"], args.per_envelope, args.replay))
    train += asyncio.run(anchors())
    random.Random(SEED).shuffle(train)
    val = asyncio.run(
        build(*split["val"], args.per_envelope // VAL_ONE_IN, args.replay // VAL_ONE_IN)
    )
    rows = train + val
    args.out.mkdir(parents=True, exist_ok=True)
    _write(args.out / "train.jsonl", train)
    _write(args.out / "val.jsonl", val)
    (args.out / "sources.json").write_text(
        json.dumps(
            {
                "seed": SEED,
                "benign_texts": len(benign),
                "attack_texts": len(attack),
                "rows": len(rows),
                "sources": provenance,
            },
            indent=2,
        )
    )
    print(
        f"{len(rows)} rows from {len(benign)} benign and {len(attack)} attack texts -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
