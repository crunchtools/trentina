"""Does L1's briefing help L3? An ablation of the Layer contract's findings.

L1 is count-only: it never changes what L2 or L3 read, and its one lever on
L3 is the briefing (``build_l3_briefing`` names each non-zero count). This
measures whether that lever does anything. Every payload is unpacked as
``defend()`` does it (decoded and labelled, #367), then goes through real L1
and real L2, then L3 twice over:

- ``full``: the production briefing, L1's findings by type.
- ``ablated``: the same briefing built from empty L1 stats, so L3 is told
  "no known patterns". L2's line and the caveat are identical.

Where L1 found nothing the two briefings are the same string, so only the
``full`` arm runs. Each arm is called ``--reps`` times and majority-voted;
the agreement rate is L3's own noise floor, against which a flip is read.

The pipeline verdict is reported too: L1's own refusal (high/critical) or L2
or L3, against L2 or the ablated L3 — L1's whole contribution, briefing and
vote together.

Payload sets: the semantic corpus plain, both its attacks and its benign
cases under the six transforms of ``l2_obfuscation.py``, and the L1 pattern
cases (attacks and near-misses). The semantic corpus is built to slip past
L1, so the transformed and pattern sets are where L1 has something to say.

Needs a loaded L2 model and an L3 key, as the gateway does:

    CLASSIFIER_MODEL_PATH=<export> TRENTINA_MODEL_PROVIDER=openrouter \\
    OPENROUTER_API_KEY=... uv run python benchmarks/l1_briefing.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.l2_obfuscation import TRANSFORMS
from corpora.internal import ATTACKS, BENIGN
from corpora.l1_patterns import L1_PATTERN_CASES
from trentina.defense import build_l3_briefing
from trentina.l1 import run_l1
from trentina.l1.pipeline import PipelineStats
from trentina.quarantine.agent import quarantine_detect
from trentina.quarantine.classifier import (
    ClassifierResult,
    classify,
    is_classifier_available,
)
from trentina.unpack.scan import unpack

_L1_REFUSES = ("high", "critical")


@dataclass
class Row:
    set: str
    attack: bool
    l1_findings: list[str]
    l1_refuses: bool
    l2_flags: bool
    full: list[bool | None] = field(default_factory=list)
    ablated: list[bool | None] = field(default_factory=list)


async def _l3(sem: asyncio.Semaphore, text: str, briefing: str) -> bool | None:
    """L3's verdict, or None when it could not answer after retries."""
    for attempt in range(4):
        async with sem:
            result = await quarantine_detect(text, layer1_context=briefing)
        if not result.get("l3_unavailable"):
            return result.get("injection_detected") is True
        await asyncio.sleep(2**attempt)
    return None


def _vote(calls: list[bool | None]) -> bool | None:
    answered = [c for c in calls if c is not None]
    return None if not answered else sum(answered) * 2 > len(answered)


async def _judge(
    sem: asyncio.Semaphore,
    row: Row,
    text: str,
    stats: PipelineStats,
    reps: int,
    l2: ClassifierResult | None,
) -> None:
    full = build_l3_briefing(stats, l2)
    ablated = build_l3_briefing(PipelineStats(), l2)
    row.full = list(await asyncio.gather(*(_l3(sem, text, full) for _ in range(reps))))
    if full != ablated:
        row.ablated = list(await asyncio.gather(*(_l3(sem, text, ablated) for _ in range(reps))))


def _pct(n: int, d: int) -> str:
    return f"{n}/{d}" if d else "-"


def _report(rows: list[Row]) -> str:
    lines = [
        (
            "| set | n | L1 fired | L1 refuses | L2 flags | L3 full | L3 ablated | "
            "L3 flips + / - | pipeline full | pipeline ablated |"
        ),
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    noise = Counter[str]()
    for name in dict.fromkeys(r.set + (" (attack)" if r.attack else " (benign)") for r in rows):
        group = [r for r in rows if r.set + (" (attack)" if r.attack else " (benign)") == name]
        fired = [r for r in group if r.l1_findings]
        full = [_vote(r.full) for r in fired]
        abl = [_vote(r.ablated) for r in fired]
        gained = sum(f is True and a is False for f, a in zip(full, abl, strict=True))
        lost = sum(f is False and a is True for f, a in zip(full, abl, strict=True))
        pipe_full = sum(r.l1_refuses or r.l2_flags or _vote(r.full) is True for r in group)
        pipe_abl = sum(
            r.l2_flags or _vote(r.ablated if r.ablated else r.full) is True for r in group
        )
        lines.append(
            f"| {name} | {len(group)} | {len(fired)} | {sum(r.l1_refuses for r in group)} | "
            f"{sum(r.l2_flags for r in group)} | "
            f"{_pct(sum(f is True for f in full), len(fired))} | "
            f"{_pct(sum(a is True for a in abl), len(fired))} | +{gained} / -{lost} | "
            f"{pipe_full}/{len(group)} | {pipe_abl}/{len(group)} |"
        )
        for r in group:
            for arm, calls in (("full", r.full), ("ablated", r.ablated)):
                answered = [c for c in calls if c is not None]
                if answered:
                    noise[f"{arm} calls"] += 1
                    noise[f"{arm} split"] += len(set(answered)) > 1
                noise["unanswered"] += calls.count(None)
    lines.append(
        f"\nL3 noise: {noise['full split']}/{noise['full calls']} full and "
        f"{noise['ablated split']}/{noise['ablated calls']} ablated payloads split across "
        f"reps; {noise['unanswered']} calls unanswered."
    )
    lines.append(
        "\nL3 columns count only payloads where L1 fired (elsewhere the arms are "
        "identical). Flips: + full caught or flagged what ablated did not, - the reverse. "
        "On a benign row a + is a false positive L1's briefing caused."
    )
    return "\n".join(lines)


async def _run(reps: int, concurrency: int) -> list[Row]:
    sem = asyncio.Semaphore(concurrency)
    rows: list[Row] = []
    jobs = []
    payloads = [("semantic", True, c.payload) for c in ATTACKS]
    payloads += [("semantic", False, c.payload) for c in BENIGN]
    for name, transform in TRANSFORMS.items():
        payloads += [(f"attack/{name}", True, transform(c.payload)) for c in ATTACKS]
        payloads += [(f"benign/{name}", False, transform(c.payload)) for c in BENIGN]
    payloads += [("pattern", p.expect_detection, p.payload) for p in L1_PATTERN_CASES]
    for set_name, attack, delivered in payloads:
        # What every layer reads, as defend() builds it (#367).
        view = unpack(delivered)
        text = view.text
        pipeline = run_l1(text)
        pipeline.stats.unpacked = view.stats
        l2 = classify(text)
        row = Row(
            set=set_name,
            attack=attack,
            l1_findings=pipeline.stats.findings(),
            l1_refuses=bool(pipeline.stats.total_detections())
            and pipeline.stats.risk_level() in _L1_REFUSES,
            l2_flags=l2 is not None and l2.label == "MALICIOUS",
        )
        rows.append(row)
        jobs.append(_judge(sem, row, text, pipeline.stats, reps, l2))
    await asyncio.gather(*jobs)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reps", type=int, default=3, help="L3 calls per arm (default 3)")
    parser.add_argument("--concurrency", type=int, default=8, help="L3 calls in flight")
    parser.add_argument("--json", type=Path, help="write every row here")
    args = parser.parse_args(argv)
    if not is_classifier_available():
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2
    rows = asyncio.run(_run(args.reps, args.concurrency))
    if args.json:
        args.json.write_text(json.dumps([asdict(r) for r in rows], indent=1))
    print(_report(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
