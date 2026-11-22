#!/usr/bin/env python3
"""L3 on LLM completions, as the ``/proxy/llm`` response edge judges them (a1013).

The completion edge hands ``defend()`` the provider's raw response body (JSON
or an event stream, whatever streamed) as ``MODEL_OUTPUT``, briefed with
``prompts.COMPLETION_BRIEFING``. Switching L3 to gemini-2.5-flash-lite
took Gatehouse's completions from about one flag in six hundred to one in
six: encrypted reasoning read as ``hidden_content`` and security reviews read
as ``data_exfiltration``. This measures a judge and a briefing on two sets:

- **bodies**: a directory of recorded response bodies, one per file. Every
  one is benign (the gateway delivered it to a working agent), so every flag
  is a false positive. The bodies are NOT in this repository: they are model
  output about private diffs. Record your own; ``--bodies`` reads ``*.json``.
- **attacks**: every attack in ``corpora/internal.py``, placed as the
  answer (``choices[0].message.content``) inside the first JSON body's own
  envelope, encrypted reasoning and all. What the briefing excuses must not
  include an attack that arrives inside a completion.

``--briefing none`` is the edge before a1013; ``completion`` is the shipped
briefing. L2 is not loaded: it is answered BENIGN at ``--l2-score``, which is
what production's L2 said of every flagged completion (0.15 to 0.32), so the
briefing L3 reads matches production's and L3 is measured on its own.

    TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL=google/gemini-2.5-flash-lite \\
        uv run python benchmarks/llm_completion.py --bodies <dir> --briefing none \\
        --attacks --votes 3 --json before.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.internal import ATTACKS
from trentina import defense
from trentina.defense import Provenance, defend
from trentina.quarantine import l3_cache
from trentina.quarantine.classifier import ClassifierResult
from trentina.quarantine.prompts import COMPLETION_BRIEFING
from trentina.quarantine.providers import openai as openai_provider

BRIEFINGS = {"none": None, "completion": COMPLETION_BRIEFING}


def bodies(directory: Path) -> list[tuple[str, str]]:
    """``(id, body)`` for each recorded response, by file name."""
    return [
        (path.stem, path.read_text(encoding="utf-8", errors="replace"))
        for path in sorted(directory.glob("*.json"))
    ]


def envelope(template: str, answer: str) -> str:
    """``template``'s response with ``answer`` as its first choice's content."""
    body = json.loads(template)
    body["choices"][0]["message"]["content"] = answer
    return json.dumps(body)


def attack_cases(template: str) -> list[tuple[str, str]]:
    """Each internal corpus attack as the answer of a recorded completion."""
    return [(f"{case.category}/{case.id}", envelope(template, case.payload)) for case in ATTACKS]


def stub_l2(score: float) -> None:
    """Answer L2 BENIGN at ``score`` without loading a model."""

    async def benign(text: str, source: str, *, stop_on_partial: bool) -> Any:
        return ClassifierResult(label="BENIGN", score=score, latency_ms=0.0), False

    setattr(defense, "_classify", benign)


async def judge(body: str, briefing: str | None) -> dict[str, Any]:
    """One reading of ``body`` by the layers, as the completion edge asks."""
    verdict = await defend(
        body,
        source="llm:benchmark:completion",
        source_type="llm_completion",
        provenance=Provenance.MODEL_OUTPUT,
        record=False,
        l3_context=briefing,
    )
    assessment = verdict.l3_assessment or {}
    return {
        "flagged": verdict.flagged,
        "flagged_by": verdict.flagged_by.value if verdict.flagged_by else None,
        "risk": assessment.get("risk_level") or verdict.risk_level,
        "unavailable": bool(assessment.get("l3_unavailable")),
        "error": assessment.get("summary") if assessment.get("l3_unavailable") else None,
    }


async def run(
    cases: list[tuple[str, str]], briefing: str | None, votes: int, concurrency: int
) -> dict[str, list[dict[str, Any]]]:
    """Every case ``votes`` times. The L3 cache is cleared between rounds, so
    a vote is a fresh call and not the last round's answer."""
    gate = asyncio.Semaphore(concurrency)
    readings: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id, _ in cases}

    async def one(case_id: str, body: str) -> None:
        async with gate:
            readings[case_id].append(await judge(body, briefing))

    for _ in range(votes):
        l3_cache.reset_l3_cache()
        await asyncio.gather(*(one(case_id, body) for case_id, body in cases))
    return readings


def majority(readings: list[dict[str, Any]]) -> dict[str, Any]:
    """The case's verdict: flagged on a strict majority of answered readings."""
    answered = [r for r in readings if not r["unavailable"]]
    flags = [r for r in answered if r["flagged"]]
    return {
        "flagged": len(flags) * 2 > len(answered) if answered else None,
        "risks": sorted(r["risk"] for r in flags),
        "by": sorted({r["flagged_by"] for r in flags}),
        "unavailable": len(readings) - len(answered),
        "errors": sorted({r["error"] for r in readings if r["error"]}),
    }


def summarize(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Counts over one set: flagged, by risk, and unanswered."""
    judged = [r for r in results.values() if r["flagged"] is not None]
    flagged = [r for r in judged if r["flagged"]]
    return {
        "cases": len(results),
        "judged": len(judged),
        "flagged": len(flagged),
        "rate": round(len(flagged) / len(judged), 4) if judged else None,
        "risk": dict(Counter(r["risks"][len(r["risks"]) // 2] for r in flagged if r["risks"])),
        "by": dict(Counter(layer for r in flagged for layer in r["by"])),
        "unavailable_readings": sum(r["unavailable"] for r in results.values()),
        "errors": dict(Counter(e for r in results.values() for e in r["errors"])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bodies", required=True, help="Directory of recorded response bodies.")
    parser.add_argument("--briefing", choices=sorted(BRIEFINGS), default="completion")
    parser.add_argument("--attacks", action="store_true", help="Also judge the corpus attacks.")
    parser.add_argument("--votes", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--l2-score", type=float, default=0.2)
    parser.add_argument(
        "--base-url", help="Send OpenRouter calls here instead, e.g. a gateway's /proxy/llm route."
    )
    parser.add_argument("--json", help="Write per-case verdicts (ids only, no text) here.")
    args = parser.parse_args(argv)

    if args.base_url:
        openai_provider.OPENROUTER_API_BASE = args.base_url.rstrip("/")
    stub_l2(args.l2_score)
    recorded = bodies(Path(args.bodies))
    if not recorded:
        parser.error("no *.json bodies in --bodies")
    sets = {"bodies": recorded}
    if args.attacks:
        sets["attacks"] = attack_cases(recorded[0][1])

    briefing = BRIEFINGS[args.briefing]
    report: dict[str, Any] = {"briefing": args.briefing, "votes": args.votes}
    for name, cases in sets.items():
        readings = asyncio.run(run(cases, briefing, args.votes, args.concurrency))
        results = {case_id: majority(r) for case_id, r in readings.items()}
        report[name] = {"summary": summarize(results), "cases": results}
        print(f"{name}: {json.dumps(report[name]['summary'])}")
    if args.attacks:
        missed = [i for i, r in report["attacks"]["cases"].items() if r["flagged"] is False]
        print(f"attacks missed: {missed}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
