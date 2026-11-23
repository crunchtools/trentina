#!/usr/bin/env python3
"""L3 on LLM completions, as the ``/proxy/llm`` response edge judges them (a1013).

The completion edge hands ``defend()`` the provider's raw response body (JSON
or an event stream, whatever streamed) as ``MODEL_OUTPUT``, briefed with
``prompts.COMPLETION_BRIEFING``. Switching L3 to gemini-2.5-flash-lite
took Gatehouse's completions from about one flag in six hundred to one in
six: encrypted reasoning read as ``hidden_content`` and security reviews read
as ``data_exfiltration``. This measures a judge and a briefing on four sets:

- **bodies**: a directory of recorded response bodies, one per file. Every
  one is benign (the gateway delivered it to a working agent), so every flag
  is a false positive. The bodies are NOT in this repository: they are model
  output about private diffs. Record your own; ``--bodies`` reads ``*.json``.
- **attacks**: every attack in ``corpora/internal.py``, placed as the
  answer (``choices[0].message.content``) inside the first JSON body's own
  envelope, encrypted reasoning and all. What the briefing excuses must not
  include an attack that arrives inside a completion.
- **disguised**: the same attacks ROT13'd and gzip+base64'd, set in the
  answer under an ``encrypted_reasoning`` label: the class the briefing
  excuses in the envelope, arriving where it does not.
- **envelope**: the same disguised attacks in the envelope fields the
  briefing names: the encrypted reasoning entry's ``data``, and a
  ``signature``. The unpack stage hands them to L3 decoded, and the briefing
  excuses those fields only while they read as ciphertext, so each must flag.
  An attack excused here is a hole in the briefing.

``--sets`` picks which run (``bodies`` unless the attack sets are named)
and ``--cases`` keeps only the case ids listed in a file, one a line: a
second, voted pass over the cases a single-vote run missed or split on.

``--briefing none`` is the edge before a1013; ``completion`` is the shipped
briefing. L2 is not loaded: it is answered BENIGN at ``--l2-score``, which is
what production's L2 said of every flagged completion (0.15 to 0.32), so the
briefing L3 reads matches production's and L3 is measured on its own.

    TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL=google/gemini-2.5-flash-lite \\
        uv run python benchmarks/llm_completion.py --bodies <dir> --briefing none \\
        --sets bodies,attacks --votes 3 --json before.json
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import string
import gzip
import json
import sys
from collections import Counter
from collections.abc import Callable
from operator import methodcaller
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.internal import ATTACKS
from trentina import defense
from trentina.defense import Provenance, defend
from trentina.gateway.completion_envelope import non_ciphertext_fields
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


def _gzip_base64(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode())).decode()


_ROT13 = str.maketrans(
    string.ascii_lowercase + string.ascii_uppercase,
    string.ascii_lowercase[13:]
    + string.ascii_lowercase[:13]
    + string.ascii_uppercase[13:]
    + string.ascii_uppercase[:13],
)

DISGUISES: dict[str, Callable[[str], str]] = {
    "rot13": methodcaller("translate", _ROT13),
    "gzip-base64": _gzip_base64,
}
"""How a disguised attack is encoded before it is labelled as reasoning."""


def disguised_cases(template: str) -> list[tuple[str, str]]:
    """Each corpus attack, encoded, as the answer's ``encrypted_reasoning``.

    What the briefing excuses is the provider's own envelope. An answer that
    labels its own payload as encrypted reasoning is not the envelope, and
    the layers read it decoded (the unpack stage reads gzip and base64 and
    ROT13), so each of these must still flag. Five reach L3 still ciphered,
    because ROT13 is read back only when the reading is English (known gap
    22): ``obf-leetspeak-directive``, ``obf-spanish-directive``,
    ``obf-acrostic-instruction``, ``ml-german-wiki-credentials`` and
    ``ml-japanese-mail-forward``, all as ``rot13``. Those test the briefing's
    rule that an opaque value in the answer is content.
    """
    return [
        (
            f"{name}/{case.category}/{case.id}",
            envelope(template, json.dumps({"encrypted_reasoning": encode(case.payload)})),
        )
        for name, encode in DISGUISES.items()
        for case in ATTACKS
    ]


ENVELOPE_FIELDS = ("data", "signature")
"""Where the envelope set plants an attack: the encrypted reasoning entry's
``data``, and a ``signature`` on that entry."""


def planted(template: str, field: str, value: str) -> str:
    """``template``'s response with ``value`` as ``field`` of its encrypted
    reasoning entry."""
    body = json.loads(template)
    entries = body["choices"][0]["message"]["reasoning_details"]
    entry = next(e for e in entries if e.get("type") == "reasoning.encrypted")
    entry[field] = value
    return json.dumps(body)


def envelope_cases(template: str) -> list[tuple[str, str]]:
    """Each corpus attack, encoded, in each excused envelope field."""
    return [
        (f"{field}/{name}/{case.category}/{case.id}", planted(template, field, encode(case.payload)))
        for field in ENVELOPE_FIELDS
        for name, encode in DISGUISES.items()
        for case in ATTACKS
    ]


SETS: dict[str, Callable[[str], list[tuple[str, str]]]] = {
    "attacks": attack_cases,
    "disguised": disguised_cases,
    "envelope": envelope_cases,
}
"""The attack sets, each built in the first recorded body's envelope."""


def stub_l2(score: float) -> None:
    """Answer L2 BENIGN at ``score`` without loading a model."""

    async def benign(text: str, source: str, *, stop_on_partial: bool) -> Any:
        return ClassifierResult(label="BENIGN", score=score, latency_ms=0.0), False

    setattr(defense, "_classify", benign)


async def judge(body: str, briefing: str | None) -> dict[str, Any]:
    """One reading of ``body``, as the completion edge reaches its verdict.

    With the shipped briefing the edge also checks that the excused envelope
    fields are ciphertext (``completion_envelope``) and flags a completion
    whose fields are not, whatever L3 says. So when the check fires, no L3
    call is made here: the verdict is already the edge's. ``--briefing none``
    is the edge before a1013, which had neither.
    """
    if briefing is not None and await non_ciphertext_fields(body):
        return {
            "flagged": True,
            "flagged_by": "L1",
            "risk": "high",
            "unavailable": False,
            "error": None,
        }
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
        "flags": len(flags),
        "answered": len(answered),
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
    parser.add_argument("--sets", default="bodies", help="Comma-separated: bodies, " + ", ".join(SETS))
    parser.add_argument("--cases", help="A file of case ids, one a line: judge only those.")
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
    chosen = args.sets.split(",")
    if unknown := set(chosen) - {"bodies", *SETS}:
        parser.error(f"unknown sets: {sorted(unknown)}")
    sets = {name: SETS[name](recorded[0][1]) for name in chosen if name in SETS}
    if "bodies" in chosen:
        sets = {"bodies": recorded, **sets}
    if args.cases:
        keep = set(Path(args.cases).read_text(encoding="utf-8").split())
        sets = {name: [c for c in cases if c[0] in keep] for name, cases in sets.items()}

    briefing = BRIEFINGS[args.briefing]
    report: dict[str, Any] = {"briefing": args.briefing, "votes": args.votes}
    for name, cases in sets.items():
        readings = asyncio.run(run(cases, briefing, args.votes, args.concurrency))
        results = {case_id: majority(r) for case_id, r in readings.items()}
        report[name] = {"summary": summarize(results), "cases": results}
        print(f"{name}: {json.dumps(report[name]['summary'])}")
    for name in SETS:
        if name in report:
            missed = [i for i, r in report[name]["cases"].items() if r["flagged"] is False]
            print(f"{name} missed: {missed}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
