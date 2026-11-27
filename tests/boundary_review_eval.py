"""Run the trentina-boundary-review eval suite against the Anthropic Messages API (#90).

For each case in EVAL.yml: send SKILL.md as the system prompt and the fixture,
line-numbered, as the user turn; ask for findings as JSON (structured output);
then grade them twice. The cheap check matches a finding's obligation code or
a keyword. The judge, a second and cheaper model, says whether the findings
describe each expectation (known-bad) or flag the documented behavior
(control). A known-bad case passes when every must_find passes both checks
and the judge calls no other finding at or above ``max_severity`` spurious
(#300). A control fails on any finding at or above its ``max_severity``, or
when the judge says a finding flags its ``must_not_flag`` behavior. Either
kind fails on a finding whose line is outside the file.

The reviewer sees the fixture as ``case_NN.py`` with no path: the real file
name says which cases are controls, and the history (which issue fixed what)
lives in EVAL.yml's ``source``, never in the fixture.

Exits 0 when every case passes; 1 on any miss, a flagged control, a spurious
or ungraded finding on a known-bad case, or a line outside the file; and 2
when it cannot run (no ``ANTHROPIC_API_KEY``, bad EVAL.yml). httpx only; no
SDK dependency. Not collected by pytest: it spends money, so a person runs it
by hand with the key set (docs/by-hand.md).

    uv run python tests/boundary_review_eval.py [--case NAME ...] [--json-out PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
REPO = Path(__file__).resolve().parent.parent
DEFAULT_EVAL = REPO / ".claude" / "skills" / "trentina-boundary-review" / "EVAL.yml"
REQUEST_TIMEOUT = 300.0
MAX_ATTEMPTS = 5
CONCURRENCY = 4
RETRYABLE = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
REVIEW_MAX_TOKENS = 16000
JUDGE_MAX_TOKENS = 2048
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings", "proved"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "file",
                    "line",
                    "obligation",
                    "verdict",
                    "severity",
                    "title",
                    "evidence",
                    "scenario",
                    "fix",
                ],
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "obligation": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["UNSOUND", "UNPROVED"]},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "reject_pattern": {"type": "string"},
                    "title": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["tier", "claim", "source"],
                            "properties": {
                                "tier": {"type": "string"},
                                "claim": {"type": "string"},
                                "source": {"type": "string"},
                            },
                        },
                    },
                    "scenario": {"type": "string"},
                    "fix": {"type": "string"},
                },
            },
        },
        "proved": {"type": "array", "items": {"type": "string"}},
    },
}

_VERDICTS: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "yes", "reason"],
        "properties": {
            "id": {"type": "string"},
            "yes": {"type": "boolean"},
            "reason": {"type": "string"},
        },
    },
}

JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdicts"],
    "properties": {"verdicts": _VERDICTS},
}

# Known-bad cases also grade precision: every finding not describing an
# expectation is judged valid (a real defect in the file) or spurious.
PRECISION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdicts", "extras"],
    "properties": {
        "verdicts": _VERDICTS,
        "extras": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["index", "valid", "reason"],
                "properties": {
                    "index": {"type": "integer"},
                    "valid": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
            },
        },
    },
}


class EvalSetupError(Exception):
    """The suite cannot run: missing key, unreadable EVAL.yml, bad response."""


@dataclass
class CaseResult:
    name: str
    kind: str
    passed: bool
    notes: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    spurious: int = 0


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("title", ""),
        finding.get("scenario", ""),
        finding.get("fix", ""),
        *(f"{e.get('claim', '')} {e.get('source', '')}" for e in finding.get("evidence", [])),
    ]
    return " ".join(parts).casefold()


def cheap_match(expectation: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    """A finding names one of the expected obligations or hits one of the keywords."""
    codes = {str(c).upper() for c in expectation.get("obligations", [])}
    words = [str(k).casefold() for k in expectation.get("keywords", [])]
    for finding in findings:
        # "O4" or "O4 OUTCOME-FIDELITY": the code is the first token.
        code = str(finding.get("obligation", "")).upper().split()
        if code and code[0] in codes:
            return True
        if any(word in _finding_text(finding) for word in words):
            return True
    return False


def lines_outside(findings: list[dict[str, Any]], length: int) -> list[dict[str, Any]]:
    """Findings citing a line the file does not have."""
    return [f for f in findings if not 1 <= int(f.get("line") or 0) <= length]


def over_severity(findings: list[dict[str, Any]], ceiling: str) -> list[dict[str, Any]]:
    """Findings at or above ``ceiling``."""
    floor = SEVERITY_RANK[ceiling]
    return [f for f in findings if SEVERITY_RANK.get(str(f.get("severity")), 0) >= floor]


class Client:
    """The two Messages API calls the suite makes, with retry on transient errors."""

    def __init__(self, api_key: str, http: httpx.AsyncClient) -> None:
        self._headers = {
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        self._http = http

    async def structured(
        self, *, model: str, system: str, user: str, schema: dict[str, Any], max_tokens: int
    ) -> dict[str, Any]:
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": schema}},
        }
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = await self._http.post(API_URL, headers=self._headers, json=body)
            except httpx.RequestError as exc:
                raise EvalSetupError(f"{model}: {type(exc).__name__}") from exc
            if resp.status_code not in RETRYABLE or attempt == MAX_ATTEMPTS:
                break
            # Retry-After may be seconds or an HTTP date; a date falls back to backoff.
            try:
                delay = float(resp.headers.get("retry-after") or 2**attempt)
            except ValueError:
                delay = float(2**attempt)
            await asyncio.sleep(min(delay, 60.0))
        if resp.status_code != httpx.codes.OK:
            raise EvalSetupError(f"{model}: HTTP {resp.status_code}: {resp.text[:500]}")
        message = resp.json()
        stop = message.get("stop_reason")
        if stop == "refusal":
            raise EvalSetupError(f"{model}: refused ({message.get('stop_details')})")
        blocks = message.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvalSetupError(f"{model}: not JSON (stop_reason={stop})") from exc
        if not isinstance(parsed, dict):
            raise EvalSetupError(f"{model}: JSON is not an object")
        return parsed


KNOWN_BAD_QUESTION = (
    "For each expectation below, answer yes only if at least one finding "
    "describes that same defect (same code location and same failure), "
    "not merely a nearby or related concern. Then, under extras, judge EVERY "
    "finding once, by its index: valid if it describes one of the expectations "
    "or another real defect in the file as written, spurious if the code does "
    "not do what it claims or the behavior is documented as intended."
)
CONTROL_QUESTION = (
    "For each behavior below, answer yes if ANY finding treats that behavior "
    "as a defect, at any severity."
)


async def _judge(
    client: Client,
    suite: dict[str, Any],
    case: dict[str, Any],
    source: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    known_bad = case["kind"] == "known_bad"
    items = case["must_find"] if known_bad else case["must_not_flag"]
    listing = "\n".join(f"- id={i['id']}: {' '.join(i['expectation'].split())}" for i in items)
    indexed = [{"index": n, **f} for n, f in enumerate(findings)]
    user = (
        f"{KNOWN_BAD_QUESTION if known_bad else CONTROL_QUESTION}\n\n{listing}\n\n"
        f"The file reviewed:\n<file>\n{source}\n</file>\n\nFindings (JSON):\n"
        f"{json.dumps(indexed, indent=1)}\n\nAnswer once per id."
    )
    return await client.structured(
        model=suite["judge_model"],
        system="You grade a code reviewer's findings against fixed criteria. Be literal.",
        user=user,
        schema=PRECISION_SCHEMA if known_bad else JUDGE_SCHEMA,
        max_tokens=JUDGE_MAX_TOKENS,
    )


def _grade_known_bad(result: CaseResult, case: dict[str, Any], answer: dict[str, Any]) -> None:
    verdicts = {v["id"]: v for v in answer.get("verdicts", [])}
    for item in case["must_find"]:
        cheap = cheap_match(item, result.findings)
        judged = verdicts.get(item["id"], {}).get("yes", False)
        if not (cheap and judged):
            result.passed = False
            result.notes.append(f"missed {item['id']} (cheap={cheap}, judge={judged})")
    ceiling = SEVERITY_RANK[case.get("max_severity", "medium")]
    extras = {e.get("index"): e for e in answer.get("extras", [])}
    # A finding the judge skipped is ungraded, and ungraded is not precise.
    unjudged = sorted(set(range(len(result.findings))) - extras.keys())
    if unjudged:
        result.passed = False
        result.notes.append(f"judge left findings {unjudged} ungraded")
    for index, extra in extras.items():
        if extra.get("valid", True) or not isinstance(index, int):
            continue
        if not 0 <= index < len(result.findings):
            continue
        result.spurious += 1
        finding = result.findings[index]
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) >= ceiling:
            result.passed = False
            result.notes.append(
                f"spurious at {finding.get('severity')}: line {finding.get('line')}: "
                f"{finding.get('title')}"
            )


def _grade_control(result: CaseResult, case: dict[str, Any], answer: dict[str, Any]) -> None:
    verdicts = {v["id"]: v for v in answer.get("verdicts", [])}
    for finding in over_severity(result.findings, case.get("max_severity", "medium")):
        result.passed = False
        result.notes.append(
            f"flagged at {finding.get('severity')}: {finding.get('obligation')} "
            f"line {finding.get('line')}: {finding.get('title')}"
        )
    for item in case["must_not_flag"]:
        if verdicts.get(item["id"], {}).get("yes", False):
            result.passed = False
            result.notes.append(f"judge: flagged the documented behavior {item['id']}")


def neutral_name(suite: dict[str, Any], case: dict[str, Any]) -> str:
    """``case_NN.py``, by position in EVAL.yml: says nothing about the verdict."""
    return f"case_{suite['cases'].index(case) + 1:02d}.py"


async def run_case(
    client: Client, suite: dict[str, Any], skill: str, case: dict[str, Any], base: Path
) -> CaseResult:
    fixture = (base / suite["fixtures_dir"] / case["fixture"]).resolve()
    if not fixture.is_relative_to(REPO):
        raise EvalSetupError(f"case {case['name']!r}: fixture outside the repository")
    lines = fixture.read_text().splitlines()
    source = "\n".join(f"{n:4d}: {line}" for n, line in enumerate(lines, 1))
    name = neutral_name(suite, case)
    prompt = " ".join(suite["prompt_template"].format(fixture=name).split())
    review = await client.structured(
        model=suite["reviewer_model"],
        system=skill,
        user=f'{prompt}\n\n<file path="{name}">\n{source}\n</file>',
        schema=FINDINGS_SCHEMA,
        max_tokens=REVIEW_MAX_TOKENS,
    )
    result = CaseResult(case["name"], case["kind"], True, findings=review.get("findings", []))
    for finding in lines_outside(result.findings, len(lines)):
        result.passed = False
        result.notes.append(
            f"line {finding.get('line')} is outside the file: {finding.get('title')}"
        )
    answer = await _judge(client, suite, case, source, result.findings)
    if case["kind"] == "known_bad":
        _grade_known_bad(result, case, answer)
    else:
        _grade_control(result, case, answer)
    return result


def load_suite(path: Path) -> dict[str, Any]:
    try:
        suite = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise EvalSetupError(f"cannot read {path}: {exc}") from exc
    if not isinstance(suite, dict) or not suite.get("cases"):
        raise EvalSetupError(f"{path}: no cases")
    for case in suite["cases"]:
        key = "must_find" if case.get("kind") == "known_bad" else "must_not_flag"
        if case.get("kind") not in {"known_bad", "control"} or not case.get(key):
            raise EvalSetupError(f"{path}: case {case.get('name')!r} needs kind and {key}")
    return suite


async def run(path: Path, names: list[str]) -> list[CaseResult]:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise EvalSetupError("ANTHROPIC_API_KEY is not set")
    suite = load_suite(path)
    skill = (path.parent / suite["skill"]).read_text()
    cases = [c for c in suite["cases"] if not names or c["name"] in names]
    if names and len(cases) != len(set(names)):
        raise EvalSetupError(f"unknown case in {names}")
    gate = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as http:
        client = Client(api_key, http)

        async def one(case: dict[str, Any]) -> CaseResult:
            async with gate:
                try:
                    return await run_case(client, suite, skill, case, path.parent)
                except EvalSetupError as exc:
                    return CaseResult(case["name"], case["kind"], False, [f"error: {exc}"])

        return list(await asyncio.gather(*(one(c) for c in cases)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--eval", type=Path, default=DEFAULT_EVAL)
    parser.add_argument("--case", action="append", default=[], help="run only this case")
    parser.add_argument("--json-out", type=Path, help="write per-case results and findings")
    args = parser.parse_args(argv)
    try:
        results = asyncio.run(run(args.eval.resolve(), args.case))
    except EvalSetupError as exc:
        print(f"boundary-review eval: cannot run: {exc}", file=sys.stderr)
        return 2
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            f"{status}  {r.kind:9s}  {r.name}  ({len(r.findings)} findings, {r.spurious} spurious)"
        )
        for note in r.notes:
            print(f"        {note}")
    failed = [r.name for r in results if not r.passed]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if args.json_out:
        args.json_out.write_text(json.dumps([r.__dict__ for r in results], indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
