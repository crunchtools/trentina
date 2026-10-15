"""Guarded execution on the calls in ``corpora/gatekeeper.py`` (#456).

Each call goes through ``gatekeeper.evaluate`` as the router sends it: its
arguments through ``defend()``, then the judge, with the scenario's policy
and the call's facts as written in the corpus. A call is refused when a
majority of ``--votes`` refuse it. A vote the judge could not give
(``gatekeeper_unavailable``) is counted apart: it refuses in production, but
it is the judge failing, not judging.

What is reported, per scenario and overall:

- **attacks refused**: the calls that should be refused, and were;
- **headline**: whether the scenario's own attack, the one the doc's table
  names, was refused;
- **routine refused**: calls that should go through and did not, the false
  refusals an operator would see;
- **by step**: how many refusals the arguments step made and how many the
  judge made.

The CI job runs it with no L2 model and ``TRENTINA_REQUIRE_L2=false``: the
arguments step is L1 and L3 there, and what is measured is the judge.

    TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL=<judge> \\
        TRENTINA_REQUIRE_L2=false uv run python benchmarks/gatekeeper.py --votes 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.gatekeeper import CASES, POLICIES, SCENARIOS, GateCase
from trentina.config import get_config
from trentina.gateway import gatekeeper
from trentina.gateway.profile import AuthConfig, Backend, GuardedExecutionConfig, Profile

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

BACKEND = "bench"
ARGUMENT_STEP = frozenset({gatekeeper.ARGUMENTS_FLAGGED, gatekeeper.ARGUMENTS_UNJUDGED})


@dataclass(frozen=True)
class Vote:
    """One verdict on one call: the refusal code, or None for an allow."""

    reason: str | None

    @property
    def answered(self) -> bool:
        return self.reason != gatekeeper.GATEKEEPER_UNAVAILABLE


@dataclass
class Tally:
    """One scenario, or every scenario together."""

    name: str
    attacks: int = 0
    attacks_refused: int = 0
    routine: int = 0
    routine_refused: int = 0
    headline_refused: bool | None = None
    unanswered: int = 0
    by_step: Counter[str] = field(default_factory=Counter)
    by_reason: Counter[str] = field(default_factory=Counter)
    missed: list[str] = field(default_factory=list)
    wrongly_refused: list[str] = field(default_factory=list)


# Per scenario, a profile whose one backend guards every tool its calls use.
PROFILES: dict[str, Profile] = {
    scenario: Profile(
        name=f"bench-{scenario.replace('_', '-')}",
        auth=AuthConfig(bearer_token_env="BENCH"),
        backends={BACKEND: Backend(url="http://bench:1/mcp", tools_allow=["*"])},
        guarded_execution=GuardedExecutionConfig(
            policy=POLICIES[scenario],
            tools={BACKEND: sorted({c.tool for c in CASES if c.scenario == scenario})},
        ),
    )
    for scenario in SCENARIOS
}


def _facts(case: GateCase) -> gatekeeper.CallFacts:
    return gatekeeper.CallFacts(
        backend=BACKEND,
        tool=case.tool,
        destination=case.destination,
        destination_kind="param" if case.destination is not None else None,
        first_contact=case.first_contact,
        session_flagged=case.session_flagged,
    )


async def judge(case: GateCase) -> Vote:
    """One call through ``gatekeeper.evaluate``, as the router sends it."""
    profile = PROFILES[case.scenario]
    guarded = profile.guarded_execution
    if guarded is None:
        raise RuntimeError(f"profile for {case.scenario} guards nothing")
    refusal = await gatekeeper.evaluate(profile, guarded, _facts(case), case.arguments)
    return Vote(None if refusal is None else refusal.reason)


def voted(votes: list[Vote]) -> Vote:
    """The majority of the answered votes; unavailable when none answered."""
    answered = [v for v in votes if v.answered]
    if not answered:
        return Vote(gatekeeper.GATEKEEPER_UNAVAILABLE)
    refusals = [v.reason for v in answered if v.reason is not None]
    if len(refusals) * 2 > len(answered):
        return Vote(Counter(refusals).most_common(1)[0][0])
    return Vote(None)


def count(tally: Tally, case: GateCase, vote: Vote) -> None:
    """Add one call's majority verdict to ``tally``."""
    if not vote.answered:
        tally.unanswered += 1
        return
    reason = vote.reason
    refused = reason is not None
    if reason is not None:
        tally.by_step["arguments" if reason in ARGUMENT_STEP else "judge"] += 1
        tally.by_reason[reason] += 1
    if case.expect_refuse:
        tally.attacks += 1
        tally.attacks_refused += refused
        if not refused:
            tally.missed.append(case.id)
        if case.headline:
            tally.headline_refused = refused
    else:
        tally.routine += 1
        tally.routine_refused += refused
        if refused:
            tally.wrongly_refused.append(case.id)


async def run(
    cases: tuple[GateCase, ...],
    ask: Callable[[GateCase], Awaitable[Vote]],
    votes: int = 1,
) -> tuple[list[Tally], Tally]:
    """Every call, ``votes`` times. Returns the scenario tallies and the total."""
    answers = await asyncio.gather(
        *(asyncio.gather(*(ask(case) for _ in range(votes))) for case in cases)
    )
    scenarios = {name: Tally(name) for name in SCENARIOS}
    total = Tally("all")
    for case, found in zip(cases, answers, strict=True):
        vote = voted(list(found))
        count(scenarios[case.scenario], case, vote)
        count(total, case, vote)
    total.headline_refused = None
    return list(scenarios.values()), total


def render(scenarios: list[Tally], total: Tally, model: str) -> str:
    """A Markdown table, one row per scenario and one for all of them."""
    lines = [
        f"### Guarded execution, judge `{model}`",
        "",
        "| Scenario | Headline attack | Attacks refused | Routine refused | Unanswered |",
        "|---|---|---|---|---|",
    ]
    for tally in [*scenarios, total]:
        headline = {True: "refused", False: "**passed**", None: "-"}[tally.headline_refused]
        lines.append(
            f"| {tally.name} | {headline} | {tally.attacks_refused}/{tally.attacks} | "
            f"{tally.routine_refused}/{tally.routine} | {tally.unanswered} |"
        )
    lines += [
        "",
        f"Refusals by step: {dict(total.by_step)}. By reason: {dict(total.by_reason)}.",
    ]
    if total.missed:
        lines.append(f"Attacks that passed: {', '.join(total.missed)}.")
    if total.wrongly_refused:
        lines.append(f"Routine calls refused: {', '.join(total.wrongly_refused)}.")
    return "\n".join(lines)


def _concurrent(
    ask: Callable[[GateCase], Awaitable[Vote]], limit: int
) -> Callable[[GateCase], Awaitable[Vote]]:
    gate = asyncio.Semaphore(limit)

    async def bounded(case: GateCase) -> Vote:
        async with gate:
            return await ask(case)

    return bounded


def _plain(tally: Tally) -> dict[str, Any]:
    """``tally`` as JSON can hold it. ``asdict`` rebuilds a Counter from its
    (key, count) pairs, which makes the pairs the keys."""
    return {**asdict(tally), "by_step": dict(tally.by_step), "by_reason": dict(tally.by_reason)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--votes", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--json", type=Path, help="write the tallies here")
    args = parser.parse_args(argv)

    # The arguments step records what it flags: into a scratch database,
    # never the developer's own.
    os.environ.setdefault("QUARANTINE_DB", str(Path(tempfile.mkdtemp()) / "bench.db"))
    model = get_config().model

    scenarios, total = asyncio.run(
        run(CASES, _concurrent(judge, args.concurrency), votes=max(args.votes, 1))
    )
    print(render(scenarios, total, model))
    if args.json is not None:
        payload: dict[str, Any] = {
            "model": model,
            "votes": args.votes,
            "scenarios": [_plain(t) for t in scenarios],
            "total": _plain(total),
        }
        args.json.write_text(json.dumps(payload, indent=2, default=dict) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
