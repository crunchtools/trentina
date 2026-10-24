"""The agent-egress-bench (#507): the terminating egress route, scored.

Every case in ``corpora/egress_bench.py`` is one decision the
[egress route](../docs/egress-http.md) makes, scored exactly as the route
makes it — no mock of the detector, the rails or the layers:

- **DLP** (``url_dlp``/``body_dlp``/``header_dlp``): the request is assembled
  into the one document the route judges (``egress_policy.request_document``)
  and run through the deterministic credential detector
  (``gateway.outbound.detect_credentials``). A credential in the query, body or
  a forwarded header — raw or percent-encoded — should be caught. No judge.
- **SSRF** (``ssrf``): the request is run through the route's real rails —
  ``proxy_utils.normalize_proxy_path``, ``egress_http._unsafe_path`` and
  ``EgressGrant.allows`` — and the closed refusal reason is checked against the
  case. No judge.
- **response_injection**: the response is run through ``defend()`` as ingress
  (``source_type=egress_response``), majority over ``--votes``. Judge-dependent.
- **benign**: the false-positive suite, on its own axis — a deterministic half
  (the detector must stay silent) and a judged half (the layers must).

The DLP and SSRF axes are deterministic, so they run anywhere, for free, every
CI run. The response axis needs a judge; with none available its cases are
reported ``unanswered`` rather than scored, as the gatekeeper bench does, so a
run without L3 never publishes a false false-positive rate.

    # deterministic axes only (no judge), from a checkout:
    TRENTINA_REQUIRE_L2=false uv run python benchmarks/egress_bench.py

    # with the response axis, three votes, on a judge:
    TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL=google/gemini-3.5-flash-lite \\
        TRENTINA_REQUIRE_L2=false uv run python benchmarks/egress_bench.py --votes 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.egress_bench import (
    CASES,
    CATEGORIES,
    GRANT_METHODS,
    GRANT_PATHS,
    UPSTREAM,
    EgressCase,
)
from trentina.defense import Provenance, defend
from trentina.gateway.egress_http import _unsafe_path
from trentina.gateway.egress_policy import forward_request_headers, request_document
from trentina.gateway.outbound import detect_credentials
from trentina.gateway.profile import AuthConfig, EgressGrant, EgressUpstream, Profile
from trentina.gateway.proxy_utils import normalize_proxy_path
from trentina.modes import gaps_of
from trentina.quarantine.agent import llm_available

BENCH_PROFILE = Profile(name="egress-bench", auth=AuthConfig(bearer_token_env="BENCH"))
GRANT = EgressGrant(methods=list(GRANT_METHODS), paths=list(GRANT_PATHS))
# The upstream the request document is assembled against, so the bench forwards
# exactly the headers the real route would (the allowlist, user-agent override).
BENCH_UPSTREAM = EgressUpstream(upstream="https://api.example.com")


@dataclass
class Tally:
    """One category's result. For an attack category ``hit`` is a catch; for
    ``benign`` it is a false trip."""

    name: str
    total: int = 0
    hit: int = 0
    unanswered: int = 0
    missed: list[str] = field(default_factory=list)
    wrong_reason: list[str] = field(default_factory=list)


def _rail_reason(case: EgressCase) -> str | None:
    """The route's real rail decision for a case, or None when it would pass.

    Mirrors ``egress_http._resolve_upstream`` with the route's own functions:
    only ``UPSTREAM`` is configured and granted, so any other name is one
    refusal; then the path is normalized, checked for a decoded separator or
    control character, and matched against the grant.
    """
    if case.upstream != UPSTREAM:
        return "unknown_upstream"
    path = normalize_proxy_path(case.path.lstrip("/"))
    if path is None or _unsafe_path(path):
        return "bad_path"
    return GRANT.allows(case.method, f"/{path}")


def score_deterministic(case: EgressCase) -> tuple[bool, str | None]:
    """A credential-detector or rail case, scored without a judge.

    Returns ``(blocked, note)``: whether the route would refuse, and a note for
    the report (a rail reason mismatch), if any.
    """
    if case.kind == "rail":
        reason = _rail_reason(case)
        if case.expect_block and reason != case.rail_reason:
            return (reason is not None), f"{case.id}: {reason} != {case.rail_reason}"
        return reason is not None, None
    # request DLP (and the deterministic benign half): the credential detector,
    # over the document the route assembles. Headers go through
    # forward_request_headers first, exactly as egress_http._judge_request does
    # — only the allowlist survives and the user-agent is overwritten — so a
    # secret smuggled in a stripped header never reaches the judged document
    # here either, as it never does in production.
    fwd = forward_request_headers(list(case.headers.items()), BENCH_UPSTREAM)
    document = request_document(case.method, case.path, case.query, fwd, case.body)
    return bool(detect_credentials(document)), None


async def score_response(case: EgressCase, votes: int) -> tuple[bool, bool]:
    """A response case through ``defend()`` as ingress, majority over votes.

    Returns ``(blocked, answered)``. A vote blocks when the response is flagged
    or the layers could not finish it. With no judge the case is NOT scored —
    an unjudged verdict is not a real block — so it is reported unanswered; the
    check is made once, up front, rather than running ``defend()`` to discard
    it. A provider error (``defend`` returns an unjudged verdict rather than
    raising) blocks, fail-closed, as the route does; a genuine fault is left to
    propagate and fail the run visibly, not swallowed into "unanswered".
    """
    if not llm_available():
        return False, False
    from trentina.gateway.context import profile_context

    async def one() -> bool:
        with profile_context(BENCH_PROFILE):
            rv = await defend(
                case.body or "",
                source=f"egress-bench:{case.id}",
                source_type="egress_response",
                defense=BENCH_PROFILE.defense,
                provenance=Provenance.EXTERNAL,
                stop_on_partial=True,
            )
        return rv.flagged or gaps_of(rv).blocking()

    results = await asyncio.gather(*(one() for _ in range(votes)))
    return sum(results) * 2 > len(results), True


async def run(cases: tuple[EgressCase, ...], votes: int) -> dict[str, Tally]:
    tallies = {name: Tally(name) for name in CATEGORIES}
    for case in cases:
        tally = tallies[case.category]
        tally.total += 1
        if case.kind == "response":
            blocked, answered = await score_response(case, votes)
            if not answered:
                tally.unanswered += 1
                tally.total -= 1
                continue
            note = None
        else:
            blocked, note = score_deterministic(case)
        hit = blocked if case.expect_block else not blocked
        tally.hit += hit
        if not hit:
            # An attack that slipped through, or a benign case that tripped.
            tally.missed.append(case.id)
        if note:
            tally.wrong_reason.append(note)
    return tallies


def render(tallies: dict[str, Tally], model: str, votes: int) -> str:
    lines = [
        "### Agent egress bench",
        "",
        f"Response axis: judge `{model}`, {votes} vote(s). DLP and SSRF are deterministic.",
        "",
        "| Category | Axis | Caught / clean | Unanswered |",
        "|---|---|---|---|",
    ]
    attack = ("url_dlp", "body_dlp", "header_dlp", "ssrf", "response_injection")
    for name in CATEGORIES:
        t = tallies[name]
        axis = (
            "detector"
            if name.endswith("dlp")
            else (
                "rails"
                if name == "ssrf"
                else ("layers" if name == "response_injection" else "mixed")
            )
        )
        label = "attacks caught" if name in attack else "benign clean"
        lines.append(f"| {name} ({label}) | {axis} | {t.hit}/{t.total} | {t.unanswered} |")
    misses = [m for t in tallies.values() for m in t.missed]
    wrong = [w for t in tallies.values() for w in t.wrong_reason]
    if misses:
        lines += ["", f"Not scored as expected: {', '.join(misses)}."]
    if wrong:
        lines += ["", f"Rail reason mismatches: {'; '.join(wrong)}."]
    return "\n".join(lines)


def _plain(tallies: dict[str, Tally]) -> dict[str, object]:
    return {name: vars(t) for name, t in tallies.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--votes", type=int, default=1, help="votes per response case")
    parser.add_argument("--json", metavar="PATH", help="also write the result as JSON to PATH")
    args = parser.parse_args(argv)
    if args.votes < 1:
        parser.error("--votes must be at least 1")

    model = "none"
    if llm_available():
        from trentina.config import get_config

        model = get_config().model

    tallies = asyncio.run(run(CASES, args.votes))
    # The table always goes to stdout (the CI step tees it to the summary);
    # --json additionally writes the machine-readable result to a file.
    print(render(tallies, model, args.votes))
    if args.json:
        payload = {"model": model, "votes": args.votes, "categories": _plain(tallies)}
        Path(args.json).write_text(json.dumps(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
