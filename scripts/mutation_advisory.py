"""Advisory mutation testing over the security modules (#858).

The guards, the approval state, the egress policy, file confinement and the
judge's output schema are the code where a test that passes for the wrong
reason costs the most. Until now the only mutation checks were run by hand and
written into a test's docstring ("Mutation check: ..."). This runs ``mutmut``
over those modules against the tests that own them, and reports the mutants
that survived: a line a test reaches but nothing pins down.

Advisory, never a gate. A surviving mutant is a question for a person (is it
an equivalent mutant, or a missing assertion?), not a verdict a merge can wait
on, and a red check that means "maybe" teaches people to ignore red checks.

``MODULES`` is the whole scope. A module joins it with the tests that own it,
and those tests are all a mutant is run against: the full suite under every
mutant would not finish inside any time cap worth having.

Usage::

    uv run --with mutmut==3.8.1 python scripts/mutation_advisory.py --all
    uv run --with mutmut==3.8.1 python scripts/mutation_advisory.py --changed a.py b.py

It writes a ``[tool.mutmut]`` table into ``pyproject.toml`` for the run and puts
the original back afterwards, because mutmut reads its configuration from
nowhere else. The report goes to ``$GITHUB_STEP_SUMMARY`` when that is set, and
always to ``mutation-report/`` (``summary.md``, ``stats.json``).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Security-critical module -> the tests that own it. The scope named in #858.
MODULES: dict[str, list[str]] = {
    "src/trentina/gateway/guards.py": ["tests/test_gateway_guards.py"],
    "src/trentina/gateway/approver.py": [
        "tests/test_approvals.py",
        "tests/test_approval_passkeys.py",
        "tests/test_approval_state_machine.py",
    ],
    "src/trentina/gateway/pending.py": [
        "tests/test_approvals.py",
        "tests/test_approval_state_machine.py",
    ],
    "src/trentina/gateway/egress_policy.py": ["tests/test_egress_policy.py"],
    "src/trentina/gateway/auth.py": ["tests/test_gateway_auth.py"],
    "src/trentina/tools/confine.py": [
        "tests/test_read_confinement.py",
        "tests/test_shadow_confinement.py",
    ],
    "src/trentina/quarantine/schema.py": ["tests/test_l3_schema.py"],
    "src/trentina/quarantine/providers/base.py": [
        "tests/test_l3_schema.py",
        "tests/test_provider_fallback.py",
        "tests/test_provider_no_tools.py",
        "tests/test_l3_limiter.py",
    ],
    "src/trentina/reach/egress.py": [
        "tests/test_egress.py",
        "tests/test_client_egress.py",
        "tests/test_egress_encoding.py",
    ],
}

PYPROJECT = Path("pyproject.toml")
REPORT_DIR = Path("mutation-report")

#: How many surviving mutants are shown as diffs. The rest are listed by name;
#: a summary nobody scrolls to the end of reports nothing.
SHOWN_DIFFS = 40

#: Resolved once, so every call names the same executable: the one ``uv run
#: --with mutmut`` put on PATH.
MUTMUT = shutil.which("mutmut") or "mutmut"

#: Seconds mutmut has to save its results after SIGINT before it is killed.
SAVE_GRACE = 120

#: ``mutmut results`` prints one ``    name: status`` line per mutant that was
#: not killed.
_RESULT_LINE = re.compile(r"^\s+(\S+): (.+)$")


#: A change to any of these re-runs every module: they change what a run means.
WHOLE_RUN = {"scripts/mutation_advisory.py"}


def _targets(changed: set[str]) -> list[str]:
    """The modules a change touches: the module itself, or a test that owns it.

    A test change counts because weakening an assertion is exactly what lets a
    mutant survive, and that is the change least likely to touch the module.
    """
    if changed & WHOLE_RUN:
        return sorted(MODULES)
    return sorted(m for m, tests in MODULES.items() if m in changed or changed & set(tests))


def _run_mutmut(budget: float) -> bool:
    """Run mutmut for at most ``budget`` seconds. True when it finished.

    At the cap it gets SIGINT, which mutmut handles by saving what it has
    checked, so a run that hit the cap still reports.
    """
    proc = subprocess.Popen([MUTMUT, "run"])
    try:
        proc.wait(timeout=budget)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=SAVE_GRACE)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return False
    return True


def _survivors() -> list[str]:
    out = subprocess.run([MUTMUT, "results"], capture_output=True, text=True, check=False)
    found = (_RESULT_LINE.match(line) for line in out.stdout.splitlines())
    return [m.group(1) for m in found if m and m.group(2) == "survived"]


def _diff(name: str) -> str:
    out = subprocess.run([MUTMUT, "show", name], capture_output=True, text=True, check=False)
    return out.stdout.strip()


def _report(targets: list[str], finished: bool, budget: float) -> str:
    subprocess.run([MUTMUT, "export-cicd-stats"], check=False, capture_output=True)
    stats_path = Path("mutants/mutmut-cicd-stats.json")
    stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / "stats.json").write_text(json.dumps(stats, indent=2) + "\n")

    killed = int(stats.get("killed", 0)) + int(stats.get("timeout", 0))
    tested = killed + int(stats.get("survived", 0))
    score = f"{100 * killed / tested:.1f}%" if tested else "n/a"
    survivors = _survivors()

    lines = [
        "## Mutation testing (advisory)",
        "",
        f"Modules: {', '.join(f'`{t}`' for t in targets)}",
        "",
        (
            f"**Mutation score: {score}** — {killed} killed, {len(survivors)} survived, "
            f"{stats.get('no_tests', 0)} reached by no test, "
            f"{stats.get('total', 0)} generated."
        ),
        "",
    ]
    if not finished:
        lines += [
            f"> Stopped at the {budget / 60:.0f}-minute cap; the counts cover what was checked.",
            "",
        ]
    if survivors:
        lines += [
            (
                "A survivor is a change to the code that every owning test still passes: "
                "a missing assertion, or an equivalent mutant. This check never blocks a merge."
            ),
            "",
        ]
        for name in survivors[:SHOWN_DIFFS]:
            lines += [
                "<details><summary><code>" + name + "</code></summary>",
                "",
                "```diff",
                _diff(name),
                "```",
                "</details>",
            ]
        if len(survivors) > SHOWN_DIFFS:
            lines += ["", f"…and {len(survivors) - SHOWN_DIFFS} more:", ""]
            lines += [f"- `{name}`" for name in survivors[SHOWN_DIFFS:]]
    summary = "\n".join(lines) + "\n"
    (REPORT_DIR / "summary.md").write_text(summary)
    return summary


@contextlib.contextmanager
def _mutmut_table(targets: list[str]) -> Iterator[None]:
    """``pyproject.toml`` with this run's ``[tool.mutmut]``, put back after."""
    original = PYPROJECT.read_text()
    if "[tool.mutmut]" in original:
        raise RuntimeError("pyproject.toml already has [tool.mutmut]; this script owns that table")
    tests = sorted({test for target in targets for test in MODULES[target]})
    # -o addopts= drops the suite's "-n auto": mutmut records which test reaches
    # which function, and xdist workers would hide that from it.
    table = (
        "\n[tool.mutmut]\n"
        'source_paths = ["src/"]\n'
        f"only_mutate = {json.dumps(targets)}\n"
        f"pytest_add_cli_args_test_selection = {json.dumps(tests)}\n"
        'pytest_add_cli_args = ["-o", "addopts=", "-p", "no:cacheprovider", "-q"]\n'
    )
    PYPROJECT.write_text(original + table)
    try:
        yield
    finally:
        PYPROJECT.write_text(original)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--all", action="store_true", help="every module in scope")
    scope.add_argument("--changed", nargs="*", metavar="PATH", help="changed files")
    parser.add_argument("--budget-minutes", type=float, default=40.0)
    args = parser.parse_args(argv)

    targets = sorted(MODULES) if args.all else _targets(set(args.changed))
    if not targets:
        print("No security module changed; nothing to mutate.")
        return 0

    budget = args.budget_minutes * 60
    with _mutmut_table(targets):
        summary = _report(targets, _run_mutmut(budget), budget)
    print(summary)
    # Appended, not written: other steps share the job summary.
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as f:
            f.write(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
