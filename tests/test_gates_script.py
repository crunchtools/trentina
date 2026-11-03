"""The exit-code contract of ``scripts/gates.sh`` (constitution XII).

The script's safety property is not what any one gate checks, it is that a gate
which CANNOT run says so instead of passing. Constitution XII carries that rule
because of a runner that skipped three gates with a warning and printed the
other results as if that were a pass, so the contract is asserted here rather
than trusted: 0 passed, 1 ran and failed, 2 could not run.

Each case drives the real script with stub executables earlier on PATH, so no
gate starts a container and nothing here needs podman.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GATES = REPO / "scripts" / "gates.sh"

CANNOT_RUN = 2
FAILED = 1


@dataclass
class Harness:
    """Runs a gate against stubs, with the stub directory to populate."""

    bin: Path

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        environ = dict(os.environ)
        environ["PATH"] = f"{self.bin}{os.pathsep}{environ['PATH']}"
        environ.update(env)
        return subprocess.run(
            [str(GATES), *args], capture_output=True, text=True, env=environ, cwd=REPO, check=False
        )

    def only_stubs(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run with nothing but the stubs on PATH, so a real tool cannot be found."""
        return self.run(*args, PATH=str(self.bin))

    def said(self, result: subprocess.CompletedProcess[str]) -> str:
        return result.stdout + result.stderr


@pytest.fixture
def gates(tmp_path: Path) -> Harness:
    """A harness whose `git` is a stub from the start.

    Every test controls its own environment rather than inheriting one. The
    gates themselves run inside a container with no git at all, so a test
    leaning on the real one passes on a laptop and fails in the gate -- which
    is how the push tier caught these two. A test that wants git to misbehave
    re-stubs it; `stub` overwrites.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    harness = Harness(bin=bin_dir)
    harness.stub(
        "git",
        'case "$*" in\n'
        '  "config --get core.hooksPath") exit 1 ;;\n'
        f"  *--show-toplevel*) echo {REPO} ;;\n"
        f"  *hooks/pre-push*) echo {REPO}/.git/hooks/pre-push ;;\n"
        "  *) exit 1 ;;\n"
        "esac",
    )
    return harness


def test_no_argument_is_a_gate_that_cannot_run(gates: Harness) -> None:
    result = gates.run()
    assert result.returncode == CANNOT_RUN
    assert "usage:" in result.stderr


def test_an_unknown_gate_cannot_run(gates: Harness) -> None:
    assert gates.run("not-a-gate").returncode == CANNOT_RUN


def test_a_missing_podman_cannot_run_rather_than_passing(gates: Harness) -> None:
    """The incident the rule exists for: a gate with no tool must not report success."""
    gates.stub("git", f"echo {REPO}")
    result = gates.only_stubs("semgrep")
    assert result.returncode == CANNOT_RUN
    assert "CANNOT RUN" in result.stderr


def test_a_missing_gatehouse_key_cannot_run_and_names_no_install(gates: Harness) -> None:
    # podman is checked before the key, and the gate container has none, so the
    # stub is what lets this test reach the thing it is about.
    gates.stub("podman", "exit 0")
    result = gates.run("gatehouse-range", HOME="/nonexistent")
    assert result.returncode == CANNOT_RUN
    assert "gatehouse.env" in result.stderr
    # XII: the message must not tell the operator to install anything.
    assert "install" not in result.stderr.lower()


def test_an_uninstalled_pre_push_hook_fails_the_commit(gates: Harness, tmp_path: Path) -> None:
    """hooks-installed is what keeps the whole push tier from being a silent no-op."""
    gates.stub(
        "git",
        'case "$*" in\n'
        '  "config --get core.hooksPath") exit 1 ;;\n'
        f"  *--show-toplevel*) echo {REPO} ;;\n"
        f"  *hooks/pre-push*) echo {tmp_path}/absent-hook ;;\n"
        "  *) exit 1 ;;\n"
        "esac",
    )
    result = gates.run("hooks-installed")
    assert result.returncode == FAILED
    assert "pre-commit install" in gates.said(result)


def test_a_gate_run_outside_a_checkout_cannot_run(gates: Harness) -> None:
    gates.stub("git", "exit 128")
    result = gates.run("semgrep")
    assert result.returncode == CANNOT_RUN
    assert "not a git checkout" in result.stderr


def test_a_git_that_names_no_root_cannot_run(gates: Harness) -> None:
    """git succeeding with empty output must not leave the gate in the caller's
    directory. `cd ""` fails on some shells and is a no-op on others -- the
    runner's bash accepted it and ran the gate from wherever it happened to be."""
    gates.stub("git", 'echo ""')
    result = gates.run("semgrep")
    assert result.returncode == CANNOT_RUN
    assert "named no repository root" in result.stderr


# The resource knobs are a security control, not a convenience: bash evaluates
# the CONTENTS of a variable inside $(( )), so an array subscript in one is a
# command-substitution vector and `BUILD_LIMITS` computes exactly such an
# expression. These assert the refusal happens BEFORE any arithmetic.
HOSTILE_CPUS = "x[$(touch {sentinel})]"


def test_a_hostile_cpu_budget_cannot_run_and_executes_nothing(
    gates: Harness, tmp_path: Path
) -> None:
    sentinel = tmp_path / "pwned"
    result = gates.run(
        "hooks-installed", TRENTINA_GATES_CPUS=HOSTILE_CPUS.format(sentinel=sentinel)
    )
    assert result.returncode == CANNOT_RUN
    assert "TRENTINA_GATES_CPUS" in gates.said(result)
    # The real assertion: the payload never reached arithmetic.
    assert not sentinel.exists()


# An EMPTY value is not in these lists on purpose: `${VAR:-default}` treats
# empty as unset, so clearing the knob asks for the default rather than for
# nonsense, and refusing it would make `TRENTINA_GATES_CPUS= ./gates.sh push`
# fail for no reason.
@pytest.mark.parametrize("value", ["abc", "-4", "0", "1025", "4.5", "4 5", "0x10"])
def test_a_cpu_budget_that_is_not_a_sane_count_cannot_run(gates: Harness, value: str) -> None:
    result = gates.run("hooks-installed", TRENTINA_GATES_CPUS=value)
    assert result.returncode == CANNOT_RUN
    assert "TRENTINA_GATES_CPUS" in gates.said(result)


# The accepted cases assert that VALIDATION did not refuse the value, not that
# the gate passed: `hooks-installed` legitimately fails on a checkout without
# pre-commit hooks, which is every CI runner, and asserting exit 0 made these
# pass on a laptop and fail in CI.
@pytest.mark.parametrize("value", ["1", "2", "1024"])
def test_a_cpu_budget_at_the_boundaries_is_accepted(gates: Harness, value: str) -> None:
    result = gates.run("hooks-installed", TRENTINA_GATES_CPUS=value)
    assert result.returncode != CANNOT_RUN, gates.said(result)
    assert "TRENTINA_GATES_CPUS" not in gates.said(result)


@pytest.mark.parametrize("value", ["g8", "8g;id", "8gb", "eight", "$(id)", "-8g"])
def test_a_memory_ceiling_that_is_not_a_size_cannot_run(gates: Harness, value: str) -> None:
    result = gates.run("hooks-installed", TRENTINA_GATES_MEMORY=value)
    assert result.returncode == CANNOT_RUN
    assert "TRENTINA_GATES_MEMORY" in gates.said(result)


@pytest.mark.parametrize("value", ["8g", "4096m", "512k", "16G"])
def test_a_memory_ceiling_that_is_a_size_is_accepted(gates: Harness, value: str) -> None:
    result = gates.run("hooks-installed", TRENTINA_GATES_MEMORY=value)
    assert result.returncode != CANNOT_RUN, gates.said(result)
    assert "TRENTINA_GATES_MEMORY" not in gates.said(result)


def test_a_hostile_memory_ceiling_cannot_run_and_executes_nothing(
    gates: Harness, tmp_path: Path
) -> None:
    """The memory knob gets the same sentinel as the CPU one.

    It does not reach arithmetic today -- it is only ever a quoted podman
    argument -- so this guards the change that makes it one, or that expands it
    unquoted. Without a sentinel the rejection cases above pass even if a
    regression evaluates the value first and rejects it afterwards.
    """
    sentinel = tmp_path / "pwned-by-memory"
    result = gates.run("hooks-installed", TRENTINA_GATES_MEMORY=f"$(touch {sentinel})g")
    assert result.returncode == CANNOT_RUN
    assert "TRENTINA_GATES_MEMORY" in gates.said(result)
    assert not sentinel.exists()


@pytest.mark.parametrize("knob", ["TRENTINA_GATES_CPUS", "TRENTINA_GATES_MEMORY"])
def test_an_explicitly_empty_knob_takes_the_default(gates: Harness, knob: str) -> None:
    """``${VAR:-default}`` treats empty as unset, and that is the behaviour wanted.

    Asserted rather than left as a comment: a validation change could start
    refusing an empty value while every acceptance and rejection case above
    still passed, and ``TRENTINA_GATES_CPUS= ./scripts/gates.sh push`` would
    then fail for no reason a reader could see.
    """
    result = gates.run("hooks-installed", **{knob: ""})
    # Exit 2 is this script's "could not run", which is what validation
    # raises. Asserting it is NOT 2 says exactly "validation did not refuse
    # this" -- where the absence of the knob's name alone is also satisfied by
    # any other way of failing.
    assert result.returncode != CANNOT_RUN, gates.said(result)
    assert knob not in gates.said(result)
