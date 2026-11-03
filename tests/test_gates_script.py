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
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    return Harness(bin=bin_dir)


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
    assert "git checkout" in result.stderr
