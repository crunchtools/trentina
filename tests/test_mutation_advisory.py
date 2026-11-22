"""The advisory mutation runner (scripts/mutation_advisory.py, #858).

mutmut itself is never run here. What is tested is what the script decides on
its own: which modules a change selects, that the ``[tool.mutmut]`` table it
writes into ``pyproject.toml`` is always taken out again, that a run past the
cap is interrupted so mutmut can save, and which result lines count as
survivors.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import mutation_advisory as ma

WORKFLOW = Path(".github/workflows/mutation-advisory.yml")

GUARDS = "src/trentina/gateway/guards.py"
PENDING = "src/trentina/gateway/pending.py"


@pytest.fixture
def pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "x"\n')
    monkeypatch.setattr(ma, "PYPROJECT", path)
    return path


class TestTargets:
    def test_every_module_and_test_named_exists(self) -> None:
        named = set(ma.MODULES) | {t for tests in ma.MODULES.values() for t in tests}
        assert [p for p in sorted(named) if not Path(p).is_file()] == []

    def test_the_workflow_path_filter_is_exactly_the_scope(self) -> None:
        """A path in MODULES the filter lacks is a change no PR run ever sees;
        one the filter has and MODULES lacks starts a run that mutates nothing."""
        # PyYAML reads the bare key `on` as True.
        triggers = yaml.safe_load(WORKFLOW.read_text())[True]
        scope = set(ma.MODULES) | {t for tests in ma.MODULES.values() for t in tests}
        assert set(triggers["pull_request"]["paths"]) == scope | ma.WHOLE_RUN

    def test_a_changed_module_selects_itself(self) -> None:
        assert ma._targets({GUARDS, "README.md"}) == [GUARDS]

    def test_a_changed_owning_test_selects_its_modules(self) -> None:
        picked = ma._targets({"tests/test_approval_state_machine.py"})
        assert picked == sorted([PENDING, "src/trentina/gateway/approver.py"])

    def test_a_change_to_the_runner_selects_everything(self) -> None:
        assert ma._targets({".github/workflows/mutation-advisory.yml"}) == sorted(ma.MODULES)

    def test_an_unrelated_change_selects_nothing(self) -> None:
        assert ma._targets({"docs/approvals.md"}) == []


class TestMutmutTable:
    def test_the_table_scopes_the_run_and_is_removed_after(self, pyproject: Path) -> None:
        original = pyproject.read_text()
        with ma._mutmut_table([GUARDS]):
            table = tomllib.loads(pyproject.read_text())["tool"]["mutmut"]
            assert table["only_mutate"] == [GUARDS]
            assert table["pytest_add_cli_args_test_selection"] == ma.MODULES[GUARDS]
        assert pyproject.read_text() == original

    def test_the_file_is_restored_when_the_run_raises(self, pyproject: Path) -> None:
        original = pyproject.read_text()
        with pytest.raises(RuntimeError, match="boom"), ma._mutmut_table([GUARDS]):
            raise RuntimeError("boom")
        assert pyproject.read_text() == original

    def test_an_existing_table_is_refused_and_left_alone(self, pyproject: Path) -> None:
        pyproject.write_text("[tool.mutmut]\nsource_paths = []\n")
        with pytest.raises(RuntimeError, match="already has"), ma._mutmut_table([GUARDS]):
            pass
        assert pyproject.read_text() == "[tool.mutmut]\nsource_paths = []\n"


class _Proc:
    """A ``Popen`` stand-in that never finishes until it is signalled."""

    def __init__(self, *, finishes: bool) -> None:
        self.finishes = finishes
        self.signals: list[int] = []

    def wait(self, timeout: float | None = None) -> int:
        if self.finishes or self.signals:
            return 0
        raise subprocess.TimeoutExpired("mutmut", timeout or 0)

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def kill(self) -> None:
        raise AssertionError("killed a mutmut that stopped on SIGINT")


class TestRun:
    def test_a_run_inside_the_budget_finishes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        proc = _Proc(finishes=True)
        monkeypatch.setattr(ma.subprocess, "Popen", lambda *_a, **_k: proc)
        assert ma._run_mutmut(60) is True
        assert proc.signals == []

    def test_a_run_past_the_budget_is_interrupted_not_killed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _Proc(finishes=False)
        monkeypatch.setattr(ma.subprocess, "Popen", lambda *_a, **_k: proc)
        assert ma._run_mutmut(60) is False
        assert proc.signals == [ma.signal.SIGINT]


class TestSurvivors:
    def test_only_survived_lines_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        out = (
            "    trentina.a.x_f__mutmut_1: survived\n"
            "    trentina.a.x_f__mutmut_2: no tests\n"
            "    trentina.a.x_f__mutmut_3: timeout\n"
            "not a result line: survived\n"
        )

        def run(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, stdout=out)

        monkeypatch.setattr(ma.subprocess, "run", run)
        assert ma._survivors() == ["trentina.a.x_f__mutmut_1"]
