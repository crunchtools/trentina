"""The agent-egress-bench kit (#507) is config the shipped gateway loads.

``start-gateway.sh`` renders ``profiles.yaml.in`` and appends the listen
arguments to whatever command runs the gateway; here that command is ``echo``,
so the test sees the arguments, and the rendered file is loaded as the gateway
would load it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from trentina.gateway.loader import load_profiles

KIT = Path(__file__).resolve().parent.parent / "benchmarks" / "agent_egress"


def _start(tmp_path: Path, mode: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "AEB_TRENTINA_WORK": str(tmp_path),
        "AEB_TRENTINA_RUN": "echo",
        "AEB_TRENTINA_MODE": mode,
    }
    return subprocess.run(
        ["/bin/sh", str(KIT / "start-gateway.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("mode", ["flag", "block"])
def test_the_rendered_profile_loads_in_each_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    done = _start(tmp_path, mode)
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == [
        "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8000", "--no-dbus",
    ]  # fmt: skip
    monkeypatch.setenv("BENCH_TOKEN", "bench-token-for-the-kit-test")
    monkeypatch.setenv("OPENROUTER_API_KEY", "kit-test-not-a-key")
    config = load_profiles(tmp_path / "profiles.yaml")
    bench = config.profiles["bench"]
    assert bench.route_grants["bench"].enforcement == mode
    assert bench.defense.enforcement == mode
    assert config.route_instances["bench"].type == "forward"


def test_a_mode_it_does_not_run_is_refused(tmp_path: Path) -> None:
    done = _start(tmp_path, "redact")
    assert done.returncode == 64
    assert not (tmp_path / "profiles.yaml").exists()
