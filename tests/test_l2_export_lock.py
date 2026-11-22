"""The model-builder stage installs the L2 exporter's stack from a hashed lock (#871)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts/l2-export-requirements.txt"


def test_model_builder_installs_only_from_the_lock() -> None:
    """A bare `pip install torch` here exported against versions no test saw."""
    containerfile = (ROOT / "Containerfile").read_text()
    match = re.search(r"^FROM \S+ AS model-builder\n(.*?)(?=^FROM )", containerfile, re.M | re.S)
    assert match
    stage = match.group(1)
    installs = re.findall(r"pip install(?:[^\n\\]|\\\n)*", stage)
    assert installs
    for line in installs:
        assert "--require-hashes" in line and "--no-deps" in line, line
        assert "-r /tmp/l2-export-requirements.txt" in line, line
    assert "COPY scripts/l2-export-requirements.txt /tmp/l2-export-requirements.txt" in stage


def test_every_locked_requirement_is_exact_and_hashed() -> None:
    """--require-hashes refuses the install otherwise; fail here, not in l2-train."""
    entries = re.split(r"\n(?=[a-z0-9])", LOCK.read_text())
    reqs = [e for e in entries if re.match(r"[a-z0-9]", e)]
    assert reqs
    for req in reqs:
        assert re.match(r"[a-z0-9][a-z0-9._-]*(\[[^\]]+\])?==\S+ \\", req), req.splitlines()[0]
        assert "--hash=sha256:" in req, req.splitlines()[0]


def test_lock_matches_its_input() -> None:
    """Every input is in the lock at its pinned version; a hand edit of one file is a stale lock."""
    locked = dict(re.findall(r"^([a-z0-9][a-z0-9._-]*)==(\S+) \\$", LOCK.read_text(), re.M))
    inputs = (ROOT / "scripts/l2-export-requirements.in").read_text().splitlines()
    reqs = [line for line in inputs if line and not line.startswith("#")]
    assert reqs
    for req in reqs:
        name, _, version = re.sub(r"\[[^\]]+\]", "", req).partition("==")
        assert name in locked, req
        if version:
            assert locked[name] == version, req
