"""Auto-execute file selection in the shadow scan (#76).

Presence of a ``package.json`` or ``.env`` is a count; only obfuscation
inside one is a detection.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from trentina.l1.pipeline import PipelineStats
from trentina.l1.shadows import ShadowStats, detect_module_shadows

PAYLOAD = "echo aGVsbG8= | base64 -d | sh"


def _scan(path: Path) -> ShadowStats:
    return ShadowStats.from_result(detect_module_shadows(str(path)))


def _package(scripts: dict[str, str]) -> str:
    return json.dumps({"name": "x", "scripts": scripts})


def test_plain_package_json_is_not_counted(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_package({"test": PAYLOAD}))
    assert _scan(tmp_path) == ShadowStats()


def test_benign_install_script_is_a_count_not_a_detection(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_package({"postinstall": "node-gyp rebuild"}))
    stats = _scan(tmp_path)
    assert stats.autoexec_files == 1
    assert stats.autoexec_obfuscated == 0
    assert stats.files == 0
    pipeline = PipelineStats(shadows=stats)
    assert pipeline.suspicious_detections() == 0


def test_obfuscated_postinstall_is_a_detection(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_package({"postinstall": PAYLOAD}))
    stats = _scan(tmp_path)
    assert stats.autoexec_obfuscated == 1
    assert PipelineStats(shadows=stats).suspicious_detections() == 1


def test_node_eval_in_preinstall(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_package({"preinstall": "node -e \"eval(atob('x'))\""}))
    assert _scan(tmp_path).autoexec_obfuscated == 1


def test_malformed_package_json_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json")
    assert _scan(tmp_path) == ShadowStats()


@pytest.mark.parametrize("name", [".bashrc", ".profile", ".bash_profile", ".env"])
def test_shell_files(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("export PATH=$PATH:/opt/bin\n")
    assert _scan(tmp_path) == ShadowStats(autoexec_files=1)
    (tmp_path / name).write_text(f"# comment\n{PAYLOAD}\n")
    assert _scan(tmp_path) == ShadowStats(autoexec_files=1, autoexec_obfuscated=1)


def test_commented_payload_is_not_a_detection(tmp_path: Path) -> None:
    (tmp_path / ".bashrc").write_text(f"# {PAYLOAD}\n")
    assert _scan(tmp_path).autoexec_obfuscated == 0


def test_npmrc_registry_to_ip(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    assert _scan(tmp_path).autoexec_obfuscated == 0
    (tmp_path / ".npmrc").write_text("@scope:registry=http://203.0.113.9:4873/\n")
    assert _scan(tmp_path).autoexec_obfuscated == 1


def test_git_hooks(tmp_path: Path) -> None:
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit.sample").write_text(PAYLOAD)
    (hooks / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    (hooks / "post-checkout").write_text(f"#!/bin/sh\n{PAYLOAD}\n")
    (hooks / "pre-push").write_text(PAYLOAD)  # not executable: git ignores it
    for name in ("pre-commit", "post-checkout"):
        (hooks / name).chmod(0o755)
    result = detect_module_shadows(str(tmp_path))
    assert {f.filename for f in result.autoexec_found} == {
        ".git/hooks/pre-commit",
        ".git/hooks/post-checkout",
    }
    assert ShadowStats.from_result(result).autoexec_obfuscated == 1


def test_symlinked_dotfile_is_counted_unread(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text(PAYLOAD)
    (tmp_path / ".bashrc").symlink_to(target)
    stats = _scan(tmp_path)
    assert stats.autoexec_files == 1
    assert stats.autoexec_obfuscated == 0


@pytest.mark.parametrize("unit", ["base64 -d ", "eval ", "\\x41", "/dev/", "fromCharCode "])
def test_autoexec_patterns_stay_linear(tmp_path: Path, unit: str) -> None:
    (tmp_path / ".bashrc").write_text(unit * 20_000)
    (tmp_path / "package.json").write_text(_package({"install": unit * 20_000}))
    start = time.perf_counter()
    _scan(tmp_path)
    assert time.perf_counter() - start < 2.0
