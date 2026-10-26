"""The RunPod driver the l2-train workflow trains through (scripts/runpod_train.py)."""

from __future__ import annotations

import base64
import io
import shutil
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from scripts import runpod_train

KEY = "rpa_test-key-never-printed"


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[urllib.request.Request]:
    seen: list[urllib.request.Request] = []

    def urlopen(req: urllib.request.Request, **_: Any) -> Any:
        seen.append(req)
        if req.get_method() == "DELETE" and req.full_url.endswith("/gone"):
            raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, io.BytesIO(b""))
        return io.BytesIO(b"")

    monkeypatch.setenv("RUNPOD_API_KEY", KEY)
    monkeypatch.delenv("GITHUB_ENV", raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return seen


def test_pod_is_the_card_the_recipe_was_found_on() -> None:
    spec = runpod_train.pod_spec("ssh-ed25519 AAAA test", b"host key")
    assert spec["cloudType"] == "SECURE"
    assert spec["gpuTypeIds"] == ["NVIDIA GeForce RTX 4090"]
    assert spec["interruptible"] is False
    assert spec["imageName"] == runpod_train.IMAGE
    assert spec["env"]["PUBLIC_KEY"] == "ssh-ed25519 AAAA test"
    assert base64.b64decode(spec["env"]["POD_HOST_KEY"]) == b"host key"
    boot = spec["dockerStartCmd"][0]
    assert boot.startswith(f"(sleep {runpod_train.WATCHDOG_SECONDS}; runpodctl remove pod")
    assert boot.endswith("exec /opt/nvidia/nvidia_entrypoint.sh /start.sh")


def test_ssh_pins_the_host_key_it_made(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    ssh = runpod_train.ssh_base("192.0.2.1", "10802")
    assert "StrictHostKeyChecking=yes" in ssh
    assert f"HostKeyAlias={runpod_train.HOST_ALIAS}" in ssh


def test_terminate_tolerates_a_pod_already_gone(calls: list[urllib.request.Request]) -> None:
    assert runpod_train.terminate("gone") == 0
    assert calls[0].get_method() == "DELETE"


def test_terminate_without_a_pod_calls_nothing(calls: list[urllib.request.Request]) -> None:
    assert runpod_train.terminate("") == 0
    assert not calls


def test_key_goes_only_in_the_header(
    calls: list[urllib.request.Request], capsys: pytest.CaptureFixture[str]
) -> None:
    runpod_train.terminate("p1")
    req = calls[0]
    assert req.get_header("Authorization") == f"Bearer {KEY}"
    assert KEY not in req.full_url
    assert KEY not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("code", "body", "wait"),
    [
        (500, b"", True),
        (429, b"", True),
        (400, b"There are no longer any instances available", True),
        (401, b"unauthorized", False),
        (400, b"gpuTypeIds: invalid value", False),
    ],
)
def test_create_waits_only_for_capacity(code: int, body: bytes, wait: bool) -> None:
    assert runpod_train.retryable(code, body) is wait


def test_export_appends_to_github_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / "env"
    monkeypatch.setenv("GITHUB_ENV", str(env))
    runpod_train.export(POD_ID="p1", POD_PORT="10802")
    assert env.read_text() == "POD_ID=p1\nPOD_PORT=10802\n"


def test_remote_script_trains_the_recipe() -> None:
    script = runpod_train.remote_script(2.0)
    assert "--epochs 2.0" in script
    assert "l2-pod-requirements.txt" in script
    assert f"cd {runpod_train.REMOTE}" in script


def _archive(path: Path, names: dict[str, bytes], link: str | None = None) -> Path:
    with tarfile.open(path, "w") as tar:
        for name, content in names.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        if link:
            info = tarfile.TarInfo(link)
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(info)
    return path


def test_model_archive_unpacks_the_model(tmp_path: Path) -> None:
    archive = _archive(tmp_path / "a.tar", {"build/l2-model/config.json": b"{}"})
    runpod_train.unpack_model(archive, tmp_path / "out")
    assert (tmp_path / "out/build/l2-model/config.json").read_bytes() == b"{}"


@pytest.mark.parametrize(
    ("names", "link"),
    [
        ({"scripts/train_l2_model.py": b"import os"}, None),
        ({"build/l2-model-evil/x": b""}, None),
        ({"build/l2-model/../../scripts/x.py": b""}, None),
        ({"build/l2-model/config.json": b"{}"}, "build/l2-model/link"),
    ],
)
def test_model_archive_refuses_anything_else(
    tmp_path: Path, names: dict[str, bytes], link: str | None
) -> None:
    archive = _archive(tmp_path / "a.tar", names, link)
    with pytest.raises(ValueError, match="unexpected members"):
        runpod_train.unpack_model(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("text", ["0", "-1", "nan", "inf"])
def test_epochs_must_be_finite_and_above_zero(text: str) -> None:
    with pytest.raises(SystemExit):
        runpod_train.cli().parse_args(["run", "--host", "h", "--port", "1", "--epochs", text])


def test_create_exports_the_pod_before_waiting_on_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POD_ID reaches GITHUB_ENV even when the pod never comes up, so terminate finds it."""
    replies = iter(
        [{"id": "p1"}, {"id": "p1", "publicIp": "192.0.2.1", "portMappings": {"22": 10802}}]
    )
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "env"))
    monkeypatch.setattr(runpod_train, "api", lambda *_: next(replies))
    monkeypatch.setattr(runpod_train, "READY_FOR_SECONDS", 0.5)
    monkeypatch.setattr(runpod_train, "POLL_SECONDS", 1)
    monkeypatch.setattr(runpod_train, "ssh_base", lambda *_: [shutil.which("false") or "false"])
    assert runpod_train.create() == 1  # sshd never answers
    assert (tmp_path / "env").read_text() == "POD_ID=p1\n"
    pinned = (tmp_path / "pod_known_hosts").read_text().split()
    assert pinned[0] == runpod_train.HOST_ALIAS
    assert pinned[1:] == (tmp_path / "pod_host_key.pub").read_text().split()[:2]


def test_create_gives_up_at_once_on_a_bad_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: Any) -> Any:
        raise urllib.error.HTTPError(runpod_train.API, 401, "no", {}, io.BytesIO(b"unauthorized"))

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "env"))
    monkeypatch.setattr(runpod_train, "api", refuse)
    monkeypatch.setattr(runpod_train.time, "sleep", lambda _: pytest.fail("waited on a 401"))
    assert runpod_train.create() == 1
    assert not (tmp_path / "env").exists()


def test_run_stops_before_training_when_the_upload_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runpod_train, "ssh_base", lambda *_: ["ssh"])
    monkeypatch.setattr(runpod_train, "upload", lambda *_: False)
    monkeypatch.setattr(
        runpod_train.subprocess,
        "run",
        lambda *_, **__: pytest.fail("trained after a failed upload"),
    )
    assert runpod_train.run("192.0.2.1", "10802", 2.0) == 1


def test_create_waits_out_a_busy_api_then_proceeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replies: list[Any] = [
        urllib.error.HTTPError(runpod_train.API, 503, "busy", {}, io.BytesIO(b"")),
        {"id": "p1"},
        {"id": "p1", "publicIp": "192.0.2.1", "portMappings": {"22": 10802}},
    ]

    def api(*_: Any) -> Any:
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "env"))
    monkeypatch.setattr(runpod_train, "api", api)
    monkeypatch.setattr(runpod_train.time, "sleep", lambda _: None)
    monkeypatch.setattr(runpod_train, "ssh_base", lambda *_: [shutil.which("true") or "true"])
    assert runpod_train.create() == 0
    assert (tmp_path / "env").read_text() == "POD_ID=p1\nPOD_HOST=192.0.2.1\nPOD_PORT=10802\n"
