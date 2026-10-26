"""Run ``train_l2_model.py`` on one RunPod GPU pod, for the l2-train workflow.

The recipe was found on an RTX 4090 in Secure Cloud (docs/benchmark.md, GPU
rounds); the run that ships trains on the same card, image and pip pins, so
what the gates pass is what was screened. On the runner's CPU two epochs
took past GitHub's six-hour job limit.

    python scripts/runpod_train.py create   # POD_ID, POD_HOST, POD_PORT to $GITHUB_ENV
    python scripts/runpod_train.py run --host "$POD_HOST" --port "$POD_PORT" --epochs 2
    python scripts/runpod_train.py terminate --pod "$POD_ID"   # in an always() step

``RUNPOD_API_KEY`` comes from the environment (the ``runpod`` GitHub
environment) and is never printed or put in an argv. The SSH key is made per
run in ``$RUNNER_TEMP``. A watchdog on the pod removes it after
``WATCHDOG_SECONDS`` in case the runner dies before ``terminate`` runs.

RunPod publishes no host keys, so the runner makes the pod's: it is handed
over in the create call (to RunPod, which runs the host anyway), installed
before the image's own ``/start.sh`` starts sshd, and pinned on this side,
so no connection trusts a key it first saw on the wire. What the pod sends
back is held to that too: the model archive is unpacked only if every
member is a plain file or directory under ``build/l2-model``.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

API = "https://rest.runpod.io/v1/pods"
GPU = "NVIDIA GeForce RTX 4090"
"""The card every GPU round ran on; no fallback, so a run cannot drift by hardware."""
IMAGE = "runpod/pytorch:2.8.0-py3.11-cuda12.8.1-cudnn-devel-ubuntu22.04"
CONTAINER_DISK_GB = 40
"""Image, pip wheels, the base model and four checkpoints, with room to spare."""
CREATE_FOR_SECONDS = 600
READY_FOR_SECONDS = 600
POLL_SECONDS = 15
WATCHDOG_SECONDS = 7200
SSH_ATTEMPTS = 5
"""Run 40260690102 trained, then lost the download to one connect timeout."""
SSH_UNREACHABLE = 255
REMOTE = "/workspace/w"
MODEL_DIR = "build/l2-model"
HOST_ALIAS = "trentina-l2-pod"
"""The name the pinned host key is filed under, whatever address the pod gets."""


def boot_command(watchdog_seconds: int) -> str:
    """Runs as the pod's first process, with the env SSH sessions do not get.

    Arms the watchdog (the pod-scoped key may remove only its own pod) and
    installs the host key the runner pinned, then hands over to the image's
    entrypoint and command, which start sshd.
    """
    remove = 'runpodctl remove pod "$RUNPOD_POD_ID" || runpodctl pod delete "$RUNPOD_POD_ID"'
    return (
        f"(sleep {watchdog_seconds}; {remove}) >/dev/null 2>&1 & "
        "mkdir -p /etc/ssh && umask 077 && "
        'echo "$POD_HOST_KEY" | base64 -d > /etc/ssh/ssh_host_ed25519_key && '
        "ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key > /etc/ssh/ssh_host_ed25519_key.pub && "
        "umask 022 && exec /opt/nvidia/nvidia_entrypoint.sh /start.sh"
    )


CAPACITY_HINTS = ("available", "capacity", "instances")
"""Words in a create refusal that mean "try again soon", not "this request is wrong"."""


def runner_temp() -> Path:
    """The runner's per-job temp directory (``$RUNNER_TEMP``), where the keys live."""
    return Path(os.environ["RUNNER_TEMP"])


def pod_spec(public_key: str, host_key: bytes) -> dict[str, Any]:
    """The create body: ``public_key`` logs the runner in, ``host_key`` (private,
    OpenSSH format) is the one sshd on the pod serves and the runner pins."""
    return {
        "name": "trentina-l2-train",
        "cloudType": "SECURE",
        "computeType": "GPU",
        "gpuCount": 1,
        "gpuTypeIds": [GPU],
        "imageName": IMAGE,
        "containerDiskInGb": CONTAINER_DISK_GB,
        "volumeInGb": 0,
        "ports": ["22/tcp"],
        "env": {"PUBLIC_KEY": public_key, "POD_HOST_KEY": base64.b64encode(host_key).decode()},
        "dockerEntrypoint": ["bash", "-c"],
        "dockerStartCmd": [boot_command(WATCHDOG_SECONDS)],
        "interruptible": False,
    }


def api(method: str, url: str, body: dict | None = None) -> Any:
    """One REST call; the decoded JSON reply, or None for an empty one.

    Raises ``urllib.error.HTTPError`` on a refusal, which callers sort by code.
    """
    req = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {os.environ['RUNPOD_API_KEY']}",
            "Content-Type": "application/json",
            # Cloudflare in front of the API refuses urllib's default (error 1010).
            "User-Agent": "trentina-l2-train",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


def retryable(code: int, body: bytes) -> bool:
    """Busy or out of 4090s: wait. A bad key or a bad spec will not improve."""
    if code == 429 or code >= 500:
        return True
    return code in {400, 409} and any(
        w in body.decode(errors="replace").lower() for w in CAPACITY_HINTS
    )


def export(**values: str) -> None:
    """Hand values to later workflow steps."""
    if path := os.environ.get("GITHUB_ENV"):
        with open(path, "a") as f:
            f.writelines(f"{k}={v}\n" for k, v in values.items())


def ssh_base(host: str, port: str) -> list[str]:
    """The ssh argv prefix for root on the pod at ``host``:``port``, host key pinned."""
    keys = runner_temp()
    return [
        shutil.which("ssh") or "ssh",
        "-i", str(keys / "pod_key"),
        "-p", port,
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"HostKeyAlias={HOST_ALIAS}",
        "-o", f"UserKnownHostsFile={keys / 'pod_known_hosts'}",
        "-o", "ServerAliveInterval=30",
        "-o", "ConnectTimeout=20",
        f"root@{host}",
    ]  # fmt: skip


def keypair(path: Path) -> Path:
    """A fresh passphraseless ed25519 pair at ``path`` (and .pub), replacing any."""
    path.unlink(missing_ok=True)
    path.with_suffix(".pub").unlink(missing_ok=True)
    keygen = shutil.which("ssh-keygen") or "ssh-keygen"
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path)], check=True)
    return path


def create() -> int:
    """Make the keys, create the pod, wait for its sshd; 0 once it answers.

    Exports ``POD_ID`` as soon as RunPod returns one (so ``terminate`` finds
    the pod whatever fails next), then ``POD_HOST`` and ``POD_PORT``. Returns 1
    on a refusal that waiting will not cure, or when either wait runs out.
    """
    keys = runner_temp()
    login, host_key = keypair(keys / "pod_key"), keypair(keys / "pod_host_key")
    pinned = host_key.with_suffix(".pub").read_text().split()[:2]
    (keys / "pod_known_hosts").write_text(f"{HOST_ALIAS} {' '.join(pinned)}\n")
    spec = pod_spec(login.with_suffix(".pub").read_text().strip(), host_key.read_bytes())

    deadline = time.monotonic() + CREATE_FOR_SECONDS
    while True:
        try:
            pod = api("POST", API, spec)
            break
        except urllib.error.HTTPError as e:
            body = e.read()
            if not retryable(e.code, body) or time.monotonic() > deadline:
                print(f"no pod: {e.code} {body[:300]!r}", file=sys.stderr)
                return 1
            time.sleep(POLL_SECONDS)
    export(POD_ID=pod["id"])  # before anything else can fail, so terminate finds it
    print(f"pod {pod['id']} on {GPU}")

    deadline, last = time.monotonic() + READY_FOR_SECONDS, b"not yet addressable"
    while time.monotonic() < deadline:
        pod = api("GET", f"{API}/{pod['id']}")
        host, port = pod.get("publicIp"), (pod.get("portMappings") or {}).get("22")
        if host and port:
            probe = subprocess.run(
                [*ssh_base(host, str(port)), "true"], check=False, capture_output=True
            )
            if probe.returncode == 0:
                export(POD_HOST=host, POD_PORT=str(port))
                print(f"ssh up on {host}:{port}")
                return 0
            last = probe.stderr
        time.sleep(POLL_SECONDS)
    print(f"pod not reachable after {READY_FOR_SECONDS}s: {last[-300:]!r}", file=sys.stderr)
    return 1


def remote_script(epochs: float) -> str:
    """The bash the pod runs: install the pins, then train ``epochs`` into MODEL_DIR."""
    return f"""set -euo pipefail
cd {REMOTE}
nvidia-smi --query-gpu=name,driver_version --format=csv,noheader
pip install -q -r scripts/l2-pod-requirements.txt
python scripts/train_l2_model.py --data build/l2-train --out {MODEL_DIR} --epochs {epochs!r}
"""


def unpack_model(archive: Path, dest: Path) -> None:
    """Unpack only plain files and directories under MODEL_DIR into ``dest``.

    Raises ``ValueError``, unpacking nothing, if any member is something else:
    a link, a device, a path outside MODEL_DIR, or one that climbs with ``..``.
    """
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        stray = [
            m.name
            for m in members
            if not (m.isfile() or m.isdir())
            or not (m.name == MODEL_DIR or m.name.startswith(f"{MODEL_DIR}/"))
            or ".." in Path(m.name).parts
        ]
        if stray:
            raise ValueError(f"unexpected members in the model archive: {stray[:5]}")
        tar.extractall(dest, filter="data")


def upload(ssh: list[str], paths: list[str]) -> bool:
    """Stream ``paths`` into REMOTE.

    False if the local tar failed; a failed ssh raises ``CalledProcessError``.
    """
    packer = subprocess.Popen(
        [shutil.which("tar") or "tar", "cf", "-", *paths], stdout=subprocess.PIPE
    )
    try:
        subprocess.run(
            [*ssh, f"mkdir -p {REMOTE} && tar xf - -C {REMOTE}"], stdin=packer.stdout, check=True
        )
    finally:  # an ssh failure must not leave the packer blocked on a full pipe
        if packer.stdout:
            packer.stdout.close()
        if packer.poll() is None:
            packer.kill()
    return packer.wait() == 0


def again_if_unreachable(step: Callable[[], Any]) -> Any:
    """Repeat ``step`` while ssh cannot connect (exit 255); for steps safe to repeat."""
    for attempt in range(1, SSH_ATTEMPTS + 1):
        try:
            return step()
        except subprocess.CalledProcessError as e:
            if e.returncode != SSH_UNREACHABLE or attempt == SSH_ATTEMPTS:
                raise
            print(
                f"ssh unreachable on {e.cmd[-1]!r}, attempt {attempt} of {SSH_ATTEMPTS}",
                file=sys.stderr,
            )
            time.sleep(POLL_SECONDS)
    return None


def fetch(ssh: list[str], archive: Path) -> None:
    """Write the pod's MODEL_DIR to ``archive`` as a tar, whole or not at all."""
    with archive.open("wb") as out:
        subprocess.run([*ssh, f"tar cf - -C {REMOTE} {MODEL_DIR}"], stdout=out, check=True)


def run(host: str, port: str, epochs: float) -> int:
    """Ship the scripts and training set, train on the pod, bring MODEL_DIR back.

    Returns 1 if the local tar of the upload failed; a failed ssh step raises
    ``CalledProcessError`` and a tampered archive ``ValueError``.
    """
    ssh = ssh_base(host, port)
    if not again_if_unreachable(lambda: upload(ssh, ["scripts", "build/l2-train"])):
        return 1
    subprocess.run([*ssh, "bash -s"], input=remote_script(epochs).encode(), check=True)
    archive = runner_temp() / "l2-model.tar"
    again_if_unreachable(lambda: fetch(ssh, archive))
    unpack_model(archive, Path.cwd())
    return 0


def terminate(pod: str) -> int:
    """Delete ``pod`` (empty: nothing was created); a pod already gone is success.

    Raises ``RuntimeError`` on any other refusal, so the step fails loudly.
    """
    if not pod:
        print("no pod to terminate")
        return 0
    try:
        api("DELETE", f"{API}/{pod}")
    except urllib.error.HTTPError as e:
        if e.code != 404:  # already gone is the goal
            raise RuntimeError(f"pod {pod} not terminated: {e.code} {e.read()[:300]!r}") from e
    print(f"pod {pod} terminated")
    return 0


def epochs_above_zero(text: str) -> float:
    """argparse type: a finite float above zero, else ``ArgumentTypeError``."""
    value = float(text)
    if not (math.isfinite(value) and value > 0):
        raise argparse.ArgumentTypeError(f"epochs must be a finite number above zero, not {text}")
    return value


def cli() -> argparse.ArgumentParser:
    """The ``create``, ``run`` and ``terminate`` subcommands, each bound to its handler."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(required=True)
    commands.add_parser("create").set_defaults(handler=lambda _: create())
    train = commands.add_parser("run")
    train.add_argument("--host", required=True)
    train.add_argument("--port", type=int, required=True)
    train.add_argument("--epochs", type=epochs_above_zero, default=2.0)
    train.set_defaults(handler=lambda a: run(a.host, str(a.port), a.epochs))
    stop = commands.add_parser("terminate")
    stop.add_argument("--pod", default="")
    stop.set_defaults(handler=lambda a: terminate(a.pod))
    return parser


if __name__ == "__main__":
    args = cli().parse_args()
    sys.exit(args.handler(args))
