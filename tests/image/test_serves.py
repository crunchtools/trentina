"""The image starts the way production runs it, and answers /health.

Runs INSIDE the built image, through python-sdlc's `pytest-in-image`: no
network, a read-only root, no capabilities. Outside the image these tests are
ignored (`--ignore=tests/image` in pyproject.toml), because what they prove is
about the image -- that the gateway starts in a distroless runtime with nothing
writable but what it is given -- not about the code.

The default stdio transport exits on the EOF of a detached stdin and proves
nothing, so this starts the streamable-HTTP transport and polls it.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PORT = 8019
STARTUP_SECONDS = 60


def _gateway_env(tmp_path: Path) -> dict[str, str]:
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        "profiles:\n  ci:\n    auth:\n      bearer_token_env: CI_TOKEN\n    backends: {}\n"
    )
    token = tmp_path / "token"
    token.write_text(secrets.token_hex(16))
    # /data is a volume in production; the root is read-only here, so every
    # path the gateway writes is pointed at the test's own directory.
    return dict(
        os.environ,
        TRENTINA_GATEWAY_ENABLED="1",
        TRENTINA_PROFILES_PATH=str(profiles),
        CI_TOKEN_FILE=str(token),
        QUARANTINE_DB=str(tmp_path / "quarantine.db"),
        FASTMCP_HOME=str(tmp_path / "fastmcp"),
    )


def test_gateway_starts_and_answers_health(tmp_path: Path) -> None:
    log = tmp_path / "gateway.log"
    with log.open("wb") as out:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "trentina",
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                str(PORT),
            ],
            env=_gateway_env(tmp_path),
            stdout=out,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + STARTUP_SECONDS
        body = None
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=5) as r:
                    body = r.read().decode()
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(1)
        assert body is not None, f"no /health answer; gateway log:\n{log.read_text()[-4000:]}"
        assert '"status"' in body
    finally:
        proc.terminate()
        proc.wait(timeout=10)
