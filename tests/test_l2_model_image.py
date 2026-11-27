"""The L2 model image's pin: its Containerfile and the committed export record agree."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASES = "https://github.com/crunchtools/trentina/releases/download/"
ZERO = "0" * 64


def containerfile_pin() -> tuple[str, str]:
    text = (ROOT / "scripts/l2-model/Containerfile").read_text()
    sha = re.search(r"^ADD --checksum=sha256:(\S+) \\\n\s+(\S+) /export\.tar$", text, re.M)
    assert sha, "no ADD --checksum line"
    return sha.group(1), sha.group(2)


def record() -> dict:
    return json.loads((ROOT / "scripts/l2-model/export.json").read_text())


def test_the_model_image_pins_a_checksum_and_a_release_asset() -> None:
    sha, url = containerfile_pin()
    assert re.fullmatch(r"[0-9a-f]{64}", sha)
    assert url.startswith(RELEASES)
    assert re.fullmatch(r"[0-9a-f]{64}", record()["training_sha256"])


def test_the_export_record_matches_the_containerfile() -> None:
    sha, url = containerfile_pin()
    assert record()["sha256"] == sha
    assert record()["url"] == url


# While a1813's placeholders are in, the sha is all zeros. Filling it in turns
# this XFAIL into an XPASS, which strict makes a failure: whoever fills it in
# removes the marker, so the image can never ship with the placeholder quietly.
@pytest.mark.xfail(strict=True, reason="a1813 fills the model sha")
def test_the_model_sha_is_not_the_placeholder() -> None:
    sha, url = containerfile_pin()
    assert sha != ZERO
    assert "A1813-PLACEHOLDER" not in url
    assert record()["training_sha256"] != ZERO
