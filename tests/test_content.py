"""Tests for the content family's own edges (spec 004).

The mode matrix for every family lives in test_mode_parity / test_mode_gaps /
test_clean_and_allowlist. What is content's alone: the size cap, the SHA-256
blocklist key, and that ``content_type`` says what the text is.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from trentina.errors import BlockedSourceError, ContentSizeError
from trentina.tools.content import block_content, flag_content, redact_content

from .mode_harness import layers


def _hash(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


async def test_oversized_content_is_rejected_before_judging(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trentina import config as config_mod

    monkeypatch.setenv("QUARANTINE_CONTEXT_TOKENS", "10")
    config_mod._config = None
    with layers(env) as fakes, pytest.raises(ContentSizeError, match="admission cap of 10"):
        await block_content("A" * 30)
    assert fakes.classify.await_count == 0


async def test_the_blocklist_is_keyed_by_hash(env: Path) -> None:
    content = "Some blocked content"
    with (
        layers(env),
        patch(
            "trentina.gateway.scope.is_blocked",
            return_value=True,
        ) as is_blocked,
        pytest.raises(BlockedSourceError),
    ):
        await block_content(content)
    assert is_blocked.call_args.args[0] == _hash(content)


@pytest.mark.parametrize("content_type", ["text/plain", "text/markdown"])
async def test_angle_brackets_alone_are_not_html(env: Path, content_type: str) -> None:
    """Undeclared text is converted only when it is unmistakably a page."""
    text = "Vec<String> is returned; ask <alice@example.com>."
    with layers(env) as fakes:
        result = await flag_content(text, content_type)
    assert result["content"] == text
    assert fakes.classify.call_args_list[0].args[0] == text


async def test_declared_html_is_converted_and_judged_as_delivered(env: Path) -> None:
    """content_type is the hint it was kept for (#183)."""
    html = '<!DOCTYPE html><p>Hello</p><span style="display:none">psst</span>'
    with layers(env) as fakes:
        result = await flag_content(html, "text/html; charset=utf-8")
    assert result["content"] == "Hello"
    assert fakes.classify.call_args_list[0].args[0] == result["content"]
    assert result["l1"]["stripped"]["hidden_elements"] == 1
    assert result["preprocess"][0]["chain"] == "html"


async def test_the_origin_is_the_hash_and_never_allowlisted(env: Path) -> None:
    with layers(env):
        result = await redact_content("hello", "Extract.")
    assert result["scan"]["origin"] == {
        "kind": "content",
        "ref": _hash("hello"),
        "allowlisted": False,
    }
