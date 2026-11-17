"""The constitution's verdict-cache rule (v2.20.0, #816), held against both caches.

A layer's verdict may be served from cache only when the key binds the content,
the grant owner and everything that can change the verdict; only completed
verdicts are kept; entries expire; and a miss judges, never passes. The L3
detection cache (``quarantine/l3_cache.py``) is held to each in
``tests/test_judge_burst.py``. This file holds the perimeter verdict cache
(``gateway/verdict_cache.py``) to the same four.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from trentina.gateway import verdict_cache
from trentina.gateway.profile import AuthConfig, Profile

_JUDGE = ("openrouter", "google/gemini-3.5-flash-lite")
_CLEAN: dict[str, Any] = {"injection_detected": False}


def test_the_key_binds_content_owner_judge_and_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    def key(
        owner: str = "alpha",
        text: str = "same text",
        judge: tuple[str, str] = _JUDGE,
        effort: str | None = None,
    ) -> str:
        monkeypatch.setattr(
            verdict_cache, "get_config", lambda: SimpleNamespace(reasoning_effort=effort)
        )
        profile = Profile(name=owner, auth=AuthConfig(bearer_token_env="T"))
        return verdict_cache._cache_key(profile, "response", text, judge)

    base = key()
    assert key() == base
    assert key(text="same text.") != base
    assert key(owner="beta") != base
    assert key(judge=("anthropic", "claude-haiku-5-5")) != base
    assert key(effort="high") != base


@pytest.mark.parametrize(
    "gap", ["l3_unavailable", "l3_truncated", "l2_truncated", "l2_unavailable", "oversize"]
)
def test_an_incomplete_verdict_is_never_kept(gap: str) -> None:
    verdict_cache._cache_put("k", {**_CLEAN, gap: True})
    assert verdict_cache._cache_get("k") == (False, None)


async def test_a_judgement_that_fails_is_not_kept() -> None:
    with pytest.raises(RuntimeError):
        await verdict_cache._single_flight("k", AsyncMock(side_effect=RuntimeError("judge down")))
    assert verdict_cache._cache_get("k") == (False, None)


@pytest.mark.xfail(strict=True, reason="perimeter verdicts have no TTL: crunchtools/trentina#817")
def test_perimeter_entries_expire(monkeypatch: pytest.MonkeyPatch) -> None:
    verdict_cache._cache_put("k", _CLEAN)
    later = time.time() + 365 * 86400
    monkeypatch.setattr(time, "time", lambda: later)
    monkeypatch.setattr(time, "monotonic", lambda: later)
    assert verdict_cache._cache_get("k")[0] is False
