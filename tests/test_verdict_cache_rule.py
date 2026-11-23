"""The constitution's verdict-cache rule (v2.20.0, #816), held against both caches.

A layer's verdict may be served from cache only when the key binds the content,
the grant owner and everything that can change the verdict; only completed
verdicts are kept; entries expire, checked on every read and at load (#817);
and a miss judges, never passes. The L3 detection cache
(``quarantine/l3_cache.py``) is held to each in ``tests/test_judge_burst.py``.
This file holds the perimeter verdict cache (``gateway/verdict_cache.py``) to
the same four.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from trentina import config as config_mod
from trentina import perimeter_db
from trentina.config import DEFAULT_VERDICT_TTL_HOURS, MAX_VERDICT_TTL_HOURS, get_config
from trentina.gateway import verdict_cache
from trentina.gateway.profile import AuthConfig, Profile

_JUDGE = ("openrouter", "google/gemini-3.5-flash-lite-20260721")
_CLEAN: dict[str, Any] = {"injection_detected": False}


def test_the_key_binds_content_owner_judge_and_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    def key(
        owner: str = "alpha",
        text: str = "same text",
        judge: tuple[str, str] = _JUDGE,
        effort: str | None = None,
    ) -> str:
        monkeypatch.setattr(
            verdict_cache,
            "get_config",
            lambda: SimpleNamespace(
                reasoning_effort=effort, classifier_model_path="m", classifier_threshold=None
            ),
        )
        profile = Profile(name=owner, auth=AuthConfig(bearer_token_env="T"))
        return verdict_cache._cache_key(profile, "response", text, judge)

    base = key()
    assert key() == base
    assert key(text="same text.") != base
    assert key(owner="beta") != base
    assert key(judge=("anthropic", "claude-haiku-5-5")) != base
    assert key(effort="high") != base


def test_the_key_binds_the_perimeter_stamp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Condition 1 (a1061): a verdict reached under another L2 or perimeter
    version is not served, in memory as well as from the store."""
    profile = Profile(name="alpha", auth=AuthConfig(bearer_token_env="T"))

    def key(stamp: str) -> str:
        monkeypatch.setattr(perimeter_db, "stamp_of", lambda *_: stamp)
        verdict_cache.reset_verdict_cache()
        return verdict_cache._cache_key(profile, "response", "same text", _JUDGE)

    assert key("26:guard@rev1") == key("26:guard@rev1")
    assert key("26:guard@rev2") != key("26:guard@rev1")
    assert key("27:guard@rev1") != key("26:guard@rev1")


def test_the_default_judge_is_keyed_by_its_dated_build(monkeypatch: pytest.MonkeyPatch) -> None:
    """Condition 1 (a1061): the key names the build, never an alias a vendor
    can repoint, and the shipped pack still applies to it."""
    from trentina.gateway.service import judge_of
    from trentina.quarantine.packs import SUPPORTED, pack_for

    monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
    for alias in ("gemini-3.5-flash-lite", "google/gemini-3.5-flash-lite"):
        monkeypatch.setenv("QUARANTINE_MODEL", alias)
        monkeypatch.setattr(config_mod, "_config", None)
        judge = judge_of(None)
        assert judge == ("openrouter", "google/gemini-3.5-flash-lite-20260721")
        assert pack_for(judge).status == SUPPORTED
    monkeypatch.setattr(config_mod, "_config", None)


@pytest.mark.parametrize(
    "gap",
    ["l3_unavailable", "l3_quota", "l3_truncated", "l2_truncated", "l2_unavailable", "oversize"],
)
@pytest.mark.parametrize("description", [False, True])
def test_an_incomplete_verdict_is_never_kept(gap: str, description: bool) -> None:
    verdict_cache._cache_put("k", {**_CLEAN, gap: True}, description=description)
    assert verdict_cache._cache_get("k") == (False, None)


async def test_a_judgement_that_fails_is_not_kept() -> None:
    with pytest.raises(RuntimeError):
        await verdict_cache._single_flight("k", AsyncMock(side_effect=RuntimeError("judge down")))
    assert verdict_cache._cache_get("k") == (False, None)


def _later(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """Move the wall clock ``seconds`` past now."""
    later = time.time() + seconds
    monkeypatch.setattr(time, "time", lambda: later)
    monkeypatch.setattr(time, "monotonic", lambda: later)


def _ttl(monkeypatch: pytest.MonkeyPatch, hours: int) -> None:
    monkeypatch.setenv("TRENTINA_VERDICT_TTL_HOURS", str(hours))
    monkeypatch.setattr(config_mod, "_config", None)


def test_perimeter_entries_expire(monkeypatch: pytest.MonkeyPatch) -> None:
    verdict_cache._cache_put("k", _CLEAN)
    _later(monkeypatch, 365 * 86400)
    assert verdict_cache._cache_get("k")[0] is False


@pytest.mark.parametrize("description", [False, True])
def test_a_verdict_is_served_until_its_ttl_and_not_after(
    monkeypatch: pytest.MonkeyPatch, description: bool
) -> None:
    _ttl(monkeypatch, 2)
    verdict_cache._cache_put("k", _CLEAN, description=description)
    _later(monkeypatch, 2 * 3600 - 1)
    assert verdict_cache._cache_get("k", description=description) == (True, _CLEAN)
    _later(monkeypatch, 2)
    assert verdict_cache._cache_get("k", description=description) == (False, None)
    store = verdict_cache._descriptions if description else verdict_cache._responses
    assert "k" not in store, "dropped on the read that found it stale"


def test_a_hit_does_not_extend_the_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counted from the judgement, not the last read: a hot entry still expires."""
    _ttl(monkeypatch, 1)
    verdict_cache._cache_put("k", _CLEAN)
    for _ in range(3):
        _later(monkeypatch, 1800)
        verdict_cache._cache_get("k")
    assert verdict_cache._cache_get("k")[0] is False


def test_an_entry_from_the_future_is_rejudged(monkeypatch: pytest.MonkeyPatch) -> None:
    verdict_cache._cache_put("k", _CLEAN)
    _later(monkeypatch, -60)
    assert verdict_cache._cache_get("k")[0] is False


def test_the_ttl_is_bounded_whatever_it_is_set_to(monkeypatch: pytest.MonkeyPatch) -> None:
    _ttl(monkeypatch, 10**9)
    assert get_config().verdict_ttl_hours == MAX_VERDICT_TTL_HOURS
    _ttl(monkeypatch, 0)
    assert get_config().verdict_ttl_hours == 1
    monkeypatch.delenv("TRENTINA_VERDICT_TTL_HOURS")
    monkeypatch.setattr(config_mod, "_config", None)
    assert get_config().verdict_ttl_hours == DEFAULT_VERDICT_TTL_HOURS


def test_a_persisted_verdict_keeps_its_judge_time_across_a_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restart must not restart the clock, or a gateway restarted daily
    would serve its first boot's verdicts for ever."""
    _ttl(monkeypatch, 2)
    perimeter_db.delete_all_verdicts()
    verdict_cache._cache_put("k", _CLEAN, description=True)

    _later(monkeypatch, 3600)
    verdict_cache.reset_verdict_cache()
    assert verdict_cache.load_verdict_cache() == 1
    assert verdict_cache._cache_get("k", description=True) == (True, _CLEAN)

    _later(monkeypatch, 3601)
    assert verdict_cache._cache_get("k", description=True)[0] is False


def test_an_expired_row_is_swept_at_load(monkeypatch: pytest.MonkeyPatch) -> None:
    _ttl(monkeypatch, 1)
    perimeter_db.delete_all_verdicts()
    verdict_cache._cache_put("k", _CLEAN, description=True)
    _later(monkeypatch, 3601)
    verdict_cache.reset_verdict_cache()
    assert verdict_cache.load_verdict_cache() == 0
    rows = perimeter_db.get_perimeter_db().execute("SELECT COUNT(*) FROM verdict_cache")
    assert rows.fetchone()[0] == 0, "deleted, not merely skipped"


async def test_an_expired_verdict_is_judged_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """The point of the TTL, end to end: past it, the layers run again."""
    _ttl(monkeypatch, 1)
    judge = AsyncMock(return_value=_CLEAN)

    async def lookup() -> dict[str, Any] | None:
        hit, cached = verdict_cache._cache_get("k")
        if hit:
            return cached

        async def work() -> dict[str, Any] | None:
            verdict = await judge()
            verdict_cache._cache_put("k", verdict)
            return verdict

        return await verdict_cache._single_flight("k", work)

    await lookup()
    await lookup()
    assert judge.await_count == 1, "served from cache inside the TTL"
    _later(monkeypatch, 3601)
    await lookup()
    assert judge.await_count == 2, "judged again past it"
