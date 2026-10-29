"""Verdict persistence — a restart must not re-judge what it already judged.

Four properties, in descending order of how much it would hurt to lose them:

* A DEGRADED scan is never kept. A clean reached while L3 was down, or
  while L2 truncated its input, would otherwise survive the restart that
  fixed the outage and shadow it indefinitely. This is the property the old
  900-second TTL was really buying, and the only reason a TTL was defensible.
* A verdict from an OLDER perimeter is never trusted. Retuning a detector
  changes what a scan concludes, so rows carrying a different
  ``perimeter_stamp()`` (version, L2 model, threshold) are swept rather
  than replayed.
* The store is a cache. A write that fails costs the next boot some time
  and costs the current request nothing.
* Tool RESPONSES stay in memory. They are unbounded and mostly seen once,
  so a disk write per proxied call would buy a hit rate near zero.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from trentina import perimeter_db
from trentina.gateway import verdict_cache
from trentina.gateway.verdict_cache import (
    _cache_get,
    _cache_put,
    load_verdict_cache,
    reset_verdict_cache,
)
from trentina.perimeter_db import (
    delete_all_verdicts,
    get_all_verdicts,
    get_perimeter_db,
    perimeter_stamp,
    save_verdict,
)

FLAG = {"risk_level": "high", "flagged_by": "layer2", "l2_score": 0.97}


class TestStoreRoundTrip:
    def test_clean_verdict_round_trips(self) -> None:
        save_verdict("k-clean", None, perimeter_stamp())
        assert get_all_verdicts(perimeter_stamp()) == {"k-clean": None}

    def test_flagged_verdict_round_trips(self) -> None:
        save_verdict("k-flag", FLAG, perimeter_stamp())
        assert get_all_verdicts(perimeter_stamp())["k-flag"] == FLAG

    def test_rewriting_a_key_replaces_it(self) -> None:
        save_verdict("k", None, perimeter_stamp())
        save_verdict("k", FLAG, perimeter_stamp())
        assert get_all_verdicts(perimeter_stamp()) == {"k": FLAG}

    def test_delete_all_empties_the_store(self) -> None:
        save_verdict("k", FLAG, perimeter_stamp())
        assert delete_all_verdicts() == 1
        assert get_all_verdicts(perimeter_stamp()) == {}


class TestPerimeterVersion:
    def test_rows_from_another_version_are_not_returned(self) -> None:
        save_verdict("old", None, "0")
        save_verdict("new", None, perimeter_stamp())
        assert set(get_all_verdicts(perimeter_stamp())) == {"new"}

    def test_rows_from_another_version_are_swept(self) -> None:
        """Not merely ignored — deleted, so a stale verdict cannot come back
        if the version is ever reverted."""
        save_verdict("old", None, "0")
        get_all_verdicts(perimeter_stamp())
        remaining = get_perimeter_db().execute("SELECT COUNT(*) FROM verdict_cache").fetchone()[0]
        assert remaining == 0

    def test_unreadable_row_is_dropped_not_fatal(self) -> None:
        db = get_perimeter_db()
        db.execute(
            "INSERT INTO verdict_cache VALUES (?, ?, ?, ?)",
            ("broken", "{not json", perimeter_stamp(), "2026-09-19T00:00:00Z"),
        )
        db.commit()
        save_verdict("good", FLAG, perimeter_stamp())
        assert set(get_all_verdicts(perimeter_stamp())) == {"good"}


class TestDegradedScansAreNeverKept:
    """THE property. A verdict reached without the full pipeline is not the
    verdict the perimeter would reach today, so it is refused by the cache
    rather than stored and aged out."""

    def test_l3_outage_verdict_is_not_cached_in_memory(self) -> None:
        _cache_put("k", {"l3_unavailable": True}, persist=True)
        hit, _ = _cache_get("k")
        assert not hit, "a verdict reached during an L3 outage must be re-judged"

    def test_l3_outage_verdict_is_not_persisted(self) -> None:
        """Otherwise an outage's 'clean' survives the restart that fixed
        the outage — indefinitely, since nothing expires any more."""
        _cache_put("k", {"l3_unavailable": True}, persist=True)
        assert get_all_verdicts(perimeter_stamp()) == {}

    def test_truncated_l2_verdict_is_not_cached(self) -> None:
        _cache_put("k", {"l2_truncated": True}, persist=True)
        hit, _ = _cache_get("k")
        assert not hit
        assert get_all_verdicts(perimeter_stamp()) == {}

    def test_an_ordinary_flag_is_kept(self) -> None:
        _cache_put("k", FLAG, persist=True)
        hit, value = _cache_get("k")
        assert hit and value == FLAG

    def test_a_clean_verdict_is_kept(self) -> None:
        _cache_put("k", None, persist=True)
        hit, value = _cache_get("k")
        assert hit and value is None


class TestCachePut:
    def test_persist_writes_to_the_store(self) -> None:
        _cache_put("k", FLAG, persist=True)
        assert get_all_verdicts(perimeter_stamp())["k"] == FLAG

    def test_responses_are_not_persisted(self) -> None:
        """The default. Tool responses are unbounded and mostly seen once;
        a disk write per proxied call buys nothing."""
        _cache_put("k", FLAG)
        hit, value = _cache_get("k")
        assert hit and value == FLAG
        assert get_all_verdicts(perimeter_stamp()) == {}

    def test_a_failed_write_does_not_raise(self) -> None:
        """A store that cannot be written is a slow next boot, never a
        failed request."""
        with patch.object(
            perimeter_db, "save_verdict", side_effect=sqlite3.OperationalError("disk")
        ):
            _cache_put("k", FLAG, persist=True)
        hit, value = _cache_get("k")
        assert hit and value == FLAG, "the in-memory cache still took it"

    def test_a_failed_write_stops_further_attempts(self) -> None:
        """Whatever broke one write breaks the next two hundred. Retrying
        each one turns a read-only disk into a log flood."""
        with patch.object(
            perimeter_db, "save_verdict", side_effect=sqlite3.OperationalError("disk")
        ) as save:
            _cache_put("a", FLAG, persist=True)
            _cache_put("b", FLAG, persist=True)
            _cache_put("c", FLAG, persist=True)
        assert save.call_count == 1

    def test_a_restart_re_arms_persistence(self) -> None:
        """The disk may have been fixed. A fresh boot deserves a fresh try."""
        with patch.object(
            perimeter_db, "save_verdict", side_effect=sqlite3.OperationalError("disk")
        ):
            _cache_put("a", FLAG, persist=True)
        load_verdict_cache()
        _cache_put("b", FLAG, persist=True)
        assert "b" in get_all_verdicts(perimeter_stamp())


class TestStartupLoad:
    def test_load_populates_the_in_memory_cache(self) -> None:
        save_verdict("k", FLAG, perimeter_stamp())
        reset_verdict_cache()
        assert load_verdict_cache() == 1
        hit, value = _cache_get("k")
        assert hit and value == FLAG

    def test_load_respects_the_memory_bound(self) -> None:
        """A store larger than the LRU must not push the process over it."""
        for i in range(verdict_cache._CACHE_MAX + 10):
            save_verdict(f"k{i}", None, perimeter_stamp())
        reset_verdict_cache()
        assert load_verdict_cache() == verdict_cache._CACHE_MAX

    def test_reset_does_not_touch_the_store(self) -> None:
        """reset_verdict_cache is the test hook; forgetting a verdict in
        memory must not silently erase it from disk."""
        save_verdict("k", FLAG, perimeter_stamp())
        reset_verdict_cache()
        assert get_all_verdicts(perimeter_stamp())["k"] == FLAG


class TestStoreSeparation:
    def test_verdicts_do_not_live_in_the_blocklist_database(self) -> None:
        """Two stores, deliberately. The split is worth nothing today and
        everything if these ever move to a database with real grants — and
        it cannot be retrofitted once callers assume one connection."""
        from trentina import database
        from trentina import perimeter_db as store

        assert "verdict_cache" not in database.SCHEMA
        assert "verdict_cache" in store.SCHEMA

    def test_the_two_stores_are_different_files(self) -> None:
        from trentina.config import get_config

        config = get_config()
        assert Path(config.perimeter_db_path) != Path(config.db_path)


class TestSurvivesARestart:
    def test_a_verdict_written_before_a_restart_is_reused_after(self) -> None:
        """The whole point, end to end: judge once, then simulate the
        process dying and coming back."""
        _cache_put("tool:sha", None, persist=True)

        # The restart: memory gone, connection gone, store untouched.
        reset_verdict_cache()
        perimeter_db._db = None

        load_verdict_cache()
        hit, value = _cache_get("tool:sha")
        assert hit, "a restart must not re-judge what the last boot judged"
        assert value is None


@pytest.fixture(autouse=True)
def _fresh_store() -> None:
    """Each test starts with an empty store on its own tmp path."""
    delete_all_verdicts()


def test_saved_rows_carry_a_timestamp() -> None:
    save_verdict("k", None, perimeter_stamp())
    row = (
        get_perimeter_db()
        .execute("SELECT cached_at, warning_json FROM verdict_cache WHERE cache_key = 'k'")
        .fetchone()
    )
    assert row["cached_at"]
    assert row["warning_json"] is None
    json.dumps(row["cached_at"])  # plain string, serializable


class TestStampCarriesTheL2Model:
    """Switching CLASSIFIER_MODEL changes what a scan concludes (#350), so a
    verdict another model reached must be swept, not replayed."""

    def _stamp(self, model: object) -> str:
        """The stamp for ``model``, or for one that fails to resolve when None."""
        effect = ValueError("unresolvable") if model is None else None
        with patch(
            "trentina.quarantine.classifier.resolve_model",
            return_value=model,
            side_effect=effect,
        ):
            return perimeter_stamp()

    def test_an_unresolvable_model_stamps_as_absent(self) -> None:
        assert self._stamp(None) == f"{perimeter_db.PERIMETER_VERSION}:l2-absent"

    def test_the_stamp_names_model_revision_and_threshold(self) -> None:
        from trentina.quarantine.classifier import ModelInfo

        a = ModelInfo(id="a", revision="r1", threshold=0.7, malicious=(1,))
        stamp = self._stamp(a)
        assert stamp.startswith(perimeter_db.PERIMETER_VERSION + ":")
        assert stamp != self._stamp(ModelInfo(id="b", revision="r1", threshold=0.7, malicious=(1,)))
        assert stamp != self._stamp(ModelInfo(id="a", revision="r2", threshold=0.7, malicious=(1,)))
        assert stamp != self._stamp(ModelInfo(id="a", revision="r1", threshold=0.5, malicious=(1,)))
        polarity = ModelInfo(id="a", revision="r1", threshold=0.7, malicious=(0,))
        assert stamp != self._stamp(polarity), "a manifest's polarity changes the verdicts"

    def test_another_models_verdicts_are_swept_on_load(self) -> None:
        from trentina.quarantine.classifier import ModelInfo

        old = self._stamp(ModelInfo(id="old", revision="", threshold=0.5, malicious=(1,)))
        save_verdict("k", FLAG, old)
        new = self._stamp(ModelInfo(id="new", revision="", threshold=0.7, malicious=(1,)))
        assert get_all_verdicts(new) == {}
        assert get_all_verdicts(old) == {}, "swept, not merely hidden"
