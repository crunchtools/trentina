"""The bounded git verdict table (spec 027)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from trentina import perimeter_db
from trentina.perimeter_db import (
    delete_git_verdicts,
    get_git_verdicts,
    get_perimeter_db,
    save_git_verdicts,
)

if TYPE_CHECKING:
    import pytest

FLAG = {"risk_level": "high", "flagged_by": "layer2"}
DAY = 86400.0


def test_round_trip_keeps_clean_and_flagged() -> None:
    now = time.time()
    save_git_verdicts([("clean", None, now), ("bad", FLAG, now)], "s1")
    assert get_git_verdicts(["clean", "bad", "never"], "s1", DAY) == {"clean": None, "bad": FLAG}


def test_a_stamp_mismatch_is_a_miss() -> None:
    save_git_verdicts([("k", None, time.time())], "s1")
    assert get_git_verdicts(["k"], "s2", DAY) == {}


def test_an_expired_row_is_a_miss() -> None:
    save_git_verdicts([("old", None, time.time() - 2 * DAY), ("new", None, time.time())], "s")
    assert set(get_git_verdicts(["old", "new"], "s", DAY)) == {"new"}


def test_a_future_dated_row_is_a_miss() -> None:
    save_git_verdicts([("future", None, time.time() + 3600)], "s")
    assert get_git_verdicts(["future"], "s", DAY) == {}


def test_rewriting_replaces() -> None:
    save_git_verdicts([("k", None, time.time())], "s")
    save_git_verdicts([("k", FLAG, time.time())], "s")
    assert get_git_verdicts(["k"], "s", DAY) == {"k": FLAG}


def test_lru_eviction_keeps_recently_used_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(perimeter_db, "GIT_VERDICTS_MAX", 10)
    now = time.time()
    save_git_verdicts([(f"k{i}", None, now) for i in range(10)], "s")
    time.sleep(0.01)
    assert set(get_git_verdicts(["k0", "k1"], "s", DAY)) == {"k0", "k1"}  # touched
    time.sleep(0.01)
    save_git_verdicts([(f"n{i}", None, now) for i in range(4)], "s")
    count = get_perimeter_db().execute("SELECT COUNT(*) FROM git_verdicts").fetchone()[0]
    assert count == 10
    kept = set(
        get_git_verdicts([f"k{i}" for i in range(10)] + [f"n{i}" for i in range(4)], "s", DAY)
    )
    assert {"k0", "k1"} <= kept
    assert {f"n{i}" for i in range(4)} <= kept
    assert len(kept) == 10


def test_a_1200_key_batch_read_works() -> None:
    now = time.time()
    keys = [f"k{i}" for i in range(1200)]
    save_git_verdicts([(k, None, now) for k in keys], "s")
    got = get_git_verdicts([*keys, "absent"], "s", DAY)
    assert len(got) == 1200


def test_unreadable_row_is_a_miss() -> None:
    db = get_perimeter_db()
    db.execute(
        "INSERT INTO git_verdicts VALUES (?, ?, ?, ?, ?)", ("bad", "{no", "s", time.time(), 0)
    )
    db.commit()
    assert get_git_verdicts(["bad"], "s", DAY) == {}


def test_empty_calls_and_delete() -> None:
    assert get_git_verdicts([], "s", DAY) == {}
    save_git_verdicts([], "s")
    save_git_verdicts([("k", None, time.time())], "s")
    assert delete_git_verdicts() == 1
