"""The audit hash chain (#472): what verifies, what breaks, what is not a break."""

from __future__ import annotations

import sqlite3
import time
from typing import Any

import pytest

from trentina import audit_chain
from trentina.outcomes import Outcome

DAY = 86400


@pytest.fixture
def db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    import trentina.database as db_mod

    db_mod._db = None
    cfg = type(
        "Cfg",
        (),
        {
            "db_path": str(tmp_path / "chain.db"),
            "ensure_db_dir": lambda self: None,
            "blocklist_ttl_days": 30,
        },
    )()
    monkeypatch.setattr(db_mod, "get_config", lambda: cfg)
    monkeypatch.setenv("TRENTINA_AUDIT_RETENTION_DAYS", "1")
    # No sweep of its own mid-test: the tests call it when they mean to.
    monkeypatch.setattr(db_mod, "_last_sweep", time.monotonic())
    yield db_mod
    db_mod._db = None


def _calls(db: Any, count: int = 5, aged: tuple[int, ...] = ()) -> None:
    """Record *count* calls; the 1-based positions in *aged* are stamped five days ago."""
    real = time.time
    try:
        for index in range(count):
            stamp = real() - (5 * DAY if index + 1 in aged else 0)
            db.time.time = lambda stamp=stamp: stamp
            db.record_gateway_call(
                "p", "web", f"tool{index}", Outcome.OK.value, 1, call_ref=f"c{index}"
            )
    finally:
        db.time.time = real


def _verify(db: Any, **kwargs: Any) -> dict[str, Any]:
    return audit_chain.verify(db.get_db(), ttl_seconds=30 * DAY, **kwargs)


def test_canonical_follows_rfc_8785() -> None:
    assert audit_chain.canonical({"b": 1, "a": None}) == b'{"a":null,"b":1}'
    assert audit_chain.canonical([1.0, 0.5, 1e21, 1e-7, 0.000001, -2.5]) == (
        b"[1,0.5,1e+21,1e-7,0.000001,-2.5]"
    )
    assert audit_chain.canonical({"k": "é\n\u0001"}) == '{"k":"é\\n\\u0001"}'.encode()
    # Keys sort by UTF-16 code unit: U+FF5E (BMP) after U+1F600 (surrogates D83D).
    tilde = "\N{FULLWIDTH TILDE}"
    expected = ('{"\U0001f600":2,"' + tilde + '":1}').encode()
    assert audit_chain.canonical({tilde: 1, "\U0001f600": 2}) == expected


def test_untouched_chain_verifies(db: Any) -> None:
    _calls(db)
    result = _verify(db)
    assert result["ok"] is True
    assert result["checked"] == 5
    assert result["checkpoint"]["kind"] == "genesis"


def test_genesis_checkpoint_is_written_once(db: Any) -> None:
    """Re-running the migration adds no second genesis and none that covers an
    existing call (#472). The check and insert hold one write lock, so two
    processes opening the same database cannot both write a genesis; a stale
    one would make verify read an already-written call as predating the chain.
    """
    _calls(db, 3)
    conn = db.get_db()
    before = conn.execute("SELECT last_id FROM audit_checkpoints WHERE kind = 'genesis'").fetchall()
    assert len(before) == 1
    assert before[0]["last_id"] == 0  # genesis stands before every call
    db._migrate(conn)  # a second opener re-running the same migration
    after = conn.execute("SELECT last_id FROM audit_checkpoints WHERE kind = 'genesis'").fetchall()
    assert len(after) == 1
    assert after[0]["last_id"] == 0
    # The calls are still inside the chain, not skipped as pre-genesis.
    assert _verify(db)["checked"] == 3


def test_tampered_row_is_caught(db: Any) -> None:
    _calls(db)
    db.get_db().execute("UPDATE gateway_calls SET outcome = 'ok', tool = 'x' WHERE id = 3")
    result = _verify(db)
    assert result["ok"] is False
    assert result["first_break"] == {"id": 3, "reason": "row_hash_mismatch"}


def test_deleted_row_is_caught(db: Any) -> None:
    _calls(db)
    db.get_db().execute("DELETE FROM gateway_calls WHERE id = 3")
    result = _verify(db)
    assert result["first_break"] == {"id": 4, "reason": "prev_hash_mismatch"}


def test_reordered_rows_are_caught(db: Any) -> None:
    _calls(db)
    conn = db.get_db()
    conn.execute("UPDATE gateway_calls SET id = 99 WHERE id = 2")
    conn.execute("UPDATE gateway_calls SET id = 2 WHERE id = 3")
    conn.execute("UPDATE gateway_calls SET id = 3 WHERE id = 99")
    result = _verify(db)
    assert result["ok"] is False
    assert result["first_break"]["id"] == 2


def test_pruned_prefix_verifies_clean(db: Any) -> None:
    _calls(db, aged=(1, 2, 3))
    assert db.sweep_old_gateway_calls() == 3

    result = _verify(db)
    assert result["ok"] is True
    assert result["checked"] == 2
    assert result["checkpoint"] == {"kind": "prune", "last_id": 3}
    # New rows keep chaining from the survivors.
    _calls(db, 1)
    assert _verify(db)["ok"] is True


def test_prune_takes_a_prefix_not_the_old_rows_around_a_gap(db: Any) -> None:
    """Rows 1 and 3 are old, 2 is not: only 1 may go, or the hole reads as a break."""
    _calls(db, aged=(1, 3))
    assert db.sweep_old_gateway_calls() == 1
    ids = [r["id"] for r in db.get_db().execute("SELECT id FROM gateway_calls ORDER BY id")]
    assert ids == [2, 3, 4, 5]
    assert _verify(db)["ok"] is True


def test_pruning_everything_leaves_a_chain_the_next_row_extends(db: Any) -> None:
    _calls(db, 2, aged=(1, 2))
    db.sweep_old_gateway_calls()
    assert db.get_db().execute("SELECT COUNT(*) FROM gateway_calls").fetchone()[0] == 0
    _calls(db, 1)
    assert _verify(db)["ok"] is True


def test_a_reset_is_on_the_record_and_not_a_break(db: Any) -> None:
    _calls(db, 3)
    assert db.reset_gateway_calls() == 3
    assert _verify(db)["checkpoint"]["kind"] == "reset"
    _calls(db, 2)
    result = _verify(db)
    assert result["ok"] is True
    assert result["checked"] == 2


def test_a_row_after_a_checkpoint_cannot_skip_the_link(db: Any) -> None:
    _calls(db, 3, aged=(1,))
    db.sweep_old_gateway_calls()
    db.get_db().execute(
        "UPDATE audit_checkpoints SET last_row_hash = 'forged' WHERE kind = 'prune'"
    )
    assert _verify(db)["first_break"] == {"id": 2, "reason": "prev_hash_mismatch"}


def test_detections_are_committed_to_by_the_call_row(db: Any) -> None:
    db.record_detection("web", "s", None, {}, "high", call_ref="c0")
    db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1, call_ref="c0")
    row = db.get_db().execute("SELECT detections_digest FROM gateway_calls").fetchone()
    assert row[0] is not None
    assert _verify(db)["ok"] is True

    db.get_db().execute("UPDATE detections SET risk_level = 'low'")
    assert _verify(db)["first_break"] == {"id": 1, "reason": "detections_mismatch"}


def test_expired_detections_are_noted_not_a_break(db: Any) -> None:
    db.record_detection("web", "s", None, {}, "high", call_ref="c0")
    db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1, call_ref="c0")
    db.get_db().execute("DELETE FROM detections")

    assert _verify(db)["first_break"]["reason"] == "detections_mismatch"
    later = _verify(db, now=time.time() + 31 * DAY)
    assert later["ok"] is True
    assert later["detections_expired"] == 1


def test_calls_without_a_call_ref_carry_no_digest(db: Any) -> None:
    db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1)
    assert db.get_db().execute("SELECT detections_digest FROM gateway_calls").fetchone()[0] is None
    assert _verify(db)["ok"] is True


class _Named(sqlite3.OperationalError):
    """An OperationalError carrying the ``sqlite_errorname`` a real one would.

    Subclassed rather than set on an instance: the real attribute comes from
    the C module, so assigning to it needs a type suppression.
    """

    def __init__(self, name: str) -> None:
        super().__init__("database is locked")
        self.sqlite_errorname = name


class TestLostRows:
    """A failed audit write leaves no break; the loss record is the only signal (#662)."""

    @pytest.fixture(autouse=True)
    def _reset(self, db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(db, "_lost_pending", 0)
        monkeypatch.setattr(db, "_lost_reason", "")

    def _flaky(self, db: Any, monkeypatch: pytest.MonkeyPatch, failures: int) -> list[int]:
        real = db._write_call
        calls: list[int] = []

        def write(conn: Any, fields: Any) -> Any:
            calls.append(1)
            if len(calls) <= failures:
                raise sqlite3.OperationalError("locking protocol")
            return real(conn, fields)

        monkeypatch.setattr(db, "_write_call", write)
        return calls

    def test_two_failures_then_success_writes_one_row(
        self, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = self._flaky(db, monkeypatch, 2)
        db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1)
        assert len(calls) == 3
        assert db.get_db().execute("SELECT COUNT(*) FROM gateway_calls").fetchone()[0] == 1
        assert _verify(db)["ok"] is True

    def test_a_busy_or_locked_failure_is_retried_like_any_other(
        self, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SQLite's busy handler never runs for SQLITE_LOCKED, and SQLITE_BUSY comes
        back at once when a deferred transaction cannot be upgraded. Neither has
        "already waited", so neither may cost the row its remaining attempts."""
        for name in ("SQLITE_BUSY", "SQLITE_LOCKED"):
            monkeypatch.setattr(db, "_lost_pending", 0)
            real = db._write_call
            calls: list[int] = []

            def write(
                conn: Any, fields: Any, _real: Any = real, _calls: Any = calls, _name: str = name
            ) -> Any:
                _calls.append(1)
                if len(_calls) <= 2:
                    raise _Named(_name)
                return _real(conn, fields)

            monkeypatch.setattr(db, "_write_call", write)
            db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1)
            assert len(calls) == 3, name
            monkeypatch.setattr(db, "_write_call", real)

        assert _verify(db)["lost_rows"] == 0

    def test_a_retry_waits_only_what_is_left_of_the_budget(
        self, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The budget is checked between attempts, so a retry's own busy wait is
        cut to the remainder; otherwise it could run a whole busy timeout past it.

        The clock is driven by the first attempt rather than slept through: the
        remainder is asserted exactly, and an upper bound measured off a real
        sleep fails on a machine that overshoots it.
        """
        real = db._write_call
        now = 0.0
        monkeypatch.setattr(db.time, "monotonic", lambda: now)
        spent = 0.2  # what the first attempt spends waiting
        timeouts: list[int] = []

        def write(conn: Any, _fields: Any) -> Any:
            nonlocal now
            timeouts.append(conn.execute("PRAGMA busy_timeout").fetchone()[0])
            if len(timeouts) == 1:
                now += spent
                raise sqlite3.OperationalError("database is locked")
            return real(conn, _fields)

        monkeypatch.setattr(db, "_write_call", write)
        db.record_gateway_call("p", "web", "t", Outcome.OK.value, 1)
        assert timeouts[0] == db.BUSY_TIMEOUT_MS
        assert len(timeouts) == 2
        assert timeouts[1] == int((db.AUDIT_RETRY_BUDGET - spent) * 1000)
        conn = db.get_db()
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == db.BUSY_TIMEOUT_MS

    def test_a_row_never_written_reports_incomplete_not_broken(
        self, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db.record_gateway_call("p", "web", "first", Outcome.OK.value, 1)
        calls = self._flaky(db, monkeypatch, 3)
        with pytest.raises(sqlite3.OperationalError):
            db.record_gateway_call("p", "web", "lost", Outcome.OK.value, 1)
        assert len(calls) == 3
        db.record_gateway_call("p", "web", "after", Outcome.OK.value, 1)

        report = _verify(db)
        assert report["first_break"] is None  # the chain is continuous
        assert report["lost_rows"] == 1
        assert report["ok"] is False
