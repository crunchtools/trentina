"""Tests for the gateway audit outcome taxonomy.

Each test here pins one of the four defects the taxonomy replaced:

1. fail-closed defense blocks counted as errors,
2. backend-reported tool errors counted as successes,
3. allowlist and guard denials not recorded at all,
4. the disambiguating data present in the row but discarded by the aggregate.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

import pytest

from trentina.errors import (
    BlockedSourceError,
    ConfigError,
    FetchError,
    UnscannableContentError,
    UnsupportedContentTypeError,
)
from trentina.gateway.errors import BackendCallError
from trentina.outcomes import (
    BLOCKED_OUTCOMES,
    FAILED_OUTCOMES,
    TRIPPED_OUTCOMES,
    Outcome,
    classify_exception,
    group_of,
)


class TestClassifyException:
    """classify_exception must see through the BackendCallError wrapper."""

    def test_defense_block_through_wrapper(self) -> None:
        """A fail-closed block wrapped by call_internal_tool stays a block.

        This is the exact shape internal.py produces: the real error reachable
        only via __cause__. Reading the outer type alone yields backend_error,
        which is what made a working defense look like a broken tool.
        """
        original = BlockedSourceError("https://evil.test", "2026-09-05")
        wrapped = BackendCallError("internal tool 'block_fetch' call failed")
        wrapped.__cause__ = original

        assert classify_exception(wrapped) is Outcome.BLOCKED_DEFENSE

    def test_unscannable_content_is_a_block_not_a_failure(self) -> None:
        """Fail-closed on oversized untrusted content is policy, not breakage."""
        exc = UnscannableContentError("https://big.test", 90_000, 32_768)
        assert classify_exception(exc) is Outcome.BLOCKED_DEFENSE

    def test_binary_content_refusal_is_a_block(self) -> None:
        """Refusing a redirect-to-binary is a defense, and a known attack path."""
        exc = UnsupportedContentTypeError("https://x.test/a.zip", "application/zip")
        assert classify_exception(exc) is Outcome.BLOCKED_DEFENSE

    def test_upstream_fetch_failure_is_a_backend_error(self) -> None:
        """A site returning 403 is not our bug and not a policy block."""
        exc = FetchError("https://blocked.test", "403 Forbidden", status_code=403)
        assert classify_exception(exc) is Outcome.BACKEND_ERROR

    def test_config_error_is_a_gateway_error(self) -> None:
        """Misconfiguration is ours to fix, so it must reach the health signal."""
        assert classify_exception(ConfigError("no key")) is Outcome.GATEWAY_ERROR

    def test_unknown_exception_defaults_to_backend_error(self) -> None:
        """Unknowns must not inflate gateway_error, the one outcome that pages."""
        assert classify_exception(RuntimeError("who knows")) is Outcome.BACKEND_ERROR

    def test_cause_cycle_terminates(self) -> None:
        """A self-referential cause chain must not hang the audit path."""
        a = BackendCallError("a")
        b = BackendCallError("b")
        a.__cause__ = b
        b.__cause__ = a

        assert classify_exception(a) is Outcome.BACKEND_ERROR


class TestGrouping:
    def test_every_outcome_lands_in_exactly_one_group(self) -> None:
        """No outcome may be ungrouped, or totals silently stop reconciling."""
        for outcome in Outcome:
            assert group_of(outcome.value) in {"ok", "blocked", "tripped", "failed"}

    def test_blocked_and_failed_are_disjoint(self) -> None:
        assert not (BLOCKED_OUTCOMES & FAILED_OUTCOMES)

    def test_a_decoy_trip_is_neither_a_block_nor_a_failure(self) -> None:
        """It is an alarm about the caller: counted apart, so a health read
        does not page on it and a block count does not absorb it (#357)."""
        assert group_of(Outcome.DECOY_TRIPPED.value) == "tripped"
        assert not (TRIPPED_OUTCOMES & (BLOCKED_OUTCOMES | FAILED_OUTCOMES))

    def test_a_caller_that_hung_up_is_a_failure(self) -> None:
        assert group_of(Outcome.CLIENT_ABANDONED.value) == "failed"

    def test_legacy_rows_are_unknown_not_guessed(self) -> None:
        """Pre-migration rows must not be back-fitted into a real outcome."""
        assert group_of("legacy") == "unknown"
        assert group_of("") == "unknown"


class TestAuditRecording:
    """End-to-end: the router writes the right outcome for each path."""

    @pytest.fixture
    def db(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
        import trentina.database as db_mod

        db_mod._db = None
        cfg = type(
            "Cfg",
            (),
            {
                "db_path": str(tmp_path / "audit.db"),
                "ensure_db_dir": lambda self: None,
                # The first call of a process sweeps, and the sweep reads this.
                "blocklist_ttl_days": 30,
            },
        )()
        monkeypatch.setattr(db_mod, "get_config", lambda: cfg)
        yield db_mod
        db_mod._db = None

    def test_success_is_derived_from_outcome(self, db: Any) -> None:
        """The legacy boolean can never disagree with the taxonomy."""
        db.record_gateway_call("p", "web", "block_fetch", Outcome.OK.value, 10)
        db.record_gateway_call("p", "web", "block_read", Outcome.BLOCKED_DEFENSE.value, 10)

        rows = {
            r["tool"]: r["success"]
            for r in db.get_db().execute("SELECT tool, success FROM gateway_calls")
        }
        assert rows == {"block_fetch": 1, "block_read": 0}

    def test_blocked_is_separated_from_failed(self, db: Any) -> None:
        """The headline fix: 34 blocks must not read as 34 failures."""
        for _ in range(34):
            db.record_gateway_call("p", "web", "block_read", Outcome.BLOCKED_DEFENSE.value, 5)
        db.record_gateway_call("p", "web", "block_read", Outcome.OK.value, 5)
        db.record_gateway_call("p", "web", "block_read", Outcome.GATEWAY_ERROR.value, 5, "boom")

        entry = db.get_gateway_call_stats(days=1)["by_tool"][0]
        assert entry["calls"] == 36
        assert entry["ok"] == 1
        assert entry["blocked"] == 34
        assert entry["failed"] == 1

    def test_totals_reconcile_with_per_tool_counts(self, db: Any) -> None:
        db.record_gateway_call("p", "a", "t1", Outcome.OK.value, 1)
        db.record_gateway_call("p", "b", "t2", Outcome.DENIED_GUARD.value, 1, "no")
        db.record_gateway_call("p", "c", "t3", Outcome.TOOL_ERROR.value, 1)

        stats = db.get_gateway_call_stats(days=1)
        assert stats["total_calls"] == 3
        assert stats["totals"] == {"ok": 1, "blocked": 1, "tripped": 0, "failed": 1, "unknown": 0}

    def test_legacy_rows_report_as_unknown(self, db: Any) -> None:
        """A row written before the migration must not be silently miscounted."""
        conn = db.get_db()
        conn.execute(
            "INSERT INTO gateway_calls (timestamp, profile, backend, tool, success, "
            "duration_ms, error_message, outcome) VALUES (?,?,?,?,?,?,?,NULL)",
            (time.time(), "p", "web", "block_read", 0, 5, "old"),
        )
        conn.commit()

        stats = db.get_gateway_call_stats(days=1)
        assert stats["totals"]["unknown"] == 1
        assert stats["by_tool"][0]["failed"] == 0

    def test_migration_adds_outcome_to_an_old_table(self, tmp_path: Any) -> None:
        """An existing deployment's table must gain the column on next open.

        CREATE TABLE IF NOT EXISTS leaves an old table untouched, so without
        _migrate the new column never reaches production.
        """
        import trentina.database as db_mod

        path = str(tmp_path / "old.db")
        old = sqlite3.connect(path)
        old.executescript(
            "CREATE TABLE gateway_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp REAL NOT NULL, profile TEXT NOT NULL, backend TEXT NOT NULL, "
            "tool TEXT NOT NULL, success BOOLEAN NOT NULL, "
            "duration_ms INTEGER NOT NULL, error_message TEXT);"
        )
        old.execute(
            "INSERT INTO gateway_calls (timestamp, profile, backend, tool, success, "
            "duration_ms) VALUES (1, 'p', 'web', 'block_read', 0, 1)"
        )
        old.commit()
        old.close()

        db_mod._db = None
        conn = db_mod.get_db(path)
        try:
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(gateway_calls)")}
            assert "outcome" in columns
            preserved = conn.execute("SELECT COUNT(*) AS c FROM gateway_calls")
            assert preserved.fetchone()["c"] == 1
        finally:
            db_mod._db = None

    def test_reset_clears_rows_and_reports_count(self, db: Any) -> None:
        for _ in range(3):
            db.record_gateway_call("p", "web", "block_fetch", Outcome.OK.value, 1)

        assert db.reset_gateway_calls() == 3
        assert db.get_gateway_call_stats(days=1)["total_calls"] == 0


def test_refusal_of_finds_a_nested_refusal() -> None:
    from trentina.errors import BlockedSourceError
    from trentina.gateway.errors import BackendCallError
    from trentina.outcomes import refusal_of

    inner = BlockedSourceError("s", "flagged by L3", refusal={"alternatives": ["redact"]})
    outer = BackendCallError("wrapped")
    outer.__cause__ = inner
    assert refusal_of(outer) == {"alternatives": ["redact"]}
    assert refusal_of(RuntimeError("x")) is None


class TestDeliverySizes:
    @pytest.fixture
    def db(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
        import trentina.database as db_mod

        db_mod._db = None
        cfg = type(
            "Cfg",
            (),
            {"db_path": str(tmp_path / "sizes.db"), "ensure_db_dir": lambda self: None},
        )()
        monkeypatch.setattr(db_mod, "get_config", lambda: cfg)
        yield db_mod
        db_mod._db = None

    def test_only_rows_with_both_sizes_count(self, db: Any) -> None:
        """An internal tool's delivered bytes have no arrived size to save against."""
        db.record_gateway_call("p", "a", "t", "ok", 1, bytes_arrived=1000, bytes_delivered=400)
        db.record_gateway_call("p", "web", "fetch", "ok", 1, bytes_delivered=900)
        db.record_gateway_call("p", "a", "t", "denied_guard", 0, "no")

        delivery = db.get_gateway_call_stats(days=1)["delivery"]
        assert delivery["calls_measured"] == 1
        assert delivery["bytes_arrived"] == 1000
        assert delivery["bytes_delivered"] == 400
        assert delivery["savings_percent"] == 60
        assert delivery["estimated_tokens_saved"] == 150
        assert delivery["top_tools"][0]["tool"] == "t"

    def test_delivery_is_profile_filtered(self, db: Any) -> None:
        db.record_gateway_call("p", "a", "t", "ok", 1, bytes_arrived=10, bytes_delivered=5)
        db.record_gateway_call("q", "a", "t", "ok", 1, bytes_arrived=99, bytes_delivered=1)

        assert db.get_gateway_call_stats(profile="p", days=1)["delivery"]["bytes_arrived"] == 10

    def test_migration_adds_size_columns(self, tmp_path: Any) -> None:
        import trentina.database as db_mod

        path = str(tmp_path / "old_sizes.db")
        old = sqlite3.connect(path)
        old.executescript(
            "CREATE TABLE gateway_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp REAL NOT NULL, profile TEXT NOT NULL, backend TEXT NOT NULL, "
            "tool TEXT NOT NULL, success BOOLEAN NOT NULL, "
            "duration_ms INTEGER NOT NULL, error_message TEXT, outcome TEXT);"
        )
        old.close()

        db_mod._db = None
        conn = db_mod.get_db(path)
        try:
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(gateway_calls)")}
            assert {"bytes_arrived", "bytes_delivered"} <= columns
        finally:
            db_mod._db = None
