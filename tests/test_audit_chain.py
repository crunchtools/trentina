"""The audit hash chain (#472): what verifies, what breaks, what is not a break."""

from __future__ import annotations

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
    expected = '{"\U0001f600":2,"～":1}'.encode()
    assert audit_chain.canonical({"～": 1, "\U0001f600": 2}) == expected


def test_untouched_chain_verifies(db: Any) -> None:
    _calls(db)
    result = _verify(db)
    assert result["ok"] is True
    assert result["checked"] == 5
    assert result["checkpoint"]["kind"] == "genesis"


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
