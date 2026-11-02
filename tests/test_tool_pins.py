"""Tool pinning (#469): a new or changed tool is held until an operator approves it."""

from __future__ import annotations

import copy
import pathlib
import sqlite3
import time
from typing import TYPE_CHECKING, Any

from trentina import perimeter_db
from trentina.gateway import tool_pins

# Imported at module load, before conftest's autouse fixture replaces it on the module.
from trentina.gateway.tool_pins import backend_id, check_tools, decide, held, pending

if TYPE_CHECKING:
    import pytest

URL = "http://backend.invalid/mcp"


def _tool(**over: Any) -> dict[str, Any]:
    tool: dict[str, Any] = {
        "name": "send",
        "description": "Send a note.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    }
    tool.update(over)
    return tool


def _names(tools: list[dict[str, Any]]) -> list[str]:
    return [t["name"] for t in tools]


def _upgraded() -> None:
    """Open the store, then say it was upgraded just now."""
    perimeter_db.get_perimeter_db()
    perimeter_db.pins_upgraded_at = time.monotonic()


def _approved(tool: dict[str, Any]) -> None:
    check_tools(URL, "b", [tool])
    assert decide(URL, tool["name"], approve=True)


def test_a_new_tool_is_held_until_approved() -> None:
    assert check_tools(URL, "b", [_tool()]) == []
    assert [p["tool"] for p in pending(URL)] == ["send"]
    assert decide(URL, "send", approve=True)
    assert _names(check_tools(URL, "b", [_tool()])) == ["send"]
    assert pending(URL) == []


def test_held_is_true_until_a_tool_is_approved() -> None:
    # The call gate (#469): fail closed on a missing row, held while pending,
    # false once approved.
    assert held(URL, "send") is True  # no pin row yet
    check_tools(URL, "b", [_tool()])  # creates the pending hold
    assert held(URL, "send") is True
    assert decide(URL, "send", approve=True)
    assert held(URL, "send") is False  # approved


def test_held_is_true_for_a_rejected_tool() -> None:
    check_tools(URL, "b", [_tool(name="x")])
    assert decide(URL, "x", approve=False)  # rejected
    assert held(URL, "x") is True


def test_pin_hold_flags_reports_each_state() -> None:
    # The DB helper the call gate reads (#469): None when the tool has no rows
    # at all (fail closed), (pending, rejected) otherwise — never any
    # definition JSON. Aggregated over every definition of the tool since
    # 6.1.0, because the gate is asked about a CALL and a call names no
    # definition: anything held under this tool is a reason to refuse it.
    bid = tool_pins.backend_id(URL)
    assert perimeter_db.pin_hold_flags(bid, "send") is None  # no rows
    check_tools(URL, "b", [_tool()])  # creates the pending hold
    assert perimeter_db.pin_hold_flags(bid, "send") == (True, False)
    assert decide(URL, "send", approve=False)  # that definition is rejected
    assert perimeter_db.pin_hold_flags(bid, "send") == (False, True)
    # A SECOND definition arrives and is held: both flags now stand, one from
    # each row, which is what a per-tool question should answer.
    check_tools(URL, "b", [_tool(description="other")])
    assert perimeter_db.pin_hold_flags(bid, "send") == (True, True)


def test_count_pending_pins_is_gateway_wide() -> None:
    # Held tools on two different backends; the count sums across both (#592,
    # E1c), and approving one decrements it.
    other = "http://other.invalid/mcp"
    live = {backend_id(URL), backend_id(other)}
    check_tools(URL, "b", [_tool(name="send")])
    check_tools(other, "c", [_tool(name="fetch")])
    assert perimeter_db.count_pending_pins(live) == 2
    assert decide(URL, "send", approve=True)
    assert perimeter_db.count_pending_pins(live) == 1


def test_count_pending_pins_ignores_a_backend_that_no_longer_exists() -> None:
    # A backend's id is the hash of its URL, so a URL change or a removed
    # backend leaves the old identity's rows behind. tool_pins resolves by the
    # LIVE url, so it can neither list nor approve those rows: counting them
    # reported a held tool nothing was withholding and nobody could release.
    gone = "http://moved.invalid/mcp"
    check_tools(URL, "b", [_tool(name="send")])
    check_tools(gone, "b", [_tool(name="send")])
    assert perimeter_db.count_pending_pins({backend_id(URL), backend_id(gone)}) == 2
    assert perimeter_db.count_pending_pins({backend_id(URL)}) == 1
    # No backends at all is zero rather than every row ever written.
    assert perimeter_db.count_pending_pins(set()) == 0
    # The rows are kept, not swept: the URL coming back finds its approvals
    # again instead of re-holding everything it offers.
    assert pending(gone) != []


def test_first_boot_of_the_upgrade_pins_current_tools_as_approved() -> None:
    _upgraded()
    assert _names(check_tools(URL, "b", [_tool()])) == ["send"]
    assert pending(URL) == []


def test_the_baseline_window_closes() -> None:
    _upgraded()
    perimeter_db.pins_upgraded_at = time.monotonic() - tool_pins.BASELINE_SECONDS - 1
    assert check_tools(URL, "b", [_tool()]) == []


def test_an_existing_store_without_pins_is_an_upgrade_and_a_fresh_one_is_not(
    tmp_path: pathlib.Path,
) -> None:
    legacy = sqlite3.connect(tmp_path / "legacy.db")
    legacy.execute("CREATE TABLE verdict_cache (cache_key TEXT)")
    legacy.commit()
    legacy.close()
    perimeter_db._db = None
    opened = perimeter_db.get_perimeter_db(str(tmp_path / "legacy.db"))
    assert perimeter_db.pins_upgraded_at is not None
    opened.close()
    perimeter_db._db = None
    perimeter_db.get_perimeter_db(str(tmp_path / "fresh.db"))
    assert perimeter_db.pins_upgraded_at is None


def test_a_changed_description_is_held() -> None:
    _approved(_tool())
    assert check_tools(URL, "b", [_tool(description="Send a note, then email it.")]) == []
    assert pending(URL)[0]["changed"] == ["description"]


def test_a_grown_schema_is_held() -> None:
    _approved(_tool())
    grown = _tool()
    grown["inputSchema"] = copy.deepcopy(grown["inputSchema"])
    grown["inputSchema"]["properties"]["url"] = {"type": "string"}
    assert check_tools(URL, "b", [grown]) == []
    assert pending(URL)[0]["changed"] == ["inputSchema"]


def test_an_annotation_only_change_is_held_and_marked_loosened() -> None:
    _approved(_tool())
    loosened = _tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    assert check_tools(URL, "b", [loosened]) == []
    held = pending(URL)[0]
    assert held["changed"] == ["annotations"]
    assert held["safety_loosened"] is True


def test_a_tightened_annotation_is_not_marked_loosened() -> None:
    _approved(_tool(annotations={"readOnlyHint": True}))
    check_tools(URL, "b", [_tool(annotations={"readOnlyHint": False})])
    assert pending(URL)[0]["safety_loosened"] is False


def test_a_second_list_changed_relist_keeps_it_held_and_reports_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports: list[str] = []
    monkeypatch.setattr(tool_pins, "_report", lambda b, t, o, n: reports.append(t))
    _approved(_tool())
    reports.clear()
    changed = _tool(description="different")
    assert check_tools(URL, "b", [changed]) == []
    assert check_tools(URL, "b", [changed]) == []
    assert reports == ["send"]


def test_reverting_to_the_approved_definition_serves_it_again() -> None:
    """And the definition that was held stays held (6.1.0).

    Before, a re-list matching the approved hash CLEARED the pending hold as a
    "revert". That is unsound once tool lists are partitioned per credential:
    "the backend went back to X" is only true for the tenant that listed X, and
    another tenant may still be served Y — so clearing Y's hold on one tenant's
    say-so was how two tenants flapped the pin and wrote a detection row on
    alternate passes. Y now stays held until an operator decides it, which is
    the fail-closed direction; `tool_pins reject` is how it goes away.
    """
    _approved(_tool())
    assert check_tools(URL, "b", [_tool(description="x")]) == []
    assert _names(check_tools(URL, "b", [_tool()])) == ["send"]
    still_held = pending(URL)
    assert [row["tool"] for row in still_held] == ["send"]
    assert still_held[0]["rejected"] is False


def test_reject_keeps_it_withheld() -> None:
    _approved(_tool())
    changed = _tool(description="different")
    check_tools(URL, "b", [changed])
    assert decide(URL, "send", approve=False)
    assert check_tools(URL, "b", [changed]) == []
    assert pending(URL)[0]["rejected"] is True


def test_approving_the_changed_version_serves_it() -> None:
    _approved(_tool())
    changed = _tool(description="different")
    check_tools(URL, "b", [changed])
    assert decide(URL, "send", approve=True)
    assert check_tools(URL, "b", [changed]) == [changed]


def test_decide_on_nothing_held_is_false() -> None:
    assert decide(URL, "ghost", approve=True) is False


def test_pins_belong_to_the_backend_not_the_list() -> None:
    _approved(_tool())
    assert check_tools("http://other.invalid/mcp", "b", [_tool()]) == []


# --- E1b: a federated secondary's first connect is approved as a unit (#592) ---


def test_a_federated_backends_first_list_is_approved_as_a_unit() -> None:
    tools = [_tool(name=f"t{i}") for i in range(5)]
    served = check_tools(URL, "b", tools, federated=True)
    assert len(served) == 5  # no per-tool approval storm
    assert pending(URL) == []


def test_a_new_federated_tool_after_first_connect_is_held_once() -> None:
    first = [_tool(name="a"), _tool(name="b"), _tool(name="c")]
    assert sorted(_names(check_tools(URL, "b", first, federated=True))) == ["a", "b", "c"]
    assert pending(URL) == []
    # A later list grows one tool: only the new one is held — "re-pins once".
    second = [*first, _tool(name="d")]
    served = check_tools(URL, "b", second, federated=True)
    assert sorted(_names(served)) == ["a", "b", "c"]
    assert [p["tool"] for p in pending(URL)] == ["d"]


def test_a_non_federated_first_list_still_holds() -> None:
    assert check_tools(URL, "b", [_tool()], federated=False) == []
    assert [p["tool"] for p in pending(URL)] == ["send"]


def test_has_pins_reflects_backend_rows() -> None:
    bid = tool_pins.backend_id(URL)
    assert perimeter_db.has_pins(bid) is False
    check_tools(URL, "b", [_tool()], federated=True)
    assert perimeter_db.has_pins(bid) is True


def test_an_empty_federated_first_list_still_records_the_connect() -> None:
    # An empty first list writes no tool rows; the connect must still be marked
    # so a tool the peer adds later is held, not auto-approved (#592, E1b).
    bid = tool_pins.backend_id(URL)
    assert check_tools(URL, "b", [], federated=True) == []
    assert perimeter_db.has_pins(bid) is True
    served = check_tools(URL, "b", [_tool(name="late")], federated=True)
    assert served == []
    assert [p["tool"] for p in pending(URL)] == ["late"]


class TestTwoTenantsTwoDefinitions:
    """6.1.0: tool lists are partitioned per credential, so one backend can
    legitimately offer two profiles different definitions of the same tool.

    One row per (backend, tool) could hold only one of them, and the damage was
    not that an unapproved definition got served — it never did — but that the
    two builds fought: the second listing overwrote the first's pending hash,
    a re-list matching the approved hash cleared the other's hold as a
    "revert", and a fresh detection row was written on alternate passes.
    """

    def test_both_are_held_independently(self) -> None:
        mine = _tool(description="mine")
        theirs = _tool(description="theirs")

        assert check_tools(URL, "b", [mine]) == []
        assert check_tools(URL, "b", [theirs]) == []

        held_rows = pending(URL)
        assert [row["tool"] for row in held_rows] == ["send", "send"]
        assert len({row["hash"] for row in held_rows}) == 2

    def test_neither_listing_clears_the_others_hold(self) -> None:
        """The flap, asserted gone: listing one definition repeatedly must not
        disturb the other's row, however many passes the builds take."""
        mine = _tool(description="mine")
        theirs = _tool(description="theirs")
        check_tools(URL, "b", [mine])
        check_tools(URL, "b", [theirs])

        for _ in range(3):
            check_tools(URL, "b", [mine])
            check_tools(URL, "b", [theirs])

        held_rows = pending(URL)
        assert len(held_rows) == 2
        assert all(row["rejected"] is False for row in held_rows)

    def test_approving_one_leaves_the_other_held(self) -> None:
        mine = _tool(description="mine")
        theirs = _tool(description="theirs")
        check_tools(URL, "b", [mine])
        check_tools(URL, "b", [theirs])
        mine_hash = next(
            row["hash"]
            for row in pending(URL)
            if row["hash"] == tool_pins.digest(tool_pins.canonical(mine))
        )

        assert decide(URL, "send", approve=True, definition_hash=mine_hash)

        assert check_tools(URL, "b", [mine]) == [mine]
        assert check_tools(URL, "b", [theirs]) == []
        assert [row["hash"] for row in pending(URL)] != [mine_hash]

    def test_an_approval_covers_every_tenant_served_those_exact_bytes(self) -> None:
        """One approval per distinct definition, not per tenant. A thousand
        tenants on a backend that answers identically is one decision."""
        shared = _tool()
        check_tools(URL, "b", [shared])
        assert decide(URL, "send", approve=True)

        # Whoever lists it next — any profile, any partition — is served it
        # without a second approval, because the approval named the bytes.
        assert check_tools(URL, "b", [shared]) == [shared]
        assert pending(URL) == []

    def test_deciding_without_a_hash_refuses_when_two_are_held(self) -> None:
        """There is no single thing "approve this tool" could mean then."""
        check_tools(URL, "b", [_tool(description="mine")])
        check_tools(URL, "b", [_tool(description="theirs")])

        assert decide(URL, "send", approve=True) is False
        assert len(pending(URL)) == 2

    def test_deciding_without_a_hash_is_fine_when_one_is_held(self) -> None:
        """The one-argument call every operator has been making stays correct."""
        check_tools(URL, "b", [_tool()])

        assert decide(URL, "send", approve=True) is True

    def test_a_call_is_refused_while_any_definition_is_held(self) -> None:
        """The call gate is asked about a CALL, which names no definition, so
        anything held under the tool is a reason to refuse it."""
        _approved(_tool())
        assert held(URL, "send") is False

        check_tools(URL, "b", [_tool(description="changed")])

        assert held(URL, "send") is True


class TestTheReKeyMigration:
    """A pre-6.1.0 store had one row per tool with an approved and a pending
    definition in it. The re-key turns each into up to two rows and keeps the
    old table, so a rollback to 6.0.x finds its approvals rather than holding
    every remote tool on the gateway at once.
    """

    def _old_store(self, path: pathlib.Path) -> None:
        con = sqlite3.connect(path)
        con.executescript(
            "CREATE TABLE tool_pins (backend_id TEXT NOT NULL, tool TEXT NOT NULL, "
            "approved_hash TEXT, approved_json TEXT, pending_hash TEXT, pending_json TEXT, "
            "rejected INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, "
            "last_seen TEXT NOT NULL, PRIMARY KEY (backend_id, tool));"
            "CREATE TABLE verdict_cache (cache_key TEXT PRIMARY KEY, warning_json TEXT, "
            "perimeter_version TEXT NOT NULL, judged_at TEXT NOT NULL);"
        )
        bid = backend_id(URL)
        approved = tool_pins.canonical(_tool())
        changed = tool_pins.canonical(_tool(description="changed"))
        con.executemany(
            "INSERT INTO tool_pins VALUES (?, ?, ?, ?, ?, ?, ?, 'now', 'now')",
            [
                (bid, "send", tool_pins.digest(approved), approved, None, None, 0),
                (
                    bid,
                    "wipe",
                    None,
                    None,
                    tool_pins.digest(changed),
                    changed,
                    1,
                ),
            ],
        )
        con.commit()
        con.close()

    def test_an_approved_definition_survives_and_is_still_served(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "perimeter.db"
        self._old_store(path)
        perimeter_db._db = None
        monkeypatch.setenv("TRENTINA_PERIMETER_DB", str(path))
        from trentina import config as config_mod

        config_mod._config = None

        # The tool its operator had approved is served without a new approval.
        assert check_tools(URL, "b", [_tool()]) == [_tool()]

    def test_a_rejected_definition_stays_rejected_and_the_old_table_is_kept(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "perimeter.db"
        self._old_store(path)
        perimeter_db._db = None
        monkeypatch.setenv("TRENTINA_PERIMETER_DB", str(path))
        from trentina import config as config_mod

        config_mod._config = None

        db = perimeter_db.get_perimeter_db()
        states = dict(db.execute("SELECT tool, state FROM tool_pins ORDER BY tool").fetchall())
        assert states == {"send": "approved", "wipe": "rejected"}
        # Kept, not dropped: a 6.0.x rollback reads it.
        assert db.execute(
            "SELECT 1 FROM sqlite_master WHERE name = ?", (perimeter_db._LEGACY_PINS,)
        ).fetchone()


class TestDefinitionsAreBounded:
    """One row per definition is what lets two tenants hold independently, and
    without a ceiling a backend whose descriptions churn would keep every
    version it has ever sent, JSON and all, for the life of the store.

    Gatehouse caught this; it is the same mistake as the unbounded description
    cache, in a second place.
    """

    def test_the_oldest_definitions_are_dropped(self) -> None:
        bid = backend_id(URL)
        for i in range(perimeter_db.MAX_DEFINITIONS_PER_TOOL + 5):
            check_tools(URL, "b", [_tool(description=f"version {i}")])

        rows = (
            perimeter_db.get_perimeter_db()
            .execute(
                "SELECT count(*) FROM tool_pins WHERE backend_id = ? AND tool = ?",
                (bid, "send"),
            )
            .fetchone()[0]
        )

        assert rows == perimeter_db.MAX_DEFINITIONS_PER_TOOL

    def test_eviction_is_fail_closed(self) -> None:
        """A dropped row reads as a definition never seen, and never seen is
        HELD — so the worst an eviction costs is a re-approval, never a tool
        served without one. That is what makes a plain LRU safe here."""
        first = _tool(description="the first version")
        check_tools(URL, "b", [first])
        assert decide(URL, "send", approve=True)
        assert check_tools(URL, "b", [first]) == [first]

        # Push it out with a flood of distinct definitions.
        for i in range(perimeter_db.MAX_DEFINITIONS_PER_TOOL + 1):
            check_tools(URL, "b", [_tool(description=f"version {i}")])

        # Its approval is gone with its row, so it is held rather than served.
        assert check_tools(URL, "b", [first]) == []
        assert held(URL, "send") is True

    def test_a_tools_definitions_do_not_evict_another_tools(self) -> None:
        check_tools(URL, "b", [_tool(name="keep")])
        assert decide(URL, "keep", approve=True)

        for i in range(perimeter_db.MAX_DEFINITIONS_PER_TOOL + 5):
            check_tools(URL, "b", [_tool(name="churn", description=f"v{i}")])

        assert _names(check_tools(URL, "b", [_tool(name="keep")])) == ["keep"]
