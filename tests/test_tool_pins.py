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
from trentina.gateway.tool_pins import check_tools, decide, held, pending

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
    # The DB helper the call gate reads (#469): None when no row (fail closed),
    # (pending, rejected) otherwise — never the approved/pending JSON.
    bid = tool_pins.backend_id(URL)
    assert perimeter_db.pin_hold_flags(bid, "send") is None  # no row
    check_tools(URL, "b", [_tool()])  # creates the pending hold
    assert perimeter_db.pin_hold_flags(bid, "send") == (True, False)
    assert decide(URL, "send", approve=False)  # rejected; the pending def stays
    assert perimeter_db.pin_hold_flags(bid, "send") == (True, True)
    assert decide(URL, "send", approve=True)  # approved clean
    assert perimeter_db.pin_hold_flags(bid, "send") == (False, False)


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


def test_reverting_to_the_approved_definition_releases_the_tool() -> None:
    _approved(_tool())
    assert check_tools(URL, "b", [_tool(description="x")]) == []
    assert _names(check_tools(URL, "b", [_tool()])) == ["send"]
    assert pending(URL) == []


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
