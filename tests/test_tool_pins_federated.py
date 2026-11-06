"""E1a: a held federated tool shows up in `tool_pins list` (#592).

Field note from running federation: on mypeer, `tool_pins list backend=peergw`
returned `held: []` while the raw `tool_pins` table held several pending — the
operator could not see, by name, what the federated secondary was holding.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from trentina import perimeter_db
from trentina.gateway import compress, tool_pins
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import Profile
from trentina.gateway.tool_pins import backend_id, check_tools
from trentina.tools.pins import manage_tool_pins

pytestmark = pytest.mark.asyncio

PEERGW_URL = "https://peergw:8019/gateway/josui/mcp"

YAML = f"""\
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      peergw:
        url: {PEERGW_URL}
        federated: {{}}
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Profile]:
    monkeypatch.setenv("OP_TOKEN", "o")
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    try:
        return dict(config.profiles)
    finally:
        pass


@pytest.fixture(autouse=True)
def _drop_profiles() -> object:
    yield
    compress._profiles = None


async def test_a_held_federated_tool_is_listed(gateway: dict[str, Profile]) -> None:
    # peergw's tool is held primary under backend_id(the federated backend url).
    perimeter_db.put_pin(
        backend_id(PEERGW_URL), "send_message", "h", perimeter_db.PIN_PENDING, "{}"
    )
    with profile_context(gateway["op"]):
        result = await manage_tool_pins("list", "peergw")
    assert "error" not in result, result
    assert any(h["tool"] == "send_message" for h in result["held"]), result


async def test_approve_by_name_releases_a_federated_hold(gateway: dict[str, Profile]) -> None:
    perimeter_db.put_pin(
        backend_id(PEERGW_URL), "send_message", "h", perimeter_db.PIN_PENDING, "{}"
    )
    with profile_context(gateway["op"]):
        approved = await manage_tool_pins("approve", "peergw", "send_message")
        after = await manage_tool_pins("list", "peergw")
    assert approved == {
        "backend": "peergw",
        "tool": "send_message",
        "action": "approve",
        # One held definition, so the hash is implied and the operator
        # need not name it.
        "hash": None,
    }
    assert not any(h["tool"] == "send_message" for h in after["held"]), after


async def test_an_unknown_backend_is_not_found(gateway: dict[str, Profile]) -> None:
    with profile_context(gateway["op"]):
        result = await manage_tool_pins("list", "nope")
    assert "error" in result
    assert "not found" in result["error"]


async def test_an_agent_cannot_manage_pins() -> None:
    # Pins belong to a backend's whole surface, so only the operator may list
    # or release them; an agent profile is refused without learning anything.
    agent = Profile.model_validate(
        {
            "name": "ag",
            "auth": {"bearer_token_env": "A"},
            "backends": {"peergw": {"url": PEERGW_URL, "federated": {}}},
        }
    )
    with profile_context(agent):
        result = await manage_tool_pins("list", "peergw")
    assert "error" in result
    assert "operator" in result["error"].lower()


class TestAFirstConnectIsReported:
    """Auto-approving a federated peer's whole offered set is the one place
    this gateway trusts a tool set it never showed anyone.

    Holds wrote a log line and a detections row; approvals wrote nothing. That
    made the quieter path the one that trusts more — a container brought up
    without its perimeter volume re-approved every peer's set and said nothing.

    `check_tools` is called through the name imported at module scope, not
    `tool_pins.check_tools`: conftest's `_tools_not_pinned` stubs the module
    attribute for the whole suite, and a test of pinning that goes through the
    stub asserts nothing. `tests/test_tool_pins.py` does the same.

    Each test gets an empty perimeter store (conftest's
    `_isolated_perimeter_store`), so every federated list here is a first
    connect unless the test makes one itself.
    """

    PIN_LOGGER = "trentina.gateway.tool_pins"

    def _offered(self, count: int) -> list[dict[str, Any]]:
        return [{"name": f"tool_{i}", "description": "d"} for i in range(count)]

    def _pin_lines(self, caplog: pytest.LogCaptureFixture) -> list[str]:
        """Only this module's lines: `perimeter_db`'s empty-store warning
        names a first connect too, since that is what a lost store causes."""
        return [r.getMessage() for r in caplog.records if r.name == self.PIN_LOGGER]

    def test_a_first_connect_warns_with_the_count(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            served = check_tools(PEERGW_URL, "peergw", self._offered(3), federated=True)
        assert len(served) == 3  # approved as a unit, as the design says
        line = next(m for m in self._pin_lines(caplog) if "first connect" in m)
        assert "of 3 tool(s)" in line
        assert "unreviewed" in line

    def test_the_tool_names_are_not_in_the_line(self, caplog: pytest.LogCaptureFixture) -> None:
        """#262: the backend name is config, the peer's tool names are not."""
        offered = [{"name": "secret_peer_tool", "description": "d"}]
        with caplog.at_level(logging.WARNING):
            check_tools(PEERGW_URL, "peergw", offered, federated=True)
        assert all("secret_peer_tool" not in r.getMessage() for r in caplog.records)

    def test_a_first_connect_leaves_a_detections_row(self) -> None:
        """`blocked=False`: nothing was withheld, which is why recording it is
        the point. An operator reviewing what this gateway trusted has a row
        to find."""
        with patch.object(tool_pins, "record_detection") as recorded:
            check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)
        kwargs = recorded.call_args.kwargs
        assert kwargs["source_type"] == "tool_pin"
        assert kwargs["blocked"] is False
        assert kwargs["layer1_stats"] == {"first_connect": True, "approved_unreviewed": 2}

    def test_the_second_list_is_not_a_first_connect(self, caplog: pytest.LogCaptureFixture) -> None:
        """The sentinel is what stops a later-added tool reading as another
        first connect."""
        check_tools(PEERGW_URL, "peergw", self._offered(1), federated=True)
        # `at_level` changes the level, it does not scope capture: the first
        # call's own first-connect line is still in `records` without this.
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            served = check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)
        assert all("first connect" not in m for m in self._pin_lines(caplog))
        assert len(served) == 1  # the new tool is HELD, not auto-approved

    def test_a_non_federated_backend_is_never_a_first_connect(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            served = check_tools(PEERGW_URL, "plain", self._offered(2))
        assert all("first connect" not in m for m in self._pin_lines(caplog))
        assert served == []  # held for approval, one at a time

    def test_an_empty_perimeter_store_says_so(self, caplog: pytest.LogCaptureFixture) -> None:
        """The other half: a container without its volume. The quiet version of
        this is what made a lost store cost the trust it was protecting."""
        import trentina.perimeter_db as pdb

        pdb._db = None
        with caplog.at_level(logging.WARNING):
            pdb.get_perimeter_db()
        assert any("created empty" in r.getMessage() for r in caplog.records)


class TestAUrlEditIsNotAFirstConnect:
    """A pin is keyed by a hash of the URL, so normalising a trailing slash or
    writing an explicit `:443` presented the peer as new — and a federated
    first connect approves the whole offered set as a unit. Loud since the
    first-connect report; carried across now, so it does not happen at all."""

    @staticmethod
    def _offered(count: int) -> list[dict[str, Any]]:
        return [{"name": f"t{n}", "description": "d", "inputSchema": {}} for n in range(count)]

    @staticmethod
    def _profile(url: str) -> Profile:
        from pydantic import SecretStr

        from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig

        profile = Profile(
            name="josui",
            auth=AuthConfig(bearer_token_env="T"),
            backends={"peergw": Backend(url=url, federated=FederatedConfig(), tools_allow=["*"])},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("t")
        return profile

    def test_the_pins_move_with_the_url(self, caplog: pytest.LogCaptureFixture) -> None:
        moved_to = PEERGW_URL + "/"
        check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)
        assert perimeter_db.has_pins(backend_id(PEERGW_URL))

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(PEERGW_URL)}, {"josui": self._profile(moved_to)}
        )

        assert migrated == ["josui.peergw"]
        assert perimeter_db.has_pins(backend_id(moved_to))
        assert not perimeter_db.has_pins(backend_id(PEERGW_URL))

        # And the point of all of it: the next list at the new URL is not a
        # first connect, so a newly offered tool is HELD rather than trusted.
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            served = check_tools(moved_to, "peergw", self._offered(3), federated=True)
        assert all("first connect" not in r.getMessage() for r in caplog.records)
        assert len(served) == 2

    def test_pins_already_at_the_new_url_are_not_overwritten(self) -> None:
        """Two backends may legitimately name one URL, and `(backend_id, tool)`
        is the primary key: the pins already there are not this edit's to
        replace, and an UPDATE would collide on every shared tool."""
        other = "https://other:8019/gateway/josui/mcp"
        check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)
        check_tools(other, "other", self._offered(1), federated=True)

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(PEERGW_URL)}, {"josui": self._profile(other)}
        )

        assert migrated == []
        assert perimeter_db.has_pins(backend_id(PEERGW_URL))

    def test_a_different_host_is_not_a_moved_url(self) -> None:
        """The hole in the first cut of this, which Gatehouse caught: migrating
        on ANY url change means repointing a federated backend at a server the
        writer controls inherits the real peer's approvals, with no first
        connect and no review. Only the SAME endpoint spelled differently
        moves; a new host gets the first connect it should."""
        elsewhere = "https://attacker.example/gateway/josui/mcp"
        check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(PEERGW_URL)}, {"josui": self._profile(elsewhere)}
        )

        assert migrated == []
        assert not perimeter_db.has_pins(backend_id(elsewhere))
        assert perimeter_db.has_pins(backend_id(PEERGW_URL))

    def test_a_port_written_out_is_the_same_endpoint(self) -> None:
        """`same_gateway_endpoint` keeps the path and the query and forgives the
        spelling: a default port written explicitly is one gateway, not two."""
        https = "https://peergw.example/gateway/josui/mcp"
        with_port = "https://Peergw.example:443/gateway/josui/mcp/"
        check_tools(https, "peergw", self._offered(2), federated=True)

        assert tool_pins.migrate_federated_pins(
            {"josui": self._profile(https)}, {"josui": self._profile(with_port)}
        ) == ["josui.peergw"]

    def test_a_different_query_is_not_the_same_endpoint(self) -> None:
        """A token-in-URL backend carries its credential in the query, so two
        URLs differing only there can be two endpoints."""
        one = "https://peergw.example/gateway/josui/mcp?t=aaa"
        two = "https://peergw.example/gateway/josui/mcp?t=bbb"
        check_tools(one, "peergw", self._offered(2), federated=True)

        assert (
            tool_pins.migrate_federated_pins(
                {"josui": self._profile(one)}, {"josui": self._profile(two)}
            )
            == []
        )

    def test_a_backend_that_stopped_being_federated_keeps_its_own_pins(self) -> None:
        """Losing the `federated` block changes what the backend IS, not where
        it lives, so its pins are not carried to a new URL by this rule."""
        from trentina.gateway.profile import AuthConfig, Backend

        check_tools(PEERGW_URL, "peergw", self._offered(2), federated=True)
        plain = Profile(
            name="josui",
            auth=AuthConfig(bearer_token_env="T"),
            backends={"peergw": Backend(url=PEERGW_URL + "/", tools_allow=["*"])},
        )

        assert (
            tool_pins.migrate_federated_pins({"josui": self._profile(PEERGW_URL)}, {"josui": plain})
            == []
        )


class TestTheHashAtTheToolBoundary:
    """`tool_pins approve` with two held definitions, through the tool itself.

    `decide` is covered directly in `test_tool_pins.py`; this is the operator's
    actual path, including what the refusal tells them.
    """

    @staticmethod
    def _hold_two() -> list[str]:
        bid = backend_id(PEERGW_URL)
        for body in ('{"name": "send_message", "v": 1}', '{"name": "send_message", "v": 2}'):
            perimeter_db.put_pin(
                bid, "send_message", tool_pins.digest(body), perimeter_db.PIN_PENDING, body
            )
        return perimeter_db.pending_hashes(bid, "send_message")

    async def test_a_hashless_approve_refuses_and_offers_both(
        self, gateway: dict[str, Profile]
    ) -> None:
        held = self._hold_two()

        with profile_context(gateway["op"]):
            result = await manage_tool_pins("approve", "peergw", "send_message")

        assert "more than one held definition" in result["error"]
        assert sorted(result["held"]) == sorted(held)
        # And nothing was decided by accident.
        assert len(perimeter_db.pending_hashes(backend_id(PEERGW_URL), "send_message")) == 2

    async def test_approving_by_hash_takes_only_that_definition(
        self, gateway: dict[str, Profile]
    ) -> None:
        held = self._hold_two()
        chosen = held[0]

        with profile_context(gateway["op"]):
            result = await manage_tool_pins("approve", "peergw", "send_message", chosen)

        assert result["hash"] == chosen
        assert result["action"] == "approve"
        # The other one is still held, which is the whole point of the hash.
        assert perimeter_db.pending_hashes(backend_id(PEERGW_URL), "send_message") == [held[1]]

    async def test_rejecting_by_hash_takes_only_that_definition(
        self, gateway: dict[str, Profile]
    ) -> None:
        held = self._hold_two()

        with profile_context(gateway["op"]):
            await manage_tool_pins("reject", "peergw", "send_message", held[1])
            listed = await manage_tool_pins("list", "peergw")

        states = {row["hash"]: row["rejected"] for row in listed["held"]}
        assert states[held[1]] is True
        assert states[held[0]] is False

    async def test_a_hash_that_is_not_held_is_refused(self, gateway: dict[str, Profile]) -> None:
        self._hold_two()

        with profile_context(gateway["op"]):
            result = await manage_tool_pins("approve", "peergw", "send_message", "not-a-held-hash")

        assert result["error"] == "no such held tool"


def _defn(description: str) -> str:
    """One tool definition differing only in the description, which is what a
    re-compression moves."""
    return tool_pins.canonical({"name": "send_message", "description": description})


class TestApprovingAWholeHeldSet:
    """`approve_all`: one decision for a set the gateway's own compressor moved.

    6.1.0's `tool_compressions` `owner` column dropped pre-migration rows, and a
    pin is keyed by the definition AS SERVED — which under
    `preprocess_tool_descriptions` is the compressor's output. Re-compressing is
    a fresh model call, so it is not byte-identical, and mypeer held 582
    definitions across 352 tools on one federated backend. Releasing those one
    at a time is not a control; it is how an operator learns to stop reading.

    The gate is therefore the SET, not the operator's patience: the digest binds
    the approval to the bytes `list` showed, and `BULK_FIELDS` keeps every
    rug-pull shape on the one-at-a-time path.
    """

    @staticmethod
    def _approved(tool: str, body: str) -> None:
        perimeter_db.put_pin(
            backend_id(PEERGW_URL), tool, tool_pins.digest(body), perimeter_db.PIN_APPROVED, body
        )

    @staticmethod
    def _held(tool: str, body: str, state: str = perimeter_db.PIN_PENDING) -> str:
        h = tool_pins.digest(body)
        perimeter_db.put_pin(backend_id(PEERGW_URL), tool, h, state, body)
        return h

    def _recompressed(self) -> None:
        """What a re-compression looks like: the description rewritten, and for
        some tools the schema compacted differently too."""
        for i, tool in enumerate(("send_message", "read_entry", "list_feeds")):
            schema = {"properties": {"body": {"type": "string", "description": "the full text"}}}
            old = {"name": tool, "description": "original prose", "inputSchema": schema}
            new: dict[str, Any] = {
                "name": tool,
                "description": "tighter prose",
                "inputSchema": schema,
            }
            if i == 2:
                # The compressor rewrites the descriptions INSIDE a schema too,
                # which is the only way inputSchema may differ in a batch.
                new["inputSchema"] = {
                    "properties": {"body": {"type": "string", "description": "text"}}
                }
            self._approved(tool, tool_pins.canonical(old))
            self._held(tool, tool_pins.canonical(new))

    async def test_the_whole_set_goes_on_one_decision(self, gateway: dict[str, Profile]) -> None:
        self._recompressed()
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert result["approved"] == 3, result
        assert {row["tool"] for row in result["tools"]} == {
            "send_message",
            "read_entry",
            "list_feeds",
        }
        # The manifest says what each one changed, so the decision is auditable
        # after the fact rather than only at the moment it was taken.
        changed = {row["tool"]: row["changed"] for row in result["tools"]}
        assert changed["list_feeds"] == ["description", "inputSchema"]
        assert changed["send_message"] == ["description"]
        with profile_context(gateway["op"]):
            assert (await manage_tool_pins("list", "peergw"))["held"] == []

    async def test_a_stale_digest_refuses_and_changes_nothing(
        self, gateway: dict[str, Profile]
    ) -> None:
        self._recompressed()
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            # Another profile lists for the first time and a fourth tool is held.
            self._approved(
                "alert_history", tool_pins.canonical({"name": "alert_history", "description": "a"})
            )
            self._held(
                "alert_history", tool_pins.canonical({"name": "alert_history", "description": "b"})
            )
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "changed since it was listed" in result["error"]
        with profile_context(gateway["op"]):
            assert len((await manage_tool_pins("list", "peergw"))["held"]) == 4

    async def test_the_digest_moves_when_a_swap_keeps_the_count(
        self, gateway: dict[str, Profile]
    ) -> None:
        """The attack a count would have missed, which is why it is a digest.

        My first design required the `expect` COUNT that `list` returned. A
        re-list that swaps N definitions for N others keeps the count exactly,
        so the operator would have approved bytes nobody read. Fable (the `cto`
        agent) rejected the count on this ground; the test is here so the
        reasoning cannot be lost to a later simplification.
        """
        bid = backend_id(PEERGW_URL)
        self._approved("send_message", tool_pins.canonical({"name": "send_message", "d": 0}))
        first = self._held("send_message", tool_pins.canonical({"name": "send_message", "d": 1}))
        with profile_context(gateway["op"]):
            before = (await manage_tool_pins("list", "peergw"))["digest"]

        perimeter_db.set_pin_state(bid, "send_message", first, perimeter_db.PIN_APPROVED)
        self._held("send_message", tool_pins.canonical({"name": "send_message", "d": 2}))
        with profile_context(gateway["op"]):
            after = await manage_tool_pins("list", "peergw")

        assert len(after["held"]) == 1  # the count is identical
        assert after["digest"] != before  # the digest is not

    async def test_a_tool_with_no_approved_definition_refuses_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        """`changed == ["new"]`: nobody has ever approved this tool. That is
        precisely what #469 exists to put in front of a person, and it is not
        batch work however many of them arrive at once (era holds 49)."""
        self._recompressed()
        self._held("brand_new_tool", tool_pins.canonical({"name": "brand_new_tool", "d": 1}))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "1 of 4 held definitions will not go in a batch" in result["error"]
        assert "brand_new_tool (changed in new)" in result["error"]
        # Nothing was released: a batch that took most of itself and reported
        # the rest would be read as a success.
        with profile_context(gateway["op"]):
            assert len((await manage_tool_pins("list", "peergw"))["held"]) == 4

    async def test_an_annotation_change_refuses_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        old = {"name": "send_message", "description": "d", "annotations": {"readOnlyHint": False}}
        new = {"name": "send_message", "description": "d", "annotations": {"readOnlyHint": True}}
        self._approved("send_message", tool_pins.canonical(old))
        self._held("send_message", tool_pins.canonical(new))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "send_message (changed in annotations)" in result["error"]

    async def test_a_loosened_hint_is_refused_even_if_the_field_rule_widens(
        self, gateway: dict[str, Profile], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Why the `safety_loosened` guard is there at all.

        It is unreachable while `BULK_FIELDS` excludes `annotations`, since that
        is the only field a loosened hint can live in. It is kept so that
        widening the field rule later cannot quietly start passing one, and this
        test widens it to prove the guard, not the subset, is what refuses.
        """
        monkeypatch.setattr(
            tool_pins, "BULK_FIELDS", frozenset({"description", "inputSchema", "annotations"})
        )
        old = {"name": "send_message", "annotations": {"destructiveHint": True}}
        new = {"name": "send_message", "annotations": {"destructiveHint": False}}
        self._approved("send_message", tool_pins.canonical(old))
        self._held("send_message", tool_pins.canonical(new))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "send_message (loosened a safety hint)" in result["error"]

    async def test_a_rejected_definition_stays_rejected(self, gateway: dict[str, Profile]) -> None:
        """A rejection is a standing decision. It is outside the digest, so it
        neither blocks the batch nor is reversed by it."""
        self._approved("send_message", _defn("as approved"))
        kept = self._held("send_message", _defn("recompressed"))
        refused = self._held("send_message", _defn("rejected once"), perimeter_db.PIN_REJECTED)
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert [row["hash"] for row in result["tools"]] == [kept]
        with profile_context(gateway["op"]):
            still = (await manage_tool_pins("list", "peergw"))["held"]
        assert [(row["hash"], row["rejected"]) for row in still] == [(refused, True)]

    async def test_both_definitions_of_one_tool_are_released(
        self, gateway: dict[str, Profile]
    ) -> None:
        """Two profiles served different bytes by one backend: both answers are
        real (`docs/tool-pinning.md`), and both are the compressor's own output.
        230 of mypeer's 352 held tools were this shape."""
        self._approved("send_message", _defn("as approved"))
        one = self._held("send_message", _defn("as one profile reads it"))
        two = self._held("send_message", _defn("as the other reads it"))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert sorted(row["hash"] for row in result["tools"]) == sorted([one, two])
        assert perimeter_db.pending_hashes(backend_id(PEERGW_URL), "send_message") == []

    async def test_it_leaves_one_detections_row_for_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        self._recompressed()
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            with patch.object(tool_pins, "record_detection") as recorded:
                await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert recorded.call_count == 1
        kwargs = recorded.call_args.kwargs
        assert kwargs["source_type"] == "tool_pin"
        assert kwargs["blocked"] is False
        assert kwargs["layer1_stats"] == {"approved_bulk": 3}

    async def test_the_tool_names_are_not_logged(
        self, gateway: dict[str, Profile], caplog: pytest.LogCaptureFixture
    ) -> None:
        """#262: the backend name is config; the peer's tool names are not. The
        count stands for them, and the manifest carries the rest."""
        self._recompressed()
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            with caplog.at_level(logging.WARNING):
                await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        messages = [r.getMessage() for r in caplog.records]
        assert any("released 3 held tool definition(s)" in m for m in messages)
        assert all("send_message" not in m for m in messages)

    async def test_it_refuses_without_a_digest(self, gateway: dict[str, Profile]) -> None:
        self._recompressed()
        with profile_context(gateway["op"]):
            result = await manage_tool_pins("approve_all", "peergw")

        assert "needs the set_digest" in result["error"]
        with profile_context(gateway["op"]):
            assert len((await manage_tool_pins("list", "peergw"))["held"]) == 3

    async def test_a_schema_that_gained_an_input_refuses_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        """What keeps `inputSchema` safe to batch at all.

        The compressor rewrites the descriptions INSIDE a schema as well as the
        tool's own (`compress._compressed_properties`), which is why 278 of
        mypeer's 582 rows reported `description,inputSchema`. It never adds a
        property — so a schema that grew is the backend's doing, and "a schema
        that grows a `recipient` or `url` parameter" is the rug pull this module
        exists to catch.
        """
        old = {
            "name": "send_message",
            "inputSchema": {"properties": {"body": {"description": "the text"}}},
        }
        new = {
            "name": "send_message",
            "inputSchema": {
                "properties": {
                    "body": {"description": "text"},
                    "recipient": {"description": "who"},
                }
            },
        }
        self._approved("send_message", tool_pins.canonical(old))
        self._held("send_message", tool_pins.canonical(new))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert listed["held"][0]["changed"] == ["inputSchema"]
        assert listed["held"][0]["schema_shape_changed"] is True
        assert "beyond its descriptions" in result["error"]
        assert perimeter_db.pending_hashes(backend_id(PEERGW_URL), "send_message")

    async def test_a_rewritten_property_description_still_batches(
        self, gateway: dict[str, Profile]
    ) -> None:
        """The other side of the same rule: the compressor's actual output."""
        old = {
            "name": "send_message",
            "inputSchema": {"properties": {"body": {"description": "the text to send"}}},
        }
        new = {
            "name": "send_message",
            "inputSchema": {"properties": {"body": {"description": "text"}}},
        }
        self._approved("send_message", tool_pins.canonical(old))
        self._held("send_message", tool_pins.canonical(new))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert listed["held"][0]["schema_shape_changed"] is False
        assert result["approved"] == 1

    async def test_a_new_required_entry_refuses_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        """Making an existing optional mandatory changes what a call must carry,
        and adds no key path, so `required` is compared by value."""
        props = {"properties": {"body": {"description": "d"}, "to": {"description": "d"}}}
        self._approved(
            "send_message",
            tool_pins.canonical({"name": "send_message", "inputSchema": {**props, "required": []}}),
        )
        self._held(
            "send_message",
            tool_pins.canonical(
                {"name": "send_message", "inputSchema": {**props, "required": ["to"]}}
            ),
        )
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "beyond its descriptions" in result["error"]

    async def test_a_write_that_cannot_move_every_row_moves_none(
        self, gateway: dict[str, Profile]
    ) -> None:
        """All-or-nothing, in one transaction.

        A partial release reported as a success is worse than a refusal: the
        operator believes the set went, and the rows that quietly failed are
        the ones nothing has reviewed.
        """
        self._recompressed()
        bid = backend_id(PEERGW_URL)
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            # One row vanishes between the digest check and the write.
            with patch.object(perimeter_db, "set_pin_states", side_effect=lambda *a, **k: None):
                result = await manage_tool_pins(
                    "approve_all", "peergw", set_digest=listed["digest"]
                )

        assert "moved while it was being approved" in result["error"]
        assert len(perimeter_db.list_pending_pins(bid)) == 3  # nothing released

    @pytest.mark.parametrize(
        ("old_schema", "new_schema", "what"),
        [
            (
                {"properties": {"to": {"enum": ["alice"]}}},
                {"properties": {"to": {"enum": ["alice", "anyone"]}}},
                "a widened enum",
            ),
            (
                {"properties": {"body": {"type": "string"}}},
                {"properties": {"body": {"type": "object"}}},
                "a changed type",
            ),
            (
                {"properties": {"body": {"type": "string"}}, "additionalProperties": False},
                {"properties": {"body": {"type": "string"}}, "additionalProperties": True},
                "relaxed additionalProperties",
            ),
            (
                {
                    "properties": {
                        "a": {"required": ["id"], "properties": {"id": {"type": "string"}}},
                        "b": {"required": [], "properties": {"id": {"type": "string"}}},
                    }
                },
                {
                    "properties": {
                        "a": {"required": ["id"], "properties": {"id": {"type": "string"}}},
                        "b": {"required": ["id"], "properties": {"id": {"type": "string"}}},
                    }
                },
                "a required entry added where a sibling already had it",
            ),
        ],
    )
    async def test_a_change_that_adds_no_key_still_refuses_the_batch(
        self,
        gateway: dict[str, Profile],
        old_schema: dict[str, Any],
        new_schema: dict[str, Any],
        what: str,
    ) -> None:
        """Why the rule is equality-apart-from-descriptions, not "did it grow".

        The first cut asked whether the schema gained a key path or a `required`
        name. Gatehouse pointed out that every case here adds neither, and all
        four change what a call means. Comparing what must NOT change beats
        enumerating the ways it could.
        """
        self._approved(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": old_schema})
        )
        self._held(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": new_schema})
        )
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert listed["held"][0]["schema_shape_changed"] is True, what
        assert "beyond its descriptions" in result["error"], what

    async def test_a_property_actually_named_description_is_part_of_the_shape(
        self, gateway: dict[str, Profile]
    ) -> None:
        """The annotation is dropped before comparing; a property of that name
        is not. `_NAME_MAPS` is what tells them apart."""
        old = {"properties": {"description": {"type": "string"}}}
        new = {"properties": {"description": {"type": "integer"}}}
        self._approved(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": old})
        )
        self._held(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": new})
        )
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")

        assert listed["held"][0]["schema_shape_changed"] is True

    async def test_dropping_a_property_also_refuses_the_batch(
        self, gateway: dict[str, Profile]
    ) -> None:
        """Equality is symmetric, so a schema that SHRANK is reviewed too. The
        growth check passed this silently."""
        old = {"properties": {"body": {"type": "string"}, "to": {"type": "string"}}}
        new = {"properties": {"body": {"type": "string"}}}
        self._approved(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": old})
        )
        self._held(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": new})
        )
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "beyond its descriptions" in result["error"]

    @pytest.mark.parametrize("keyword", ["const", "default", "examples", "enum"])
    async def test_a_description_inside_a_literal_value_is_data(
        self, gateway: dict[str, Profile], keyword: str
    ) -> None:
        """`description` is only an annotation at a schema position.

        Inside `const`, `default`, `examples` or `enum` it is part of the value
        a call must send, so changing it changes what the schema accepts. The
        first cut of `_schema_shape` stripped every string-valued `description`
        key at any depth and would have batched this.
        """
        payload = (
            [{"description": "old"}] if keyword in ("examples", "enum") else {"description": "old"}
        )
        newer = (
            [{"description": "new"}] if keyword in ("examples", "enum") else {"description": "new"}
        )
        old = {"properties": {"body": {"type": "object", keyword: payload}}}
        new = {"properties": {"body": {"type": "object", keyword: newer}}}
        self._approved(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": old})
        )
        self._held(
            "send_message", tool_pins.canonical({"name": "send_message", "inputSchema": new})
        )
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert listed["held"][0]["schema_shape_changed"] is True, keyword
        assert "beyond its descriptions" in result["error"], keyword

    async def test_the_refusal_names_every_exception_not_the_first(
        self, gateway: dict[str, Profile]
    ) -> None:
        """At 582 held definitions, a refusal that stops at the first exception
        turns clearing a backlog into one round trip per exception — and an
        operator doing that reads none of them, which is what this affordance
        exists to avoid."""
        self._recompressed()
        for name in ("brand_new_a", "brand_new_b", "brand_new_c"):
            self._held(name, tool_pins.canonical({"name": name, "description": "d"}))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        assert "3 of 6 held definitions will not go in a batch" in result["error"]
        for name in ("brand_new_a", "brand_new_b", "brand_new_c"):
            assert f"{name} (changed in new)" in result["error"]

    @pytest.mark.parametrize("over", [-1, 0, 5])
    async def test_a_long_exception_list_is_counted_rather_than_printed(
        self, gateway: dict[str, Profile], over: int
    ) -> None:
        """The refusal is a tool result an agent reads, so it stays bounded —
        and the boundary itself is tested: just under the cap, exactly at it,
        and over, where only the surplus is counted."""
        count = tool_pins.MAX_NAMED_EXCEPTIONS + over
        names = [f"brand_new_{i:02d}" for i in range(count)]
        for name in names:
            self._held(name, tool_pins.canonical({"name": name, "description": "d"}))
        with profile_context(gateway["op"]):
            listed = await manage_tool_pins("list", "peergw")
            result = await manage_tool_pins("approve_all", "peergw", set_digest=listed["digest"])

        error = result["error"]
        assert f"{count} of {count} held definitions" in error
        if over > 0:
            assert f"and {over} more" in error
            # The named set must be the FIRST cap names and no others, or a
            # regression that picked the wrong subset would still pass.
            for name in names[: tool_pins.MAX_NAMED_EXCEPTIONS]:
                assert name in error, name
            for name in names[tool_pins.MAX_NAMED_EXCEPTIONS :]:
                assert name not in error, name
        else:
            assert "more" not in error
            for name in names:
                assert name in error
