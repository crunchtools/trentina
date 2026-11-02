"""E1a: a held federated tool shows up in `tool_pins list` (#592).

Field note from running federation: on breetai, `tool_pins list backend=lotor`
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

LOTOR_URL = "https://lotor:8019/gateway/josui/mcp"

YAML = f"""\
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      lotor:
        url: {LOTOR_URL}
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
    # lotor's tool is held primary under backend_id(the federated backend url).
    perimeter_db.put_pin(
        backend_id(LOTOR_URL), "send_message", approved=None, pending=("h", "{}"), rejected=False
    )
    with profile_context(gateway["op"]):
        result = await manage_tool_pins("list", "lotor")
    assert "error" not in result, result
    assert any(h["tool"] == "send_message" for h in result["held"]), result


async def test_approve_by_name_releases_a_federated_hold(gateway: dict[str, Profile]) -> None:
    perimeter_db.put_pin(
        backend_id(LOTOR_URL), "send_message", approved=None, pending=("h", "{}"), rejected=False
    )
    with profile_context(gateway["op"]):
        approved = await manage_tool_pins("approve", "lotor", "send_message")
        after = await manage_tool_pins("list", "lotor")
    assert approved == {"backend": "lotor", "tool": "send_message", "action": "approve"}
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
            "backends": {"lotor": {"url": LOTOR_URL, "federated": {}}},
        }
    )
    with profile_context(agent):
        result = await manage_tool_pins("list", "lotor")
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
            served = check_tools(LOTOR_URL, "lotor", self._offered(3), federated=True)
        assert len(served) == 3  # approved as a unit, as the design says
        line = next(m for m in self._pin_lines(caplog) if "first connect" in m)
        assert "of 3 tool(s)" in line
        assert "unreviewed" in line

    def test_the_tool_names_are_not_in_the_line(self, caplog: pytest.LogCaptureFixture) -> None:
        """#262: the backend name is config, the peer's tool names are not."""
        offered = [{"name": "secret_peer_tool", "description": "d"}]
        with caplog.at_level(logging.WARNING):
            check_tools(LOTOR_URL, "lotor", offered, federated=True)
        assert all("secret_peer_tool" not in r.getMessage() for r in caplog.records)

    def test_a_first_connect_leaves_a_detections_row(self) -> None:
        """`blocked=False`: nothing was withheld, which is why recording it is
        the point. An operator reviewing what this gateway trusted has a row
        to find."""
        with patch.object(tool_pins, "record_detection") as recorded:
            check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)
        kwargs = recorded.call_args.kwargs
        assert kwargs["source_type"] == "tool_pin"
        assert kwargs["blocked"] is False
        assert kwargs["layer1_stats"] == {"first_connect": True, "approved_unreviewed": 2}

    def test_the_second_list_is_not_a_first_connect(self, caplog: pytest.LogCaptureFixture) -> None:
        """The sentinel is what stops a later-added tool reading as another
        first connect."""
        check_tools(LOTOR_URL, "lotor", self._offered(1), federated=True)
        # `at_level` changes the level, it does not scope capture: the first
        # call's own first-connect line is still in `records` without this.
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            served = check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)
        assert all("first connect" not in m for m in self._pin_lines(caplog))
        assert len(served) == 1  # the new tool is HELD, not auto-approved

    def test_a_non_federated_backend_is_never_a_first_connect(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            served = check_tools(LOTOR_URL, "plain", self._offered(2))
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
            backends={"lotor": Backend(url=url, federated=FederatedConfig(), tools_allow=["*"])},
        )
        assert profile.auth is not None
        profile.auth.bearer_token = SecretStr("t")
        return profile

    def test_the_pins_move_with_the_url(self, caplog: pytest.LogCaptureFixture) -> None:
        moved_to = LOTOR_URL + "/"
        check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)
        assert perimeter_db.has_pins(backend_id(LOTOR_URL))

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(LOTOR_URL)}, {"josui": self._profile(moved_to)}
        )

        assert migrated == ["josui.lotor"]
        assert perimeter_db.has_pins(backend_id(moved_to))
        assert not perimeter_db.has_pins(backend_id(LOTOR_URL))

        # And the point of all of it: the next list at the new URL is not a
        # first connect, so a newly offered tool is HELD rather than trusted.
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            served = check_tools(moved_to, "lotor", self._offered(3), federated=True)
        assert all("first connect" not in r.getMessage() for r in caplog.records)
        assert len(served) == 2

    def test_pins_already_at_the_new_url_are_not_overwritten(self) -> None:
        """Two backends may legitimately name one URL, and `(backend_id, tool)`
        is the primary key: the pins already there are not this edit's to
        replace, and an UPDATE would collide on every shared tool."""
        other = "https://other:8019/gateway/josui/mcp"
        check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)
        check_tools(other, "other", self._offered(1), federated=True)

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(LOTOR_URL)}, {"josui": self._profile(other)}
        )

        assert migrated == []
        assert perimeter_db.has_pins(backend_id(LOTOR_URL))

    def test_a_different_host_is_not_a_moved_url(self) -> None:
        """The hole in the first cut of this, which Gatehouse caught: migrating
        on ANY url change means repointing a federated backend at a server the
        writer controls inherits the real peer's approvals, with no first
        connect and no review. Only the SAME endpoint spelled differently
        moves; a new host gets the first connect it should."""
        elsewhere = "https://attacker.example/gateway/josui/mcp"
        check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)

        migrated = tool_pins.migrate_federated_pins(
            {"josui": self._profile(LOTOR_URL)}, {"josui": self._profile(elsewhere)}
        )

        assert migrated == []
        assert not perimeter_db.has_pins(backend_id(elsewhere))
        assert perimeter_db.has_pins(backend_id(LOTOR_URL))

    def test_a_port_written_out_is_the_same_endpoint(self) -> None:
        """`same_gateway_endpoint` keeps the path and the query and forgives the
        spelling: a default port written explicitly is one gateway, not two."""
        https = "https://lotor.example/gateway/josui/mcp"
        with_port = "https://Lotor.example:443/gateway/josui/mcp/"
        check_tools(https, "lotor", self._offered(2), federated=True)

        assert tool_pins.migrate_federated_pins(
            {"josui": self._profile(https)}, {"josui": self._profile(with_port)}
        ) == ["josui.lotor"]

    def test_a_different_query_is_not_the_same_endpoint(self) -> None:
        """A token-in-URL backend carries its credential in the query, so two
        URLs differing only there can be two endpoints."""
        one = "https://lotor.example/gateway/josui/mcp?t=aaa"
        two = "https://lotor.example/gateway/josui/mcp?t=bbb"
        check_tools(one, "lotor", self._offered(2), federated=True)

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

        check_tools(LOTOR_URL, "lotor", self._offered(2), federated=True)
        plain = Profile(
            name="josui",
            auth=AuthConfig(bearer_token_env="T"),
            backends={"lotor": Backend(url=LOTOR_URL + "/", tools_allow=["*"])},
        )

        assert (
            tool_pins.migrate_federated_pins({"josui": self._profile(LOTOR_URL)}, {"josui": plain})
            == []
        )
