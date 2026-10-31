"""config_tool (#633): the operator edits profiles.yaml through the gateway.

The acceptance for the whole program runs through here: a change applies with
no restart, a change that does not validate leaves both the file and the
running gateway exactly as they were, and the two writes that are not the
operator's to make freely are refused.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

from trentina import config as config_mod
from trentina.gateway import config_store
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import get_active_config, load_profiles, register_active_config
from trentina.gateway.profile import Profile
from trentina.tools.config import manage_config

pytestmark = pytest.mark.anyio

YAML = """\
# The gateway's profiles.
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
  ag:
    auth:
      bearer_token_env: AG_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
    defense:
      enforcement: block
"""


@pytest.fixture
def gateway(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.setenv("OP_TOKEN", "o" * 20)
    monkeypatch.setenv("AG_TOKEN", "a" * 20)
    config_mod._config = None
    path = tmp_path / "config" / "profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(YAML, encoding="utf-8")

    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield path
    config_mod._config = None


async def _as_operator(*args: Any, **kwargs: Any) -> dict[str, Any]:
    operator = (get_active_config() or pytest.fail("no active config")).config.profiles["op"]
    with profile_context(operator):
        return await manage_config(*args, **kwargs)


async def _hash() -> str:
    read = await _as_operator("get")
    return str(read["hash"])


class TestReading:
    async def test_get_returns_the_file_and_its_hash(self, gateway: pathlib.Path) -> None:
        read = await _as_operator("get")
        assert read["hash"] == config_store.config_hash(gateway.read_text(encoding="utf-8"))
        assert "ag" in read["value"]["profiles"]

    async def test_get_at_a_path_returns_that_node(self, gateway: pathlib.Path) -> None:
        read = await _as_operator("get", "profiles.ag.defense.enforcement")
        assert read["value"] == "block"

    async def test_get_at_a_missing_path_says_so(self, gateway: pathlib.Path) -> None:
        read = await _as_operator("get", "profiles.nope")
        assert "not set" in read["error"]

    async def test_a_hand_broken_file_is_reported_not_raised(
        self, gateway: pathlib.Path
    ) -> None:
        """A person can edit the file while the gateway runs, so a read has to
        say the file is broken rather than raise out of the tool."""
        gateway.write_text("profiles:\n  a: [unclosed\n", encoding="utf-8")
        result = await _as_operator("get")
        assert "not valid YAML" in result["error"]

    async def test_an_inline_api_key_is_masked(self, gateway: pathlib.Path) -> None:
        """The only field in the schema that can hold a credential value rather
        than the name of one. An internal tool's result skips the judge and the
        log scrubber, so the tool is the only place this can happen."""
        gateway.write_text(
            YAML.replace(
                "    defense:\n      enforcement: block\n",
                "    defense:\n      enforcement: block\n"
                "    llm_keys:\n      openrouter:\n        api_key: sk-the-real-secret\n",
            ),
            encoding="utf-8",
        )
        read = await _as_operator("get", "profiles.ag.llm_keys.openrouter.api_key")
        assert read["value"] == "[REDACTED]"


class TestWriting:
    async def test_a_set_applies_with_no_restart(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())

        assert result["applied"] is True
        assert "enforcement: flag" in gateway.read_text(encoding="utf-8")
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert running.defense.enforcement == "flag"

    async def test_adding_a_backend_reaches_the_running_profile(
        self, gateway: pathlib.Path
    ) -> None:
        result = await _as_operator(
            "set",
            "profiles.ag.backends.lotor",
            {"url": "https://lotor.example/gateway/fed/mcp", "tools_allow": ["*"]},
            await _hash(),
        )

        assert result["applied"] is True
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert "lotor" in running.backends

    async def test_a_write_returns_the_next_hash(self, gateway: pathlib.Path) -> None:
        """So a run of changes needs one read at the start, not one per write."""
        first = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())
        second = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "block", first["hash_after"]
        )
        assert second["applied"] is True

    async def test_an_unset_removes_the_key(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("unset", "profiles.ag.defense.enforcement", None, await _hash())
        assert result["applied"] is True
        assert "enforcement:" not in gateway.read_text(encoding="utf-8")

    async def test_comments_survive_a_write(self, gateway: pathlib.Path) -> None:
        await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())
        assert "# The gateway's profiles." in gateway.read_text(encoding="utf-8")

    async def test_the_previous_version_is_kept(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())
        assert pathlib.Path(result["backup"]).read_text(encoding="utf-8") == before


class TestRefusals:
    async def test_a_stale_hash_is_refused_and_the_file_is_untouched(
        self, gateway: pathlib.Path
    ) -> None:
        """The whole reason a hand edit and a tool write can share one file."""
        stale = await _hash()
        gateway.write_text(
            YAML.replace("enforcement: block", "enforcement: flag"), encoding="utf-8"
        )
        edited = gateway.read_text(encoding="utf-8")

        result = await _as_operator("set", "profiles.ag.defense.enforcement", "redact", stale)

        assert "changed since that hash" in result["error"]
        assert gateway.read_text(encoding="utf-8") == edited

    async def test_a_write_with_no_hash_is_refused(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("set", "profiles.ag.defense.enforcement", "redact")
        assert "expect_hash" in result["error"]

    async def test_a_change_that_does_not_validate_changes_nothing(
        self, gateway: pathlib.Path
    ) -> None:
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "not-a-mode", await _hash()
        )

        assert "does not validate" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert running.defense.enforcement == "block"

    async def test_no_candidate_file_is_left_behind(self, gateway: pathlib.Path) -> None:
        await _as_operator("set", "profiles.ag.defense.enforcement", "not-a-mode", await _hash())
        await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())
        assert sorted(p.name for p in gateway.parent.iterdir()) == ["profiles.yaml"]

    async def test_promoting_a_profile_to_operator_is_refused(self, gateway: pathlib.Path) -> None:
        """Root over the gateway, not over who gets to be root."""
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator("set", "profiles.ag.role", "operator", await _hash())
        # Refused by the loader's at-most-one-operator rule before the seat
        # check even runs; either way nothing was written.
        assert "error" in result
        assert gateway.read_text(encoding="utf-8") == before

    async def test_moving_the_seat_wholesale_is_refused(self, gateway: pathlib.Path) -> None:
        """The write the loader cannot catch: one valid operator, a different
        one. Replacing the whole `profiles` mapping keeps the config legal and
        hands root to someone else, which is what the seat check is for."""
        before = gateway.read_text(encoding="utf-8")
        moved = {
            "op": {
                "auth": {"bearer_token_env": "OP_TOKEN"},
                "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
            },
            "ag": {
                "role": "operator",
                "defense": {"provider": "ollama"},
                "auth": {"bearer_token_env": "AG_TOKEN"},
                "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
            },
        }

        result = await _as_operator("set", "profiles", moved, await _hash())

        assert "operator seat" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_changing_the_operators_own_auth_is_refused(self, gateway: pathlib.Path) -> None:
        result = await _as_operator(
            "set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash()
        )
        assert "operator seat" in result["error"]

    async def test_turning_on_scan_once_trust_is_refused(self, gateway: pathlib.Path) -> None:
        """`trust_verdict` makes this gateway serve another gateway's response
        without scanning it. The constitution keeps trust decisions
        administrator-set and says trust never changes WHETHER a layer runs, so
        this one setting is not writable through the API."""
        result = await _as_operator(
            "set",
            "profiles.ag.backends.lotor",
            {
                "url": "https://lotor.example/gateway/fed/mcp",
                "federated": {"trust_verdict": {"public_key": "x", "perimeter_stamp": "y"}},
            },
            await _hash(),
        )
        assert "not writable through this tool" in result["error"]

    async def test_a_no_op_write_is_refused(self, gateway: pathlib.Path) -> None:
        result = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "block", await _hash()
        )
        assert "already in the configuration" in result["error"]

    async def test_a_refused_reload_puts_the_file_back(
        self, gateway: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file ahead of the running gateway lies to the next reader: a
        person, the drift check, or the next write's expect_hash."""
        import trentina.tools.config as config_tool_mod

        before = gateway.read_text(encoding="utf-8")

        async def refusing_reload() -> dict[str, Any]:
            return {"reloaded": False, "error": "nope"}

        monkeypatch.setattr(config_tool_mod, "reload_profiles", refusing_reload)
        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())

        assert "the reload refused it" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_a_file_the_editor_cannot_reproduce_is_refused_untouched(
        self, gateway: pathlib.Path
    ) -> None:
        """Writing re-emits the whole document, so on a file whose layout the
        editor cannot reproduce exactly, a one-key change would reformat
        everything else. It refuses instead, and changes nothing."""
        mixed = YAML + "mixed:\n  a:\n  - x\n  b:\n    - y\n"
        gateway.write_text(mixed, encoding="utf-8")

        result = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "flag", await _hash()
        )

        assert "without reformatting the rest of it" in result["error"]
        assert gateway.read_text(encoding="utf-8") == mixed

    async def test_a_bad_path_is_refused(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("set", "profiles.ag/../../etc", 1, await _hash())
        assert "not a config key" in result["error"]


class TestScope:
    async def test_an_agent_cannot_read_the_configuration(self, gateway: pathlib.Path) -> None:
        agent = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        with profile_context(agent):
            result = await manage_config("get")
        assert "operator" in result["error"].lower()

    async def test_an_agent_cannot_write_the_configuration(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        agent = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        with profile_context(agent):
            result = await manage_config(
                "set", "profiles.ag.defense.enforcement", "flag", config_store.config_hash(before)
            )
        assert "operator" in result["error"].lower()
        assert gateway.read_text(encoding="utf-8") == before

    async def test_an_unbound_caller_is_refused(self, gateway: pathlib.Path) -> None:
        result = await manage_config("get")
        assert "error" in result


class TestUnknownAction:
    async def test_it_names_the_three(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("delete", "profiles.ag", None, await _hash())
        assert "get, set or unset" in result["error"]


def test_the_profile_model_still_refuses_an_unknown_mode() -> None:
    """The validation the tool leans on. If this ever stopped refusing, the
    "does not validate" test above would pass for the wrong reason."""
    with pytest.raises(ValueError, match="enforcement"):
        Profile.model_validate(
            {
                "name": "ag",
                "auth": {"bearer_token_env": "A"},
                "backends": {},
                "defense": {"enforcement": "not-a-mode"},
            }
        )
