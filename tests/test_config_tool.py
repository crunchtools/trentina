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
import yaml

from trentina import config as config_mod
from trentina.gateway import approver, config_patch, config_store, pending
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import get_active_config, load_profiles, register_active_config
from trentina.gateway.profile import Profile
from trentina.tools.config import manage_config

pytestmark = pytest.mark.anyio


def _ed25519_public() -> str:
    """A real public PEM: ``TrustVerdict.public_key`` is validated at load, so a
    placeholder would be refused for the wrong reason."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


_ED25519_PUBLIC = _ed25519_public()

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
    # A person can approve here, so the two guarded writes stage rather than
    # being refused. Without this they are refused, which is its own test.
    monkeypatch.setenv(
        "TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier("correct horse battery staple")
    )
    pending.clear()
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

    async def test_moving_the_seat_wholesale_is_staged_not_applied(
        self, gateway: pathlib.Path
    ) -> None:
        """The write the loader cannot catch: one valid operator, a different
        one. Replacing the whole `profiles` mapping keeps the config legal and
        hands root to someone else, which is what the seat check is for.

        Since #637 it is not refused — it waits for a person, and the file is
        untouched until they say yes."""
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

        assert result["staged"] is True
        assert result["awaiting"] == "operator seat"
        # NOTHING returned here may be enough to approve with. The first cut of
        # #637 handed back a capability URL, which an agent reads out of its own
        # tool result and an operator with code execution can POST.
        assert "approve_url" not in result
        assert "token" not in repr(result)
        # The facts a person is shown name who holds root now and who would.
        shown = " ".join(result["shown_for_approval"].values())
        assert "op" in shown and "ag" in shown
        assert gateway.read_text(encoding="utf-8") == before

    async def test_changing_the_operators_own_auth_is_staged(
        self, gateway: pathlib.Path
    ) -> None:
        """How a caller BECOMES the operator is the seat too, not just who holds it."""
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash()
        )
        assert result["awaiting"] == "operator seat"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_turning_on_scan_once_trust_is_staged_not_applied(
        self, gateway: pathlib.Path
    ) -> None:
        """`trust_verdict` makes this gateway serve another gateway's response
        without running its own layers over it. Since #637 the operator may
        PROPOSE it; a person decides, and the file does not move until they
        do."""
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set",
            "profiles.ag.backends.lotor",
            {
                "url": "https://lotor.example/gateway/fed/mcp",
                "federated": {
                    "trust_verdict": {
                        "public_key": _ED25519_PUBLIC,
                        "perimeter_stamp": "v7:guard-small@abc123:0.7",
                        "judge": "openrouter/google/gemini-3.5-flash-lite/pack-1",
                    }
                },
            },
            await _hash(),
        )
        assert result["staged"] is True
        assert result["awaiting"] == "federation trust"
        shown = result["shown_for_approval"]
        assert shown["Backend to trust"] == "ag.lotor"
        # A fingerprint, not the PEM: a wall of base64 is not reviewed by eye.
        assert shown["Its key"].startswith("sha256:")
        assert "WITHOUT this gateway running" in shown["What this means"]
        assert gateway.read_text(encoding="utf-8") == before

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
    async def test_it_names_the_four(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("delete", "profiles.ag", None, await _hash())
        assert "get, set, unset or normalize" in result["error"]


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


#: The same two profiles, written the way a file that needs normalizing is:
#: a machine-named anchor ruamel will renumber, and one list indented against
#: the majority. Loads to the same configuration as ``YAML``.
UNNORMALIZED = """\
# The gateway's profiles.
shared: &id001
  enforcement: block
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
    defense: *id001  # an alias, and a comment riding on it
"""


class TestNormalize:
    async def test_a_file_that_already_round_trips_is_refused(
        self, gateway: pathlib.Path
    ) -> None:
        """Nothing to do is said plainly, not reported as a successful rewrite."""
        result = await _as_operator("normalize", None, None, await _hash())
        assert "already reproduces itself" in result["error"]
        assert gateway.read_text(encoding="utf-8") == YAML

    async def test_it_takes_no_path(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("normalize", "profiles.ag", None, await _hash())
        assert "takes no path" in result["error"]

    async def test_it_needs_expect_hash_like_any_write(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("normalize")
        assert "expect_hash" in result["error"]

    async def test_a_stale_hash_is_refused(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("normalize", None, None, "deadbeef")
        assert "changed since that hash" in result["error"]
        assert gateway.read_text(encoding="utf-8") == YAML

    async def test_an_agent_caller_is_refused(self, gateway: pathlib.Path) -> None:
        agent = (get_active_config() or pytest.fail("no config")).config.profiles["ag"]
        with profile_context(agent):
            result = await manage_config("normalize", None, None, await _hash())
        assert "operator" in result["error"]
        assert gateway.read_text(encoding="utf-8") == YAML

    async def test_it_rewrites_a_file_that_does_not_round_trip(
        self, gateway: pathlib.Path
    ) -> None:
        gateway.write_text(UNNORMALIZED, encoding="utf-8")
        register_active_config(gateway, load_profiles(gateway), {})

        result = await _as_operator("normalize", None, None, await _hash())

        assert result["applied"] is True
        assert result["reshaped"]["lines"] > 0
        after = gateway.read_text(encoding="utf-8")
        assert after != UNNORMALIZED
        # The point of the whole thing: writes work on it now.
        assert config_patch.round_trips(after) is True
        # And it still says the same thing, comment included.
        assert yaml.safe_load(after) == yaml.safe_load(UNNORMALIZED)
        assert "# an alias, and a comment riding on it" in after
        assert "# The gateway's profiles." in after

    async def test_the_previous_version_is_kept(
        self, gateway: pathlib.Path
    ) -> None:
        gateway.write_text(UNNORMALIZED, encoding="utf-8")
        register_active_config(gateway, load_profiles(gateway), {})

        result = await _as_operator("normalize", None, None, await _hash())

        kept = pathlib.Path(result["backup"])
        assert kept.read_text(encoding="utf-8") == UNNORMALIZED

    async def test_a_set_that_was_refused_before_applies_after(
        self, gateway: pathlib.Path
    ) -> None:
        """The acceptance for C1, end to end."""
        gateway.write_text(UNNORMALIZED, encoding="utf-8")
        register_active_config(gateway, load_profiles(gateway), {})

        refused = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "flag", await _hash()
        )
        assert "without reformatting" in refused["error"]

        await _as_operator("normalize", None, None, await _hash())
        applied = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "flag", await _hash()
        )
        assert applied["applied"] is True


class TestWithNoApprover:
    """No approval password, no feature: the two guarded writes are refused
    exactly as they were before #637. The absence of a way to approve is never
    an approval anyone can give."""

    @pytest.fixture(autouse=True)
    def _no_approver(
        self, gateway: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Depends on `gateway` so it runs AFTER it: that fixture configures an
        # approver, and an autouse fixture would otherwise be undone by it.
        del gateway
        monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
        pending.clear()

    async def test_a_seat_change_is_refused_outright(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash()
        )
        assert "no approval password" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_nothing_is_left_staged_by_a_refusal(self, gateway: pathlib.Path) -> None:
        """A refusal must not leave something a later-configured password could
        approve: the proposal never existed."""
        await _as_operator("set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash())
        assert pending.outstanding() == {}

    async def test_an_ordinary_write_still_applies(self, gateway: pathlib.Path) -> None:
        """Only the two guarded writes need a person; everything else is the
        operator's as it always was."""
        result = await _as_operator(
            "set", "profiles.ag.defense.enforcement", "flag", await _hash()
        )
        assert result["applied"] is True


class TestOneApprovalPerWrite:
    """Gatehouse, against the constitution: a write could move the seat AND
    pin trust, or pin two backends, while the page showed one of them — so the
    rest would be applied unseen on the back of the one a person read."""

    async def test_a_write_needing_two_approvals_is_refused(
        self, gateway: pathlib.Path
    ) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set",
            "profiles",
            {
                "op": {
                    "role": "operator",
                    "defense": {"provider": "ollama"},
                    "auth": {"bearer_token_env": "AG_TOKEN"},
                    "backends": {
                        "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                    },
                },
                "ag": {
                    "auth": {"bearer_token_env": "AG_TOKEN"},
                    "backends": {
                        "lotor": {
                            "url": "https://lotor.example/gateway/fed/mcp",
                            "federated": {
                                "trust_verdict": {
                                    "public_key": _ED25519_PUBLIC,
                                    "perimeter_stamp": "v7:guard@abc:0.7",
                                    "judge": "openrouter/m/pack-1",
                                }
                            },
                        }
                    },
                    "defense": {"enforcement": "block"},
                },
            },
            await _hash(),
        )
        assert "more than one approval" in result["error"]
        assert "operator seat" in result["error"]
        assert "federation trust" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before
        assert pending.outstanding() == {}
