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
from trentina.gateway import approver, config_guard, config_patch, config_store, pending
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

#: A write that changes something real and needs nobody's approval.
#:
#: Every test here that just needed SOME applying write used to spell it
#: ``defense.enforcement: flag``. That write is now a ``DEFENSE_DOWNGRADE`` and
#: stages for a person, so a test that means "an ordinary write" has to say so
#: by name rather than borrow the one setting whose whole point is that it is
#: not ordinary. ``l2_threshold`` is a consequence dial, guarded by nothing.
ORDINARY_PATH = "profiles.ag.defense.l2_threshold"
ORDINARY_VALUE = 0.9


@pytest.fixture
def gateway(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.setenv("OP_TOKEN", "o" * 20)
    monkeypatch.setenv("AG_TOKEN", "a" * 20)
    # A shared seat keeps its own way in, so the federation fixtures need one.
    monkeypatch.setenv("FED_TOKEN", "f" * 20)
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

    async def test_a_hand_broken_file_is_reported_not_raised(self, gateway: pathlib.Path) -> None:
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
        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())

        assert result["applied"] is True
        assert "l2_threshold: 0.9" in gateway.read_text(encoding="utf-8")
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert running.defense.l2_threshold == ORDINARY_VALUE

    async def test_adding_a_backend_reaches_the_running_profile(
        self, gateway: pathlib.Path
    ) -> None:
        result = await _as_operator(
            "set",
            "profiles.ag.backends.lotor",
            # An ordinary MCP server: the test is about a write reaching the
            # running profile. A gateway federation endpoint without a
            # `federated:` block is the interim path, refused since 5.0.0.
            {"url": "https://memory.example/mcp", "tools_allow": ["*"]},
            await _hash(),
        )

        assert result["applied"] is True
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert "lotor" in running.backends

    async def test_a_write_returns_the_next_hash(self, gateway: pathlib.Path) -> None:
        """So a run of changes needs one read at the start, not one per write."""
        first = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        second = await _as_operator("set", ORDINARY_PATH, 0.8, first["hash_after"])
        assert second["applied"] is True

    async def test_an_unset_removes_the_key(self, gateway: pathlib.Path) -> None:
        await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        result = await _as_operator("unset", ORDINARY_PATH, None, await _hash())
        assert result["applied"] is True
        assert "l2_threshold" not in gateway.read_text(encoding="utf-8")

    async def test_comments_survive_a_write(self, gateway: pathlib.Path) -> None:
        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        # Asserted, because on a staged write the file is untouched and the
        # comment survives for the wrong reason — which is exactly what this
        # test did while it was spelled as an enforcement change.
        assert result["applied"] is True
        assert "# The gateway's profiles." in gateway.read_text(encoding="utf-8")

    async def test_the_previous_version_is_kept(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
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
                # Its `enforcement: block` is carried over deliberately. Dropping
                # it would stand ag's perimeter down as well, and a write that
                # moves the seat AND downgrades defense is refused for needing
                # two approvals — which would pass this test for the wrong
                # reason. One decision per write is the rule being respected
                # here, not one being dodged.
                "defense": {"provider": "ollama", "enforcement": "block"},
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
        assert not {"approve_url", "handle", "token", "password"} & set(result)
        # This read `"token" not in repr(result)` until #652, as a proxy for
        # "nothing here approves anything". The facts now name how a caller
        # BECOMES the operator, so they legitimately carry
        # `bearer_token_env=AG_TOKEN` — the name of a variable, out of the file
        # this caller just wrote, and no more a capability than the profile
        # name beside it. What must never appear is the resolved secret, and
        # it cannot: `auth.bearer_token` is `Field(exclude=True)`, asserted
        # directly in test_no_secret_bearing_field_reaches_the_seat_comparison.
        assert "bearer_token=" not in repr(result)
        # The facts a person is shown name who holds root now and who would.
        shown = " ".join(result["shown_for_approval"].values())
        assert "op" in shown and "ag" in shown
        assert gateway.read_text(encoding="utf-8") == before

    async def test_changing_the_operators_own_auth_is_staged(self, gateway: pathlib.Path) -> None:
        """How a caller BECOMES the operator is the seat too, not just who holds it."""
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash()
        )
        assert result["awaiting"] == "operator seat"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_a_credential_swap_on_an_unchanged_seat_is_visible(
        self, gateway: pathlib.Path
    ) -> None:
        """Staging it is only half the job: the page has to SAY what moved.

        The facts used to be the set of profile names holding the seat, before
        and after. A write that swaps the credential behind an unchanged name
        leaves that set identical, so the most dangerous shape of this change —
        a different key making someone root, same seat — reached a person as
        "op, then op" and read as a no-op. Found in QE by a reviewer who was
        told to decline, saw that page, and approved.
        """
        result = await _as_operator(
            "set", "profiles.op.auth.bearer_token_env", "AG_TOKEN", await _hash()
        )
        facts = result["shown_for_approval"]
        assert result["awaiting"] == "operator seat"

        held = [v for k, v in facts.items() if "Holds" in k or "Would hold" in k]
        assert held == ["op", "op"], "the seat itself does not move — that is the point"

        now = facts["op.auth now"]
        after = facts["op.auth after this change"]
        assert now != after, f"a credential swap must not render identically: {facts}"
        assert "OP_TOKEN" in now
        assert "AG_TOKEN" in after

    async def test_a_seat_field_too_long_to_read_is_refused_not_truncated(
        self, gateway: pathlib.Path
    ) -> None:
        """Every fragment is length-checked, but the operator writes how many
        fragments there are. Burying the one line that matters under a thousand
        that do not would get a change approved by exhausting the reader, so
        past the limit the write is refused and nothing is staged."""
        from trentina.tools.config import _SEAT_VALUE_CHARS, _seat_facts

        seat = {"op": {"auth": {"bearer_token_env": "OP_TOKEN"}}}
        flooded = {"op": {"auth": {f"f{n}": "x" * 40 for n in range(_SEAT_VALUE_CHARS // 10)}}}
        with pytest.raises(pending.PendingError, match="too long to show"):
            _seat_facts(seat, flooded)

    def test_a_new_operator_shows_how_it_becomes_root(self) -> None:
        """A seat MOVE has the same blindness as a credential swap if only the
        names are shown. "josui, then ops" says the seat moved and nothing
        about how ops authenticates — and an allowlist admitting an address
        nobody recognises is exactly what that line would hide."""
        from trentina.tools.config import _seat_facts

        facts = _seat_facts(
            {"josui": {"auth": {"bearer_token_env": "JOSUI_TOKEN"}, "oauth": None}},
            {"ops": {"auth": None, "oauth": {"allowed_emails": ["stranger@example.com"]}}},
        )
        assert facts["Holds the operator seat now"] == "josui"
        assert facts["Would hold it after this change"] == "ops"
        assert facts["ops.oauth now"] == "absent"
        assert "stranger@example.com" in facts["ops.oauth after this change"]
        assert "JOSUI_TOKEN" in facts["josui.auth now"]
        assert facts["josui.auth after this change"] == "absent"

    @pytest.mark.parametrize(("value", "shown"), [(True, "yes"), (False, "no")])
    def test_a_boolean_seat_field_reads_as_a_word(self, value: bool, shown: str) -> None:
        """``oauth.enabled`` is a bool, and "True" on an approval page is a
        Python repr rather than an answer to the question being asked."""
        from trentina.tools.config import _shown_value

        assert _shown_value(value) == shown

    def test_the_seat_field_limit_is_exact(self) -> None:
        """Exactly at the limit is shown; one character past it is refused.

        A bound tested only far above itself says nothing about where it
        actually falls, and this one decides between a page a person reads and
        a write that does not happen.
        """
        from trentina.tools.config import _SEAT_VALUE_CHARS, _seat_facts, _shown_value

        # 14 fragments of 141, joined by 13 ", " separators: 1974 + 26 = 2000.
        fits = ["x" * 141] * 14
        assert len(_shown_value(fits)) == _SEAT_VALUE_CHARS
        shown = _seat_facts({"op": {"matrix_networks": None}}, {"op": {"matrix_networks": fits}})
        assert shown["op.matrix_networks after this change"].startswith("xxx")

        over = [*fits[:-1], "x" * 142]
        assert len(_shown_value(over)) == _SEAT_VALUE_CHARS + 1
        with pytest.raises(pending.PendingError, match="too long to show"):
            _seat_facts({"op": {"matrix_networks": None}}, {"op": {"matrix_networks": over}})

    def test_an_absent_seat_field_is_not_shown_as_an_unset_one(self) -> None:
        """``dict.get`` alone reports a missing key and a key set to ``None``
        identically, so a change between them would vanish from the page."""
        from trentina.tools.config import _seat_facts

        facts = _seat_facts({"op": {}}, {"op": {"auth": None}})
        assert facts["op.auth now"] == "absent"
        assert facts["op.auth after this change"] == "not set"

    def test_no_secret_bearing_field_reaches_the_seat_comparison(self) -> None:
        """What the seat facts render is whatever ``operator_seat`` dumped, and
        that is now shown on a web page rather than merely compared.

        ``auth`` and ``oauth`` each carry a resolved ``SecretStr``. Both are
        ``Field(exclude=True)``, so neither appears in ``model_dump`` — which
        is the only reason rendering the dump is safe. A new secret field added
        without that marker would be published to the approval page, so the
        marker is asserted rather than trusted.
        """
        from trentina.gateway.profile import AuthConfig, OAuthConfig

        for model in (AuthConfig, OAuthConfig):
            secrets = [
                name
                for name, field in model.model_fields.items()
                if "SecretStr" in str(field.annotation)
            ]
            assert secrets, f"{model.__name__} should still hold a secret to exclude"
            for name in secrets:
                assert model.model_fields[name].exclude is True, (
                    f"{model.__name__}.{name} holds a credential and is not excluded "
                    "from model_dump, so it would reach the approval page"
                )

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
        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())

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

        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())

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
    async def test_a_file_that_already_round_trips_is_refused(self, gateway: pathlib.Path) -> None:
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

    async def test_it_rewrites_a_file_that_does_not_round_trip(self, gateway: pathlib.Path) -> None:
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

    async def test_the_previous_version_is_kept(self, gateway: pathlib.Path) -> None:
        gateway.write_text(UNNORMALIZED, encoding="utf-8")
        register_active_config(gateway, load_profiles(gateway), {})

        result = await _as_operator("normalize", None, None, await _hash())

        kept = pathlib.Path(result["backup"])
        assert kept.read_text(encoding="utf-8") == UNNORMALIZED

    async def test_a_set_that_was_refused_before_applies_after(self, gateway: pathlib.Path) -> None:
        """The acceptance for C1, end to end."""
        gateway.write_text(UNNORMALIZED, encoding="utf-8")
        register_active_config(gateway, load_profiles(gateway), {})

        refused = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        assert "without reformatting" in refused["error"]

        await _as_operator("normalize", None, None, await _hash())
        applied = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        assert applied["applied"] is True


class TestWithNoApprover:
    """No approval password, no feature: every guarded write is refused exactly
    as the first two were before #637. The absence of a way to approve is never
    an approval anyone can give."""

    @pytest.fixture(autouse=True)
    def _no_approver(self, gateway: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
        """Only the guarded writes need a person; everything else is the
        operator's as it always was."""
        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())
        assert result["applied"] is True

    async def test_a_defense_downgrade_is_refused_outright(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())
        assert "no approval password" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before


class TestOneApprovalPerWrite:
    """Gatehouse, against the constitution: a write could move the seat AND
    pin trust, or pin two backends, while the page showed one of them — so the
    rest would be applied unseen on the back of the one a person read."""

    async def test_a_write_needing_two_approvals_is_refused(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")
        result = await _as_operator(
            "set",
            "profiles",
            {
                "op": {
                    "role": "operator",
                    "defense": {"provider": "ollama"},
                    "auth": {"bearer_token_env": "AG_TOKEN"},
                    "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
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

    async def test_a_write_mixing_two_of_the_new_kinds_is_refused(
        self, gateway: pathlib.Path
    ) -> None:
        """The rule has to hold for the kinds added later, not only for the two
        it was written against. A parent-key write is the shape that reaches
        several at once: here one profile gains a peer and another gains an
        egress host."""
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles",
            {
                "op": _OPERATOR,
                "ag": {
                    "auth": {"bearer_token_env": "AG_TOKEN"},
                    "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
                    "defense": {"enforcement": "block"},
                    "client_egress": {
                        "source_networks": ["10.9.0.0/24"],
                        "hosts": ["exfil.example"],
                    },
                },
                "fed": {
                    "auth": {"bearer_token_env": "FED_TOKEN"},
                    "federation": {"peers": {"down": {"public_key": _ED25519_PUBLIC}}},
                    "backends": {
                        "memory": {"url": "https://memory.example/mcp", "tools_allow": ["*"]}
                    },
                },
            },
            await _hash(),
        )

        assert "more than one approval" in result["error"]
        assert "federation peers" in result["error"]
        assert "egress grant" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before
        assert pending.outstanding() == {}


_SECOND_PUBLIC = _ed25519_public()


def _rewrite(path: pathlib.Path, document: dict[str, Any]) -> None:
    """Put ``document`` on disk as the live config and register it.

    The base state for a widening test is itself a guarded write, so it cannot
    be made through the tool — the tool is what is under test. Written straight
    to the file and loaded, which is also how a person sets one of these up.
    """
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)


_OPERATOR = {
    "role": "operator",
    "defense": {"provider": "ollama"},
    "auth": {"bearer_token_env": "OP_TOKEN"},
    "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
}


def _with_peers(peers: dict[str, Any]) -> dict[str, Any]:
    """A config whose ``fed`` SEAT is shared with ``peers``.

    ``federation`` is declared on the seat whose tools are shared, and the
    gateway derives the ``fed-federation`` ingress from it — so the seat keeps
    its own ``auth``, and what the peer is offered is the seat's own remote
    backends. ``role`` is left at its default agent, which a shared seat must
    be.
    """
    return {
        "profiles": {
            "op": _OPERATOR,
            "fed": {
                "auth": {"bearer_token_env": "FED_TOKEN"},
                "federation": {"peers": peers},
                "backends": {"memory": {"url": "https://memory.example/mcp", "tools_allow": ["*"]}},
            },
        }
    }


class TestAdmittingAFederationPeer:
    """`federation.peers` decides WHO may authenticate to an ingress as a
    primary gateway, which is an access grant and was deliberately left
    unguarded in #633 — on the ground that refusing it would make an ingress
    impossible to build through the API. Since #637 a grant is proposed rather
    than refused, so that ground no longer holds and the grant is visible."""

    async def test_adding_a_peer_is_staged_not_applied(self, gateway: pathlib.Path) -> None:
        _rewrite(gateway, _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}}))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "federation peers"
        shown = result["shown_for_approval"]
        assert shown["fed.beta"].startswith("sha256:")
        # The peer already admitted is not re-proposed: a page listing it would
        # ask a person to approve what they approved before.
        assert "fed.alpha" not in shown
        assert "may authenticate to that seat's federation ingress" in shown["What this means"]
        # And what the link actually hands over, not just the key fingerprints:
        # a derived ingress spends the SEAT's grants, so admitting a peer to a
        # seat holding one sends that peer's calls out as the account a person
        # authorized here. That is the consent this page takes.
        # With its DESTINATION, not its name alone: the approval is bound to
        # the facts shown, so a name list would let two candidates differing
        # only in where a backend points be one proposal to that digest.
        assert shown["Tools shared from fed"] == "memory -> https://memory.example/mcp"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_changing_a_peers_key_under_its_name_is_staged(
        self, gateway: pathlib.Path
    ) -> None:
        """The sneaky one. The peer list looks the same afterwards and a
        different gateway holds the seat, so a rule comparing names would see
        nothing."""
        _rewrite(gateway, _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}}))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.fed.federation.peers.alpha.public_key",
            _SECOND_PUBLIC,
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "federation peers"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_removing_a_peer_applies_at_once(self, gateway: pathlib.Path) -> None:
        """Withdrawing a grant only makes this gateway stricter. A gate in front
        of that teaches an operator that the page is something to get past."""
        _rewrite(
            gateway,
            _with_peers(
                {
                    "alpha": {"public_key": _ED25519_PUBLIC},
                    "beta": {"public_key": _SECOND_PUBLIC},
                }
            ),
        )

        result = await _as_operator(
            "unset", "profiles.fed.federation.peers.beta", None, await _hash()
        )

        assert result["applied"] is True
        running = (get_active_config() or pytest.fail("gone")).config.profiles["fed"]
        assert running.federation is not None
        assert set(running.federation.peers) == {"alpha"}

    async def test_a_parent_key_write_of_the_same_grant_still_stages(
        self, gateway: pathlib.Path
    ) -> None:
        """Every rule is computed on the LOADED candidate, so reaching a peer by
        writing the block above it changes nothing about whether it is seen."""
        _rewrite(gateway, _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}}))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.fed.federation",
            {
                "peers": {
                    "alpha": {"public_key": _ED25519_PUBLIC},
                    "beta": {"public_key": _SECOND_PUBLIC},
                }
            },
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "federation peers"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_sharing_a_seat_for_the_first_time_is_staged(self, gateway: pathlib.Path) -> None:
        """A seat that was not shared at all becoming shared is the widest form
        of this write, and the one Fable called the consent moment that actually
        moves: it creates the link AND hands the peer the seat's sign-ins."""
        unshared = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        del unshared["profiles"]["fed"]["federation"]
        _rewrite(gateway, unshared)
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.fed.federation",
            {"peers": {"alpha": {"public_key": _ED25519_PUBLIC}}},
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "federation peers"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_the_page_says_the_seats_sign_in_will_serve_the_link(
        self, gateway: pathlib.Path
    ) -> None:
        """A derived ingress spends the SEAT's grant, so admitting a peer to a
        seat holding one sends that peer's calls out as the account a person
        authorized here. A page showing only key fingerprints would take that
        consent without asking for it."""
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        document["profiles"]["fed"]["backends"]["era"] = {
            "url": "https://context.era.app/mcp",
            "tools_allow": ["*"],
            "auth": {"type": "oauth"},
        }
        _rewrite(gateway, document)

        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        shown = pending.outstanding()[pending.Kind.FEDERATION_PEERS]

        assert (
            shown["Tools shared from fed"]
            == "era -> https://context.era.app/mcp, memory -> https://memory.example/mcp"
        )
        assert "era" in shown["Runs as your sign-in on fed"]
        assert "will serve the link" in shown["Runs as your sign-in on fed"]

    async def test_repointing_a_shared_backend_changes_what_was_approved(
        self, gateway: pathlib.Path
    ) -> None:
        """A person's approval is bound to the digest of the facts they read,
        so anything absent from the facts is not consented to.

        With backend NAMES alone, "share memory with this peer" and "share
        memory, which now points at someone else, with this peer" were the same
        proposal to that digest: the agent is root over its own `url` fields,
        so it could let a person read one and approve the other. The
        destination is in the facts now, which is what makes the digest cover
        it — so the swap is caught by `pending.approve` instead of applying.
        """
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        as_read = pending.digest_of(pending.outstanding()[pending.Kind.FEDERATION_PEERS])

        document["profiles"]["fed"]["backends"]["memory"]["url"] = "https://evil.example/mcp"
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        repointed = pending.outstanding()[pending.Kind.FEDERATION_PEERS]

        assert repointed["Tools shared from fed"] == "memory -> https://evil.example/mcp"
        assert pending.digest_of(repointed) != as_read
        # And the earlier consent no longer applies to what is staged.
        with pytest.raises(pending.PendingError, match="not what is staged"):
            await pending.approve(pending.Kind.FEDERATION_PEERS, as_read)

    async def test_a_query_is_fingerprinted_rather_than_printed(
        self, gateway: pathlib.Path
    ) -> None:
        """A query can carry a credential, so the page shows the readable part
        of the destination and a fingerprint of the whole URL.

        The fingerprint is what keeps the digest total: a person cannot read a
        query off the page, but changing one still changes what they approved.
        """
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        document["profiles"]["fed"]["backends"]["memory"]["url"] = (
            "https://memory.example/mcp?access_token=not-for-the-page"
        )
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        shown = pending.outstanding()[pending.Kind.FEDERATION_PEERS]
        row = shown["Tools shared from fed"]

        assert row.startswith("memory -> https://memory.example/mcp (sha256:")
        assert "not-for-the-page" not in row
        assert "access_token" not in row

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            ("https://user:pw-in-the-url@memory.example/mcp", "pw-in-the-url"),
            # The empty username is the one truthiness gets wrong: `username`
            # is "" here, not None, so a falsiness test leaves the password
            # neither shown nor fingerprinted.
            ("https://:pw-in-the-url@memory.example/mcp", "pw-in-the-url"),
            ("https://memory.example/mcp#frag-not-shown", "frag-not-shown"),
        ],
    )
    async def test_every_unshowable_url_part_is_fingerprinted(
        self, gateway: pathlib.Path, url: str, secret: str
    ) -> None:
        """Userinfo and a fragment are hidden for the same reason a query is,
        and each has to reach the fingerprint: a component that is neither
        shown nor fingerprinted can change without changing what was approved.
        """
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        document["profiles"]["fed"]["backends"]["memory"]["url"] = url
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        row = pending.outstanding()[pending.Kind.FEDERATION_PEERS]["Tools shared from fed"]

        assert "sha256:" in row, row
        assert secret not in row, row

    @pytest.mark.parametrize(
        ("url", "shown"),
        [
            # urlsplit strips an IPv6 literal's brackets, so without putting
            # them back `[::1]:443` and `[::1:443]` render identically.
            ("https://[::1]:443/mcp", "memory -> https://[::1]:443/mcp"),
            ("https://[::1:443]/mcp", "memory -> https://[::1:443]/mcp"),
            # Port 0 is a real port and a falsy integer.
            ("https://memory.example:0/mcp", "memory -> https://memory.example:0/mcp"),
            ("https://memory.example/mcp", "memory -> https://memory.example/mcp"),
        ],
    )
    async def test_two_destinations_never_render_the_same(
        self, gateway: pathlib.Path, url: str, shown: str
    ) -> None:
        """The digest is of what was rendered, so a rendering that collides is
        a consent that transfers between two different destinations."""
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        document["profiles"]["fed"]["backends"]["memory"]["url"] = url
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )

        facts = pending.outstanding()[pending.Kind.FEDERATION_PEERS]
        assert facts["Tools shared from fed"] == shown

    async def test_a_token_in_the_path_is_shown_as_its_variable(
        self, gateway: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """These are the LOADED profiles, and `loader._expand_backend_url`
        substitutes `${VAR}` into a backend's path on purpose (#268) — a
        token-in-URL backend keeps its credential in the environment, so by
        the time it reaches the approval page the path holds the token's VALUE.

        The loader reads it through `read_secret_env`, which holds it, so
        `logsafe.scrub` puts the reference back. The person sees which variable
        is in the path, `/admin` still differs from `/mcp`, and the digest
        still moves when the path moves — without the page becoming a new
        place the secret is written down.
        """
        monkeypatch.setenv("WIKI_PATH_TOKEN", "s3cret-path-token")
        document = _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}})
        document["profiles"]["fed"]["backends"]["memory"]["url"] = (
            "https://memory.example/mcp/${WIKI_PATH_TOKEN}"
        )
        _rewrite(gateway, document)
        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        row = pending.outstanding()[pending.Kind.FEDERATION_PEERS]["Tools shared from fed"]

        assert "s3cret-path-token" not in row, row
        assert "WIKI_PATH_TOKEN" in row, row
        assert row.startswith("memory -> https://memory.example/mcp/"), row

    async def test_the_page_says_none_when_no_sign_in_is_involved(
        self, gateway: pathlib.Path
    ) -> None:
        """An explicit "none" rather than a missing row: absence reads as "the
        page did not mention it", which is the wrong thing to make a person
        resolve for themselves."""
        _rewrite(gateway, _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}}))

        await _as_operator(
            "set",
            "profiles.fed.federation.peers.beta",
            {"public_key": _SECOND_PUBLIC},
            await _hash(),
        )
        shown = pending.outstanding()[pending.Kind.FEDERATION_PEERS]

        assert shown["Runs as your sign-in on fed"] == "none"

    async def test_a_derived_ingress_does_not_double_count_its_seats_peers(
        self, gateway: pathlib.Path
    ) -> None:
        """The ingress carries the seat's block verbatim, so counting both would
        show every peer twice and make a one-peer write look like two."""
        _rewrite(gateway, _with_peers({"alpha": {"public_key": _ED25519_PUBLIC}}))
        config = (get_active_config() or pytest.fail("gone")).config

        peers = config_guard.federation_peers(config.profiles)

        assert "fed-federation" in config.profiles  # the ingress is live
        assert sorted(peers) == ["fed.alpha"]


class TestStandingAPerimeterDown:
    """`flag` delivers exactly the bytes that arrived. It is the only setting
    besides `trust_verdict` that decides whether this gateway's perimeter
    enforces anything, and an operator could apply it to any profile with
    nobody watching."""

    async def test_moving_enforcement_to_flag_is_staged(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator("set", "profiles.ag.defense.enforcement", "flag", await _hash())

        assert result["staged"] is True
        assert result["awaiting"] == "defense downgrade"
        shown = result["shown_for_approval"]
        assert shown["ag.enforcement"] == "block  ->  flag"
        assert "will still DETECT" in shown["What this means"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_unsetting_an_enforcing_value_is_staged(self, gateway: pathlib.Path) -> None:
        """`unset` is immediate for trust because removing trust only scans
        more. Removing `enforcement: block` is the opposite: the schema default
        is `flag`, so deleting the line stands the perimeter down."""
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator("unset", "profiles.ag.defense.enforcement", None, await _hash())

        assert result["staged"] is True
        assert result["awaiting"] == "defense downgrade"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_offering_flag_as_a_choosable_mode_is_staged(self, gateway: pathlib.Path) -> None:
        """`modes` is what the agent may pick per call. Guarding the default an
        omitted mode resolves to and not the list it may choose from would be a
        gate with its own door open."""
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "profiles.ag.defense.modes", ["block", "flag"], await _hash()
        )

        assert result["staged"] is True
        assert result["awaiting"] == "defense downgrade"
        shown = result["shown_for_approval"]
        # The loader fills an unset `modes` with `[enforcement]`, so the
        # comparison is against the effective set rather than the literal file.
        assert shown["ag.modes"] == "block  ->  block, flag"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_making_a_streamed_completion_detect_only_is_staged(
        self, gateway: pathlib.Path
    ) -> None:
        """`llm_completion` is the same decision on the response edge of
        /proxy/llm. Its own default is already `flag`, so only a profile moved
        OFF `block` is a downgrade."""
        _rewrite(
            gateway,
            {
                "profiles": {
                    "op": _OPERATOR,
                    "ag": {
                        "auth": {"bearer_token_env": "AG_TOKEN"},
                        "backends": {
                            "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                        },
                        "defense": {"enforcement": "block", "llm_completion": "block"},
                    },
                }
            },
        )
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "profiles.ag.defense.llm_completion", "flag", await _hash()
        )

        assert result["staged"] is True
        assert result["awaiting"] == "defense downgrade"
        assert result["shown_for_approval"]["ag.llm_completion"] == "block  ->  flag"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_tightening_applies_at_once(self, gateway: pathlib.Path) -> None:
        """A write that takes `flag` away and makes the default a refusal. Both
        fields move at once because a validator refuses `modes` that does not
        contain `enforcement`, so they cannot be tightened one at a time."""
        _rewrite(
            gateway,
            {
                "profiles": {
                    "op": _OPERATOR,
                    "ag": {
                        "auth": {"bearer_token_env": "AG_TOKEN"},
                        "backends": {
                            "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                        },
                        "defense": {"enforcement": "flag", "modes": ["block", "flag"]},
                    },
                }
            },
        )

        result = await _as_operator(
            "set",
            "profiles.ag.defense",
            {"enforcement": "block", "modes": ["block"]},
            await _hash(),
        )

        assert result["applied"] is True
        running = (get_active_config() or pytest.fail("gone")).config.profiles["ag"]
        assert running.defense.modes == ["block"]

    def test_more_changed_settings_than_a_page_can_show_is_refused(self) -> None:
        """The defense page counts ROWS, not profiles: each profile can
        contribute three, so a limit on profiles would let it run to three
        times the stated length. Called directly — building nine profiles
        through the tool to prove an arithmetic bound is a slower test that
        asserts less."""
        from trentina.gateway.config_guard import ConfigWriteError
        from trentina.tools.config import _MAX_PROPOSAL_ROWS, _defense_facts

        def downgrades(count: int) -> dict[str, Any]:
            return {
                f"p{n}": {
                    "before": {
                        "modes": ["block"],
                        "enforcement": "block",
                        "llm_completion": "block",
                    },
                    "after": {"modes": ["flag"], "enforcement": "flag", "llm_completion": "flag"},
                }
                for n in range(count)
            }

        # Three rows each, so the limit lands mid-profile either way.
        fits = _defense_facts(downgrades(_MAX_PROPOSAL_ROWS // 3))
        assert len(fits) == _MAX_PROPOSAL_ROWS + 1  # the rows, plus "What this means"

        with pytest.raises(ConfigWriteError) as refused:
            _defense_facts(downgrades(_MAX_PROPOSAL_ROWS // 3 + 1))
        assert "more than an approval page can show" in refused.value.payload["error"]

    async def test_a_new_profile_at_the_schema_default_is_not_a_downgrade(
        self, gateway: pathlib.Path
    ) -> None:
        """The shipped default is `flag` on both edges. Reading that as a
        downgrade would stage an approval for every profile ever created, and a
        page a person learns to click through protects nothing."""
        result = await _as_operator(
            "set",
            "profiles.new",
            {
                "auth": {"bearer_token_env": "AG_TOKEN"},
                "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
            },
            await _hash(),
        )

        assert result["applied"] is True


class TestGrantingAWayOut:
    """Each of these three is a route out of `--network=none`, and the blast
    radius beats trusting a peer: a trusted peer has at least run three layers
    over the response, while known gap 26 says nothing reads a CONNECT tunnel's
    bytes at all."""

    def _with_egress(self, hosts: list[str]) -> dict[str, Any]:
        return {
            "profiles": {
                "op": _OPERATOR,
                "ag": {
                    "auth": {"bearer_token_env": "AG_TOKEN"},
                    "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
                    "defense": {"enforcement": "block"},
                    "client_egress": {"source_networks": ["10.9.0.0/24"], "hosts": hosts},
                },
            }
        }

    async def test_adding_an_egress_host_is_staged(self, gateway: pathlib.Path) -> None:
        _rewrite(gateway, self._with_egress(["api.anthropic.com"]))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.ag.client_egress.hosts",
            ["api.anthropic.com", "exfil.example"],
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        shown = result["shown_for_approval"]
        assert shown["client_egress:ag.exfil.example"] == "exfil.example:443, tunnelled and unread"
        assert "client_egress:ag.api.anthropic.com" not in shown
        assert "UNREAD channel out" in shown["What this means"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_removing_an_egress_host_applies_at_once(self, gateway: pathlib.Path) -> None:
        _rewrite(gateway, self._with_egress(["api.anthropic.com", "files.example"]))

        result = await _as_operator(
            "set", "profiles.ag.client_egress.hosts", ["api.anthropic.com"], await _hash()
        )

        assert result["applied"] is True

    async def test_a_parent_key_write_of_the_same_host_still_stages(
        self, gateway: pathlib.Path
    ) -> None:
        _rewrite(gateway, self._with_egress(["api.anthropic.com"]))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.ag.client_egress",
            {"source_networks": ["10.9.0.0/24"], "hosts": ["api.anthropic.com", "exfil.example"]},
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        assert gateway.read_text(encoding="utf-8") == before

    async def test_widening_who_may_open_a_tunnel_is_staged(self, gateway: pathlib.Path) -> None:
        """A `client_egress` block grants two things: where the tunnel may go,
        and who may open one. The peer address is what picks the profile, so
        widening the networks hands the same unread channel out to more clients
        without naming a new destination. Gatehouse caught the first cut
        watching only `hosts`."""
        _rewrite(gateway, self._with_egress(["api.anthropic.com"]))
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "profiles.ag.client_egress.source_networks",
            ["10.9.0.0/24", "10.0.0.0/8"],
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        shown = result["shown_for_approval"]
        assert "may open that profile's tunnels" in shown["client_egress:ag.from.10.0.0.0/8"]
        assert "client_egress:ag.from.10.9.0.0/24" not in shown
        assert gateway.read_text(encoding="utf-8") == before

    async def test_narrowing_who_may_open_a_tunnel_applies_at_once(
        self, gateway: pathlib.Path
    ) -> None:
        _rewrite(
            gateway,
            {
                "profiles": {
                    "op": _OPERATOR,
                    "ag": {
                        "auth": {"bearer_token_env": "AG_TOKEN"},
                        "backends": {
                            "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                        },
                        "defense": {"enforcement": "block"},
                        "client_egress": {
                            "source_networks": ["10.9.0.0/24", "10.0.0.0/8"],
                            "hosts": ["api.anthropic.com"],
                        },
                    },
                }
            },
        )

        result = await _as_operator(
            "set", "profiles.ag.client_egress.source_networks", ["10.9.0.0/24"], await _hash()
        )

        assert result["applied"] is True

    async def test_repointing_an_approved_upstream_is_staged(self, gateway: pathlib.Path) -> None:
        """The key is unchanged and the destination is not. Replacing an
        already-approved origin is a new grant, not a no-op, so `widened`
        compares values and not only keys."""
        _rewrite(
            gateway,
            {
                "egress_upstreams": {"reports": {"upstream": "https://reports.example"}},
                "profiles": {"op": _OPERATOR},
            },
        )
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "egress_upstreams.reports.upstream", "https://elsewhere.example", await _hash()
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        assert result["shown_for_approval"]["egress_upstreams:reports"] == (
            "https://elsewhere.example"
        )
        assert gateway.read_text(encoding="utf-8") == before

    async def test_adding_an_egress_upstream_is_staged(self, gateway: pathlib.Path) -> None:
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "egress_upstreams.reports",
            {"upstream": "https://reports.example"},
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        assert result["shown_for_approval"]["egress_upstreams:reports"] == (
            "https://reports.example"
        )
        assert gateway.read_text(encoding="utf-8") == before

    async def test_adding_an_llm_provider_says_it_is_not_live_yet(
        self, gateway: pathlib.Path
    ) -> None:
        """`llm_providers` binds at startup, so `reload_profiles` cannot apply
        it. The page has to say so rather than let a reader assume the approval
        opened the route."""
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set",
            "llm_providers.anthropic",
            {
                "enabled": True,
                "upstream": "https://api.anthropic.com",
                "api_key_env": "ANTHROPIC_API_KEY",
            },
            await _hash(),
        )

        assert result["staged"] is True
        assert result["awaiting"] == "egress grant"
        shown = result["shown_for_approval"]
        assert shown["llm_providers:anthropic"] == "https://api.anthropic.com"
        assert "until this gateway is restarted" in shown["Not live until a restart"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_disabling_a_provider_applies_at_once(self, gateway: pathlib.Path) -> None:
        """Turning a provider off withdraws the route, so it must not wait for
        a person. It did: the grant's value carried `(on)`/`(off)`, so
        `widened` read the change as a new grant and staged a WITHDRAWAL —
        exactly what the narrowing rule forbids. Gatehouse caught it. A
        provider that is not enabled is now absent from the grants entirely,
        because absence is the only spelling `widened` reads correctly."""
        _rewrite(
            gateway,
            {
                "llm_providers": {
                    "openrouter": {
                        "enabled": True,
                        "upstream": "https://openrouter.ai/api",
                        "api_key_env": "OP_TOKEN",
                    }
                },
                "profiles": {"op": _OPERATOR},
            },
        )

        result = await _as_operator("set", "llm_providers.openrouter.enabled", False, await _hash())

        assert result["applied"] is True

    async def test_approving_a_file_level_grant_persists_it(self, gateway: pathlib.Path) -> None:
        """`egress_upstreams` is a file-level section, not a profile block, so
        the candidate loader had to start returning the whole config. The
        approval has to reach the file, which is the half staging does not
        prove."""
        read = await _as_operator("get")
        staged = await _as_operator(
            "set", "egress_upstreams.reports", {"upstream": "https://reports.example"}, read["hash"]
        )
        assert staged["staged"] is True

        shown = pending.outstanding()[pending.Kind.EGRESS_GRANT]
        await pending.approve(pending.Kind.EGRESS_GRANT, pending.digest_of(shown))

        assert "reports.example" in gateway.read_text(encoding="utf-8")
        active = get_active_config() or pytest.fail("gone")
        assert "reports" in active.config.egress_upstreams

    async def test_more_grants_than_a_page_can_show_is_refused_untouched(
        self, gateway: pathlib.Path
    ) -> None:
        """A write adding one host nobody recognises among forty familiar ones
        is a way to get it approved. Past the limit the write is refused and
        the operator is told to make it in the file, where a person reads a
        diff."""
        from trentina.tools.config import _MAX_PROPOSAL_ROWS

        _rewrite(gateway, self._with_egress(["kept.example"]))
        before = gateway.read_text(encoding="utf-8")
        # The host already granted is not re-proposed, so the new ones are
        # exactly as many as the limit allows.
        at_limit = ["kept.example", *(f"host{n}.example" for n in range(_MAX_PROPOSAL_ROWS))]

        fits = await _as_operator("set", "profiles.ag.client_egress.hosts", at_limit, await _hash())
        assert fits["staged"] is True
        # The granted rows, plus the one "What this means" line beneath them.
        assert len(fits["shown_for_approval"]) == _MAX_PROPOSAL_ROWS + 1
        assert "client_egress:ag.kept.example" not in fits["shown_for_approval"]

        over = await _as_operator(
            "set",
            "profiles.ag.client_egress.hosts",
            [*at_limit, "one.too.many.example"],
            await _hash(),
        )
        assert "more than an approval page can show" in over["error"]
        assert gateway.read_text(encoding="utf-8") == before

    async def test_narrowing_a_source_network_applies_at_once(self, gateway: pathlib.Path) -> None:
        """`10.0.0.0/8` to `10.9.0.0/24` is a new CIDR string and strictly less
        access. Diffing the written networks as a set stages that tightening,
        which the narrowing rule forbids, so they are compared as address
        ranges. Gatehouse caught the string version."""
        _rewrite(
            gateway,
            {
                "profiles": {
                    "op": _OPERATOR,
                    "ag": {
                        "auth": {"bearer_token_env": "AG_TOKEN"},
                        "backends": {
                            "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                        },
                        "defense": {"enforcement": "block"},
                        "client_egress": {
                            "source_networks": ["10.0.0.0/8"],
                            "hosts": ["api.anthropic.com"],
                        },
                    },
                }
            },
        )

        result = await _as_operator(
            "set", "profiles.ag.client_egress.source_networks", ["10.9.0.0/24"], await _hash()
        )

        assert result["applied"] is True

    async def test_the_operator_seats_own_networks_stay_with_the_seat_rule(
        self, gateway: pathlib.Path
    ) -> None:
        """On an operator profile the same field decides who is ROOT, so
        `operator_seat` owns it. Counting it as an egress grant too would make
        one unsplittable field need two approvals, and the write would be
        refused with no way to comply."""
        _rewrite(
            gateway,
            {
                "profiles": {
                    "op": {
                        **_OPERATOR,
                        "client_egress": {
                            "source_networks": ["10.9.0.0/24"],
                            "hosts": ["api.anthropic.com"],
                        },
                    }
                }
            },
        )
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "profiles.op.client_egress.source_networks", ["10.0.0.0/8"], await _hash()
        )

        assert result["staged"] is True
        assert result["awaiting"] == "operator seat"
        assert gateway.read_text(encoding="utf-8") == before

    def test_an_upstream_cannot_carry_a_credential_to_the_page(self) -> None:
        """`egress_grants` renders an `egress_upstreams` origin as the model
        reduced it. That is only safe because the validator refuses userinfo
        and a query, so the premise is asserted rather than trusted: loosening
        it would publish a credential to an approval page."""
        from pydantic import ValidationError

        from trentina.gateway.profile import EgressUpstream

        for bad in (
            "https://user:pw@reports.example",
            "https://reports.example/?token=sk-real",
            "https://reports.example/path#frag",
        ):
            with pytest.raises(ValidationError):
                EgressUpstream(upstream=bad)
        assert EgressUpstream(upstream="https://reports.example").upstream == (
            "https://reports.example"
        )

    @pytest.mark.parametrize("upstream", ["not-a-url", "https://x.example:bad", ""])
    async def test_a_grant_with_no_checkable_destination_is_refused(
        self, gateway: pathlib.Path, upstream: str
    ) -> None:
        """The constitution requires an approval to state the change in values
        a person can CHECK. A placeholder is not one — it asks someone to grant
        a route out without saying where to — so the write is refused instead
        of staged. `https://x.example:bad` is the case that also used to raise:
        urlparse defers validating the port until it is read."""
        before = gateway.read_text(encoding="utf-8")

        result = await _as_operator(
            "set", "llm_providers.vague", {"enabled": True, "upstream": upstream}, await _hash()
        )

        assert "no destination a person could check" in result["error"]
        assert "llm_providers:vague" in result["error"]
        assert gateway.read_text(encoding="utf-8") == before
        assert pending.outstanding() == {}

    async def test_an_unshowable_entry_already_in_the_file_blocks_nothing_else(
        self, gateway: pathlib.Path
    ) -> None:
        """`egress_grants` runs over the config as it already is as well as the
        candidate, so refusing inside it would let one malformed provider
        already on disk refuse every later write — including the one that fixes
        it."""
        _rewrite(
            gateway,
            {
                "llm_providers": {"broken": {"enabled": True, "upstream": "not-a-url"}},
                "profiles": {
                    "op": _OPERATOR,
                    "ag": {
                        "auth": {"bearer_token_env": "AG_TOKEN"},
                        "backends": {
                            "web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}
                        },
                        "defense": {"enforcement": "block"},
                    },
                },
            },
        )

        result = await _as_operator("set", ORDINARY_PATH, ORDINARY_VALUE, await _hash())

        assert result["applied"] is True

    async def test_no_inline_provider_credential_reaches_the_page(
        self, gateway: pathlib.Path
    ) -> None:
        """`llm_providers` is `dict[str, Any]` straight from the file, so it can
        hold whatever a writer put there — an inline key, or a credential in
        the upstream URL itself. Nothing but the origin is carried, and the
        origin is reduced to scheme, host and port: a page is the one place a
        credential must never be rendered. The URL half of this was a Gatehouse
        HIGH, in the same commit whose comment said the section is unvalidated.
        """
        result = await _as_operator(
            "set",
            "llm_providers.sneaky",
            {
                "enabled": True,
                "upstream": "https://user:sk-in-the-url@x.example/v1?token=sk-in-the-query",
                "api_key": "sk-the-real-secret",
            },
            await _hash(),
        )

        shown = result["shown_for_approval"]
        assert shown["llm_providers:sneaky"] == "https://x.example"
        rendered = " ".join(shown.values())
        for secret in ("sk-the-real-secret", "sk-in-the-url", "sk-in-the-query", "user:"):
            assert secret not in rendered
