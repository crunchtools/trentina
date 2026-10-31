"""config_guard (#633): the two writes that are not the operator's to make freely.

The operator is root on the gateway and these are not a privilege boundary —
there is none, by design. They exist because the operator is an LLM: minting a
second operator, and accepting another gateway's security verdict, are both
easy to slip into a plausible-looking request and expensive to discover later.
"""

from __future__ import annotations

import pytest

from trentina.gateway.config_guard import (
    REDACTED,
    ConfigWriteError,
    check_write_request,
    mask_inline_secrets,
    operator_seat,
    trust_is_isolated,
)
from trentina.gateway.profile import Profile


def _profile(**overrides: object) -> Profile:
    body: dict[str, object] = {
        "name": "op",
        "role": "operator",
        "auth": {"bearer_token_env": "OP_TOKEN"},
        "backends": {},
    }
    body.update(overrides)
    return Profile.model_validate(body)


class TestOperatorSeat:
    def test_only_the_operator_is_in_it(self) -> None:
        agent = Profile.model_validate(
            {"name": "ag", "auth": {"bearer_token_env": "A"}, "backends": {}}
        )
        seat = operator_seat({"op": _profile(), "ag": agent})
        assert list(seat) == ["op"]

    def test_promoting_a_profile_changes_it(self) -> None:
        """The write that matters: a second root."""
        agent = Profile.model_validate(
            {"name": "ag", "auth": {"bearer_token_env": "A"}, "backends": {}}
        )
        before = operator_seat({"op": _profile(), "ag": agent})
        after = operator_seat(
            {"op": _profile(), "ag": agent.model_copy(update={"role": "operator"})}
        )
        assert before != after

    def test_removing_the_operator_changes_it(self) -> None:
        before = operator_seat({"op": _profile()})
        assert before != operator_seat({})

    def test_changing_the_operators_auth_changes_it(self) -> None:
        before = operator_seat({"op": _profile()})
        after = operator_seat({"op": _profile(auth={"bearer_token_env": "SOMEONE_ELSES"})})
        assert before != after

    def test_widening_the_operators_source_networks_changes_it(self) -> None:
        """The peer address picks the profile on those paths (#330), so this is
        a way to make another caller the operator without touching `role`."""
        narrow = _profile(
            client_egress={"hosts": ["example.com"], "source_networks": ["10.0.0.1/32"]}
        )
        wide = _profile(client_egress={"hosts": ["example.com"], "source_networks": ["10.0.0.0/8"]})
        assert operator_seat({"op": narrow}) != operator_seat({"op": wide})

    def test_an_unrelated_edit_leaves_it_alone(self) -> None:
        """Otherwise every ordinary write would be refused as a seat change."""
        before = operator_seat({"op": _profile()})
        after = operator_seat(
            {"op": _profile(backends={"web": {"url": "internal://web", "tools_allow": ["*"]}})}
        )
        assert before == after


class TestTrustIsolation:
    @pytest.mark.parametrize(
        ("keys", "value"),
        [
            (("profiles", "a", "backends", "b", "federated", "trust_verdict"), {"x": 1}),
            (("profiles", "a", "backends", "b", "federated"), {"trust_verdict": {"x": 1}}),
            (("profiles", "a", "federation"), {"peers": {"p": {"public_key": "k"}}}),
            (("profiles", "a", "federation", "peers"), {"p": {"public_key": "k"}}),
        ],
    )
    def test_a_trust_write_inside_a_federation_block_is_allowed(
        self, keys: tuple[str, ...], value: object
    ) -> None:
        assert trust_is_isolated(keys, value)

    @pytest.mark.parametrize(
        ("keys", "value"),
        [
            # Smuggled in as part of a whole-profile or whole-backend write.
            (("profiles", "a"), {"backends": {"b": {"federated": {"trust_verdict": {"x": 1}}}}}),
            (("profiles",), {"a": {"federation": {"peers": {}}}}),
            (("profiles", "a", "backends", "b"), {"federated": {"trust_verdict": {"x": 1}}}),
            # Or written somewhere that is not a federation block at all.
            (("profiles", "a", "defense"), {"trust_verdict": True}),
        ],
    )
    def test_a_trust_decision_riding_along_is_refused(
        self, keys: tuple[str, ...], value: object
    ) -> None:
        assert not trust_is_isolated(keys, value)

    def test_an_ordinary_write_is_untouched(self) -> None:
        assert trust_is_isolated(("profiles", "a", "defense", "enforcement"), "block")

    def test_unsetting_an_ancestor_is_allowed_because_it_fails_closed(self) -> None:
        """Removing a backend removes its trust with it, which can only make the
        downstream scan more."""
        assert trust_is_isolated(("profiles", "a", "backends", "b"), None)


class TestMasking:
    def test_an_inline_api_key_is_redacted(self) -> None:
        text = (
            "profiles:\n  a:\n    llm_keys:\n      openrouter:\n"
            "        api_key: sk-the-real-secret\n"
        )
        masked = mask_inline_secrets(text)
        assert "sk-the-real-secret" not in masked
        assert REDACTED in masked

    def test_an_env_reference_is_left_alone(self) -> None:
        """A name is not a secret, and blanking it would make the file unreadable
        for the operator who has to maintain it."""
        text = "profiles:\n  a:\n    llm_keys:\n      openrouter:\n        api_key_env: OR_KEY\n"
        assert mask_inline_secrets(text) == text

    def test_a_file_with_no_inline_secret_is_returned_byte_for_byte(self) -> None:
        """No round trip at all when there is nothing to hide, so `get` hands
        back exactly what is on disk."""
        text = "# a comment\nprofiles:\n  a:\n    defense:\n      enforcement: block\n"
        assert mask_inline_secrets(text) is text

    def test_masking_keeps_the_rest_of_the_file(self) -> None:
        text = (
            "# keep me\nprofiles:\n  a:\n    llm_keys:\n      openrouter:\n"
            "        api_key: sk-secret\n    defense:\n      enforcement: block\n"
        )
        masked = mask_inline_secrets(text)
        assert "# keep me" in masked
        assert "enforcement: block" in masked


class TestWriteRequest:
    def test_a_well_formed_write_passes(self) -> None:
        check_write_request("set", ("profiles", "a"), "abc", "abc")

    def test_an_unknown_action_names_the_three(self) -> None:
        with pytest.raises(ConfigWriteError) as refused:
            check_write_request("delete", ("profiles", "a"), "abc", "abc")
        assert "get, set or unset" in refused.value.payload["error"]

    def test_a_write_needs_a_path(self) -> None:
        with pytest.raises(ConfigWriteError, match="need a path"):
            check_write_request("set", (), "abc", "abc")

    def test_a_write_needs_a_hash(self) -> None:
        """Required, not optional: without it a tool write composed against one
        version of the file lands on another, which is exactly what the file
        being the source of truth is supposed to prevent."""
        with pytest.raises(ConfigWriteError, match="expect_hash"):
            check_write_request("set", ("profiles", "a"), None, "abc")

    def test_a_stale_hash_is_refused_and_the_current_one_is_offered(self) -> None:
        with pytest.raises(ConfigWriteError) as refused:
            check_write_request("set", ("profiles", "a"), "old", "new")
        assert refused.value.payload["hash"] == "new"
