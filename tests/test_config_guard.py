"""config_guard (#633): the two writes that are not the operator's to make freely.

The operator is root on the gateway and these are not a privilege boundary —
there is none, by design. They exist because the operator is an LLM: minting a
second operator, and accepting another gateway's security verdict, are both
easy to slip into a plausible-looking request and expensive to discover later.
"""

from __future__ import annotations

import pytest
import yaml

from trentina.gateway.config_guard import (
    REDACTED,
    ConfigWriteError,
    check_write_request,
    echoes_redaction,
    equivalent,
    mask_inline_secrets,
    operator_seat,
    trust_stays_human,
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

    def test_changing_the_operators_oauth_changes_it(self) -> None:
        """`allowed_emails` is the seat for a web client that cannot hold a
        static bearer."""
        before = operator_seat({"op": _profile()})
        after = operator_seat(
            {
                "op": _profile(
                    oauth={"enabled": True, "allowed_emails": ["someone-else@example.com"]}
                )
            }
        )
        assert before != after

    def test_widening_the_operators_matrix_networks_changes_it(self) -> None:
        narrow = _profile(matrix_ingress={"source_networks": ["10.0.0.1/32"]})
        wide = _profile(matrix_ingress={"source_networks": ["10.0.0.0/8"]})
        assert operator_seat({"op": narrow}) != operator_seat({"op": wide})

    def test_an_unrelated_edit_leaves_it_alone(self) -> None:
        """Otherwise every ordinary write would be refused as a seat change."""
        before = operator_seat({"op": _profile()})
        after = operator_seat(
            {"op": _profile(backends={"web": {"url": "internal://web", "tools_allow": ["*"]}})}
        )
        assert before == after


class TestTrustStaysHuman:
    """`trust_verdict` makes this gateway serve another gateway's response
    without running its own layers. The constitution keeps trust decisions
    administrator-set and says trust never changes WHETHER a layer runs, so
    this one setting is not writable through the API at all."""

    @pytest.mark.parametrize(
        ("keys", "value"),
        [
            (("profiles", "a", "backends", "b", "federated", "trust_verdict"), {"x": 1}),
            (("profiles", "a", "backends", "b", "federated"), {"trust_verdict": {"x": 1}}),
            (("profiles", "a", "backends", "b"), {"federated": {"trust_verdict": {"x": 1}}}),
            (("profiles", "a"), {"backends": {"b": {"federated": {"trust_verdict": {}}}}}),
            (("profiles",), {"a": {"backends": {"b": {"federated": {"trust_verdict": {}}}}}}),
        ],
    )
    def test_setting_trust_is_refused_however_it_is_spelled(
        self, keys: tuple[str, ...], value: object
    ) -> None:
        assert not trust_stays_human("set", keys, value)

    def test_removing_trust_is_allowed_because_it_fails_closed(self) -> None:
        """Dropping it only makes this gateway scan more."""
        assert trust_stays_human(
            "unset", ("profiles", "a", "backends", "b", "federated", "trust_verdict"), None
        )
        assert trust_stays_human("unset", ("profiles", "a", "backends", "b"), None)

    def test_the_rest_of_federation_is_the_operators(self) -> None:
        """Minting keys, declaring the edge and naming peers are all the
        operator's. `peers` decides who may AUTHENTICATE — an access grant like
        any other, not a decision to believe someone's scan. Refusing it would
        make a federation ingress impossible to create through the API, because
        `federation.peers` is what authenticates one."""
        assert trust_stays_human(
            "set",
            ("profiles", "up", "federation"),
            {"peers": {"breetai": {"public_key": "..."}}, "secondary_key_name": "sign"},
        )
        assert trust_stays_human(
            "set", ("profiles", "down", "backends", "lotor", "federated"), {"primary_key_name": "k"}
        )

    def test_an_ordinary_write_is_untouched(self) -> None:
        assert trust_stays_human("set", ("profiles", "a", "defense", "enforcement"), "block")


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

    def test_an_unknown_action_names_the_four(self) -> None:
        with pytest.raises(ConfigWriteError) as refused:
            check_write_request("delete", ("profiles", "a"), "abc", "abc")
        assert "get, set, unset or normalize" in refused.value.payload["error"]

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


class TestRedactionEcho:
    """`get` masks the one inline credential field, so read-change-write would
    otherwise store the placeholder as a real key."""

    def test_the_placeholder_as_a_value_is_caught(self) -> None:
        assert echoes_redaction(REDACTED)

    def test_the_placeholder_nested_in_a_write_is_caught(self) -> None:
        assert echoes_redaction({"llm_keys": {"openrouter": {"api_key": REDACTED}}})
        assert echoes_redaction(["a", REDACTED])

    def test_an_ordinary_value_passes(self) -> None:
        assert not echoes_redaction({"url": "https://example.com", "tools_allow": ["*"]})
        assert not echoes_redaction("sk-a-real-looking-key")


class TestEquivalent:
    """The gate on the one write whose bytes are meant to change."""

    def test_the_same_text_is_equivalent(self) -> None:
        text = "a: 1  # note\nb:\n  - x\n"
        assert equivalent(text, text) is True

    def test_reformatting_without_changing_meaning_passes(self) -> None:
        before = "a: 1\nb:\n    - x\n    - y\n"
        after = "a: 1\nb:\n  - x\n  - y\n"
        assert equivalent(before, after) is True

    def test_a_changed_value_is_refused(self) -> None:
        assert equivalent("a: 1\n", "a: 2\n") is False

    def test_a_dropped_key_is_refused(self) -> None:
        assert equivalent("a: 1\nb: 2\n", "a: 1\n") is False

    def test_a_reordered_sequence_is_refused(self) -> None:
        """Mapping order is presentation; sequence order is meaning."""
        assert equivalent("a:\n  - x\n  - y\n", "a:\n  - y\n  - x\n") is False

    def test_a_lost_comment_is_refused_even_though_the_meaning_holds(self) -> None:
        """The check safe_load alone cannot make: it discards every comment, so
        a dump that threw the documentation away would satisfy it completely."""
        before = "# why this file exists\na: 1\n"
        after = "a: 1\n"
        assert yaml.safe_load(before) == yaml.safe_load(after)
        assert equivalent(before, after) is False

    def test_a_lost_inline_comment_is_refused(self) -> None:
        assert equivalent("a: 1  # from the unit file\n", "a: 1\n") is False

    def test_a_comment_that_only_moved_is_allowed(self) -> None:
        """A comment travels with the line it is attached to, so position is
        not compared — only that every comment is still there."""
        before = "a: 1\n# about b\nb: 2\n"
        after = "# about b\nb: 2\na: 1\n"
        assert equivalent(before, after) is True

    def test_a_hash_inside_a_quoted_value_does_not_confuse_it(self) -> None:
        text = 'a: "not # a comment"\n'
        assert equivalent(text, text) is True
