"""A profile may not be NAMED after a role (Scott, 2026-11-02).

`role: operator` says what a profile may do. A profile *named* `operator` says
nothing and reads as though it did — and both turn up in the same sentences:
"the operator profile", "an operator reload", `/gateway/operator/mcp`. lotor had
exactly that profile, and the ambiguity was not theoretical: it took a side-by-
side comparison to establish that lotor's `josui` is an agent and the operator
is a different profile entirely, because every sentence about it could be read
either way.

Reserving the words costs one validator. Disambiguating them costs every
sentence anybody writes about a deployment, forever.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from trentina.gateway.profile import AuthConfig, Backend, Profile, ProfileRole


def _profile(name: str) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TOK"),
        backends={"wiki": Backend(url="https://wiki.example/mcp")},
    )


@pytest.mark.parametrize("role", sorted(get_args(ProfileRole)))
def test_no_profile_may_be_named_after_a_role(role: str) -> None:
    """Parametrized over the role enum, so a role added later is covered by
    having been added — the same reason the validator reads `get_args` rather
    than carrying its own list."""
    with pytest.raises(ValidationError, match="is a role name, which is reserved"):
        _profile(role)


@pytest.mark.parametrize("name", ["operator", "agent"])
def test_the_refusal_says_what_to_do_instead(name: str) -> None:
    with pytest.raises(ValidationError) as caught:
        _profile(name)
    message = str(caught.value)
    # Names the role spelling it collides with, so the reader sees the
    # ambiguity rather than just being told no.
    assert f"`role: {name}`" in message
    assert "Name it for what it is" in message


def test_a_name_that_merely_contains_a_role_is_fine() -> None:
    """The rule is equality, not a substring match. `operator-prime` and
    `agents` are unambiguous, and a substring rule would also have to explain
    why `agent-smith` was refused."""
    for name in ("operator-prime", "agents", "co-operator", "josui"):
        assert _profile(name).name == name


def test_case_does_not_get_around_it() -> None:
    """`PROFILE_NAME_RE` already forbids upper case, so this is belt and
    braces — the two rules are independent and this one should not quietly
    stop working if that one is ever loosened. Asserted on the model's own
    validator rather than through a config file, since the slug rule would
    reject these first."""
    for name in ("Operator", "OPERATOR", "oPeRaToR"):
        # Called directly, so the raw ValueError rather than pydantic's wrapper.
        with pytest.raises(ValueError, match="is a role name, which is reserved"):
            Profile.name_is_not_a_role(name)
