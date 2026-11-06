"""Deriving a federation ingress from the profile that shares it (#592).

The test that matters most here is `test_every_profile_field_is_decided`. The
old shape let an operator hand-list what a peer was offered, and the whole
point of deriving it is that nobody has to remember. The risk that replaces
drift is a field added to `Profile` later which silently crosses to a peer
because no one thought about it — so the partition is asserted, not assumed,
and a new field fails this file until someone puts it in `CARRIED` or
`DROPPED`.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.federation_link import (
    CARRIED,
    CONSTRUCTED,
    DROPPED,
    derive_all,
    derive_ingress,
    ingress_name,
    offerable_backends,
)
from trentina.gateway.loader import load_profiles
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    ClientEgressConfig,
    DecoyTool,
    DefenseConfig,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    LlmKeyOverride,
    Profile,
)


def _public_pem() -> str:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _profile(**over: Any) -> Profile:
    base: dict[str, Any] = {
        "name": "josui",
        "auth": AuthConfig(bearer_token_env="JOSUI_TOKEN"),
        "federation": FederationConfig(peers={"mypeer": FederationPeer(public_key=_public_pem())}),
        "backends": {"wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"])},
    }
    base.update(over)
    return Profile(**base)


def test_every_profile_field_is_decided() -> None:
    """No field of `Profile` may be undecided.

    A field in none of the three sets is one nobody ruled on, and the default
    for an undecided field is whatever `derive_ingress` happens to do — which
    for a carried-by-accident field means a peer gets it. Fix by adding the
    name to `CARRIED` or `DROPPED` in `federation_link.py`, having first
    decided which.
    """
    decided = CARRIED | DROPPED | CONSTRUCTED
    fields = set(Profile.model_fields)

    assert fields - decided == set(), "undecided Profile field(s): put each in CARRIED or DROPPED"
    assert decided - fields == set(), "named field(s) that no longer exist on Profile"
    assert not (CARRIED & DROPPED), "a field cannot be both carried and dropped"


def test_the_derived_ingress_is_named_for_its_profile() -> None:
    ingress = derive_ingress(_profile())

    assert ingress.name == ingress_name("josui") == "josui-federation"
    assert ingress.federation_of == "josui"
    assert ingress.role == "agent"


def test_the_profiles_policy_travels_with_its_tools() -> None:
    """Every carried field is carried, by value.

    Not a spot check: dropping any one of these would make the link LOOSER
    than the profile whose tools it offers, which is the one direction derivation
    must never go.
    """
    profile = _profile(
        defense=DefenseConfig(enforcement="block", modes=["block"], l2_threshold=0.9),
        llm_keys={"openrouter": LlmKeyOverride(api_key_env="OR_KEY")},
        declare_modes=True,
        short_names=False,
    )
    ingress = derive_ingress(profile)

    for field in CARRIED:
        assert getattr(ingress, field) == getattr(profile, field), field


def test_the_profiles_ways_in_and_its_own_things_are_dropped() -> None:
    """A second way in would admit a caller with no peer and no sub; the rest
    are routes bound for the profile, or things the profile planted."""
    profile = _profile(
        client_egress=ClientEgressConfig(source_networks=["10.0.0.0/8"], hosts=["ok.example"]),
    )
    ingress = derive_ingress(profile)

    assert ingress.auth is None
    assert ingress.client_egress is None
    assert ingress.honeytokens == {}
    assert ingress.honeypot is False


def test_a_federated_backend_is_never_re_exported() -> None:
    """This is what makes A-to-B-to-C unsayable rather than refused, and it is
    why one profile may now both consume a peer and share itself."""
    profile = _profile(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "onward": Backend(
                url="https://c.example/gateway/x/mcp",
                tools_allow=["*"],
                federated=FederatedConfig(primary_key_env="K"),
            ),
        }
    )

    assert set(offerable_backends(profile)) == {"wiki"}
    assert "onward" not in derive_ingress(profile).backends


def test_a_decoy_is_not_offered_to_a_peer() -> None:
    """A decoy belongs to the profile that set it: a trip should name that profile,
    and a peer tripping a copy would be a second profile's alarm."""
    profile = _profile(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "bait": Backend(
                url="decoy://bait",
                decoys={"ssh_keys": DecoyTool(description="Read SSH keys", result="denied")},
            ),
        }
    )

    assert "bait" not in derive_ingress(profile).backends


def test_the_internal_surface_is_one_backend_not_the_shared_profiles_copy() -> None:
    """The peer gets ONE internal backend under the derived label, never the
    shared profile's backend under its own name.

    That part did not change in 6.0.0 and is worth keeping separate from what
    did: the backend is still constructed, so a peer cannot reach `internal://`
    by the name the operator happened to give it, and there is exactly one
    place the derived surface comes from.
    """
    profile = _profile(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["read_part_tool"]),
        }
    )
    ingress = derive_ingress(profile)

    assert "web" not in ingress.backends
    assert ingress.backends["trentina"].tools_allow == ["read_part_tool"]


def test_the_internal_surface_follows_an_operator_profile() -> None:
    """6.0.0, Scott's instruction: an OPERATOR profile's internal allowlist
    crosses, so its peer can reach this gateway's admin tools. Through 5.x it
    was `read_part_tool` whatever the profile declared.

    `docs/federation.md` carries what this costs. The test is here because the
    property is now a derivation behaviour rather than a constant.
    """
    profile = _profile(
        role="operator",
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(
                url="internal://web",
                tools_allow=["read_part_tool", "reload_profiles_tool", "tool_pins_tool"],
            ),
        },
    )

    assert derive_ingress(profile).backends["trentina"].tools_allow == [
        "read_part_tool",
        "reload_profiles_tool",
        "tool_pins_tool",
    ]


def test_the_paging_reader_is_added_even_if_the_shared_profile_omits_it() -> None:
    """`parts.py` delivers a peer's paged response through this backend part by
    part, so a profile whose own internal backend leaves the reader out would
    otherwise break paging for its peer while looking fine."""
    profile = _profile(
        role="operator",
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["tool_pins_tool"]),
        },
    )

    assert derive_ingress(profile).backends["trentina"].tools_allow == [
        "read_part_tool",
        "tool_pins_tool",
    ]


@pytest.mark.parametrize(
    "allow",
    [
        pytest.param(["*"], id="star"),
        pytest.param(["read_*"], id="prefix-glob"),
        pytest.param(["read_part_tool", "config_*"], id="one-exact-one-glob"),
    ],
)
def test_a_glob_on_a_shared_operator_profile_is_refused(allow: list[str]) -> None:
    """Gatehouse's constitution agent caught this: an approval page showing a
    pattern names no tool a person can check, and the pattern silently covers
    every tool a later release adds. A shared operator lists exact names.

    `read_*` as well as `*`, because the prefix glob is the one an operator
    would actually reach for and a rule catching only `*` would read as if it
    had been thought about when it had not. The other fnmatch metacharacters
    cannot get this far -- see the test below.
    """
    with pytest.raises(ValueError, match="List the tools by exact name"):
        _profile(
            role="operator",
            backends={
                "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
                "web": Backend(url="internal://web", tools_allow=allow),
            },
        )


@pytest.mark.parametrize("allow", [["read_part_too?"], ["[rc]onfig_tool"]])
def test_other_glob_characters_are_refused_earlier_and_better(allow: list[str]) -> None:
    """Layering worth recording, so nobody widens `_GLOB_CHARS` back out.

    `Backend` already holds `tools_allow` to alphanumerics, underscore, hyphen
    and `*`, with a message that says so. These never reach the shared-operator
    rule, so carrying `?[]` in its character set would be unreachable code that
    looked considered.
    """
    with pytest.raises(ValueError, match="Invalid glob pattern"):
        _profile(
            role="operator",
            backends={
                "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
                "web": Backend(url="internal://web", tools_allow=allow),
            },
        )


def test_an_agent_profile_shares_the_paging_reader_and_nothing_more() -> None:
    """The role and the surface are ONE change. An agent profile's peer cannot
    call an admin tool anyway -- `require_operator` refuses it -- so carrying
    the rest would widen every existing agent link, which is most of them, for
    no capability anybody asked for. `*` included: it stays on the profile and
    does not cross.
    """
    profile = _profile(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["*"]),
        }
    )

    assert profile.backends["web"].tools_allow == ["*"]
    assert derive_ingress(profile).backends["trentina"].tools_allow == ["read_part_tool"]


def test_a_shared_profile_with_no_internal_backend_gets_the_reader_alone() -> None:
    """The floor, which is also the old behaviour."""
    profile = _profile(
        backends={"wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"])}
    )

    assert derive_ingress(profile).backends["trentina"].tools_allow == ["read_part_tool"]


def test_a_profile_that_shares_nothing_reachable_is_refused() -> None:
    """An empty link is a misconfiguration, not an empty offering."""
    with pytest.raises(ValueError, match="offers a peer no backend"):
        derive_ingress(_profile(backends={"web": Backend(url="internal://web", tools_allow=["*"])}))


def test_derive_all_skips_profiles_that_share_nothing() -> None:
    profiles = {
        "josui": _profile(),
        "plain": Profile(name="plain", auth=AuthConfig(bearer_token_env="P"), backends={}),
    }

    assert set(derive_all(profiles)) == {"josui-federation"}


def test_deriving_a_profile_with_no_federation_block_is_a_programming_error() -> None:
    plain = Profile(name="plain", auth=AuthConfig(bearer_token_env="P"), backends={})
    with pytest.raises(ValueError, match="declares no federation block"):
        derive_ingress(plain)


# --- through the loader, which is where it has to work ---

_BASE_PROFILE = {
    "auth": {"bearer_token_env": "JOSUI_TOKEN"},
    "backends": {"wiki": {"url": "https://wiki.example/mcp", "tools_allow": ["*"]}},
    "defense": {"enforcement": "block"},
}


@pytest.fixture(autouse=True)
def _profile_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JOSUI_TOKEN", "j" * 20)
    monkeypatch.setenv(
        "PRIMARY_KEY",
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode(),
    )


def _write(path: pathlib.Path, profiles: dict[str, Any]) -> pathlib.Path:
    path.write_text(yaml.safe_dump({"profiles": profiles}, sort_keys=False), encoding="utf-8")
    return path


def test_the_loader_serves_an_ingress_nobody_wrote(tmp_path: pathlib.Path) -> None:
    path = _write(
        tmp_path / "profiles.yaml",
        {
            "josui": {
                **_BASE_PROFILE,
                "federation": {"peers": {"mypeer": {"public_key": _public_pem()}}},
            }
        },
    )

    profiles = load_profiles(path).profiles

    assert set(profiles) == {"josui", "josui-federation"}
    assert profiles["josui-federation"].federation_of == "josui"


def test_the_loader_refuses_a_name_that_collides_with_a_derived_one(
    tmp_path: pathlib.Path,
) -> None:
    """Either way it went, an operator would have one profile named after
    another's link — and the derived one carries the profile's grants."""
    path = _write(
        tmp_path / "profiles.yaml",
        {
            "josui": {
                **_BASE_PROFILE,
                "federation": {"peers": {"b": {"public_key": _public_pem()}}},
            },
            "josui-federation": {**_BASE_PROFILE},
        },
    )

    with pytest.raises(ProfileConfigError, match="collides with the ingress derived from profile"):
        load_profiles(path)


def test_the_loader_refuses_a_file_that_claims_another_profiles_grants(
    tmp_path: pathlib.Path,
) -> None:
    """`federation_of` is privilege: it names whose OAuth grants this profile
    spends. A hand-written profile setting it would claim them."""
    path = _write(
        tmp_path / "profiles.yaml",
        {"thief": {**_BASE_PROFILE, "federation_of": "josui"}},
    )

    with pytest.raises(ProfileConfigError, match="'federation_of' is set by the gateway"):
        load_profiles(path)


def test_a_profile_may_share_itself_and_consume_a_peer(tmp_path: pathlib.Path) -> None:
    """The configuration "one profile is one role" had to refuse, loading."""
    path = _write(
        tmp_path / "profiles.yaml",
        {
            "josui": {
                **_BASE_PROFILE,
                "federation": {"peers": {"mypeer": {"public_key": _public_pem()}}},
                "backends": {
                    "wiki": {"url": "https://wiki.example/mcp", "tools_allow": ["*"]},
                    "peergw": {
                        "url": "https://peergw.example/gateway/x-federation/mcp",
                        "tools_allow": ["*"],
                        "federated": {"primary_key_env": "PRIMARY_KEY"},
                    },
                },
            }
        },
    )

    profiles = load_profiles(path).profiles

    assert "peergw" in profiles["josui"].backends
    assert set(profiles["josui-federation"].backends) == {"wiki", "trentina"}
