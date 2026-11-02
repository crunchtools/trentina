"""Deriving a federation ingress from the seat that shares it (#592).

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


def _seat(**over: Any) -> Profile:
    base: dict[str, Any] = {
        "name": "josui",
        "auth": AuthConfig(bearer_token_env="JOSUI_TOKEN"),
        "federation": FederationConfig(peers={"breetai": FederationPeer(public_key=_public_pem())}),
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


def test_the_derived_ingress_is_named_for_its_seat() -> None:
    ingress = derive_ingress(_seat())

    assert ingress.name == ingress_name("josui") == "josui-federation"
    assert ingress.federation_of == "josui"
    assert ingress.role == "agent"


def test_the_seats_policy_travels_with_its_tools() -> None:
    """Every carried field is carried, by value.

    Not a spot check: dropping any one of these would make the link LOOSER
    than the seat whose tools it offers, which is the one direction derivation
    must never go.
    """
    seat = _seat(
        defense=DefenseConfig(enforcement="block", modes=["block"], l2_threshold=0.9),
        llm_keys={"openrouter": LlmKeyOverride(api_key_env="OR_KEY")},
        declare_modes=True,
        short_names=False,
    )
    ingress = derive_ingress(seat)

    for field in CARRIED:
        assert getattr(ingress, field) == getattr(seat, field), field


def test_the_seats_ways_in_and_its_own_things_are_dropped() -> None:
    """A second way in would admit a caller with no peer and no sub; the rest
    are routes bound for the seat, or things the seat planted."""
    seat = _seat(
        client_egress=ClientEgressConfig(source_networks=["10.0.0.0/8"], hosts=["ok.example"]),
    )
    ingress = derive_ingress(seat)

    assert ingress.auth is None
    assert ingress.client_egress is None
    assert ingress.honeytokens == {}
    assert ingress.honeypot is False


def test_a_federated_backend_is_never_re_exported() -> None:
    """This is what makes A-to-B-to-C unsayable rather than refused, and it is
    why one seat may now both consume a peer and share itself."""
    seat = _seat(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "onward": Backend(
                url="https://c.example/gateway/x/mcp",
                tools_allow=["*"],
                federated=FederatedConfig(primary_key_env="K"),
            ),
        }
    )

    assert set(offerable_backends(seat)) == {"wiki"}
    assert "onward" not in derive_ingress(seat).backends


def test_a_decoy_is_not_offered_to_a_peer() -> None:
    """A decoy belongs to the seat that set it: a trip should name that seat,
    and a peer tripping a copy would be a second profile's alarm."""
    seat = _seat(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "bait": Backend(
                url="decoy://bait",
                decoys={"ssh_keys": DecoyTool(description="Read SSH keys", result="denied")},
            ),
        }
    )

    assert "bait" not in derive_ingress(seat).backends


def test_the_internal_surface_is_replaced_not_filtered() -> None:
    """`internal://` is one server carrying the whole native surface, admin
    tools included, so the peer gets a fresh backend rather than a copy."""
    seat = _seat(
        backends={
            "wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["*"]),
        }
    )
    ingress = derive_ingress(seat)

    assert "web" not in ingress.backends
    assert ingress.backends["trentina"].tools_allow == ["read_part_tool"]


def test_a_seat_that_shares_nothing_reachable_is_refused() -> None:
    """An empty link is a misconfiguration, not an empty offering."""
    with pytest.raises(ValueError, match="offers a peer no backend"):
        derive_ingress(_seat(backends={"web": Backend(url="internal://web", tools_allow=["*"])}))


def test_derive_all_skips_profiles_that_share_nothing() -> None:
    seats = {
        "josui": _seat(),
        "plain": Profile(name="plain", auth=AuthConfig(bearer_token_env="P"), backends={}),
    }

    assert set(derive_all(seats)) == {"josui-federation"}


def test_deriving_a_profile_with_no_federation_block_is_a_programming_error() -> None:
    plain = Profile(name="plain", auth=AuthConfig(bearer_token_env="P"), backends={})
    with pytest.raises(ValueError, match="declares no federation block"):
        derive_ingress(plain)


# --- through the loader, which is where it has to work ---

_BASE_SEAT = {
    "auth": {"bearer_token_env": "JOSUI_TOKEN"},
    "backends": {"wiki": {"url": "https://wiki.example/mcp", "tools_allow": ["*"]}},
    "defense": {"enforcement": "block"},
}


@pytest.fixture(autouse=True)
def _seat_token(monkeypatch: pytest.MonkeyPatch) -> None:
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
                **_BASE_SEAT,
                "federation": {"peers": {"breetai": {"public_key": _public_pem()}}},
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
    another's link — and the derived one carries the seat's grants."""
    path = _write(
        tmp_path / "profiles.yaml",
        {
            "josui": {**_BASE_SEAT, "federation": {"peers": {"b": {"public_key": _public_pem()}}}},
            "josui-federation": {**_BASE_SEAT},
        },
    )

    with pytest.raises(ProfileConfigError, match="collides with the ingress derived from seat"):
        load_profiles(path)


def test_the_loader_refuses_a_file_that_claims_another_seats_grants(
    tmp_path: pathlib.Path,
) -> None:
    """`federation_of` is privilege: it names whose OAuth grants this profile
    spends. A hand-written profile setting it would claim them."""
    path = _write(
        tmp_path / "profiles.yaml",
        {"thief": {**_BASE_SEAT, "federation_of": "josui"}},
    )

    with pytest.raises(ProfileConfigError, match="'federation_of' is set by the gateway"):
        load_profiles(path)


def test_a_seat_may_share_itself_and_consume_a_peer(tmp_path: pathlib.Path) -> None:
    """The configuration "one profile is one role" had to refuse, loading."""
    path = _write(
        tmp_path / "profiles.yaml",
        {
            "josui": {
                **_BASE_SEAT,
                "federation": {"peers": {"breetai": {"public_key": _public_pem()}}},
                "backends": {
                    "wiki": {"url": "https://wiki.example/mcp", "tools_allow": ["*"]},
                    "lotor": {
                        "url": "https://lotor.example/gateway/x-federation/mcp",
                        "tools_allow": ["*"],
                        "federated": {"primary_key_env": "PRIMARY_KEY"},
                    },
                },
            }
        },
    )

    profiles = load_profiles(path).profiles

    assert "lotor" in profiles["josui"].backends
    assert set(profiles["josui-federation"].backends) == {"wiki", "trentina"}
