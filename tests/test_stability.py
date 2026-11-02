"""The preview tier is only worth something if it is stated in every place.

A surface declared in code and absent from the docs is a licence to break
things that no operator was told about; a ``### Preview`` changelog section
naming a surface nobody declared is a minor release breaking a stable shape.
Both are caught here rather than in a release postmortem.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from trentina.gateway.loader import GatewayConfig
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.stability import PREVIEW_SURFACES, in_use, warn_preview_surfaces

ROOT = Path(__file__).resolve().parent.parent
STABILITY_DOC = ROOT / "docs" / "stability.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def test_every_surface_is_documented() -> None:
    """A surface in code has a row in the stability doc and its own doc exists."""
    doc = STABILITY_DOC.read_text(encoding="utf-8")
    for name, surface in PREVIEW_SURFACES.items():
        assert f"`{name}`" in doc, f"{name} is declared in code but has no stability.md row"
        assert surface.issue in doc, f"{name}'s issue {surface.issue} is not in stability.md"
        assert (ROOT / surface.doc).is_file(), f"{name} names a doc that does not exist"


def test_surface_fields_are_well_formed() -> None:
    """The table key matches the surface's own name, and the issue is an issue."""
    for name, surface in PREVIEW_SURFACES.items():
        assert surface.name == name
        assert re.fullmatch(r"#\d+", surface.issue), surface.issue
        assert surface.doc.startswith("docs/")
        assert surface.summary and not surface.summary.endswith(".")


def test_changelog_preview_sections_name_declared_surfaces() -> None:
    """A `### Preview` heading is how a MINOR release breaks something.

    So every surface named under one must be declared: a heading naming an
    undeclared feature is a stable shape broken in a minor release.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    sections = re.findall(r"^### Preview\n(.*?)(?=^#{2,3} |\Z)", text, re.MULTILINE | re.DOTALL)
    for body in sections:
        assert any(name in body for name in PREVIEW_SURFACES), (
            "a ### Preview changelog section names no declared preview surface, so "
            "it is a minor release breaking a stable shape; declared: "
            f"{sorted(PREVIEW_SURFACES)}"
        )


def test_human_approval_is_not_preview() -> None:
    """The approval page is the one gate an operator agent cannot talk its way
    past, so "this may change in a minor" is the wrong thing to say about it.

    Scott's call, 2026-11-01. This pins it so a later edit has to argue with
    the decision rather than quietly reverse it. Every spelling, because the
    point is the feature and not one key: an assertion naming only
    ``"approval"`` would pass against a surface keyed ``"approvals"``.
    """
    for spelling in ("approval", "approvals", "human_approval", "human-approval"):
        assert spelling not in PREVIEW_SURFACES

    # And the surface that IS declared covers the tool's shape, not the rules
    # deciding what a person must approve.
    assert "config_guard" not in PREVIEW_SURFACES["config-api"].summary
    assert "stable" in PREVIEW_SURFACES["config-api"].summary


#: A real Ed25519 public key, so `FederationPeer` validates rather than being
#: stubbed. Generated for this test; it authenticates nothing.
PEER_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PUBLIC KEY-----\n"
)


def _config(**profiles: Profile) -> GatewayConfig:
    return GatewayConfig(profiles=dict(profiles))


def _seat(
    name: str, *, offers: bool = False, consumes: bool = False, operator: bool = False
) -> Profile:
    """A real `Profile`: either half of a link, neither, or both.

    Built through the real models rather than a stub, so a field rename in
    `Profile` or `FederationConfig` fails this file instead of letting
    `in_use` silently stop detecting anything. `operator` is what makes
    `config_tool` reachable, and so what puts `config-api` in use.
    """
    federation = (
        FederationConfig(peers={"peer": FederationPeer(public_key=PEER_KEY)}) if offers else None
    )
    backends = (
        {
            "peer": Backend(
                url="https://peer.example/gateway/shared/mcp",
                tools_allow=["*"],
                federated=FederatedConfig(primary_key_env="TEST_PRIMARY_KEY"),
            )
        }
        if consumes
        else {}
    )
    return Profile(
        name=name,
        role="operator" if operator else "agent",
        auth=AuthConfig(bearer_token_env="TEST_TOKEN"),
        defense=DefenseConfig(enforcement="block"),
        backends=backends,
        federation=federation,
    )


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (_config(), []),
        (_config(a=_seat("a")), []),
        (_config(a=_seat("a", offers=True)), ["federation"]),
        (_config(a=_seat("a", consumes=True)), ["federation"]),
        (_config(a=_seat("a"), b=_seat("b", offers=True)), ["federation"]),
        # `config_tool` is operator-only, so a file with no operator cannot
        # reach the surface at all.
        (_config(a=_seat("a", operator=True)), ["config-api"]),
        (
            _config(a=_seat("a", operator=True), b=_seat("b", offers=True)),
            ["config-api", "federation"],
        ),
    ],
    ids=["empty", "neither", "offers", "consumes", "one-of-two", "operator", "both-surfaces"],
)
def test_in_use_detects_the_surfaces_a_config_actually_uses(
    config: GatewayConfig, expected: list[str]
) -> None:
    """Offering a link and consuming one both count as the federation surface;
    an operator seat is what makes `config-api` reachable."""
    assert in_use(config) == expected


def test_warn_names_the_surface_and_no_profile(caplog: pytest.LogCaptureFixture) -> None:
    """One WARNING per surface, naming constants only (#262).

    A profile name in this line would make the startup log a list of which
    seats federate, which is a topology an agent reading the journal through
    another backend's ``journal_query`` should not be handed.
    """
    with caplog.at_level("WARNING"):
        names = warn_preview_surfaces(_config(josui=_seat("josui", offers=True)))

    assert names == ["federation"]
    records = [r for r in caplog.records if "PREVIEW" in r.getMessage()]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "federation" in message
    assert "#592" in message
    assert "docs/stability.md" in message
    assert "josui" not in message


def test_no_warning_without_the_surface(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        assert warn_preview_surfaces(_config(josui=_seat("josui"))) == []
    assert not [r for r in caplog.records if "PREVIEW" in r.getMessage()]
