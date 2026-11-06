"""What a federation link looks like to the operator who built it (#592).

Three audit passes over federation found twenty defects and none of them was
"the operator cannot see what they configured" — because a security review asks
whether each path is safe, not whether a person can tell what they built. This
is the answer to the two questions they actually have: what am I sharing and
with whom, and is the trust pin buying me anything.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from trentina.gateway.federation_link import derive_ingress
from trentina.gateway.federation_report import key_fingerprint, link_report
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    BackendAuth,
    FederatedConfig,
    FederationConfig,
    FederationPeer,
    Profile,
    TrustVerdict,
)

if TYPE_CHECKING:
    import pytest

PEER_PEM = (
    Ed25519PrivateKey.generate()
    .public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


def _profile(*, signs: bool = True, with_oauth_backend: bool = True) -> Profile:
    federation = FederationConfig(peers={"mypeer": FederationPeer(public_key=PEER_PEM)})
    if signs:
        federation.secondary_key = SecretStr(
            Ed25519PrivateKey.generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
    backends = {"wiki": Backend(url="https://wiki.example/mcp", tools_allow=["*"])}
    if with_oauth_backend:
        backends["era"] = Backend(url="https://context.era.app/mcp", auth=BackendAuth(type="oauth"))
    return Profile(
        name="josui",
        auth=AuthConfig(bearer_token_env="JOSUI_TOKEN"),
        federation=federation,
        backends=backends,
    )


def _consumer(*, pinned: bool) -> Profile:
    federated = FederatedConfig(primary_key_env="PRIMARY_KEY")
    if pinned:
        federated.trust_verdict = TrustVerdict(
            public_key=PEER_PEM, perimeter_stamp="stamp-1", judge="judge-1"
        )
    return Profile(
        name="down",
        auth=AuthConfig(bearer_token_env="DOWN_TOKEN"),
        backends={
            "peergw": Backend(
                url="https://peergw.example/gateway/josui-federation/mcp",
                tools_allow=["*"],
                federated=federated,
            )
        },
    )


class TestWhatAmISharing:
    def test_the_link_names_its_profile_its_ingress_and_its_peers(self) -> None:
        profile = _profile()
        profiles = {"josui": profile, "josui-federation": derive_ingress(profile)}

        (shared,) = link_report(profiles, {})["shared"]

        assert shared["profile"] == "josui"
        assert shared["ingress"] == "josui-federation"
        assert shared["peers"] == [{"peer": "mypeer", "key": key_fingerprint(PEER_PEM)}]

    def test_it_says_which_backends_cross_and_which_use_the_sign_in(self) -> None:
        """A derived ingress spends the PROFILE's grant, so `uses_sign_in` is where
        a peer's calls go out as the account a person authorized here."""
        profile = _profile()
        profiles = {"josui": profile, "josui-federation": derive_ingress(profile)}

        (shared,) = link_report(profiles, {})["shared"]

        assert shared["offers"] == ["era", "wiki"]
        assert shared["uses_sign_in"] == ["era"]

    def test_a_link_that_signs_nothing_says_so(self) -> None:
        """It authenticates and costs double: the primary re-judges everything
        this gateway already judged. Nothing else reports it."""
        profile = _profile(signs=False)
        profiles = {"josui": profile, "josui-federation": derive_ingress(profile)}

        (shared,) = link_report(profiles, {})["shared"]

        assert shared["signs_verdicts"] is False

    def test_the_whole_pem_is_never_printed(self) -> None:
        """Not a secret, but a wall of base64 nobody checks. The fingerprint is
        what the operator at the other end can read down a phone."""
        profile = _profile()
        profiles = {"josui": profile, "josui-federation": derive_ingress(profile)}

        assert "BEGIN PUBLIC KEY" not in repr(link_report(profiles, {}))

    def test_a_gateway_sharing_nothing_reports_nothing(self) -> None:
        plain = Profile(name="solo", auth=AuthConfig(bearer_token_env="S"), backends={})
        assert link_report({"solo": plain}, {})["shared"] == []


class TestIsThePinBuyingAnything:
    def test_it_names_the_audience_not_the_url(self) -> None:
        """The audience is what identifies the link; the URL is not reported."""
        report = link_report({"down": _consumer(pinned=True)}, {})
        (consumed,) = report["consumed"]

        assert consumed["audience"] == "josui-federation"
        assert consumed["trust_pinned"] is True
        assert "peergw.example" not in repr(report)

    def test_a_pin_that_has_stopped_matching_is_visible(self) -> None:
        """The number an operator cannot otherwise read. A pin that matches
        nothing keeps working and keeps costing a full local re-judge, and the
        only trace is the reason in these rows."""
        verdicts = {"down.peergw": {"hash_mismatch": 41, "stale": 1}}

        (consumed,) = link_report({"down": _consumer(pinned=True)}, verdicts)["consumed"]

        assert consumed["verdicts"] == {"hash_mismatch": 41, "stale": 1}
        assert consumed["top_rejudged_reason"] == "hash_mismatch"

    def test_a_working_pin_has_no_rejudged_reason(self) -> None:
        """`incomplete` is not a failure: the assertion was fine, the secondary
        just could not fully read the content, so it is not reported as one."""
        verdicts = {"down.peergw": {"trusted": 900, "incomplete": 3}}

        (consumed,) = link_report({"down": _consumer(pinned=True)}, verdicts)["consumed"]

        assert consumed["top_rejudged_reason"] is None

    def test_an_unpinned_federated_backend_is_still_reported(self) -> None:
        """#592 says to prove a link works before turning trust on, so this is
        a normal state — and the operator should be able to see they are in it."""
        (consumed,) = link_report({"down": _consumer(pinned=False)}, {})["consumed"]

        assert consumed["trust_pinned"] is False
        assert consumed["verdicts"] == {}


def test_both_directions_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """One profile may share itself AND consume a peer since the ingress is
    derived, so a gateway can appear on both lists."""
    monkeypatch.setenv("PRIMARY_KEY", "unused-by-this-report")
    profile = _profile()
    profiles = {
        "josui": profile,
        "josui-federation": derive_ingress(profile),
        "down": _consumer(pinned=True),
    }

    report = link_report(profiles, {})

    assert [s["profile"] for s in report["shared"]] == ["josui"]
    assert [c["backend"] for c in report["consumed"]] == ["peergw"]


class TestSharedJudge:
    """#666: the judge to pin is the ingress's, not the operator's."""

    def test_shared_judge_is_what_the_ingress_asserts(self) -> None:
        from trentina.gateway.service import judge_stamp

        profile = _profile()
        derived = derive_ingress(profile)
        ingress = derived.model_copy(
            update={"defense": derived.defense.model_copy(update={"model": "ingress-judge-model"})}
        )
        profile = profile.model_copy(
            update={"defense": profile.defense.model_copy(update={"model": "operator-judge-model"})}
        )
        assert judge_stamp(ingress) != judge_stamp(profile)
        profiles = {"josui": profile, "josui-federation": ingress}

        (shared,) = link_report(profiles, {})["shared"]

        assert shared["judge"] == judge_stamp(ingress)
        assert shared["judge"] != judge_stamp(profile)


class TestHeldForApproval:
    """A tool waiting for a pin is one the peer is not being served, so the
    count belongs on the link rather than only in `tool_pins`."""

    def test_the_shared_count_sums_across_offered_backends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = {"https://wiki.example/mcp": [{"tool": "edit"}], "https://context.era.app/mcp": []}
        monkeypatch.setattr("trentina.gateway.tool_pins.pending", lambda url: held.get(url, []))
        profile = _profile()
        profiles = {"josui": profile, "josui-federation": derive_ingress(profile)}

        (shared,) = link_report(profiles, {})["shared"]

        assert shared["held_for_approval"] == 1

    def test_the_consumed_count_is_its_own_backends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "trentina.gateway.tool_pins.pending",
            lambda url: [{"tool": "a"}, {"tool": "b"}] if "peergw.example" in url else [],
        )

        (consumed,) = link_report({"down": _consumer(pinned=True)}, {})["consumed"]

        assert consumed["held_for_approval"] == 2


class TestTheStatsIntegration:
    """`quarantine_stats` is where an operator actually reads this, so the
    wiring gets its own tests rather than being inferred from `link_report`."""

    def test_no_running_gateway_reports_an_empty_pair(self) -> None:
        """Standalone, or before the gateway is up: no links, not an error."""
        from trentina.gateway.loader import reset_active_config
        from trentina.tools.stats import _federation

        reset_active_config()
        report = _federation()

        assert report == {"shared": [], "consumed": [], "verdict_window_days": 30}

    def test_it_pairs_the_running_profiles_with_the_audit_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.gateway.loader import (
            GatewayConfig,
            register_active_config,
            reset_active_config,
        )
        from trentina.tools import stats

        profile = _profile()
        config = GatewayConfig(
            profiles={"josui": profile, "josui-federation": derive_ingress(profile)}
        )
        register_active_config(pathlib.Path("/nonexistent/profiles.yaml"), config, {})

        asked: list[int] = []

        def _verdicts(days: int) -> dict[str, dict[str, int]]:
            asked.append(days)
            return {}

        monkeypatch.setattr("trentina.database.get_federated_verdict_stats", _verdicts)
        try:
            report = stats._federation()
        finally:
            reset_active_config()

        assert asked == [30], "the report must cover the stated window"
        assert [s["profile"] for s in report["shared"]] == ["josui"]
