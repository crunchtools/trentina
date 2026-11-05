"""``proxies:`` meets the approval rules (#535 R12b).

Every way out of the network a ``proxies:`` write opens is a grant a person
approves, and every narrowing applies at once — the same rules that hold the
older blocks, read off the same loaded objects. And a file rewritten from the
older spelling into ``proxies:`` changes nothing a person would be asked about.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests import perimeter_golden as g
from trentina.gateway import config_guard, config_patch
from trentina.gateway.loader import GatewayConfig, load_profiles

_PROFILE = {"auth": {"bearer_token_env": "APPROVAL_AGENT_TOKEN"}}


@pytest.fixture(autouse=True)
def _tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPROVAL_AGENT_TOKEN", "approval-agent-token-value")
    for name, value in g.ENV.items():
        monkeypatch.setenv(name, value)


def _load(tmp_path: Path, document: dict[str, Any], name: str = "profiles.yaml") -> GatewayConfig:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return load_profiles(path)


def _forward(
    hosts: list[str], grant_hosts: list[str], enforcement: str = "block"
) -> dict[str, Any]:
    return {
        "proxies": {"bench": {"type": "forward", "hosts": hosts}},
        "profiles": {
            "agent1": {
                **_PROFILE,
                "proxies": {"bench": {"hosts": grant_hosts, "enforcement": enforcement}},
            }
        },
    }


def _grants(config: GatewayConfig) -> dict[str, str]:
    return config_guard.egress_grants(
        config.profiles, config.egress_upstreams, config.llm_providers, config.route_instances
    )


class TestDestinationsArePersonApproved:
    def test_a_new_forward_host_is_a_grant(self, tmp_path: Path) -> None:
        before = _load(tmp_path, _forward(["a.example"], ["a.example"]), "before.yaml")
        after = _load(tmp_path, _forward(["a.example", "b.example"], ["b.example"]), "after.yaml")
        widened = config_guard.widened(_grants(before), _grants(after))
        assert set(widened) == {"proxies:bench.hosts.b.example", "proxies:agent1.bench.b.example"}

    def test_removing_a_host_applies_at_once(self, tmp_path: Path) -> None:
        before = _load(tmp_path, _forward(["a.example", "b.example"], ["b.example"]), "b.yaml")
        after = _load(tmp_path, _forward(["a.example"], ["a.example"]), "a.yaml")
        assert set(config_guard.widened(_grants(before), _grants(after))) == {
            "proxies:agent1.bench.a.example"
        }
        assert not config_guard.widened(
            _grants(before), _grants(_load(tmp_path, _forward(["a.example"], []), "c.yaml"))
        )

    def test_any_host_says_so(self, tmp_path: Path) -> None:
        grants = _grants(_load(tmp_path, _forward(["*"], ["*"])))
        assert grants["proxies:bench.hosts.*"].startswith("ANY host")

    def test_a_plugin_origin_is_a_grant_and_its_options_are_not(self, tmp_path: Path) -> None:
        document = {
            "proxies": {
                "acme": {
                    "type": "acme-route:acme",
                    "origins": {"api": "https://api.acme.example"},
                    "options": {"mirror": "https://elsewhere.example/upload"},
                }
            },
            "profiles": {"agent1": _PROFILE},
        }
        grants = _grants(_load(tmp_path, document))
        assert grants == {"proxies:acme.api": "https://api.acme.example"}

    def test_an_origin_carrying_userinfo_never_loads(self, tmp_path: Path) -> None:
        from trentina.gateway.errors import ProfileConfigError

        document = {
            "proxies": {"acme": {"type": "acme:acme", "origins": {"api": "https://u:p@api.acme"}}},
            "profiles": {"agent1": _PROFILE},
        }
        with pytest.raises(ProfileConfigError, match="no userinfo"):
            _load(tmp_path, document)


class TestAFlagGrantIsADowngrade:
    def _posture(self, config: GatewayConfig) -> dict[str, dict[str, Any]]:
        return config_guard.defense_posture(config.profiles)

    def test_a_route_grant_moving_to_flag_stages(self, tmp_path: Path) -> None:
        before = _load(tmp_path, _forward(["a.example"], ["a.example"]), "before.yaml")
        after = _load(tmp_path, _forward(["a.example"], ["a.example"], "flag"), "after.yaml")
        downgraded = config_guard.defense_downgraded(self._posture(before), self._posture(after))
        assert downgraded["agent1"]["after"]["flag_grants"] == ["proxies.bench"]

    def test_an_egress_http_grant_moving_to_flag_stages_too(self, tmp_path: Path) -> None:
        def document(enforcement: str) -> dict[str, Any]:
            return {
                "proxies": {"github": {"type": "http", "upstream": "https://api.github.com"}},
                "profiles": {
                    "agent1": {**_PROFILE, "proxies": {"github": {"enforcement": enforcement}}}
                },
            }

        before = _load(tmp_path, document("block"), "before.yaml")
        after = _load(tmp_path, document("flag"), "after.yaml")
        assert "agent1" in config_guard.defense_downgraded(
            self._posture(before), self._posture(after)
        )

    def test_the_approval_page_shows_the_flag_grant(self, tmp_path: Path) -> None:
        from trentina.tools.config import _defense_facts

        before = _load(tmp_path, _forward(["a.example"], ["a.example"]), "before.yaml")
        after = _load(tmp_path, _forward(["a.example"], ["a.example"], "flag"), "after.yaml")
        facts = _defense_facts(
            config_guard.defense_downgraded(self._posture(before), self._posture(after))
        )
        assert "proxies.bench" in facts["agent1.flag_grants"]

    def test_back_to_block_applies_at_once(self, tmp_path: Path) -> None:
        before = _load(tmp_path, _forward(["a.example"], ["a.example"], "flag"), "before.yaml")
        after = _load(tmp_path, _forward(["a.example"], ["a.example"]), "after.yaml")
        assert not config_guard.defense_downgraded(self._posture(before), self._posture(after))


def test_rewriting_the_older_spelling_into_proxies_stages_nothing() -> None:
    """The deploy-day check (cto, #535): the same gateway in the new spelling is
    no new grant, no wider network, no downgrade."""
    blocks, proxies = load_profiles(g.CONFIG), load_profiles(g.CONFIG_PROXIES)
    assert not config_guard.widened(_grants(blocks), _grants(proxies))
    assert not config_guard.source_networks_widened(
        config_guard.client_egress_networks(blocks.profiles),
        config_guard.client_egress_networks(proxies.profiles),
    )
    assert not config_guard.defense_downgraded(
        config_guard.defense_posture(blocks.profiles),
        config_guard.defense_posture(proxies.profiles),
    )


def test_a_proxies_write_round_trips() -> None:
    """config_tool's writer keeps the file as written around a proxies: edit."""
    text = g.CONFIG_PROXIES.read_text(encoding="utf-8")
    written = config_patch.set_at(
        text, ("proxies", "bench"), {"type": "forward", "hosts": ["x.example"]}
    )
    assert config_patch.round_trips(written)
    assert written.startswith(text.split("proxies:")[0])
    assert yaml.safe_load(written)["proxies"]["bench"] == {
        "type": "forward",
        "hosts": ["x.example"],
    }
