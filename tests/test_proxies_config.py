"""``proxies:``: one block, read into one home per fact (#535 R12).

The golden oracle proves a whole gateway reads the same in either spelling
(``tests/test_perimeter_golden.py``). These hold each rule of the spelling: what
it refuses, where each kind lands, and that a built-in type never lands among
the route instances, where a rule written over them alone would miss it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import GatewayConfig, load_profiles

if TYPE_CHECKING:
    from typing import Any

_PROFILE = {"auth": {"bearer_token_env": "PROXIES_AGENT_TOKEN"}}


@pytest.fixture(autouse=True)
def _tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROXIES_AGENT_TOKEN", "proxies-agent-token-value")
    monkeypatch.setenv("PROXIES_FORGE_TOKEN", "proxies-forge-token-value")


def _load(tmp_path: Path, document: dict[str, Any]) -> GatewayConfig:
    path = tmp_path / "profiles.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return load_profiles(path)


def _agent(**blocks: Any) -> dict[str, Any]:
    return {"profiles": {"agent1": {**_PROFILE, **blocks}}}


class TestWhereEachKindLands:
    def test_a_forward_instance_and_grant_are_route_instances_and_grants(
        self, tmp_path: Path
    ) -> None:
        config = _load(
            tmp_path,
            {
                "proxies": {"bench": {"type": "forward", "hosts": ["aeb-fixture.test"]}},
                **_agent(proxies={"bench": {"hosts": ["aeb-fixture.test"]}}),
            },
        )
        assert set(config.route_instances) == {"bench"}
        assert config.route_instances["bench"].hosts == ["aeb-fixture.test"]
        assert set(config.profiles["agent1"].route_grants) == {"bench"}

    def test_a_built_in_never_lands_among_the_route_instances(self, tmp_path: Path) -> None:
        config = _load(
            tmp_path,
            {
                "proxies": {
                    "github": {"type": "http", "upstream": "https://api.github.com"},
                    "forge": {"type": "git", "upstream": "https://github.com"},
                    "egress": {"type": "connect"},
                },
                **_agent(
                    proxies={
                        "github": {"methods": ["GET"]},
                        "forge": {"token_env": "PROXIES_FORGE_TOKEN", "fetch": ["acme/*"]},
                        "egress": {"source_networks": ["10.0.0.0/24"], "hosts": ["a.example"]},
                    }
                ),
            },
        )
        assert config.route_instances == {}
        profile = config.profiles["agent1"]
        assert profile.route_grants == {}
        assert set(config.egress_upstreams) == {"github"}
        assert set(config.git_remotes) == {"forge"}
        assert set(profile.egress_http) == {"github"}
        assert set(profile.git) == {"forge"}
        assert profile.client_egress is not None

    def test_a_grant_token_is_resolved_like_any_other(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PROXIES_BENCH_TOKEN", "bench-token-value")
        config = _load(
            tmp_path,
            {
                "proxies": {"bench": {"type": "forward", "hosts": ["*"]}},
                **_agent(proxies={"bench": {"hosts": ["*"], "token_env": "PROXIES_BENCH_TOKEN"}}),
            },
        )
        token = config.profiles["agent1"].route_grants["bench"].token
        assert token is not None
        assert token.get_secret_value() == "bench-token-value"

    def test_a_matrix_instance_joins_a_block_that_holds_only_the_bridge(
        self, tmp_path: Path
    ) -> None:
        config = _load(
            tmp_path,
            {
                "matrix": {"other_agent_user_ids": ["@ashigaru:matrix.org"]},
                "proxies": {"matrix": {"type": "matrix", "upstream": "https://hs.example.org"}},
                **_agent(),
            },
        )
        assert config.matrix == {
            "enabled": True,
            "upstream": "https://hs.example.org",
            "other_agent_user_ids": ["@ashigaru:matrix.org"],
        }
        # The bridge's own block is not the proxy's, so it is not an older spelling.
        assert config.deprecated_keys == ()

    def test_the_older_blocks_load_and_are_named(self, tmp_path: Path) -> None:
        config = _load(
            tmp_path,
            {
                "egress_upstreams": {"github": {"upstream": "https://api.github.com"}},
                **_agent(egress_http={"github": {"methods": ["GET"]}}),
            },
        )
        assert set(config.egress_upstreams) == {"github"}
        assert config.deprecated_keys == ("egress_upstreams", "profiles.*.egress_http")


@pytest.mark.parametrize(
    ("document", "refusal"),
    [
        pytest.param(
            {
                "egress_upstreams": {"old": {"upstream": "https://api.github.com"}},
                "proxies": {"new": {"type": "http", "upstream": "https://api.github.com"}},
                **_agent(),
            },
            "both under proxies",
            id="http-both-spellings",
        ),
        pytest.param(
            {
                "proxies": {"egress": {"type": "connect"}},
                **_agent(
                    client_egress={"source_networks": ["10.0.0.0/24"], "hosts": ["a.example"]}
                ),
            },
            "both under proxies",
            id="connect-both-spellings",
        ),
        pytest.param(
            {"proxies": {}, **_agent(proxies={"ghost": {"methods": ["GET"]}})},
            "names no instance",
            id="grant-names-no-instance",
        ),
        pytest.param(
            {**_agent(proxies={"ghost": {}})},
            "there is no proxies",
            id="profile-proxies-without-instances",
        ),
        pytest.param(
            {
                "proxies": {
                    "one": {"type": "matrix", "upstream": "https://a.example.org"},
                    "two": {"type": "matrix", "upstream": "https://b.example.org"},
                },
                **_agent(),
            },
            "one matrix instance",
            id="two-homeservers",
        ),
        pytest.param(
            {"proxies": {"one": {"type": "connect"}, "two": {"type": "connect"}}, **_agent()},
            "one connect instance",
            id="two-listeners",
        ),
        pytest.param(
            {"proxies": {"egress": {"type": "connect", "port": 8021}}, **_agent()},
            "takes no settings",
            id="connect-with-settings",
        ),
        pytest.param(
            {
                "proxies": {"claude": {"type": "llm", "upstream": "https://api.anthropic.com"}},
                **_agent(proxies={"claude": {}}),
            },
            "llm_keys",
            id="llm-grant-under-proxies",
        ),
        pytest.param(
            {**_agent(route_grants={})},
            "is not a key",
            id="route-grants-written-directly",
        ),
        pytest.param(
            {"proxies": {"Bad_Name": {"type": "forward", "hosts": ["*"]}}, **_agent()},
            "not an instance name",
            id="instance-name",
        ),
        pytest.param(
            {"proxies": {"x": {"type": "socks", "hosts": ["*"]}}, **_agent()},
            "neither forward nor",
            id="unknown-type",
        ),
        pytest.param(
            {"proxies": {"x": {"type": "forward", "hosts": ["10.0.0.1"]}}, **_agent()},
            "not a DNS name",
            id="address-as-host",
        ),
        pytest.param(
            {
                "proxies": {"x": {"type": "acme:acme", "origins": {"api": "http://api.acme"}}},
                **_agent(),
            },
            "https origin",
            id="plain-http-origin",
        ),
        pytest.param(
            {
                "proxies": {
                    "x": {"type": "acme:acme", "options": {"key": "sk-ant-" + "a" * 40}},
                },
                **_agent(),
            },
            "shaped like a credential",
            id="credential-in-options",
        ),
    ],
)
def test_a_malformed_proxies_block_is_refused(
    tmp_path: Path, document: dict[str, Any], refusal: str
) -> None:
    with pytest.raises(ProfileConfigError, match=refusal):
        _load(tmp_path, document)
