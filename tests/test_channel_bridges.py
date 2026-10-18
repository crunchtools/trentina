"""More than one upstream per profile (#483, spec 020).

``matrix_bridge`` is the ``matrix`` channel; ``bridges`` holds the rest. What
these pin down: a second channel loads and gets its own doors, its own store
and its own label, and nothing a misconfiguration could share between two
channels (a bridge URL, a token, an appservice namespace) is accepted.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr, ValidationError
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles
from trentina.gateway.matrix_bridge import routes as routes_mod
from trentina.gateway.matrix_bridge.routes import BridgeRoutes, register_bridge_routes
from trentina.gateway.profile import Profile

if TYPE_CHECKING:
    from pathlib import Path

MATRIX_ID = "@agent1-bot:matrix.org"
RCS_ID = "@agent1:rcs.invalid"
OTHER_RCS_ID = "@agent2:rcs.invalid"


def _bridge(n: int, user_id: str, **local: Any) -> dict[str, Any]:
    return {
        "enabled": True,
        "public_user_id": user_id,
        "bridge_url": f"http://bridge-{n}:8471",
        "bridge_token_env": f"B{n}",
        "ingress_token_env": f"I{n}",
        "local": {
            "homeserver": "http://10.0.10.3:6167",
            "server_name": "agent1.local",
            "agent_localpart": "agent1",
            "as_token_env": f"A{n}",
            "hs_token_env": f"H{n}",
        }
        | local,
    }


RCS_LOCAL = {"user_prefix": "rcs_", "sender_localpart": "trentina_rcs"}


def _body(**bridges: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "agent1",
        "auth": {"bearer_token_env": "X"},
        "matrix_bridge": _bridge(1, MATRIX_ID),
        "bridges": bridges or {"rcs": _bridge(2, RCS_ID, **RCS_LOCAL)},
    }


def _resolved(body: dict[str, Any]) -> Profile:
    """A profile whose every bridge has tokens, named after its env vars."""
    profile = Profile.model_validate(body)
    for cfg in profile.channel_bridges().values():
        cfg.bridge_token = SecretStr(f"bridge-{cfg.bridge_token_env}")
        cfg.ingress_token = SecretStr(f"ingress-{cfg.ingress_token_env}")
        cfg.local.as_token = SecretStr(f"as-{cfg.local.as_token_env}")
        cfg.local.hs_token = SecretStr(f"hs-{cfg.local.hs_token_env}")
    return profile


class TestConfig:
    def test_a_second_channel_loads_beside_matrix(self) -> None:
        profile = Profile.model_validate(_body())
        assert list(profile.channel_bridges()) == ["matrix", "rcs"]
        assert profile.channel_bridges()["rcs"].public_user_id == RCS_ID

    def test_a_profile_with_no_bridges_has_no_channels(self) -> None:
        body = _body()
        del body["matrix_bridge"], body["bridges"]
        assert Profile.model_validate(body).channel_bridges() == {}

    @pytest.mark.parametrize("name", ["matrix", "RCS", "1rcs", "r-cs", "a" * 17])
    def test_a_channel_name_is_a_slug_and_not_matrix(self, name: str) -> None:
        with pytest.raises(ValidationError, match="bridges"):
            Profile.model_validate(_body(**{name: _bridge(2, RCS_ID, **RCS_LOCAL)}))

    def test_two_channels_may_not_share_a_bridge_url(self) -> None:
        rcs = _bridge(2, RCS_ID, **RCS_LOCAL) | {"bridge_url": "http://bridge-1:8471"}
        with pytest.raises(ValidationError, match="bridge_url is also matrix_bridge's"):
            Profile.model_validate(_body(rcs=rcs))

    @pytest.mark.parametrize("field", ["bridge_token_env", "ingress_token_env"])
    def test_two_channels_may_not_share_a_token(self, field: str) -> None:
        rcs = _bridge(2, RCS_ID, **RCS_LOCAL) | {field: _bridge(1, MATRIX_ID)[field]}
        with pytest.raises(ValidationError, match="is also matrix_bridge's"):
            Profile.model_validate(_body(rcs=rcs))

    def test_one_bridge_may_not_reuse_its_own_token_env(self) -> None:
        """A bridge token that is also the hs_token would let the bridge
        process pose as the homeserver and inject "agent" events."""
        rcs = _bridge(2, RCS_ID, **RCS_LOCAL)
        rcs["local"]["hs_token_env"] = "B2"
        with pytest.raises(ValidationError, match="four token envs must all differ"):
            Profile.model_validate(_body(rcs=rcs))

    def test_two_channels_may_not_share_an_appservice_token(self) -> None:
        rcs = _bridge(2, RCS_ID, **RCS_LOCAL)
        rcs["local"]["hs_token_env"] = "H1"
        with pytest.raises(ValidationError, match="token env H1"):
            Profile.model_validate(_body(rcs=rcs))

    @pytest.mark.parametrize(
        "local",
        [
            {},  # both default to remote_ and trentina
            {"user_prefix": "remote_rcs_", "sender_localpart": "trentina_rcs"},
            {"user_prefix": "rem", "sender_localpart": "trentina_rcs"},
            {"user_prefix": "rcs_", "sender_localpart": "trentina"},
            {"user_prefix": "rcs_", "sender_localpart": "remote_bot"},
            {"user_prefix": "trentin", "sender_localpart": "rcs_bot"},
        ],
    )
    def test_namespaces_may_not_overlap_on_one_homeserver(self, local: dict[str, str]) -> None:
        with pytest.raises(ValidationError, match="namespace overlaps matrix_bridge's"):
            Profile.model_validate(_body(rcs=_bridge(2, RCS_ID, **local)))

    def test_the_same_namespace_on_another_homeserver_is_fine(self) -> None:
        rcs = _bridge(2, RCS_ID, homeserver="http://10.0.11.3:6167", server_name="agent2.local")
        assert "rcs" in Profile.model_validate(_body(rcs=rcs)).channel_bridges()

    def test_one_homeserver_by_another_url_is_still_one(self) -> None:
        """Namespaces are per server_name: a second URL for the same Conduit
        does not make its namespaces separate."""
        rcs = _bridge(2, RCS_ID, homeserver="http://conduit-agent1:6167")
        with pytest.raises(ValidationError, match="namespace overlaps"):
            Profile.model_validate(_body(rcs=rcs))

    def test_a_honeypot_carries_no_bridges(self) -> None:
        body = _body()
        del body["matrix_bridge"]
        body |= {
            "role": "agent",
            "honeypot": True,
            "defense": {"enforcement": "flag"},
        }
        with pytest.raises(ValidationError, match="bridges does not apply"):
            Profile.model_validate(body)


_YAML = """\
profiles:
  agent1:
    auth:
      bearer_token_env: TEST_BEARER
    bridges:
      rcs:
        enabled: true
        public_user_id: "@agent1:rcs.invalid"
        bridge_url: http://127.0.0.1:8472
        bridge_token_env: RCS_BRIDGE
        ingress_token_env: RCS_INGRESS
        local:
          homeserver: http://127.0.0.1:6167
          server_name: agent1.local
          agent_localpart: agent1
          as_token_env: RCS_AS
          hs_token_env: RCS_HS
          user_prefix: rcs_
          sender_localpart: trentina_rcs
"""
_SECRETS = {name: name.lower() * 4 for name in ("RCS_BRIDGE", "RCS_INGRESS", "RCS_AS", "RCS_HS")}


class TestLoader:
    @pytest.fixture(autouse=True)
    def _bearer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_BEARER", "b" * 32)

    def test_an_enabled_channel_needs_every_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "profiles.yaml"
        path.write_text(_YAML, encoding="utf-8")
        for missing in _SECRETS:
            for name, value in _SECRETS.items():
                if name == missing:
                    monkeypatch.delenv(name, raising=False)
                else:
                    monkeypatch.setenv(name, value)
            with pytest.raises(ProfileConfigError, match=r"bridges\.rcs"):
                load_profiles(path)
        for name, value in _SECRETS.items():
            monkeypatch.setenv(name, value)
        rcs = load_profiles(path).profiles["agent1"].bridges["rcs"]
        assert rcs.local.hs_token is not None
        assert rcs.local.hs_token.get_secret_value() == _SECRETS["RCS_HS"]


class TestBuild:
    async def test_each_channel_gets_its_own_bridge_store_and_label(self, tmp_path: Path) -> None:
        bridges = routes_mod.build_bridges({"agent1": _resolved(_body())}, tmp_path)
        try:
            assert set(bridges) == {("agent1", "matrix"), ("agent1", "rcs")}
            assert bridges[("agent1", "matrix")].label == "agent1"
            assert bridges[("agent1", "rcs")].label == "agent1/rcs"
            assert bridges[("agent1", "rcs")].cfg.public_user_id == RCS_ID
            # The matrix store keeps its pre-#483 name: no rooms re-mirrored.
            assert sorted(p.name for p in tmp_path.glob("*.db")) == [
                "bridge-agent1-rcs.db",
                "bridge-agent1.db",
            ]
        finally:
            for bridge in bridges.values():
                await bridge.aclose()

    async def test_a_disabled_channel_builds_nothing(self, tmp_path: Path) -> None:
        body = _body()
        body["bridges"]["rcs"]["enabled"] = False
        bridges = routes_mod.build_bridges({"agent1": _resolved(body)}, tmp_path)
        try:
            assert set(bridges) == {("agent1", "matrix")}
        finally:
            for bridge in bridges.values():
                await bridge.aclose()

    async def test_the_agent_rule_spans_channels(self, tmp_path: Path) -> None:
        """Another profile's rcs identity is another agent on every channel of
        this one; this profile's own identities on other channels are not."""
        other = copy.deepcopy(_body())
        other["name"] = "agent2"
        del other["matrix_bridge"]
        other["bridges"]["rcs"]["public_user_id"] = OTHER_RCS_ID
        assert routes_mod.bridged_agents(
            {"agent1": Profile.model_validate(_body()), "agent2": Profile.model_validate(other)}
        ) == {MATRIX_ID, RCS_ID, OTHER_RCS_ID}
        bridges = routes_mod.build_bridges(
            {"agent1": _resolved(_body()), "agent2": _resolved(other)}, tmp_path / "a"
        )
        try:
            matrix = bridges[("agent1", "matrix")]
            assert matrix._is_other_agent(OTHER_RCS_ID)
            assert not matrix._is_other_agent(RCS_ID)
            assert not bridges[("agent1", "rcs")]._is_other_agent(MATRIX_ID)
        finally:
            for bridge in bridges.values():
                await bridge.aclose()


class StubBridge:
    def __init__(self, profile: Profile, channel: str) -> None:
        self.profile = profile
        self.cfg = profile.channel_bridges()[channel]
        self.label = f"agent1/{channel}"
        self.events: list[dict[str, Any]] = []
        self.transactions: list[str] = []

    async def inbound(self, event: dict[str, Any]) -> str:
        self.events.append(event)
        return "delivered"

    async def outbound(self, txn: str, _events: list[Any]) -> None:
        self.transactions.append(txn)

    async def typing(self, _ephemeral: list[Any]) -> None:
        return None


_EVENT = {"room_id": "!r:rcs.invalid", "event_id": "$e", "sender": "@s:rcs.invalid", "type": "x"}


class TestRoutes:
    @pytest.fixture
    def stubs(self) -> dict[str, StubBridge]:
        profile = _resolved(_body())
        return {channel: StubBridge(profile, channel) for channel in ("matrix", "rcs")}

    @pytest.fixture
    def client(self, stubs: dict[str, StubBridge]) -> TestClient:
        bridges: Any = {("agent1", channel): stub for channel, stub in stubs.items()}
        handlers = BridgeRoutes(bridges)
        legacy = "/bridge/as/{profile}/_matrix/app/v1"
        prefix = "/bridge/as/{profile}/{channel}/_matrix/app/v1"
        return TestClient(
            Starlette(
                routes=[
                    Route("/bridge/{profile}/event", handlers.event, methods=["POST"]),
                    Route("/bridge/{profile}/{channel}/event", handlers.event, methods=["POST"]),
                    Route(legacy + "/transactions/{txn}", handlers.transaction, methods=["PUT"]),
                    Route(prefix + "/transactions/{txn}", handlers.transaction, methods=["PUT"]),
                ]
            )
        )

    def _post(self, client: TestClient, path: str, token: str) -> int:
        resp = client.post(path, json=_EVENT, headers={"Authorization": f"Bearer {token}"})
        return resp.status_code

    def test_each_channel_opens_only_to_its_own_ingress_token(
        self, client: TestClient, stubs: dict[str, StubBridge]
    ) -> None:
        assert self._post(client, "/bridge/agent1/rcs/event", "ingress-I2") == 200
        assert self._post(client, "/bridge/agent1/rcs/event", "ingress-I1") == 401
        assert self._post(client, "/bridge/agent1/event", "ingress-I2") == 401
        assert self._post(client, "/bridge/agent1/event", "ingress-I1") == 200
        assert self._post(client, "/bridge/agent1/sms/event", "ingress-I2") == 401
        assert len(stubs["rcs"].events) == 1
        assert len(stubs["matrix"].events) == 1

    def test_each_channel_takes_only_its_own_homeservers_transactions(
        self, client: TestClient, stubs: dict[str, StubBridge]
    ) -> None:
        def put(path: str, token: str) -> int:
            headers = {"Authorization": f"Bearer {token}"}
            return client.put(path, json={"events": []}, headers=headers).status_code

        rcs = "/bridge/as/agent1/rcs/_matrix/app/v1/transactions/t1"
        matrix = "/bridge/as/agent1/_matrix/app/v1/transactions/t1"
        assert put(rcs, "hs-H1") == 403
        assert put(matrix, "hs-H2") == 403
        assert put(rcs, "hs-H2") == 200
        assert put(matrix, "hs-H1") == 200
        assert stubs["rcs"].transactions == ["t1"]
        assert stubs["matrix"].transactions == ["t1"]


class FakeMCP:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def custom_route(self, path: str, methods: list[str]) -> Any:
        self.paths.append(path)
        return lambda handler: handler


class TestRegister:
    async def test_channel_routes_exist_only_when_a_channel_does(self, tmp_path: Path) -> None:
        only_matrix = _body()
        del only_matrix["bridges"]
        for body, expected in ((only_matrix, False), (_body(), True)):
            mcp = FakeMCP()
            register_bridge_routes(mcp, {"agent1": _resolved(body)}, tmp_path / str(expected))
            prefix = "/bridge/as/{profile}/{channel}/_matrix/app/v1"
            for path in (
                "/bridge/{profile}/{channel}/event",
                f"{prefix}/transactions/{{txn}}",
                f"{prefix}/users/{{user}}",
                f"{prefix}/rooms/{{alias}}",
                f"{prefix}/ping",
            ):
                assert (path in mcp.paths) is expected, path
            assert "/bridge/{profile}/event" in mcp.paths
            assert "/bridge/as/{profile}/_matrix/app/v1/transactions/{txn}" in mcp.paths
            await routes_mod.close_bridges()


class TestYamlErrors:
    def test_a_parse_error_names_the_place_not_the_line(self, tmp_path: Path) -> None:
        """A malformed line can hold an inline secret; the error must not quote it."""
        path = tmp_path / "profiles.yaml"
        path.write_text("profiles:\n  a:\n    key: sk-live-SECRET: oops\n", encoding="utf-8")
        with pytest.raises(ProfileConfigError) as err:
            load_profiles(path)
        assert "line 3" in str(err.value)
        assert "SECRET" not in str(err.value)
        assert err.value.__cause__ is None
        assert err.value.__suppress_context__
