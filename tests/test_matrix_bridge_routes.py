"""Who may call the bridge endpoints on the gateway.

Two credentials, two doors, and neither opens the other: the bridge process
presents ``ingress_token`` to hand over upstream events, Conduit presents
``hs_token`` to push the agent's. A bridge holding its own token must not be
able to pose as the homeserver and inject "agent" events outbound.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from trentina.gateway.matrix_bridge.appservice import ConduitError
from trentina.gateway.matrix_bridge.core import BridgeUnavailableError
from trentina.gateway.matrix_bridge.routes import (
    BridgeRoutes,
    register_bridge_routes,
)

from .test_matrix_bridge import _profile

if TYPE_CHECKING:
    from pathlib import Path


class StubBridge:
    def __init__(self) -> None:
        profile = _profile()
        self.profile = profile
        self.cfg = profile.matrix_bridge
        self.label = profile.name
        self.inbound_events: list[dict[str, Any]] = []
        self.transactions: list[tuple[str, list[Any]]] = []
        self.typings: list[list[dict[str, Any]]] = []
        self.order: list[str] = []
        self.fail_outbound = False
        self.fail_inbound: Exception | None = None

    async def inbound(self, event: dict[str, Any]) -> str:
        if self.fail_inbound is not None:
            raise self.fail_inbound
        self.inbound_events.append(event)
        return "delivered"

    async def outbound(self, txn: str, events: list[Any]) -> None:
        if self.fail_outbound:
            raise BridgeUnavailableError("down")
        self.transactions.append((txn, events))
        self.order.append("events")

    async def typing(self, ephemeral: list[dict[str, Any]]) -> None:
        self.typings.append(ephemeral)
        self.order.append("typing")


@pytest.fixture
def stub() -> StubBridge:
    return StubBridge()


@pytest.fixture
def client(stub: StubBridge) -> TestClient:
    bridges: Any = {("agent1", "matrix"): stub}
    handlers = BridgeRoutes(bridges)
    prefix = "/bridge/as/{profile}/_matrix/app/v1"
    app = Starlette(
        routes=[
            Route("/bridge/{profile}/event", handlers.event, methods=["POST"]),
            Route(prefix + "/transactions/{txn}", handlers.transaction, methods=["PUT"]),
            Route(prefix + "/users/{user}", handlers.query, methods=["GET"]),
        ]
    )
    return TestClient(app)


def _event(**overrides: Any) -> dict[str, Any]:
    return {
        "room_id": "!r:matrix.org",
        "event_id": "$e",
        "sender": "@s:matrix.org",
        "type": "m.room.message",
        "content": {"body": "hi"},
    } | overrides


EVENT_PATH = "/bridge/agent1/event"
TXN_PATH = "/bridge/as/agent1/_matrix/app/v1/transactions/t1"


class TestIngress:
    def test_a_dms_peer_reaches_the_bridge(self, stub: StubBridge, client: TestClient) -> None:
        room = {
            "name": "",
            "topic": "",
            "is_direct": True,
            "peer": "@s:matrix.org",
            "peer_displayname": "S",
        }
        resp = client.post(
            EVENT_PATH,
            json=_event(room=room),
            headers={"Authorization": "Bearer ingress-secret"},
        )
        assert resp.status_code == 200
        [event] = stub.inbound_events
        assert event["room"] == room | {"members": None}

    def test_the_bridge_token_hands_over_an_event(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        resp = client.post(
            EVENT_PATH, json=_event(), headers={"Authorization": "Bearer ingress-secret"}
        )
        assert resp.status_code == 200
        assert resp.json() == {"outcome": "delivered"}
        [event] = stub.inbound_events
        assert event["event_id"] == "$e"
        assert event["room"] == {
            "name": "",
            "topic": "",
            "is_direct": False,
            "peer": "",
            "peer_displayname": "",
            "members": None,
        }

    @pytest.mark.parametrize(
        "bad",
        [
            {"unexpected": 1},
            {"content": "not a mapping"},
            {"event_id": 7},
            {"event_id": ""},
        ],
    )
    def test_an_event_that_is_not_the_wire_format_is_refused(
        self, stub: StubBridge, client: TestClient, bad: dict[str, Any]
    ) -> None:
        resp = client.post(
            EVENT_PATH, json=_event(**bad), headers={"Authorization": "Bearer ingress-secret"}
        )
        assert resp.status_code == 400
        assert stub.inbound_events == []

    @pytest.mark.parametrize("failure", [ConduitError("down"), OSError("reset")])
    def test_a_delivery_failure_is_retryable_not_acked(
        self, stub: StubBridge, client: TestClient, failure: Exception
    ) -> None:
        """A 503, so the bridge keeps the event and does not advance past it."""
        stub.fail_inbound = failure
        resp = client.post(
            EVENT_PATH, json=_event(), headers={"Authorization": "Bearer ingress-secret"}
        )
        assert resp.status_code == 503
        assert "outcome" not in resp.json()

    def test_invalid_json_is_refused(self, stub: StubBridge, client: TestClient) -> None:
        resp = client.post(
            EVENT_PATH, content=b"{nope", headers={"Authorization": "Bearer ingress-secret"}
        )
        assert resp.status_code == 400

    @pytest.mark.parametrize("token", ["", "wrong", "hs-secret", "bridge-secret"])
    def test_any_other_token_is_refused(
        self, stub: StubBridge, client: TestClient, token: str
    ) -> None:
        resp = client.post(EVENT_PATH, json={}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        assert stub.inbound_events == []

    def test_an_unknown_profile_looks_like_a_bad_token(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        resp = client.post(
            "/bridge/other/event", json={}, headers={"Authorization": "Bearer ingress-secret"}
        )
        assert resp.status_code == 401


class TestAppservice:
    def test_conduit_pushes_a_transaction(self, stub: StubBridge, client: TestClient) -> None:
        pushed = {
            "event_id": "$a",
            "room_id": "!l:agent1.local",
            "sender": "@agent1:agent1.local",
            "type": "m.room.message",
            "content": {"body": "hi"},
            "origin_server_ts": 1,
            "unsigned": {"age": 3},
        }
        resp = client.put(
            TXN_PATH,
            json={"events": [pushed], "ephemeral": []},
            headers={"Authorization": "Bearer hs-secret"},
        )
        assert resp.status_code == 200
        [(txn, [event])] = stub.transactions
        assert txn == "t1"
        assert event["content"] == {"body": "hi"}
        assert event["sender"] == "@agent1:agent1.local"

    @pytest.mark.parametrize("key", ["ephemeral", "de.sorunome.msc2409.ephemeral"])
    def test_typing_follows_the_events_it_came_with(
        self, stub: StubBridge, client: TestClient, key: str
    ) -> None:
        pushed = {
            "event_id": "$a",
            "room_id": "!l:agent1.local",
            "sender": "@agent1:agent1.local",
            "type": "m.room.message",
            "content": {"body": "done"},
        }
        typing = {"type": "m.typing", "room_id": "!l:agent1.local", "content": {"user_ids": []}}
        resp = client.put(
            TXN_PATH,
            json={"events": [pushed], key: [typing]},
            headers={"Authorization": "Bearer hs-secret"},
        )
        assert resp.status_code == 200
        assert stub.typings == [[typing]]
        assert stub.order == ["events", "typing"]

    def test_no_typing_is_carried_from_a_transaction_not_acked(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        stub.fail_outbound = True
        typing = {"type": "m.typing", "room_id": "!l:agent1.local", "content": {"user_ids": []}}
        resp = client.put(
            TXN_PATH, json={"ephemeral": [typing]}, headers={"Authorization": "Bearer hs-secret"}
        )
        assert resp.status_code == 503
        assert stub.typings == []

    def test_a_field_the_spec_does_not_define_is_refused(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        event = {
            "event_id": "$a",
            "room_id": "!l:agent1.local",
            "sender": "@agent1:agent1.local",
            "type": "m.room.message",
            "smuggled": "x",
        }
        resp = client.put(
            TXN_PATH, json={"events": [event]}, headers={"Authorization": "Bearer hs-secret"}
        )
        assert resp.status_code == 400
        assert stub.transactions == []

    def test_an_oversized_body_is_refused_before_it_is_read(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        big = {"events": [], "ephemeral": [{"pad": "x" * 1_100_000}]}
        resp = client.put(TXN_PATH, json=big, headers={"Authorization": "Bearer hs-secret"})
        assert resp.status_code == 413
        assert stub.transactions == []

    def test_the_query_parameter_token_is_not_honoured(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        """Conduit appends it to every URL, where access logs record it."""
        resp = client.put(f"{TXN_PATH}?access_token=hs-secret", json={"events": []})
        assert resp.status_code == 403

    def test_the_bridge_cannot_pose_as_the_homeserver(
        self, stub: StubBridge, client: TestClient
    ) -> None:
        for token in ("ingress-secret", "bridge-secret", "as-secret"):
            resp = client.put(
                TXN_PATH, json={"events": []}, headers={"Authorization": f"Bearer {token}"}
            )
            assert resp.status_code == 403
        assert stub.transactions == []

    def test_a_bridge_outage_is_not_acked(self, stub: StubBridge, client: TestClient) -> None:
        stub.fail_outbound = True
        resp = client.put(
            TXN_PATH, json={"events": []}, headers={"Authorization": "Bearer hs-secret"}
        )
        assert resp.status_code == 503

    def test_nothing_is_provisioned_on_demand(self, stub: StubBridge, client: TestClient) -> None:
        resp = client.get(
            "/bridge/as/agent1/_matrix/app/v1/users/@x:agent1.local",
            headers={"Authorization": "Bearer hs-secret"},
        )
        assert resp.status_code == 404


class TestRegistration:
    class Server:
        def __init__(self) -> None:
            self.routes: list[tuple[str, tuple[str, ...]]] = []

        def custom_route(self, path: str, methods: list[str]) -> Any:
            def bind(handler: Any) -> Any:
                self.routes.append((path, tuple(methods)))
                return handler

            return bind

    def test_nothing_is_served_without_an_enabled_bridge(self, tmp_path: Path) -> None:
        server = self.Server()
        profile = _profile()
        assert profile.matrix_bridge is not None
        profile.matrix_bridge.enabled = False
        assert register_bridge_routes(server, {"agent1": profile}, tmp_path) is None
        assert server.routes == []

    def test_an_enabled_bridge_gets_both_doors(self, tmp_path: Path) -> None:
        server = self.Server()
        handlers = register_bridge_routes(server, {"agent1": _profile()}, tmp_path)
        assert handlers is not None
        assert ("/bridge/{profile}/event", ("POST",)) in server.routes
        assert (
            "/bridge/as/{profile}/_matrix/app/v1/transactions/{txn}",
            ("PUT",),
        ) in server.routes
        assert ("/bridge/as/{profile}/transactions/{txn}", ("PUT",)) in server.routes
        assert (tmp_path / "bridge-agent1.db").exists()
