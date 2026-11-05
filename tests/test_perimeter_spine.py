"""The perimeter spine, held with a route that is not the gateway's own (#535 R3).

A plugin route writes ``admit``, ``deliver`` and ``render`` and nothing else.
These tests drive one through the real spine — real ``defend()``, gate, egress
guard and pinned pool, with the models and the network faked as in the golden
oracle (``tests/perimeter_golden.py``) — and hold what the contract promises:
the route sees no profile and no secret, sends only where its instance points,
gets nothing back the spine did not judge, and cannot leave a slot held or a
row unwritten.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route as StarletteRoute

from tests import perimeter_golden as g
from tests.perimeter_golden import Call, bearer, drive, reply
from trentina.gateway.destination import DestinationKind
from trentina.gateway.loader import load_profiles
from trentina.modes import Mode
from trentina.outcomes import Outcome
from trentina.transports import perimeter
from trentina.transports.base import (
    SPINE_REFUSALS,
    Admitted,
    Bearer,
    Context,
    Grant,
    Instance,
    OperatorOrigin,
    Origin,
    Refusal,
    RefusedError,
    Route,
    Wire,
)

if TYPE_CHECKING:
    import pytest

HOST = "api.acme.example"
SECRET = "acme-secret-the-route-never-sees"


@dataclass(frozen=True)
class ToyAdmitted(Admitted):
    path: str = ""


class Toy(Route[ToyAdmitted, Context]):
    """What a plugin author writes: three methods, one table."""

    name = "toy"
    methods = ("GET", "POST")
    auth = Bearer()
    refusals: ClassVar[dict[str, Refusal]] = {
        **SPINE_REFUSALS,
        "no_admin": Refusal(403, Outcome.DENIED_GUARD),
    }
    max_request_bytes = 1024
    #: What the route saw, for the tests to inspect.
    seen: ClassVar[list[Any]] = []

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> ToyAdmitted:
        if wire.path.startswith("admin"):
            raise RefusedError("no_admin", detail="the route's own fact")
        if wire.path.startswith("elsewhere"):
            return ToyAdmitted(OperatorOrigin("not-in-the-instance"), path=wire.path)
        if wire.path.startswith("undeclared"):
            raise RefusedError("made_up")
        return ToyAdmitted(OperatorOrigin("api"), destination=f"{HOST}/{wire.path}", path=wire.path)

    async def deliver(self, admitted: ToyAdmitted, ctx: Context) -> Response:
        Toy.seen.append(ctx)
        if admitted.path.startswith("boom"):
            raise RuntimeError("the route failed")
        body = await ctx.body.read() or None
        delivered = await ctx.upstream.send(
            ctx.wire.method,
            admitted.path,
            query=ctx.wire.query,
            headers={"content-type": "application/json"},
            content=body,
        )
        return Response(delivered.body, status_code=delivered.status)

    def render(self, refused: RefusedError) -> Response:
        return JSONResponse({"refused": refused.reason}, status_code=refused.status or 403)


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    call: Call,
    handler: g.Handler,
    *,
    enforcement: Mode = Mode.BLOCK,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], perimeter.Mount]:
    """Drive ``call`` through the toy route; return the exchange, what reached
    the upstream, the audit rows and the mount (for its slots)."""
    for name, value in g.ENV.items():
        monkeypatch.setenv(name, value)
    g._fake_models(monkeypatch)
    net = g.Network(handlers={HOST: handler})
    g._install_network(monkeypatch, net)
    config = load_profiles(g.CONFIG)
    bound = perimeter.Bound(
        instance=Instance(name="acme", type="toy", origins={"api": Origin(HOST)}, options={}),
        grant=Grant(
            origins=frozenset({"api"}),
            methods=frozenset({"GET", "POST"}),
            enforcement=enforcement,
            options={},
        ),
        secret=SecretStr(SECRET),
        injection=perimeter.HeaderToken("authorization", "Bearer "),
        secret_label="ACME_TOKEN",
    )
    toy = ("toy", "acme")
    monkeypatch.setattr(
        perimeter, "bind", lambda _c, _p, route, name: bound if (route, name) == toy else None
    )
    entry = perimeter.Mount(Toy(), DestinationKind.EGRESS, config)

    async def endpoint(request: Any) -> Any:
        return await perimeter.serve(entry, request, config.profiles)

    app = Starlette(routes=[StarletteRoute(Toy().path, endpoint, methods=list(Toy.methods))])
    Toy.seen.clear()
    exchange = await drive(app, call)
    return exchange, net.seen, g.rows("gateway_calls"), entry


def _get(path: str, profile: str = "agent1", query: str = "") -> Call:
    return Call("GET", f"/proxy/toy/acme/{path}", headers=bearer(profile), query=query)


def _status(exchange: dict[str, Any]) -> int:
    return next(m["status"] for m in exchange["messages"] if m["type"] == "start")


def _body(exchange: dict[str, Any]) -> str:
    return "".join(m["body"] for m in exchange["messages"] if m["type"] == "body")


class TestThePluginSeesLittle:
    def test_a_clean_call_is_delivered_with_the_secret_injected_by_the_spine(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exchange, seen, rows, _ = asyncio.run(
            _run(monkeypatch, _get("things", query="x=1"), reply(200, '{"ok":1}'))
        )
        assert _status(exchange) == 200
        [sent] = seen
        assert sent["url"] == f"https://{HOST}/things?x=1"
        assert ["authorization", f"Bearer {SECRET}"] in sent["headers"]
        assert [r["outcome"] for r in rows] == ["ok"]

    def test_the_context_holds_no_profile_and_no_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asyncio.run(_run(monkeypatch, _get("things"), reply(200, "{}")))
        [ctx] = Toy.seen
        assert type(ctx) is Context
        assert not hasattr(ctx, "profile")
        assert not hasattr(ctx, "op")
        assert SECRET not in repr(ctx.instance) + repr(ctx.grant) + repr(ctx.wire)

    def test_the_callers_token_never_reaches_the_route(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asyncio.run(_run(monkeypatch, _get("things"), reply(200, "{}")))
        [ctx] = Toy.seen
        assert "authorization" not in {k.lower() for k in ctx.wire.headers}


class TestThePluginSendsOnlyWhereItsInstancePoints:
    def test_a_key_the_instance_does_not_hold_is_refused_before_any_dial(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exchange, seen, rows, _ = asyncio.run(
            _run(monkeypatch, _get("elsewhere"), reply(200, "{}"))
        )
        assert json.loads(_body(exchange)) == {"refused": "unknown_upstream"}
        assert seen == []
        assert [r["error_message"] for r in rows] == ["unknown_upstream"]

    def test_an_instance_nobody_configured_is_the_same_refusal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = Call("GET", "/proxy/toy/nope/things", headers=bearer("agent1"))
        exchange, seen, _, _ = asyncio.run(_run(monkeypatch, call, reply(200, "{}")))
        assert json.loads(_body(exchange)) == {"refused": "unknown_upstream"}
        assert seen == []


class TestThePluginGetsOnlyJudgedBytes:
    def test_a_flagged_request_never_leaves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call = Call(
            "POST",
            "/proxy/toy/acme/things",
            headers={**bearer("agent1"), "content-type": "application/json"},
            body=[json.dumps({"q": g.INJECT}).encode()],
        )
        exchange, seen, rows, _ = asyncio.run(_run(monkeypatch, call, reply(200, "{}")))
        assert json.loads(_body(exchange)) == {"refused": "flagged"}
        assert seen == []
        assert rows[0]["outcome"] == "blocked_defense"

    def test_a_response_the_judge_could_not_read_is_withheld(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A route that would forward upstream bytes verbatim cannot: its only
        send hands back judged bytes or a refusal."""
        exchange, seen, _, _ = asyncio.run(
            _run(monkeypatch, _get("things"), reply(200, json.dumps({"x": g.UNJUDGED})))
        )
        assert len(seen) == 1
        assert json.loads(_body(exchange)) == {"refused": "response_unjudged"}

    def test_a_flagged_response_is_withheld(self, monkeypatch: pytest.MonkeyPatch) -> None:
        exchange, _, _, _ = asyncio.run(
            _run(monkeypatch, _get("things"), reply(200, json.dumps({"x": g.INJECT})))
        )
        assert json.loads(_body(exchange)) == {"refused": "response_flagged"}

    def test_an_echo_of_the_injected_secret_is_cut(self, monkeypatch: pytest.MonkeyPatch) -> None:
        exchange, _, _, _ = asyncio.run(
            _run(monkeypatch, _get("things"), reply(200, json.dumps({"echo": SECRET})))
        )
        assert SECRET not in _body(exchange)
        assert "[REDACTED]" in _body(exchange)


class TestTheSpineKeepsTheBooks:
    def test_an_unknown_caller_gets_the_routes_refusal_and_no_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = Call("GET", "/proxy/toy/acme/things", headers={"authorization": "Bearer nope"})
        exchange, seen, rows, _ = asyncio.run(_run(monkeypatch, call, reply(200, "{}")))
        assert _status(exchange) == 401
        assert json.loads(_body(exchange)) == {"refused": "unauthorized"}
        assert seen == []
        assert rows == []

    def test_a_plugins_detail_does_not_reach_the_row(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _, _, rows, _ = asyncio.run(_run(monkeypatch, _get("admin"), reply(200, "{}")))
        assert [(r["outcome"], r["error_message"]) for r in rows] == [("denied_guard", "no_admin")]

    def test_an_undeclared_reason_is_a_gateway_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        exchange, _, rows, _ = asyncio.run(_run(monkeypatch, _get("undeclared"), reply(200, "{}")))
        assert _status(exchange) == 500
        assert [r["outcome"] for r in rows] == ["gateway_error"]

    def test_a_route_that_fails_gives_its_slot_back_and_leaves_a_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exchange, _, rows, entry = asyncio.run(_run(monkeypatch, _get("boom"), reply(200, "{}")))
        assert exchange["raised"] == "RuntimeError"
        assert entry.slots._open == {}
        assert [r["outcome"] for r in rows] == ["gateway_error"]

    def test_a_refused_call_gives_its_slot_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _, _, _, entry = asyncio.run(
            _run(monkeypatch, _get("things"), reply(200, json.dumps({"x": g.INJECT})))
        )
        assert entry.slots._open == {}

    def test_a_flag_grant_forwards_and_records_the_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = Call(
            "POST",
            "/proxy/toy/acme/things",
            headers={**bearer("agent1"), "content-type": "application/json"},
            body=[json.dumps({"q": g.INJECT}).encode()],
        )
        exchange, seen, rows, _ = asyncio.run(
            _run(monkeypatch, call, reply(200, "{}"), enforcement=Mode.FLAG)
        )
        assert _status(exchange) == 200
        assert len(seen) == 1
        assert [(r["outcome"], r["error_message"]) for r in rows] == [("ok", "flagged")]
