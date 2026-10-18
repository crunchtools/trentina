"""The RCS bridge (#485): Twilio in, the gateway out, and back.

What these pin down: nothing reaches the store unless Twilio signed it and
the owner sent it; nothing in the store is lost to a gateway outage or a
restart; a reply is sent once per chunk however often the gateway retries;
and anything RCS cannot carry is a 422, the gateway's "never".
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode

import httpx
import pytest
from starlette.testclient import TestClient

from trentina.bridge.settings import SettingsError
from trentina.quarantine.classifier import classify, is_classifier_available
from trentina.rcs_bridge import bridge as bridge_mod
from trentina.rcs_bridge.api import build_private_app, build_public_app
from trentina.rcs_bridge.backend import Inbound
from trentina.rcs_bridge.bridge import RcsBridge, RefusedError, UnavailableError
from trentina.rcs_bridge.settings import DEFAULT_ROOM_TOPIC, RcsSettings
from trentina.rcs_bridge.store import RcsStore
from trentina.rcs_bridge.text import chunks, flatten
from trentina.rcs_bridge.twilio import MAX_BODY, TwilioBackend, signature

ACCOUNT = "AC" + "0" * 32
SENDER = "kagetora_abc123_agent"
TOKEN = "twilio-auth-token"
OWNER = "+15551234567"
WEBHOOK = "https://rcs.example.com/agent1/twilio/inbound"
BRIDGE_TOKEN = "bridge-secret"


def _settings(store_dir: Path) -> RcsSettings:
    return RcsSettings(
        profile="agent1",
        channel="rcs",
        gateway_url="http://10.89.0.2:8019",
        ingress_token="ingress-secret",
        bridge_token="bridge-secret",
        agent_user_id="@agent1:rcs.invalid",
        owner_number=OWNER,
        owner_name="Owner (phone)",
        room_topic="lower trust",
        server="rcs.invalid",
        store_dir=store_dir,
        listen_host="127.0.0.1",
        listen_port=8472,
        webhook_host="127.0.0.1",
        webhook_port=8473,
        webhook_url=WEBHOOK,
        account_sid=ACCOUNT,
        auth_token=TOKEN,
        sender_id=SENDER,
        twilio_api="https://api.twilio.test",
    )


class FakeTwilio:
    """The Messages API: records each form, answers a sid or a set failure."""

    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []
        self.typing: list[dict[str, Any]] = []
        # Statuses to answer before succeeding, one per request.
        self.fail: list[tuple[int, dict[str, Any]]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"].startswith("Basic ")
        if request.url.host == "messaging.twilio.test":
            assert request.url.path == "/v3/Indicators/Typing.json"
            assert request.headers["content-type"] == "application/json"
            if self.fail:
                status, body = self.fail.pop(0)
                return httpx.Response(status, json=body)
            self.typing.append(json.loads(request.content))
            return httpx.Response(200, json={"success": True})
        assert request.url.path == f"/2010-04-01/Accounts/{ACCOUNT}/Messages.json"
        if self.fail:
            status, body = self.fail.pop(0)
            return httpx.Response(status, json=body)
        self.sent.append(dict(parse_qsl(request.content.decode())))
        return httpx.Response(201, json={"sid": f"SM{len(self.sent):032d}"})


class FakeGateway:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.statuses: list[int] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/bridge/agent1/rcs/event"
        assert request.headers["authorization"] == "Bearer ingress-secret"
        if self.statuses:
            return httpx.Response(self.statuses.pop(0), json={})
        event = json.loads(request.content)
        self.events.append(event)
        return httpx.Response(200, json={"outcome": "delivered"})


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.settings = _settings(tmp_path)
        self.twilio = FakeTwilio()
        self.gateway = FakeGateway()
        backend = TwilioBackend(
            account_sid=ACCOUNT,
            auth_token=TOKEN,
            sender_id=SENDER,
            api="https://api.twilio.test",
            messaging_api="https://messaging.twilio.test",
            client=httpx.AsyncClient(transport=httpx.MockTransport(self.twilio)),
        )
        self.store = RcsStore(tmp_path / "rcs.db")
        self.bridge = RcsBridge(
            self.settings,
            backend,
            self.store,
            gateway=httpx.AsyncClient(transport=httpx.MockTransport(self.gateway)),
        )


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


_real_sleep = asyncio.sleep


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bridge's retry backoff, made instant but still a yield."""

    async def instant(_seconds: float) -> None:
        await _real_sleep(0)

    monkeypatch.setattr(bridge_mod.asyncio, "sleep", instant)


def _form(**overrides: str) -> dict[str, str]:
    return {
        "AccountSid": ACCOUNT,
        "MessageSid": "SM" + "1" * 32,
        "From": f"rcs:{OWNER}",
        "To": "rcs:agent1_agent",
        "Body": "ship it",
        "NumMedia": "0",
    } | overrides


def _post(client: TestClient, form: dict[str, str], *, token: str = TOKEN) -> httpx.Response:
    return client.post(
        "/twilio/inbound",
        content=urlencode(form),
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "x-twilio-signature": signature(token, WEBHOOK, list(form.items())),
        },
    )


async def _drain(rig: Rig) -> None:
    """Run the delivery loop until the inbox is empty, then stop it."""
    task = asyncio.create_task(rig.bridge.run())
    for _ in range(500):
        await _real_sleep(0.001)
        if rig.bridge.ready.is_set() and not await rig.store.pending():
            break
    else:
        pytest.fail("the inbox never drained")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class TestSignature:
    def test_it_is_twilio_pythons(self) -> None:
        """Computed by twilio-python 9.x ``RequestValidator.compute_signature``
        over the same URL and parameters."""
        params = [
            ("AccountSid", "AC" + "0" * 32),
            ("MessageSid", "SM" + "1" * 32),
            ("From", "rcs:+15551234567"),
            ("To", "rcs:kagetora_agent"),
            ("Body", "Deploy it? & yes = 100% ✓"),
            ("NumMedia", "0"),
        ]
        url = "https://rcs.example.com/kagetora/twilio/inbound"
        assert signature("12345", url, params) == "0MOBtZuCnN17v98D5/82+Rz9L3g="


class TestWebhook:
    def test_a_signed_message_from_the_owner_is_held(self, rig: Rig) -> None:
        resp = _post(TestClient(build_public_app(rig.bridge)), _form())
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/xml")
        pending = asyncio.run(rig.store.pending())
        assert [(m.sender, m.body) for m in pending] == [(OWNER, "ship it")]

    @pytest.mark.parametrize(
        ("form", "token", "status"),
        [
            (_form(), "wrong-token", 403),
            (_form(From="rcs:+15559999999"), TOKEN, 403),
            (_form(From="+15559999999"), TOKEN, 403),
        ],
    )
    def test_unsigned_or_foreign_is_refused_and_nothing_held(
        self, rig: Rig, form: dict[str, str], token: str, status: int
    ) -> None:
        resp = _post(TestClient(build_public_app(rig.bridge)), form, token=token)
        assert resp.status_code == status
        assert asyncio.run(rig.store.pending()) == []

    def test_another_accounts_or_a_status_callback_is_answered_and_ignored(self, rig: Rig) -> None:
        client = TestClient(build_public_app(rig.bridge))
        assert _post(client, _form(AccountSid="AC" + "9" * 32)).status_code == 200
        status_callback = _form(MessageStatus="delivered")
        del status_callback["Body"]
        assert _post(client, status_callback).status_code == 200
        assert asyncio.run(rig.store.pending()) == []

    def test_a_tampered_body_fails_the_signature(self, rig: Rig) -> None:
        form = _form()
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "x-twilio-signature": signature(TOKEN, WEBHOOK, list(form.items())),
        }
        tampered = urlencode(form | {"Body": "rm -rf /"})
        client = TestClient(build_public_app(rig.bridge))
        assert client.post("/twilio/inbound", content=tampered, headers=headers).status_code == 403

    def test_a_retried_webhook_is_held_once(self, rig: Rig) -> None:
        client = TestClient(build_public_app(rig.bridge))
        assert _post(client, _form()).status_code == 200
        assert _post(client, _form()).status_code == 200
        assert len(asyncio.run(rig.store.pending())) == 1

    def test_not_a_form_or_too_large_is_refused(self, rig: Rig) -> None:
        client = TestClient(build_public_app(rig.bridge))
        assert client.post("/twilio/inbound", json=_form()).status_code == 415
        big = _form(Body="x" * 40_000)
        assert _post(client, big).status_code == 413


class TestDelivery:
    async def test_the_room_is_announced_then_the_message_delivered(self, rig: Rig) -> None:
        await rig.bridge.accept(Inbound("SM1", OWNER, "ship it"))
        await _drain(rig)
        announce, message = rig.gateway.events
        assert announce["type"] == "org.crunchtools.trentina.room"
        assert announce["room_id"] == "!agent1-owner:rcs.invalid"
        assert announce["room"]["members"] == ["@tel15551234567:rcs.invalid"]
        assert announce["room"]["is_direct"] is True
        assert message["sender"] == "@tel15551234567:rcs.invalid"
        assert message["sender_displayname"] == "Owner (phone)"
        assert message["content"] == {"msgtype": "m.text", "body": "ship it"}
        assert message["event_id"] == "$rcs-SM1"
        assert await rig.store.pending() == []

    async def test_a_gateway_outage_loses_nothing(self, rig: Rig) -> None:
        await rig.bridge.accept(Inbound("SM1", OWNER, "one"))
        rig.gateway.statuses = [503, 503]
        await _drain(rig)
        assert [e.get("content", {}).get("body") for e in rig.gateway.events] == [None, "one"]

    async def test_a_restart_delivers_what_was_held(self, tmp_path: Path) -> None:
        first = RcsStore(tmp_path / "rcs.db")
        await first.put(Inbound("SM1", OWNER, "held"))
        first.close()
        rig = Rig(tmp_path)
        await _drain(rig)
        assert rig.gateway.events[-1]["content"]["body"] == "held"

    async def test_a_delivered_message_stays_a_duplicate(self, rig: Rig) -> None:
        assert await rig.bridge.accept(Inbound("SM1", OWNER, "one"))
        await _drain(rig)
        assert not await rig.bridge.accept(Inbound("SM1", OWNER, "one"))

    async def test_an_attachment_is_named_not_dropped(self, rig: Rig) -> None:
        await rig.bridge.accept(Inbound("SM1", OWNER, "", attachments=2))
        await _drain(rig)
        assert "2 attachment(s) not carried" in rig.gateway.events[-1]["content"]["body"]


ROOM = "!agent1-owner:rcs.invalid"


class TestSend:
    async def test_a_text_goes_to_the_owner_over_rcs_only(self, rig: Rig) -> None:
        content = {"msgtype": "m.text", "body": "**Done.** See [the PR](https://x/1)"}
        event_id = await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        (form,) = rig.twilio.sent
        assert form == {
            "From": f"rcs:{SENDER}",
            "To": f"rcs:{OWNER}",
            "Body": "Done. See the PR (https://x/1)",
        }
        assert event_id == f"$rcs-SM{1:032d}"

    async def test_a_retry_sends_only_the_chunks_that_did_not_go(self, rig: Rig) -> None:
        body = "\n\n".join(["a" * 1000, "b" * 1000, "c" * 1000])
        content = {"msgtype": "m.text", "body": body}
        rig.twilio.fail = [(201, {"sid": "SMfirst"}), (500, {"code": 20500})]
        with pytest.raises(UnavailableError):
            await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        first = await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        again = await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        assert first == again == "$rcs-SMfirst"
        assert [f["Body"][0] for f in rig.twilio.sent] == ["b", "c"]

    @pytest.mark.parametrize(
        ("event_type", "content"),
        [
            ("m.room.message", {"msgtype": "m.image", "body": "x.png"}),
            (
                "m.room.message",
                {"msgtype": "m.text", "body": "* x", "m.relates_to": {"rel_type": "m.replace"}},
            ),
            ("m.room.message", {"msgtype": "m.text", "body": "   "}),
            ("m.room.message", {"msgtype": "m.text"}),
        ],
    )
    async def test_what_rcs_cannot_carry_is_refused(
        self, rig: Rig, event_type: str, content: dict[str, Any]
    ) -> None:
        with pytest.raises(RefusedError):
            await rig.bridge.send(ROOM, event_type, content, "out1")
        assert rig.twilio.sent == []

    async def test_a_reaction_is_dropped_not_refused(self, rig: Rig) -> None:
        content = {"m.relates_to": {"rel_type": "m.annotation", "key": "\U0001f440"}}
        first = await rig.bridge.send(ROOM, "m.reaction", content, "r1")
        again = await rig.bridge.send(ROOM, "m.reaction", content, "r1")
        assert first == again
        assert first.startswith(bridge_mod.DROPPED_PREFIX)
        assert rig.twilio.sent == []

    async def test_an_edit_goes_out_as_its_new_text(self, rig: Rig) -> None:
        content = {
            "msgtype": "m.text",
            "body": "* Done at 5.",
            "m.new_content": {"msgtype": "m.text", "body": "Done at 5."},
            "m.relates_to": {"rel_type": "m.replace", "event_id": "$x"},
        }
        await rig.bridge.send(ROOM, "m.room.message", content, "e1")
        (form,) = rig.twilio.sent
        assert form["Body"] == "(edited) Done at 5."

    async def test_only_the_owners_room(self, rig: Rig) -> None:
        with pytest.raises(RefusedError):
            await rig.bridge.send("!other:rcs.invalid", "m.room.message", {"body": "x"}, "t")

    async def test_a_body_twilio_refuses_for_good_is_refused(self, rig: Rig) -> None:
        rig.twilio.fail = [(400, {"code": 21617})]
        with pytest.raises(RefusedError):
            await rig.bridge.send(ROOM, "m.room.message", {"msgtype": "m.text", "body": "x"}, "t")


class TestTyping:
    """The agent's typing on the owner's phone (#1533)."""

    async def test_typing_starts_the_indicator(self, rig: Rig) -> None:
        await rig.bridge.typing(ROOM, True)
        assert rig.twilio.typing == [
            {"channel": "RCS", "from": f"rcs:{SENDER}", "to": OWNER, "event": "START"}
        ]
        assert rig.twilio.sent == []

    async def test_a_burst_is_one_indicator_until_it_lapses(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = [1000.0]
        monkeypatch.setattr(bridge_mod.time, "monotonic", lambda: clock[0])
        for _ in range(5):
            await rig.bridge.typing(ROOM, True)
        assert len(rig.twilio.typing) == 1
        clock[0] += bridge_mod.TYPING_EVERY
        await rig.bridge.typing(ROOM, True)
        assert len(rig.twilio.typing) == 2

    async def test_stopping_sends_nothing(self, rig: Rig) -> None:
        await rig.bridge.typing(ROOM, False)
        assert rig.twilio.typing == []

    async def test_only_the_owners_room(self, rig: Rig) -> None:
        with pytest.raises(RefusedError):
            await rig.bridge.typing("!other:rcs.invalid", True)
        assert rig.twilio.typing == []

    async def test_a_provider_failure_is_unavailable(self, rig: Rig) -> None:
        rig.twilio.fail = [(500, {"code": 20500})]
        with pytest.raises(UnavailableError):
            await rig.bridge.typing(ROOM, True)

    def test_the_gateway_contract(self, rig: Rig) -> None:
        client = TestClient(build_private_app(rig.bridge))
        headers = {"Authorization": f"Bearer {BRIDGE_TOKEN}"}
        body = {"room_id": ROOM, "typing": True}

        def post(json: dict[str, Any], auth: dict[str, str] = headers) -> tuple[int, Any]:
            resp = client.post("/typing", json=json, headers=auth)
            return resp.status_code, resp.json()

        assert post(body, {"Authorization": "Bearer x"})[0] == 401
        assert post(body | {"extra": 1})[0] == 400
        assert post(body | {"typing": "yes"})[0] == 400
        # Best effort, as on the Matrix bridge: never an error for a bubble.
        assert post(body | {"room_id": "!other:rcs.invalid"}) == (200, {"shown": False})
        rig.twilio.fail = [(503, {"code": 20503})]
        assert post(body) == (200, {"shown": False})
        assert post(body) == (200, {"shown": True}), "a failure does not hold the throttle"
        assert len(rig.twilio.typing) == 1


class TestPrivateApi:
    def _client(self, rig: Rig) -> TestClient:
        return TestClient(build_private_app(rig.bridge))

    def _send(self, client: TestClient, body: dict[str, Any], token: str = BRIDGE_TOKEN) -> int:
        resp = client.post("/send", json=body, headers={"Authorization": f"Bearer {token}"})
        return resp.status_code

    def test_the_gateway_contract(self, rig: Rig) -> None:
        client = self._client(rig)
        text = {
            "room_id": ROOM,
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "hi"},
            "txn_id": "t1",
        }
        assert self._send(client, text, token="wrong") == 401
        assert self._send(client, text) == 200
        image = {"msgtype": "m.image", "body": "x.png"}
        assert self._send(client, text | {"content": image, "txn_id": "t2"}) == 422
        assert self._send(client, text | {"extra": 1}) == 400
        redact = {"room_id": ROOM, "event_id": "$e", "txn_id": "t3"}
        headers = {"Authorization": "Bearer bridge-secret"}
        assert client.post("/redact", json=redact, headers=headers).status_code == 422
        reaction = text | {"type": "m.reaction", "content": {}, "txn_id": "t5"}
        dropped = client.post("/send", json=reaction, headers=headers).json()["event_id"]
        undo = redact | {"event_id": dropped}
        assert client.post("/redact", json=undo, headers=headers).status_code == 200
        rig.twilio.fail = [(503, {"code": 20503})]
        assert self._send(client, text | {"txn_id": "t4"}) == 502

    def test_health_is_ready_once_the_room_is_announced(self, rig: Rig) -> None:
        client = self._client(rig)
        assert client.get("/health").status_code == 503
        rig.bridge.ready.set()
        assert client.get("/health").status_code == 200


class TestText:
    def test_markup_goes_and_meaning_stays(self) -> None:
        body = "# Status\n\n**All green.** `make test` passed.\n```\nok\n```\n[docs](https://d)"
        assert flatten("m.text", body) == (
            "Status\n\nAll green. `make test` passed.\nok\ndocs (https://d)"
        )
        assert flatten("m.emote", "waves") == "* waves"
        assert flatten("m.text", "[https://x](https://x)") == "https://x"

    def test_chunks_split_at_paragraphs_and_never_exceed_the_limit(self) -> None:
        text = "\n\n".join(["p" * 900, "q" * 900, "r" * 900])
        parts = chunks(text, MAX_BODY)
        assert [p[0] for p in parts] == ["p", "q", "r"]
        assert all(len(p) <= MAX_BODY for p in parts)
        assert chunks("w" * 3500, MAX_BODY) == ["w" * 1600, "w" * 1600, "w" * 300]
        assert chunks("  ", MAX_BODY) == []


_ENV = {
    "BRIDGE_PROFILE": "agent1",
    "BRIDGE_GATEWAY_URL": "http://10.89.0.2:8019",
    "BRIDGE_INGRESS_TOKEN": "i",
    "BRIDGE_TOKEN": "b",
    "RCS_AGENT_USER_ID": "@agent1:rcs.invalid",
    "RCS_OWNER_NUMBER": OWNER,
    "RCS_WEBHOOK_URL": WEBHOOK,
    "RCS_TWILIO_ACCOUNT_SID": ACCOUNT,
    "RCS_TWILIO_AUTH_TOKEN": TOKEN,
    "RCS_TWILIO_SENDER_ID": SENDER,
}


@pytest.mark.skipif(not is_classifier_available(), reason="Prompt Guard model not available")
def test_the_default_room_topic_is_not_judged_an_injection() -> None:
    """The gateway judges the topic with every message: one that reads as an
    instruction gets every text withheld (RT #1529)."""
    assert classify(DEFAULT_ROOM_TOPIC).label == "BENIGN"


class TestSettings:
    def test_a_complete_environment_loads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name, value in _ENV.items():
            monkeypatch.setenv(name, value)
        settings = RcsSettings.from_env()
        assert settings.owner_user_id == "@tel15551234567:rcs.invalid"
        assert settings.room_id == "!agent1-owner:rcs.invalid"
        assert settings.twilio_api == "https://api.twilio.com"
        assert settings.twilio_messaging_api == "https://messaging.twilio.com"

    def test_the_sender_id_may_carry_its_rcs_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name, value in _ENV.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("RCS_TWILIO_SENDER_ID", f"rcs:{SENDER}")
        assert RcsSettings.from_env().sender_id == SENDER

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("RCS_OWNER_NUMBER", "5551234567"),
            ("RCS_WEBHOOK_URL", "http://rcs.example.com/in"),
            ("RCS_TWILIO_ACCOUNT_SID", "SK" + "0" * 32),
            ("RCS_TWILIO_SENDER_ID", "rcs:brand agent"),
            ("RCS_TWILIO_SENDER_ID", "MG" + "0" * 32 + "/x"),
            ("RCS_AGENT_USER_ID", "agent1"),
            ("BRIDGE_GATEWAY_URL", "http://8.8.8.8:8019"),
        ],
    )
    def test_a_bad_value_is_fatal(
        self, monkeypatch: pytest.MonkeyPatch, name: str, value: str
    ) -> None:
        for key, good in _ENV.items():
            monkeypatch.setenv(key, good)
        monkeypatch.setenv(name, value)
        with pytest.raises(SettingsError):
            RcsSettings.from_env()


class TestEdges:
    def test_a_full_inbox_answers_503_and_holds_nothing_new(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.rcs_bridge import store as store_mod

        monkeypatch.setattr(store_mod, "MAX_INBOX", 1)
        client = TestClient(build_public_app(rig.bridge))
        assert _post(client, _form(MessageSid="SM1")).status_code == 200
        assert _post(client, _form(MessageSid="SM2")).status_code == 503
        assert [m.message_id for m in asyncio.run(rig.store.pending())] == ["SM1"]

    def test_a_non_ascii_signature_is_refused_not_raised(self, rig: Rig) -> None:
        backend = rig.bridge.backend
        assert backend.verify(WEBHOOK, list(_form().items()), "ség") is False

    @pytest.mark.parametrize("status", [401, 403, 429, 503])
    async def test_a_not_now_from_the_gateway_is_retried(self, rig: Rig, status: int) -> None:
        await rig.bridge.accept(Inbound("SM1", OWNER, "one"))
        rig.gateway.statuses = [200, status, status]  # the announcement, then the message
        await _drain(rig)
        assert rig.gateway.events[-1]["content"]["body"] == "one"

    async def test_a_never_from_the_gateway_drops_that_message_only(self, rig: Rig) -> None:
        await rig.bridge.accept(Inbound("SM1", OWNER, "one"))
        await rig.bridge.accept(Inbound("SM2", OWNER, "two"))
        rig.gateway.statuses = [200, 422]  # the announcement, then SM1; neither recorded
        await _drain(rig)
        assert [e["content"]["body"] for e in rig.gateway.events] == ["two"]
        assert await rig.store.pending() == []

    async def test_a_transport_failure_is_retried(self, rig: Rig) -> None:
        calls = {"n": 0}
        real = rig.gateway

        def flaky(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 2:
                raise httpx.ConnectError("gateway restarting")
            return real(request)

        rig.bridge._gateway = httpx.AsyncClient(transport=httpx.MockTransport(flaky))
        await rig.bridge.accept(Inbound("SM1", OWNER, "one"))
        await _drain(rig)
        assert rig.gateway.events[-1]["content"]["body"] == "one"

    async def test_old_records_are_pruned_and_new_ones_kept(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.rcs_bridge import store as store_mod

        await rig.store.record("old", 0, "SMold")
        await rig.store.put(Inbound("SM1", OWNER, "x"))
        await rig.store.delivered("SM1")
        later = store_mod.time.time() + (store_mod.RETENTION_DAYS + 1) * 86400
        await rig.store.record("new", 0, "SMnew")
        rig.store._db.execute("UPDATE sent SET created = ? WHERE txn_id = 'new'", (later,))
        monkeypatch.setattr(store_mod.time, "time", lambda: later)
        await rig.store.prune()
        assert await rig.store.sent("old") == {}
        assert await rig.store.sent("new") == {0: "SMnew"}
        assert await rig.bridge.accept(Inbound("SM1", OWNER, "x"))

    def test_an_existing_store_is_made_private(self, tmp_path: Path) -> None:
        path = tmp_path / "rcs.db"
        path.touch(mode=0o644)
        path.chmod(0o644)
        RcsStore(path).close()
        assert path.stat().st_mode & 0o777 == 0o600

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("RCS_TWILIO_API", "http://api.twilio.com"),
            ("RCS_TWILIO_MESSAGING_API", "http://messaging.twilio.com"),
            ("RCS_TWILIO_MESSAGING_API", "https://u:p@messaging.twilio.com"),
        ],
    )
    def test_the_twilio_apis_must_be_https(
        self, monkeypatch: pytest.MonkeyPatch, name: str, value: str
    ) -> None:
        for key, good in _ENV.items():
            monkeypatch.setenv(key, good)
        monkeypatch.setenv(name, value)
        with pytest.raises(SettingsError, match=name):
            RcsSettings.from_env()


class TestChunkBoundaries:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            # A line break in the back half wins over a space.
            ("a" * 6 + "\n" + "b" * 5, ["a" * 6, "b" * 5]),
            # Only spaces: the last one in the window.
            ("aaa bbbb cccc", ["aaa bbbb", "cccc"]),
            # A separator only in the front half: cut at the limit.
            ("ab " + "c" * 12, ["ab ccccccc", "ccccc"]),
        ],
    )
    def test_where_a_chunk_ends(self, text: str, expected: list[str]) -> None:
        parts = chunks(text, 10)
        assert parts == expected
        assert all(len(p) <= 10 for p in parts)

    def test_nothing_but_split_whitespace_is_lost(self) -> None:
        text = " ".join(f"word{i}" for i in range(500))
        assert " ".join(chunks(text, 37)).split() == text.split()


class TestRun:
    """``main._run``: any one task ending ends them all, and closes the bridge."""

    @pytest.fixture
    def patched(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        from trentina.rcs_bridge import main as main_mod

        seen: dict[str, Any] = {"cancelled": [], "closed": False, "fail": None}

        async def forever(name: str) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                seen["cancelled"].append(name)
                raise

        async def run(_self: RcsBridge) -> None:
            await forever("deliver")

        async def serve(server: Any) -> None:
            if server.config.port == 8473:  # the webhook listener ends
                if seen["fail"] is not None:
                    raise seen["fail"]
                return
            await forever("api")

        async def aclose(_self: RcsBridge) -> None:
            seen["closed"] = True

        monkeypatch.setattr(main_mod.RcsBridge, "run", run)
        monkeypatch.setattr(main_mod.RcsBridge, "aclose", aclose)
        monkeypatch.setattr(main_mod.uvicorn.Server, "serve", serve)
        seen["run"] = main_mod._run
        seen["settings"] = _settings(tmp_path)
        return seen

    async def test_one_ending_cancels_the_rest_and_closes(self, patched: dict[str, Any]) -> None:
        await patched["run"](patched["settings"])
        assert sorted(patched["cancelled"]) == ["api", "deliver"]
        assert patched["closed"]

    async def test_one_failing_is_raised_after_the_rest_are_cancelled(
        self, patched: dict[str, Any]
    ) -> None:
        patched["fail"] = OSError("port in use")
        with pytest.raises(OSError, match="port in use"):
            await patched["run"](patched["settings"])
        assert sorted(patched["cancelled"]) == ["api", "deliver"]
        assert patched["closed"]


class TestTimedPrune:
    async def test_the_loop_prunes_without_a_wake_and_a_wake_still_delivers(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(bridge_mod, "PRUNE_EVERY", 0.01)
        prunes = {"n": 0}
        real_prune = rig.store.prune

        async def counting() -> None:
            prunes["n"] += 1
            await real_prune()

        monkeypatch.setattr(rig.store, "prune", counting)
        task = asyncio.create_task(rig.bridge.run())
        for _ in range(300):
            await _real_sleep(0.005)
            if prunes["n"] >= 3:
                break
        assert prunes["n"] >= 3, "the loop never pruned on its own"
        await rig.bridge.accept(Inbound("SM1", OWNER, "woken"))
        for _ in range(300):
            await _real_sleep(0.005)
            if not await rig.store.pending():
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert rig.gateway.events[-1]["content"]["body"] == "woken"


def test_a_bad_port_names_its_own_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, good in _ENV.items():
        monkeypatch.setenv(key, good)
    monkeypatch.setenv("RCS_WEBHOOK_PORT", "99999")
    with pytest.raises(SettingsError, match="RCS_WEBHOOK_PORT"):
        RcsSettings.from_env()
