"""The bridge process (#162, spec 015): the untrusted, upstream half.

What is pinned here is what the design leans on: nothing goes upstream in
plaintext into an encrypted room (reactions included, which nio would send in
the clear), nothing the gateway has not taken advances the sync position, and
an adopted mautrix device arrives with its identity and keys intact.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import httpx
import pytest
from nio import (
    JoinError,
    JoinResponse,
    LoginResponse,
    MegolmEvent,
    RoomForgetResponse,
    RoomLeaveResponse,
    RoomSendResponse,
    RoomTypingResponse,
    ShareGroupSessionError,
    SyncError,
)
from nio.crypto.sessions import (
    InboundGroupSession,
    OlmAccount,
    OutboundGroupSession,
    OutboundSession,
)
from nio.exceptions import EncryptionError
from nio.store import SqliteStore
from starlette.testclient import TestClient

from trentina.bridge import client as client_mod
from trentina.bridge import main as main_mod
from trentina.bridge.api import build_app
from trentina.bridge.client import TYPING_TIMEOUT_MS, Bridge, SendError, membership_digest
from trentina.bridge.import_mautrix import SessionImportError, import_mautrix
from trentina.bridge.settings import BridgeSettings, SettingsError

USER = "@agent1-bot:matrix.org"
ROOM = "!ops:matrix.org"
SCOTT = "@Scott_M:matrix.org"


@dataclass
class FakeNio:
    """The slice of nio's AsyncClient the bridge drives."""

    encrypted: bool = True
    encrypt_to: str = "m.room.encrypted"
    wire: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    user_id: str = USER
    device_id: str = "DEV"
    access_token: str = "tok"
    should_upload_keys: bool = False
    should_query_keys: bool = False
    should_claim_keys: bool = False
    key_requests: list[str] = field(default_factory=list)
    decrypted: Any = None
    left: list[str] = field(default_factory=list)
    forgotten: list[str] = field(default_factory=list)
    joined: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rooms = {
            ROOM: SimpleNamespace(
                encrypted=self.encrypted,
                members_synced=True,
                name="Ops",
                topic="",
                member_count=3,
                user_name=lambda _u: "Scott",
                users={USER: None, SCOTT: None},
                invited_users={},
            )
        }
        self.invited_rooms: dict[str, Any] = {}
        self.olm = SimpleNamespace(should_share_group_session=lambda _r: False)

    def encrypt(self, _room: str, event_type: str, content: dict[str, Any]) -> Any:
        return self.encrypt_to, {"ciphertext": f"<{event_type}:{json.dumps(content)}>"}

    async def _send(self, _cls: Any, _method: str, path: str, data: str, _args: Any) -> Any:
        event_type = path.split("/send/", 1)[1].split("/", 1)[0]
        self.wire.append((event_type, json.loads(data)))
        return RoomSendResponse(f"$sent{len(self.wire)}", ROOM)

    async def send_to_device_messages(self) -> None:
        return None

    async def request_room_key(self, event: Any) -> None:
        self.key_requests.append(event.session_id)

    async def join(self, room_id: str) -> Any:
        self.joined.append(room_id)
        self.invited_rooms.pop(room_id, None)
        return JoinResponse(room_id)

    async def room_leave(self, room_id: str) -> Any:
        self.left.append(room_id)
        self.invited_rooms.pop(room_id, None)
        return RoomLeaveResponse()

    async def room_forget(self, room_id: str) -> Any:
        self.forgotten.append(room_id)
        self.rooms.pop(room_id, None)
        return RoomForgetResponse(room_id)

    def decrypt_event(self, _event: Any) -> Any:
        if self.decrypted is None:
            raise EncryptionError("no key")
        return self.decrypted

    async def close(self) -> None:
        return None


def _bridge(
    tmp_path: Path,
    nio: FakeNio,
    handler: Any = None,
    inviters: frozenset[str] = frozenset({SCOTT}),
) -> Bridge:
    gateway = httpx.AsyncClient(
        transport=httpx.MockTransport(handler or (lambda _r: httpx.Response(200, json={})))
    )
    settings = BridgeSettings(
        profile="agent1",
        homeserver="https://matrix.example",
        user_id=USER,
        store_dir=tmp_path,
        pickle_key="pk",
        gateway_url="http://trentina:8019",
        ingress_token="ingress-secret",
        bridge_token="bridge-secret",
        listen_host="127.0.0.1",
        listen_port=8471,
        device_name="test",
        device_id="DEV",
        access_token="tok",
        password="",
        allowed_inviters=inviters,
    )
    fake_client: Any = nio
    bridge = Bridge(settings, client=fake_client, gateway=gateway)
    # Rooms count as vetted and announced unless a test is about that.
    bridge._vetted.update(nio.rooms)
    for room_id, room in nio.rooms.items():
        bridge._announced[room_id] = membership_digest(bridge._members(room))
    return bridge


class TestNothingUpstreamInPlaintext:
    @pytest.mark.parametrize("event_type", ["m.room.message", "m.reaction", "m.sticker"])
    async def test_every_type_is_encrypted(self, tmp_path: Path, event_type: str) -> None:
        nio = FakeNio()
        await _bridge(tmp_path, nio).send(ROOM, event_type, {"body": "secret"}, "t1")
        [(wire_type, body)] = nio.wire
        assert wire_type == "m.room.encrypted"
        assert set(body) == {"ciphertext"}

    async def test_a_send_that_would_leave_in_the_clear_is_refused(self, tmp_path: Path) -> None:
        nio = FakeNio(encrypt_to="m.reaction")
        with pytest.raises(SendError, match="unencrypted"):
            await _bridge(tmp_path, nio).send(ROOM, "m.reaction", {"key": "k"}, "t1")
        assert nio.wire == []

    async def test_an_unencrypted_room_gets_plaintext(self, tmp_path: Path) -> None:
        nio = FakeNio(encrypted=False)
        await _bridge(tmp_path, nio).send(ROOM, "m.room.message", {"body": "hi"}, "t1")
        assert nio.wire == [("m.room.message", {"body": "hi"})]

    async def test_an_unknown_room_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SendError):
            await _bridge(tmp_path, FakeNio()).send("!nope:x", "m.room.message", {}, "t1")


def _text_event(sender: str = "@scott:matrix.org", event_type: str = "m.room.message") -> Any:
    return SimpleNamespace(
        sender=sender,
        source={
            "type": event_type,
            "event_id": "$e1",
            "sender": sender,
            "content": {"msgtype": "m.text", "body": "hello"},
        },
    )


def _sync(*events: Any, next_batch: str = "s2") -> Any:
    return SimpleNamespace(
        next_batch=next_batch,
        rooms=SimpleNamespace(
            invite={}, join={ROOM: SimpleNamespace(timeline=SimpleNamespace(events=list(events)))}
        ),
    )


class TestForwarding:
    async def test_an_event_reaches_the_gateway_with_its_context(self, tmp_path: Path) -> None:
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/bridge/agent1/event"
            assert request.headers["authorization"] == "Bearer ingress-secret"
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"outcome": "delivered"})

        await _bridge(tmp_path, FakeNio(), gateway).handle(ROOM, _text_event())
        [payload] = seen
        assert payload["content"]["body"] == "hello"
        assert payload["sender_displayname"] == "Scott"
        assert payload["room"]["name"] == "Ops"

    async def test_its_own_echo_is_not_forwarded(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        bridge = _bridge(tmp_path, FakeNio(), lambda r: calls.append(r) or httpx.Response(200))
        await bridge.handle(ROOM, _text_event(sender=USER))
        assert calls == []

    async def test_state_events_are_not_forwarded(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        bridge = _bridge(tmp_path, FakeNio(), lambda r: calls.append(r) or httpx.Response(200))
        await bridge.handle(ROOM, _text_event(event_type="m.room.member"))
        assert calls == []

    async def test_the_first_sync_is_history_and_is_not_replayed(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        bridge = _bridge(tmp_path, FakeNio(), lambda r: calls.append(r) or httpx.Response(200))
        assert await bridge.process(_sync(_text_event()), first=True) == "s2"
        assert calls == []

    async def test_position_advances_only_after_the_gateway_took_the_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def no_sleep(_s: float) -> None:
            return None

        monkeypatch.setattr(client_mod.asyncio, "sleep", no_sleep)
        answers = iter([503, 503, 200])
        token_file = tmp_path / "sync_token"

        def gateway(_request: httpx.Request) -> httpx.Response:
            assert not token_file.exists(), "position written before the gateway acked"
            return httpx.Response(next(answers))

        bridge = _bridge(tmp_path, FakeNio(), gateway)
        await bridge.process(_sync(_text_event()), first=False)
        assert token_file.read_text() == "s2"

    async def test_a_permanent_refusal_does_not_stall_the_room(self, tmp_path: Path) -> None:
        calls: list[Any] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(400)

        await _bridge(tmp_path, FakeNio(), gateway).handle(ROOM, _text_event())
        assert len(calls) == 1


def _megolm(event_id: str = "$enc") -> MegolmEvent:
    event = MegolmEvent.from_dict(
        {
            "type": "m.room.encrypted",
            "event_id": event_id,
            "sender": "@scott:matrix.org",
            "origin_server_ts": 1,
            "room_id": ROOM,
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "ciphertext": "AAAA",
                "sender_key": "sk",
                "device_id": "D",
                "session_id": "sess",
            },
        }
    )
    assert isinstance(event, MegolmEvent)
    return event


class TestUndecryptable:
    async def test_it_is_parked_and_its_key_requested(self, tmp_path: Path) -> None:
        nio = FakeNio()
        calls: list[Any] = []
        bridge = _bridge(tmp_path, nio, lambda r: calls.append(r) or httpx.Response(200))
        await bridge.process(_sync(_megolm()), first=False)
        assert nio.key_requests == ["sess"]
        assert calls == []
        assert "$enc" in json.loads((tmp_path / "pending.json").read_text())

    async def test_it_survives_a_restart(self, tmp_path: Path) -> None:
        await _bridge(tmp_path, FakeNio()).process(_sync(_megolm()), first=False)
        assert "$enc" in _bridge(tmp_path, FakeNio())._pending

    async def test_before_the_deadline_it_stays_parked(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        bridge = _bridge(tmp_path, FakeNio(), lambda r: calls.append(r) or httpx.Response(200))
        await bridge.handle(ROOM, _megolm())
        await bridge._retry_pending()
        assert calls == []
        assert "$enc" in bridge._pending

    async def test_when_the_key_arrives_the_message_is_forwarded(self, tmp_path: Path) -> None:
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200)

        nio = FakeNio()
        bridge = _bridge(tmp_path, nio, gateway)
        await bridge.handle(ROOM, _megolm())
        nio.decrypted = _text_event()
        await bridge._retry_pending()
        [forwarded] = seen
        assert forwarded["content"]["body"] == "hello"
        assert bridge._pending == {}

    def test_a_corrupt_record_names_its_file(self, tmp_path: Path) -> None:
        (tmp_path / "pending.json").write_text("[1, 2]")
        with pytest.raises(RuntimeError, match=r"pending\.json"):
            _bridge(tmp_path, FakeNio())

    async def test_after_the_deadline_the_agent_is_told(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200)

        bridge = _bridge(tmp_path, FakeNio(), gateway)
        await bridge.handle(ROOM, _megolm())
        monkeypatch.setattr(client_mod, "UNDECRYPTABLE_AFTER", -1.0)
        await bridge._retry_pending()
        [notice] = seen
        assert notice["event_id"] == "$enc"
        assert "could not be decrypted" in notice["content"]["body"]
        assert bridge._pending == {}

    @pytest.mark.parametrize("how", ["left", "evicted", "gone"])
    async def test_one_parked_in_a_room_no_longer_held_is_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
    ) -> None:
        """#296: parked before the room was refused or left, it is not
        forwarded when its key arrives, nor as a notice after the deadline."""
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200)

        nio = FakeNio()
        bridge = _bridge(tmp_path, nio, gateway)
        await bridge.handle(ROOM, _megolm())
        if how == "left":
            bridge._left.add(ROOM)
        elif how == "evicted":
            bridge._evict.add(ROOM)
        else:
            nio.rooms.pop(ROOM)
        nio.decrypted = _text_event()
        monkeypatch.setattr(client_mod, "UNDECRYPTABLE_AFTER", -1.0)
        await bridge._retry_pending()
        assert seen == []
        assert bridge._pending == {}


class TestImportMautrix:
    """An adopted device keeps its identity and the keys it held."""

    CIPHERTEXT: ClassVar[dict[str, str]] = {}

    def _mautrix_db(self, path: Path) -> tuple[OlmAccount, str]:
        passphrase = f"{USER}:DEV"
        account = OlmAccount()
        outbound = OutboundGroupSession()
        inbound = InboundGroupSession(
            outbound.session_key,
            account.identity_keys["ed25519"],
            account.identity_keys["curve25519"],
            ROOM,
        )
        outbound.mark_as_shared()
        self.CIPHERTEXT["hello"] = outbound.encrypt("hello")
        peer = OlmAccount()
        peer.generate_one_time_keys(1)
        otk = next(iter(peer.one_time_keys["curve25519"].values()))
        olm = OutboundSession(account, peer.identity_keys["curve25519"], otk)
        db = sqlite3.connect(path)
        db.executescript(
            "CREATE TABLE crypto_account (account_id TEXT, device_id TEXT, shared BOOLEAN,"
            " sync_token TEXT, account BLOB);"
            "CREATE TABLE crypto_olm_session (account_id TEXT, session_id TEXT, sender_key TEXT,"
            " session BLOB, created_at TEXT);"
            "CREATE TABLE crypto_megolm_inbound_session (account_id TEXT, session_id TEXT,"
            " sender_key TEXT, signing_key TEXT, room_id TEXT, session BLOB,"
            " forwarding_chains TEXT);"
        )
        db.execute(
            "INSERT INTO crypto_account VALUES (?, 'DEV', 1, '', ?)",
            (USER, account.pickle(passphrase)),
        )
        db.execute(
            "INSERT INTO crypto_olm_session VALUES (?, ?, ?, ?, '2026-06-19 15:54:25.837366')",
            (USER, olm.id, peer.identity_keys["curve25519"], olm.pickle(passphrase)),
        )
        db.execute(
            "INSERT INTO crypto_megolm_inbound_session VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (
                USER,
                inbound.id,
                inbound.sender_key,
                inbound.ed25519,
                ROOM,
                inbound.pickle(passphrase),
            ),
        )
        db.execute(
            "INSERT INTO crypto_megolm_inbound_session VALUES (?, 'w', 'k', NULL, ?, NULL, '')",
            (USER, ROOM),
        )
        db.commit()
        db.close()
        return account, inbound.id

    def test_identity_and_sessions_carry_over(self, tmp_path: Path) -> None:
        source = tmp_path / "crypto.db"
        account, session_id = self._mautrix_db(source)
        store_dir = tmp_path / "store"

        result = import_mautrix(source, store_dir, "pk")

        assert (result.user_id, result.device_id) == (USER, "DEV")
        assert (result.olm_sessions, result.megolm_sessions, result.megolm_skipped) == (1, 1, 1)
        store = SqliteStore(USER, "DEV", str(store_dir), "pk")
        loaded = store.load_account()
        assert loaded.identity_keys == account.identity_keys
        assert loaded.shared, "an adopted identity must not be re-uploaded"
        sessions = store.load_inbound_group_sessions()
        assert sessions.get(ROOM, account.identity_keys["curve25519"], session_id) is not None
        imported = sessions.get(ROOM, account.identity_keys["curve25519"], session_id)
        plaintext, _index = imported.decrypt(self.CIPHERTEXT["hello"])
        assert plaintext == "hello", "the imported session decrypts what the original encrypted"
        olm_sessions = store.load_sessions()
        assert len(list(olm_sessions.values())) == 1, "the Olm session reached the store"

    def test_the_source_is_opened_read_only(self, tmp_path: Path) -> None:
        source = tmp_path / "crypto.db"
        self._mautrix_db(source)
        before = source.read_bytes()
        import_mautrix(source, tmp_path / "store", "pk")
        assert source.read_bytes() == before


class FakeLoginNio(FakeNio):
    """Adds what login and device deletion touch."""

    def __init__(self, login_ok: bool = True) -> None:
        super().__init__()
        self.login_ok = login_ok
        self.restored: list[tuple[str, str, str]] = []

    def restore_login(self, user_id: str, device_id: str, access_token: str) -> None:
        self.restored.append((user_id, device_id, access_token))
        self.user_id, self.device_id, self.access_token = user_id, device_id, access_token

    async def login(self, _password: str, device_name: str = "") -> Any:
        if not self.login_ok:
            return "M_FORBIDDEN"
        self.device_id, self.access_token = "NEWDEV", "newtok"
        return LoginResponse(USER, "NEWDEV", "newtok")


def _settings_with(tmp_path: Path, **changes: Any) -> BridgeSettings:
    base = BridgeSettings(
        profile="agent1",
        homeserver="https://matrix.example",
        user_id=USER,
        store_dir=tmp_path,
        pickle_key="pk",
        gateway_url="http://trentina:8019",
        ingress_token="ingress-secret",
        bridge_token="bridge-secret",
        listen_host="127.0.0.1",
        listen_port=8471,
        device_name="test",
        device_id="",
        access_token="",
        password="",
    )
    return dataclasses.replace(base, **changes)


def _login_bridge(tmp_path: Path, nio: FakeLoginNio, **changes: Any) -> Bridge:
    fake_client: Any = nio
    return Bridge(_settings_with(tmp_path, **changes), client=fake_client)


class TestLogin:
    async def test_a_device_is_adopted_and_remembered(self, tmp_path: Path) -> None:
        nio = FakeLoginNio()
        await _login_bridge(tmp_path, nio, device_id="OLD", access_token="t0").login()
        assert nio.restored == [(USER, "OLD", "t0")]
        saved = json.loads((tmp_path / "session.json").read_text())
        assert saved == {"user_id": USER, "device_id": "OLD", "access_token": "t0"}
        assert (tmp_path / "session.json").stat().st_mode & 0o777 == 0o600

    async def test_a_password_logs_in_a_new_device(self, tmp_path: Path) -> None:
        nio = FakeLoginNio()
        await _login_bridge(tmp_path, nio, password="pw").login()
        assert json.loads((tmp_path / "session.json").read_text())["device_id"] == "NEWDEV"

    async def test_the_saved_session_wins_over_the_environment(self, tmp_path: Path) -> None:
        (tmp_path / "session.json").write_text(
            json.dumps({"user_id": USER, "device_id": "SAVED", "access_token": "ts"})
        )
        nio = FakeLoginNio()
        await _login_bridge(
            tmp_path, nio, device_id="ENV", access_token="te", password="pw"
        ).login()
        assert nio.restored == [(USER, "SAVED", "ts")]

    async def test_a_failed_login_is_fatal(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="login failed"):
            await _login_bridge(tmp_path, FakeLoginNio(login_ok=False), password="pw").login()
        assert not (tmp_path / "session.json").exists()

    async def test_no_way_in_is_fatal(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="no way in"):
            await _login_bridge(tmp_path, FakeLoginNio()).login()


class TestApi:
    def test_send_needs_the_gateways_token(self, tmp_path: Path) -> None:
        nio = FakeNio()
        client = TestClient(build_app(_bridge(tmp_path, nio)))
        body = {"room_id": ROOM, "type": "m.room.message", "content": {}, "txn_id": "t"}
        for token in ("", "ingress-secret", "wrong"):
            resp = client.post("/send", json=body, headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401
        assert nio.wire == []

    def test_send_encrypts_and_answers_the_event_id(self, tmp_path: Path) -> None:
        nio = FakeNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/send",
            json={"room_id": ROOM, "type": "m.reaction", "content": {"k": 1}, "txn_id": "t"},
            headers={"Authorization": "Bearer bridge-secret"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"event_id": "$sent1"}
        assert nio.wire[0][0] == "m.room.encrypted"

    @pytest.mark.parametrize("body", [b"{nope", b'{"room_id": "!r"}'])
    def test_a_malformed_send_is_refused(self, tmp_path: Path, body: bytes) -> None:
        resp = TestClient(build_app(_bridge(tmp_path, FakeNio()))).post(
            "/send", content=body, headers={"Authorization": "Bearer bridge-secret"}
        )
        assert resp.status_code == 400

    def test_a_refused_send_is_a_bad_gateway(self, tmp_path: Path) -> None:
        resp = TestClient(build_app(_bridge(tmp_path, FakeNio()))).post(
            "/send",
            json={"room_id": "!unknown:x", "type": "m.room.message", "content": {}, "txn_id": "t"},
            headers={"Authorization": "Bearer bridge-secret"},
        )
        assert resp.status_code == 502

    def test_health_says_starting_until_the_first_sync(self, tmp_path: Path) -> None:
        nio = FakeNio()
        bridge = _bridge(tmp_path, nio)
        client = TestClient(build_app(bridge))
        assert client.get("/health").status_code == 503
        bridge.ready.set()
        assert client.get("/health").json()["status"] == "ok"


@dataclass
class RedactingNio(FakeNio):
    refuse: bool = False
    redacted: list[tuple[str, str, str | None]] = field(default_factory=list)

    async def room_redact(self, room_id: str, event_id: str, tx_id: str | None = None) -> Any:
        if self.refuse:
            return "M_FORBIDDEN"
        self.redacted.append((room_id, event_id, tx_id))
        return SimpleNamespace(event_id="$redaction")


class TestRedactApi:
    AUTH: ClassVar[dict[str, str]] = {"Authorization": "Bearer bridge-secret"}

    def test_redact_needs_the_gateways_token(self, tmp_path: Path) -> None:
        nio = RedactingNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/redact", json={"room_id": ROOM, "event_id": "$x", "txn_id": "rd1"}
        )
        assert resp.status_code == 401
        assert nio.redacted == []

    def test_redact_reaches_the_homeserver(self, tmp_path: Path) -> None:
        nio = RedactingNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/redact", json={"room_id": ROOM, "event_id": "$x", "txn_id": "rd1"}, headers=self.AUTH
        )
        assert resp.status_code == 200
        assert nio.redacted == [(ROOM, "$x", "rd1")], "the gateway's txn id reaches nio"

    def test_a_malformed_redact_is_refused(self, tmp_path: Path) -> None:
        resp = TestClient(build_app(_bridge(tmp_path, RedactingNio()))).post(
            "/redact", content=b"{nope", headers=self.AUTH
        )
        assert resp.status_code == 400

    def test_a_refused_redact_is_a_bad_gateway(self, tmp_path: Path) -> None:
        resp = TestClient(build_app(_bridge(tmp_path, RedactingNio(refuse=True)))).post(
            "/redact", json={"room_id": ROOM, "event_id": "$x", "txn_id": "rd1"}, headers=self.AUTH
        )
        assert resp.status_code == 502


@dataclass
class TypingNio(FakeNio):
    fail: Exception | None = None
    typed: list[tuple[str, bool, int]] = field(default_factory=list)

    async def room_typing(self, room_id: str, typing_state: bool = True, timeout: int = 0) -> Any:
        if self.fail is not None:
            raise self.fail
        self.typed.append((room_id, typing_state, timeout))
        return RoomTypingResponse(room_id)


class TestTypingApi:
    """The agent's typing, shown upstream (#1533)."""

    AUTH: ClassVar[dict[str, str]] = {"Authorization": "Bearer bridge-secret"}

    def test_typing_needs_the_gateways_token(self, tmp_path: Path) -> None:
        nio = TypingNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/typing", json={"room_id": ROOM, "typing": True}
        )
        assert resp.status_code == 401
        assert nio.typed == []

    @pytest.mark.parametrize("typing", [True, False])
    def test_typing_reaches_the_homeserver(self, tmp_path: Path, typing: bool) -> None:
        nio = TypingNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/typing", json={"room_id": ROOM, "typing": typing}, headers=self.AUTH
        )
        assert resp.json() == {"shown": True}
        assert nio.typed == [(ROOM, typing, TYPING_TIMEOUT_MS)]

    def test_a_room_not_held_is_not_typed_into(self, tmp_path: Path) -> None:
        nio = TypingNio()
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/typing", json={"room_id": "!gone:matrix.org", "typing": True}, headers=self.AUTH
        )
        assert (resp.status_code, resp.json()) == (200, {"shown": False})
        assert nio.typed == []

    def test_a_homeserver_failure_is_still_answered(self, tmp_path: Path) -> None:
        nio = TypingNio(fail=OSError("down"))
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/typing", json={"room_id": ROOM, "typing": True}, headers=self.AUTH
        )
        assert (resp.status_code, resp.json()) == (200, {"shown": False})

    def test_a_malformed_typing_is_refused(self, tmp_path: Path) -> None:
        resp = TestClient(build_app(_bridge(tmp_path, TypingNio()))).post(
            "/typing", json={"room_id": ROOM, "typing": "yes"}, headers=self.AUTH
        )
        assert resp.status_code == 400


class TestSettings:
    REQUIRED: ClassVar[dict[str, str]] = {
        "BRIDGE_PROFILE": "agent1",
        "BRIDGE_USER_ID": USER,
        "BRIDGE_PICKLE_KEY": "pk",
        "BRIDGE_GATEWAY_URL": "http://trentina:8019/",
        "BRIDGE_INGRESS_TOKEN": "i",
        "BRIDGE_TOKEN": "b",
    }

    def _env(self, monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
        for name in (*self.REQUIRED, "BRIDGE_PASSWORD", "BRIDGE_LISTEN_PORT", "BRIDGE_TOKEN_FILE"):
            monkeypatch.delenv(name, raising=False)
        for name, value in (self.REQUIRED | extra).items():
            monkeypatch.setenv(name, value)

    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._env(monkeypatch)
        settings = BridgeSettings.from_env()
        assert settings.homeserver == "https://matrix-client.matrix.org"
        assert settings.gateway_url == "http://trentina:8019"
        assert (settings.listen_host, settings.listen_port) == ("127.0.0.1", 8471)
        assert settings.store_dir == Path("/data")
        assert (settings.password, settings.access_token) == ("", "")

    @pytest.mark.parametrize("missing", sorted(REQUIRED))
    def test_every_required_setting_is_required(
        self, monkeypatch: pytest.MonkeyPatch, missing: str
    ) -> None:
        self._env(monkeypatch)
        monkeypatch.delenv(missing)
        with pytest.raises(SettingsError, match=missing):
            BridgeSettings.from_env()

    def test_a_secret_can_come_from_a_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("from-file\n")
        secret.chmod(0o600)
        self._env(monkeypatch, BRIDGE_TOKEN="from-env", BRIDGE_TOKEN_FILE=str(secret))
        assert BridgeSettings.from_env().bridge_token == "from-file"

    def test_a_bad_port_is_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._env(monkeypatch, BRIDGE_LISTEN_PORT="http")
        with pytest.raises(SettingsError, match="http"):
            BridgeSettings.from_env()


@dataclass
class SyncingNio(FakeNio):
    """Answers sync with a scripted sequence, then stops the loop."""

    answers: list[Any] = field(default_factory=list)
    since: list[str | None] = field(default_factory=list)

    full_state: list[bool] = field(default_factory=list)

    async def sync(self, **kwargs: Any) -> Any:
        self.since.append(kwargs.get("since"))
        self.full_state.append(bool(kwargs.get("full_state")))
        if not self.answers:
            raise asyncio.CancelledError
        return self.answers.pop(0)


class TestRun:
    async def test_it_resumes_from_the_saved_position_and_retries_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def record_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr(client_mod.asyncio, "sleep", record_sleep)
        monkeypatch.setattr(client_mod, "SyncResponse", SimpleNamespace)
        (tmp_path / "sync_token").write_text("s1")
        nio = SyncingNio(
            answers=[
                SyncError("down"),
                SyncError("down"),
                _sync(next_batch="s2"),
                _sync(next_batch="s3"),
            ]
        )
        with pytest.raises(asyncio.CancelledError):
            await _bridge(tmp_path, nio).run()
        assert nio.since == ["s1", "s1", "s1", "s2", "s3"]
        assert nio.full_state == [True, True, True, False, False], (
            "a resumed start asks for full state until its first good sync"
        )
        assert sleeps == [1.0, 2.0]
        assert (tmp_path / "sync_token").read_text() == "s3"


class TestImportFailures:
    def _empty_store(self, path: Path) -> None:
        db = sqlite3.connect(path)
        db.executescript(
            "CREATE TABLE crypto_account (account_id TEXT, device_id TEXT, shared BOOLEAN,"
            " sync_token TEXT, account BLOB);"
        )
        db.commit()
        db.close()

    def test_a_store_with_no_account_is_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "crypto.db"
        self._empty_store(source)
        with pytest.raises(ValueError, match="no account"):
            import_mautrix(source, tmp_path / "store", "pk")
        assert not (tmp_path / "store").exists()

    def test_an_account_that_will_not_open_names_itself(self, tmp_path: Path) -> None:
        source = tmp_path / "crypto.db"
        self._empty_store(source)
        db = sqlite3.connect(source)
        db.execute("INSERT INTO crypto_account VALUES (?, 'DEV', 1, '', ?)", (USER, b"garbage"))
        db.commit()
        db.close()
        with pytest.raises(SessionImportError, match="account session DEV"):
            import_mautrix(source, tmp_path / "store", "pk")


class TestForwardRetries:
    @pytest.mark.parametrize("status", [401, 403, 429])
    async def test_these_are_retried_not_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
    ) -> None:
        """An auth mismatch or a rate limit is the gateway's state, not the
        event's: dropping it would lose a message to a config typo."""

        async def no_sleep(_s: float) -> None:
            return None

        monkeypatch.setattr(client_mod.asyncio, "sleep", no_sleep)
        answers = iter([status, status, 200])
        calls: list[int] = []

        def gateway(_request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(next(answers))

        bridge = _bridge(tmp_path, FakeNio(), gateway)
        await bridge.process(_sync(_text_event()), first=False)
        assert len(calls) == 3
        assert (tmp_path / "sync_token").read_text() == "s2"


class TestApiValidation:
    AUTH: ClassVar[dict[str, str]] = {"Authorization": "Bearer bridge-secret"}

    def test_an_unexpected_field_is_refused(self, tmp_path: Path) -> None:
        nio = FakeNio()
        body = {"room_id": ROOM, "type": "m.room.message", "content": {}, "txn_id": "t", "x": 1}
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/send", json=body, headers=self.AUTH
        )
        assert resp.status_code == 400
        assert nio.wire == []

    def test_an_oversized_body_is_refused(self, tmp_path: Path) -> None:
        nio = FakeNio()
        body = {"room_id": ROOM, "type": "t", "content": {"pad": "x" * 1_100_000}, "txn_id": "t"}
        resp = TestClient(build_app(_bridge(tmp_path, nio))).post(
            "/send", json=body, headers=self.AUTH
        )
        assert resp.status_code == 413
        assert nio.wire == []


@dataclass
class PreparingNio(FakeNio):
    """A room that needs its members, keys and a group session before sending."""

    fail_share: bool = False
    steps: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.rooms[ROOM].members_synced = False
        self.should_query_keys = True
        self.olm = SimpleNamespace(should_share_group_session=lambda _r: True)

    async def joined_members(self, _room: str) -> None:
        self.steps.append("members")

    async def keys_query(self) -> None:
        self.steps.append("query")
        self.should_query_keys = False

    async def share_group_session(self, _room: str, **_kw: Any) -> None:
        self.steps.append("share")
        if self.fail_share:
            raise SendError("share failed")

    def encrypt(self, room: str, event_type: str, content: dict[str, Any]) -> Any:
        self.steps.append("encrypt")
        return super().encrypt(room, event_type, content)


class TestEncryptionPreparation:
    async def test_members_keys_and_session_come_before_the_ciphertext(
        self, tmp_path: Path
    ) -> None:
        nio = PreparingNio()
        await _bridge(tmp_path, nio).send(ROOM, "m.room.message", {"body": "x"}, "t1")
        assert nio.steps == ["members", "query", "share", "encrypt"]
        assert nio.wire[0][0] == "m.room.encrypted"

    async def test_a_failed_preparation_sends_nothing(self, tmp_path: Path) -> None:
        nio = PreparingNio(fail_share=True)
        with pytest.raises(SendError):
            await _bridge(tmp_path, nio).send(ROOM, "m.room.message", {"body": "x"}, "t1")
        assert nio.wire == []

    async def test_no_crypto_loaded_sends_nothing(self, tmp_path: Path) -> None:
        nio = PreparingNio()
        nio.olm = None
        with pytest.raises(SendError, match="not loaded"):
            await _bridge(tmp_path, nio).send(ROOM, "m.room.message", {"body": "x"}, "t1")
        assert nio.wire == []


class TestForgedRedaction:
    """A decrypted payload's type is whatever the sender wrote."""

    def _forged(self) -> Any:
        return SimpleNamespace(
            sender="@mallory:matrix.org",
            decrypted=True,
            source={
                "type": "m.room.redaction",
                "event_id": "$f",
                "sender": "@mallory:matrix.org",
                "redacts": "$victim",
                "content": {"redacts": "$victim"},
            },
        )

    async def test_an_encrypted_redaction_is_not_forwarded(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        bridge = _bridge(tmp_path, FakeNio(), lambda r: calls.append(r) or httpx.Response(200))
        await bridge.handle(ROOM, self._forged())
        assert calls == []

    async def test_nor_when_its_key_arrives_late(self, tmp_path: Path) -> None:
        calls: list[Any] = []
        nio = FakeNio()
        bridge = _bridge(tmp_path, nio, lambda r: calls.append(r) or httpx.Response(200))
        await bridge.handle(ROOM, _megolm())
        nio.decrypted = self._forged()
        await bridge._retry_pending()
        assert calls == []
        assert bridge._pending == {}

    async def test_a_real_redaction_still_is(self, tmp_path: Path) -> None:
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200)

        real = self._forged()
        real.decrypted = False
        await _bridge(tmp_path, FakeNio(), gateway).handle(ROOM, real)
        assert [e["type"] for e in seen] == ["m.room.redaction"]


class TestSettingsUrls:
    @pytest.mark.parametrize(
        ("name", "value"),
        [("BRIDGE_HOMESERVER", "ftp://matrix.org"), ("BRIDGE_GATEWAY_URL", "trentina:8019")],
    )
    def test_a_url_must_be_http(
        self, monkeypatch: pytest.MonkeyPatch, name: str, value: str
    ) -> None:
        TestSettings()._env(monkeypatch, **{name: value})
        with pytest.raises(SettingsError, match=name):
            BridgeSettings.from_env()


class TestImportRows:
    def test_skipped_megolm_rows_are_counted_and_absent(self, tmp_path: Path) -> None:
        source = tmp_path / "crypto.db"
        TestImportMautrix()._mautrix_db(source)
        result = import_mautrix(source, tmp_path / "store", "pk")
        store = SqliteStore(USER, "DEV", str(tmp_path / "store"), "pk")
        sessions = store.load_inbound_group_sessions()
        assert result.megolm_skipped == 1
        assert sessions.get(ROOM, "k", "w") is None

    @pytest.mark.parametrize(
        ("corrupt", "kind"),
        [
            ("UPDATE crypto_olm_session SET session = ?", "Olm"),
            (
                "UPDATE crypto_megolm_inbound_session SET session = ? WHERE session IS NOT NULL",
                "Megolm",
            ),
        ],
    )
    def test_a_session_that_will_not_open_names_itself(
        self, tmp_path: Path, corrupt: str, kind: str
    ) -> None:
        source = tmp_path / "crypto.db"
        TestImportMautrix()._mautrix_db(source)
        db = sqlite3.connect(source)
        db.execute(corrupt, (b"garbage",))
        db.commit()
        db.close()
        with pytest.raises(SessionImportError, match=f"{kind} session"):
            import_mautrix(source, tmp_path / "store", "pk")


class TestPendingCap:
    async def test_past_the_cap_the_agent_is_told_at_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(client_mod, "MAX_PENDING", 1)
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200)

        bridge = _bridge(tmp_path, FakeNio(), gateway)
        first = _megolm()
        second = _megolm("$enc2")
        await bridge.handle(ROOM, first)
        await bridge.handle(ROOM, second)
        assert list(bridge._pending) == ["$enc"]
        assert [e["event_id"] for e in seen] == ["$enc2"]
        assert "could not be decrypted" in seen[0]["content"]["body"]


class TestLifecycle:
    """Either task ending ends the bridge, and the clients are always closed."""

    class Stub:
        def __init__(self, sync: Any) -> None:
            self._sync = sync
            self.closed = False
            self.settings = SimpleNamespace(listen_host="127.0.0.1", listen_port=0)

        async def login(self) -> None:
            return None

        async def run(self) -> None:
            await self._sync()

        async def aclose(self) -> None:
            self.closed = True

    async def _run(self, monkeypatch: pytest.MonkeyPatch, sync: Any, serve: Any) -> Any:
        stub = self.Stub(sync)
        monkeypatch.setattr(main_mod, "Bridge", lambda _settings: stub)
        monkeypatch.setattr(main_mod, "build_app", lambda _bridge: None)
        monkeypatch.setattr(
            main_mod.uvicorn, "Server", lambda _config: SimpleNamespace(serve=serve)
        )
        monkeypatch.setattr(main_mod.uvicorn, "Config", lambda *_a, **_k: None)
        return stub, main_mod._run(stub.settings)

    async def test_a_failed_sync_stops_the_api_and_closes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        served = asyncio.Event()

        async def sync() -> None:
            raise RuntimeError("homeserver gone")

        async def serve() -> None:
            try:
                await asyncio.sleep(3600)
            finally:
                served.set()

        stub, run = await self._run(monkeypatch, sync, serve)
        with pytest.raises(RuntimeError, match="homeserver gone"):
            await run
        assert served.is_set(), "the API task was cancelled"
        assert stub.closed

    async def test_an_api_exit_stops_the_sync_and_closes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cancelled = asyncio.Event()

        async def sync() -> None:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def serve() -> None:
            return None

        stub, run = await self._run(monkeypatch, sync, serve)
        await run
        assert cancelled.is_set()
        assert stub.closed


class TestRoomAnnouncements:
    async def test_every_joined_room_is_announced_once(self, tmp_path: Path) -> None:
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"outcome": "mapped"})

        bridge = _bridge(tmp_path, FakeNio(), gateway)
        bridge._announced.clear()
        await bridge.process(_sync(), first=True)
        await bridge.process(_sync(next_batch="s3"), first=False)
        assert [(e["type"], e["room_id"]) for e in seen] == [
            ("org.crunchtools.trentina.room", ROOM)
        ]
        assert seen[0]["room"]["name"] == "Ops"


class TestJoinRetry:
    async def test_a_failed_join_is_tried_again_next_sync(self, tmp_path: Path) -> None:
        attempts: list[str] = []

        @dataclass
        class JoiningNio(FakeNio):
            invited_rooms: dict[str, Any] = field(default_factory=dict)

            async def join(self, room_id: str) -> Any:
                attempts.append(room_id)
                if len(attempts) == 1:
                    return JoinError("M_LIMIT_EXCEEDED")
                self.invited_rooms.pop(room_id, None)
                return JoinResponse(room_id)

        nio = JoiningNio()
        nio.invited_rooms["!new:matrix.org"] = SimpleNamespace(inviter=SCOTT)
        bridge = _bridge(tmp_path, nio)
        await bridge.process(_sync(), first=False)
        await bridge.process(_sync(next_batch="s3"), first=False)
        assert attempts == ["!new:matrix.org", "!new:matrix.org"]


class TestSettingsPort:
    def test_a_bad_port_is_a_settings_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        TestSettings()._env(monkeypatch, BRIDGE_LISTEN_PORT="99999")
        with pytest.raises(SettingsError, match="BRIDGE_LISTEN_PORT"):
            BridgeSettings.from_env()


class TestLoginFailureCloses:
    async def test_clients_close_when_login_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed: list[bool] = []

        class Failing:
            settings = SimpleNamespace(listen_host="127.0.0.1", listen_port=0)

            async def login(self) -> None:
                raise RuntimeError("no way in")

            async def aclose(self) -> None:
                closed.append(True)

        monkeypatch.setattr(main_mod, "Bridge", lambda _settings: Failing())
        with pytest.raises(RuntimeError, match="no way in"):
            await main_mod._run(Failing.settings)
        assert closed == [True]


class TestConnectionErrors:
    async def test_a_connection_failure_is_retried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def no_sleep(_s: float) -> None:
            return None

        monkeypatch.setattr(client_mod.asyncio, "sleep", no_sleep)
        attempts: list[int] = []
        token_file = tmp_path / "sync_token"

        def gateway(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            assert not token_file.exists()
            if len(attempts) == 1:
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200)

        await _bridge(tmp_path, FakeNio(), gateway).process(_sync(_text_event()), first=False)
        assert len(attempts) == 2
        assert token_file.read_text() == "s2"


class TestKeyShareFailure:
    async def test_a_refused_key_share_sends_nothing(self, tmp_path: Path) -> None:
        @dataclass
        class Refusing(PreparingNio):
            async def share_group_session(self, _room: str, **_kw: Any) -> Any:
                return ShareGroupSessionError("M_FORBIDDEN")

        nio = Refusing()
        with pytest.raises(SendError, match="room key"):
            await _bridge(tmp_path, nio).send(ROOM, "m.room.message", {"body": "x"}, "t1")
        assert nio.wire == []


class TestPrivateWrites:
    async def test_the_session_file_is_owner_only_and_leaves_no_temp(self, tmp_path: Path) -> None:
        bridge = _login_bridge(tmp_path, FakeLoginNio(), device_id="D", access_token="t")
        await bridge.login()
        assert (tmp_path / "session.json").stat().st_mode & 0o777 == 0o600
        assert not (tmp_path / "session.tmp").exists()


class TestGatewayUrl:
    @pytest.mark.parametrize(
        "url",
        ["https://gateway.example.com", "http://8.8.8.8:8019", "http://u:p@trentina:8019"],
    )
    def test_the_gateway_must_be_private(self, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
        TestSettings()._env(monkeypatch, BRIDGE_GATEWAY_URL=url)
        with pytest.raises(SettingsError, match="BRIDGE_GATEWAY_URL"):
            BridgeSettings.from_env()


class TestRoomInfo:
    def test_a_two_member_room_names_its_peer(self, tmp_path: Path) -> None:
        nio = FakeNio()
        room = nio.rooms[ROOM]
        room.member_count = 2
        room.users = {USER: None, "@scott:matrix.org": None}
        info = _bridge(tmp_path, nio)._room_info(room)
        assert info["is_direct"] is True
        assert info["peer"] == "@scott:matrix.org"
        assert info["peer_displayname"] == "Scott"

    def test_a_group_names_no_peer(self, tmp_path: Path) -> None:
        nio = FakeNio()
        info = _bridge(tmp_path, nio)._room_info(nio.rooms[ROOM])
        assert (info["is_direct"], info["peer"]) == (False, "")
