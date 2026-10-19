"""Attachments over RCS (#493), bridge side.

What is pinned: an attachment from the owner is fetched from this account's
Twilio media only, with the credentials never following Twilio's redirect to
its CDN, and handed to the gateway as the ``media`` item #491 judges; one the
agent sends is held under an unguessable ID, served publicly only while it
is fresh, and goes to Twilio as a ``MediaUrl``; anything else is a 422.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import sqlite3
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from starlette.testclient import TestClient

from trentina.httpbody import TooLargeError
from trentina.rcs_bridge import store as store_mod
from trentina.rcs_bridge import twilio as twilio_mod
from trentina.rcs_bridge.api import build_private_app, build_public_app
from trentina.rcs_bridge.backend import Inbound
from trentina.rcs_bridge.bridge import RefusedError, UnavailableError
from trentina.rcs_bridge.settings import RcsSettings
from trentina.rcs_bridge.store import RcsStore
from trentina.rcs_bridge.twilio import TwilioBackend, guarded_get

from .image_files import picture
from .test_rcs_bridge import _ENV, MEDIA_PREFIX, OWNER, Rig, _drain, _form, _post

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

PNG = picture("x")
PNG_B64 = base64.b64encode(PNG).decode("ascii")
MEDIA_URL = "https://rcs.example.com/agent1/media"
ROOM = "!agent1-owner:rcs.invalid"
AUTH = {"authorization": "Bearer bridge-secret"}


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    rig = Rig(tmp_path)
    rig.bridge.settings = dataclasses.replace(rig.settings, media_url=MEDIA_URL)
    return rig


def _upload(rig: Rig, **overrides: Any) -> Any:
    body = {"room_id": ROOM, "content_type": "image/png", "base64": PNG_B64} | overrides
    return TestClient(build_private_app(rig.bridge)).post("/upload", json=body, headers=AUTH)


def _held_id(resp: Any) -> str:
    url = resp.json()["url"]
    assert url.startswith("mxc://rcs.invalid/")
    return str(url.rpartition("/")[2])


class TestInbound:
    def test_the_webhook_holds_each_attachments_url_and_type(self, rig: Rig) -> None:
        form = _form(
            Body="",
            NumMedia="2",
            MediaUrl0=MEDIA_PREFIX + "ME1",
            MediaContentType0="image/png",
            MediaUrl1=MEDIA_PREFIX + "ME2",
            MediaContentType1="application/pdf",
        )
        assert _post(TestClient(build_public_app(rig.bridge)), form).status_code == 200
        [held] = asyncio.run(rig.store.pending())
        assert held.media == (
            (MEDIA_PREFIX + "ME1", "image/png"),
            (MEDIA_PREFIX + "ME2", "application/pdf"),
        )

    async def test_a_photo_reaches_the_gateway_with_its_bytes_and_caption(self, rig: Rig) -> None:
        rig.twilio.media["ME1"] = ("image/png", PNG)
        await rig.bridge.accept(
            Inbound("SM1", OWNER, "look", ((MEDIA_PREFIX + "ME1", "image/png"),))
        )
        await _drain(rig)
        event = rig.gateway.events[-1]
        assert event["event_id"] == "$rcs-SM1"
        assert event["content"] == {
            "msgtype": "m.image",
            "body": "look",
            "filename": "attachment-1.png",
            "url": "mxc://rcs.invalid/ME1",
            "info": {"mimetype": "image/png"},
        }
        assert event["media"] == {"status": "ok", "content_type": "image/png", "base64": PNG_B64}

    async def test_each_attachment_is_its_own_event_and_only_the_first_has_the_text(
        self, rig: Rig
    ) -> None:
        rig.twilio.media |= {"ME1": ("image/png", PNG), "ME2": ("application/pdf", b"%PDF-1.4")}
        media = ((MEDIA_PREFIX + "ME1", "image/png"), (MEDIA_PREFIX + "ME2", "application/pdf"))
        await rig.bridge.accept(Inbound("SM1", OWNER, "two things", media))
        await _drain(rig)
        first, second = rig.gateway.events[-2:]
        assert (first["event_id"], first["content"]["body"]) == ("$rcs-SM1", "two things")
        assert second["event_id"] == "$rcs-SM1-1"
        assert second["content"]["msgtype"] == "m.file"
        assert second["content"]["body"] == second["content"]["filename"] == "attachment-2.pdf"

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.test/2010-04-01/Accounts/x/Messages/MM1/Media/ME1",
            f"https://api.twilio.test/2010-04-01/Accounts/AC{'9' * 32}/Messages/MM1/Media/ME1",
            MEDIA_PREFIX + "ME1/../../x",
            "",
        ],
    )
    async def test_media_not_on_this_account_is_never_fetched(self, rig: Rig, url: str) -> None:
        rig.twilio.media["ME1"] = ("image/png", PNG)
        await rig.bridge.accept(Inbound("SM1", OWNER, "", ((url, "image/png"),)))
        await _drain(rig)
        assert rig.gateway.events[-1]["media"] == {"status": "unavailable"}

    async def test_a_missing_or_oversize_attachment_is_reported_not_sent(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rig.twilio.media["ME2"] = ("image/png", PNG)
        monkeypatch.setattr(twilio_mod, "MAX_MEDIA_BYTES", 16)
        media = ((MEDIA_PREFIX + "ME1", "image/png"), (MEDIA_PREFIX + "ME2", "image/png"))
        await rig.bridge.accept(Inbound("SM1", OWNER, "", media))
        await _drain(rig)
        assert [e["media"] for e in rig.gateway.events[-2:]] == [
            {"status": "unavailable"},
            {"status": "too_large"},
        ]

    @pytest.mark.parametrize(
        "cdn_base",
        ["https://127.0.0.1", "https://169.254.169.254", "http://cdn.twilio.test"],
    )
    async def test_a_redirect_inward_or_to_http_is_never_followed(
        self, rig: Rig, cdn_base: str
    ) -> None:
        """The real egress guard on the CDN hop, not the rig's stand-in."""
        rig.twilio.media["ME1"] = ("image/png", PNG)
        rig.twilio.cdn_base = cdn_base
        backend = rig.bridge.backend
        assert isinstance(backend, TwilioBackend)
        backend._cdn = guarded_get
        item = await backend.fetch_media(MEDIA_PREFIX + "ME1")
        assert item == {"status": "unavailable"}

    async def test_a_hostile_content_type_is_not_carried(self, rig: Rig) -> None:
        rig.twilio.media["ME1"] = ("image/png", PNG)
        await rig.bridge.accept(
            Inbound("SM1", OWNER, "", ((MEDIA_PREFIX + "ME1", "image/png\r\nX-Evil: 1"),))
        )
        await _drain(rig)
        content = rig.gateway.events[-1]["content"]
        assert content["msgtype"] == "m.file"
        assert "info" not in content


class TestHosting:
    def test_an_upload_is_served_publicly_by_its_id(self, rig: Rig) -> None:
        resp = _upload(rig)
        assert resp.status_code == 200
        served = TestClient(build_public_app(rig.bridge)).get(f"/media/{_held_id(resp)}")
        assert served.status_code == 200
        assert served.content == PNG
        assert served.headers["content-type"] == "image/png"
        assert served.headers["cache-control"] == "no-store"
        assert served.headers["x-content-type-options"] == "nosniff"

    def test_an_unknown_malformed_or_expired_id_is_not_found(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        public = TestClient(build_public_app(rig.bridge))
        media_id = _held_id(_upload(rig))
        assert public.get(f"/media/{'A' * 43}").status_code == 404
        assert public.get("/media/short").status_code == 404
        monkeypatch.setattr(store_mod, "MEDIA_TTL", -1.0)
        assert public.get(f"/media/{media_id}").status_code == 404

    def test_the_public_listener_takes_no_upload(self, rig: Rig) -> None:
        public = TestClient(build_public_app(rig.bridge))
        assert public.post("/upload", json={}).status_code == 404

    def test_upload_needs_the_token(self, rig: Rig) -> None:
        client = TestClient(build_private_app(rig.bridge))
        body = {"room_id": ROOM, "content_type": "image/png", "base64": PNG_B64}
        assert client.post("/upload", json=body).status_code == 401

    def test_held_media_is_capped(self, rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(store_mod, "MAX_HELD_MEDIA", 1)
        assert _upload(rig).status_code == 200
        assert _upload(rig).status_code == 502

    @pytest.mark.parametrize(
        ("overrides", "status"),
        [
            ({"room_id": "!other:rcs.invalid"}, 422),
            ({"base64": "not base64!"}, 400),
            ({"content_type": ""}, 400),
        ],
    )
    def test_a_bad_upload_is_refused(
        self, rig: Rig, overrides: dict[str, str], status: int
    ) -> None:
        assert _upload(rig, **overrides).status_code == status

    def test_no_public_media_url_means_never(self, rig: Rig) -> None:
        rig.bridge.settings = dataclasses.replace(rig.bridge.settings, media_url=None)
        assert _upload(rig).status_code == 422

    @pytest.mark.parametrize(
        "content_type",
        ["text/html", "image/svg+xml", "application/xhtml+xml", "text/html\r\nSet-Cookie: x"],
    )
    def test_active_content_is_served_as_octets_and_sandboxed(
        self, rig: Rig, content_type: str
    ) -> None:
        media_id = _held_id(_upload(rig, content_type=content_type))
        served = TestClient(build_public_app(rig.bridge)).get(f"/media/{media_id}")
        assert served.headers["content-type"] == "application/octet-stream"
        assert served.headers["content-security-policy"] == "default-src 'none'; sandbox"

    def test_a_parameter_on_an_allowed_type_is_dropped(self, rig: Rig) -> None:
        media_id = _held_id(_upload(rig, content_type="text/plain; charset=utf-8"))
        served = TestClient(build_public_app(rig.bridge)).get(f"/media/{media_id}")
        assert served.headers["content-type"].startswith("text/plain")


def _image(url: str, **extra: Any) -> dict[str, Any]:
    return {"msgtype": "m.image", "body": "cat.png", "url": url} | extra


class TestSend:
    async def test_an_image_goes_as_a_media_url_and_only_once(self, rig: Rig) -> None:
        media_id = _held_id(_upload(rig))
        content = _image(f"mxc://rcs.invalid/{media_id}")
        event_id = await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        assert event_id.startswith("$rcs-SM")
        [sent] = rig.twilio.sent
        assert sent["MediaUrl"] == f"{MEDIA_URL}/{media_id}"
        assert sent["To"] == f"rcs:{OWNER}"
        assert "Body" not in sent, "a file name alone is not a caption"
        await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        assert len(rig.twilio.sent) == 1

    async def test_a_caption_rides_with_the_media_and_a_long_one_follows_as_text(
        self, rig: Rig
    ) -> None:
        media_id = _held_id(_upload(rig))
        caption = "word " * 400
        content = _image(f"mxc://rcs.invalid/{media_id}", body=caption, filename="cat.png")
        await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        first, *rest = rig.twilio.sent
        assert first["MediaUrl"].endswith(media_id)
        assert first["Body"].startswith("word")
        assert rest
        assert all("MediaUrl" not in r for r in rest)

    async def test_a_failed_caption_chunk_is_retried_without_the_media(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        media_id = _held_id(_upload(rig))
        content = _image(f"mxc://rcs.invalid/{media_id}", body="word " * 400, filename="c.png")
        rig.twilio.fail_after = 1
        rig.twilio.fail = [(500, {})]
        with pytest.raises(UnavailableError):
            await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        assert len(rig.twilio.sent) == 1
        # The retry comes after the media expired: what is left still goes.
        monkeypatch.setattr(store_mod, "MEDIA_TTL", -1.0)
        await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        first, *rest = rig.twilio.sent
        assert "MediaUrl" in first
        assert rest
        assert all("MediaUrl" not in r for r in rest)

    async def test_an_edited_image_sends_its_new_media(self, rig: Rig) -> None:
        media_id = _held_id(_upload(rig))
        content = {
            "msgtype": "m.image",
            "body": "* cat.png",
            "m.new_content": _image(f"mxc://rcs.invalid/{media_id}"),
            "m.relates_to": {"rel_type": "m.replace", "event_id": "$x"},
        }
        await rig.bridge.send(ROOM, "m.room.message", content, "out1")
        assert rig.twilio.sent[0]["MediaUrl"].endswith(media_id)

    @pytest.mark.parametrize(
        "url",
        [f"mxc://rcs.invalid/{'B' * 43}", f"mxc://matrix.org/{'B' * 43}", "https://x/y", None],
    )
    async def test_media_this_bridge_does_not_hold_is_refused(
        self, rig: Rig, url: str | None
    ) -> None:
        with pytest.raises(RefusedError):
            await rig.bridge.send(ROOM, "m.room.message", _image(str(url)), "out1")
        assert rig.twilio.sent == []

    def test_the_api_answers_a_refused_image_422(self, rig: Rig) -> None:
        client = TestClient(build_private_app(rig.bridge))
        body = {
            "room_id": ROOM,
            "type": "m.room.message",
            "content": _image("mxc://rcs.invalid/gone"),
            "txn_id": "t1",
        }
        assert client.post("/send", json=body, headers=AUTH).status_code == 422


def _guard_answering(monkeypatch: pytest.MonkeyPatch, resp: httpx.Response) -> list[Any]:
    """``egress.open_guarded`` replaced by one answering ``resp``; the calls."""
    calls: list[Any] = []

    @contextlib.asynccontextmanager
    async def fake(method: str, url: str, **kwargs: Any) -> AsyncIterator[httpx.Response]:
        calls.append((method, url, kwargs))
        yield resp

    monkeypatch.setattr(twilio_mod.egress, "open_guarded", fake)
    return calls


class TestGuardedGet:
    """The CDN hop's own reading, with the guard's network half stood in."""

    async def test_it_reads_the_body_with_no_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resp = httpx.Response(200, content=PNG, headers={"content-type": "image/png"})
        calls = _guard_answering(monkeypatch, resp)
        assert await guarded_get("https://cdn.example/x") == (200, "image/png", PNG)
        [(method, url, kwargs)] = calls
        assert (method, url) == ("GET", "https://cdn.example/x")
        assert "headers" not in kwargs
        assert kwargs["deadline"] == twilio_mod.MEDIA_DEADLINE

    async def test_a_declared_length_over_the_cap_is_refused_unread(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(twilio_mod, "MAX_MEDIA_BYTES", 16)
        resp = httpx.Response(200, content=PNG)
        _guard_answering(monkeypatch, resp)
        with pytest.raises(TooLargeError):
            await guarded_get("https://cdn.example/x")

    async def test_an_undeclared_body_is_cut_off_at_the_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(twilio_mod, "MAX_MEDIA_BYTES", 16)

        async def drip() -> AsyncIterator[bytes]:
            for _ in range(10):
                yield b"x" * 8

        _guard_answering(monkeypatch, httpx.Response(200, content=drip()))
        with pytest.raises(TooLargeError):
            await guarded_get("https://cdn.example/x")


class TestStore:
    def test_a_store_from_before_media_still_delivers(self, tmp_path: Path) -> None:
        db = sqlite3.connect(tmp_path / "rcs.db")
        db.executescript(
            "CREATE TABLE inbox (message_id TEXT PRIMARY KEY, sender TEXT NOT NULL, "
            "body TEXT NOT NULL, attachments INTEGER NOT NULL, received REAL NOT NULL);"
            "INSERT INTO inbox VALUES ('SM1', '+15551234567', 'old', 0, 1.0);"
        )
        db.close()
        store = RcsStore(tmp_path / "rcs.db")
        assert asyncio.run(store.pending()) == [Inbound("SM1", OWNER, "old")]
        store.close()


class TestSettings:
    def _load(self, monkeypatch: pytest.MonkeyPatch, **env: str) -> RcsSettings:
        for name, value in (_ENV | env).items():
            monkeypatch.setenv(name, value)
        return RcsSettings.from_env()

    def test_the_media_url_sits_beside_the_webhook(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = self._load(
            monkeypatch, RCS_WEBHOOK_URL="https://rcs.example.com/agent1/twilio/inbound"
        )
        assert settings.media_url == "https://rcs.example.com/agent1/media"

    def test_it_can_be_set_and_must_be_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        set_url = self._load(monkeypatch, RCS_MEDIA_URL="https://cdn.example.com/m/")
        assert set_url.media_url == "https://cdn.example.com/m"
        with pytest.raises(Exception, match="RCS_MEDIA_URL"):
            self._load(monkeypatch, RCS_MEDIA_URL="http://cdn.example.com/m")

    def test_with_neither_outbound_media_is_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = self._load(monkeypatch, RCS_WEBHOOK_URL="https://rcs.example.com/hook")
        assert settings.media_url is None
