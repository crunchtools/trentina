"""Attachments upstream, bridge process side (#491).

The bridge fetches an event's main media over the authenticated media API,
decrypts it in an encrypted room (refusing bytes whose hash does not match),
and hands it to the gateway with the event. For the gateway it uploads judged
media, encrypted for an encrypted room. It judges nothing: a fetch that fails
is reported as such, never dropped and never retried into a stalled batch.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from nio.crypto.attachments import decrypt_attachment, encrypt_attachment
from starlette.testclient import TestClient

from trentina.bridge import media as media_mod
from trentina.bridge.api import build_app
from trentina.bridge.client import Bridge, SendError

from .image_files import picture
from .test_bridge_process import ROOM, FakeNio, _bridge

if TYPE_CHECKING:
    from pathlib import Path

PNG = picture("x")
AUTH = {"Authorization": "Bearer bridge-secret"}


@dataclass
class Homeserver:
    """matrix.org's media repository, as the bridge's own client reaches it."""

    stored: dict[str, bytes] = field(default_factory=lambda: {"AbC": PNG})
    status: int = 200
    upload_status: int = 200
    requests: list[httpx.Request] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == "Bearer tok"
        if request.url.path == "/_matrix/media/v3/upload":
            if self.upload_status != 200:
                return httpx.Response(self.upload_status, json={"errcode": "M_TOO_LARGE"})
            return httpx.Response(200, json={"content_uri": "mxc://matrix.org/Up"})
        prefix = "/_matrix/client/v1/media/download/matrix.org/"
        media_id = request.url.path.removeprefix(prefix)
        if self.status != 200 or media_id not in self.stored:
            return httpx.Response(self.status if self.status != 200 else 404)
        return httpx.Response(
            200, content=self.stored[media_id], headers={"content-type": "image/png"}
        )


def _rig(tmp_path: Path, nio: FakeNio | None = None) -> tuple[Bridge, Homeserver, list[Any]]:
    forwarded: list[Any] = []

    def gateway(request: httpx.Request) -> httpx.Response:
        forwarded.append(json.loads(request.content))
        return httpx.Response(200, json={"outcome": "delivered"})

    bridge = _bridge(tmp_path, nio or FakeNio(), gateway)
    homeserver = Homeserver()
    bridge._media = httpx.AsyncClient(transport=httpx.MockTransport(homeserver))
    return bridge, homeserver, forwarded


def _image_event(**content: Any) -> Any:
    return SimpleNamespace(
        sender="@scott:matrix.org",
        decrypted=False,
        source={
            "type": "m.room.message",
            "event_id": "$img",
            "sender": "@scott:matrix.org",
            "content": {
                "msgtype": "m.image",
                "body": "cat.png",
                "url": "mxc://matrix.org/AbC",
                "info": {"mimetype": "image/png"},
            }
            | content,
        },
    )


class TestFetch:
    async def test_plaintext_media_rides_with_the_event(self, tmp_path: Path) -> None:
        bridge, homeserver, forwarded = _rig(tmp_path)
        await bridge.handle(ROOM, _image_event())
        [payload] = forwarded
        assert payload["media"] == {
            "status": "ok",
            "content_type": "image/png",
            "base64": base64.b64encode(PNG).decode("ascii"),
        }
        [request] = homeserver.requests
        assert request.url.path == "/_matrix/client/v1/media/download/matrix.org/AbC"
        assert "allow_redirect" not in str(request.url)

    async def test_encrypted_media_is_decrypted(self, tmp_path: Path) -> None:
        bridge, homeserver, forwarded = _rig(tmp_path)
        ciphertext, keys = encrypt_attachment(PNG)
        homeserver.stored["EnC"] = ciphertext
        file = {"url": "mxc://matrix.org/EnC", **keys}
        await bridge.handle(ROOM, _image_event(url=None, file=file))
        assert base64.b64decode(forwarded[0]["media"]["base64"]) == PNG

    async def test_bytes_that_fail_the_hash_go_nowhere(self, tmp_path: Path) -> None:
        bridge, homeserver, forwarded = _rig(tmp_path)
        ciphertext, keys = encrypt_attachment(PNG)
        homeserver.stored["EnC"] = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        file = {"url": "mxc://matrix.org/EnC", **keys}
        await bridge.handle(ROOM, _image_event(url=None, file=file))
        assert forwarded[0]["media"] == {"status": "unavailable"}

    async def test_oversize_media_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(media_mod, "MAX_MEDIA_BYTES", 16)
        bridge, _, forwarded = _rig(tmp_path)
        await bridge.handle(ROOM, _image_event())
        assert forwarded[0]["media"] == {"status": "too_large"}

    @pytest.mark.parametrize("url", ["mxc://matrix.org/Gone", "https://evil.example/x", 7])
    async def test_media_that_cannot_be_fetched_is_reported(self, tmp_path: Path, url: Any) -> None:
        bridge, _, forwarded = _rig(tmp_path)
        await bridge.handle(ROOM, _image_event(url=url))
        assert forwarded[0]["media"] == {"status": "unavailable"}

    async def test_an_event_without_media_carries_none(self, tmp_path: Path) -> None:
        bridge, homeserver, forwarded = _rig(tmp_path)
        event = _image_event()
        del event.source["content"]["url"]
        await bridge.handle(ROOM, event)
        assert "media" not in forwarded[0]
        assert homeserver.requests == []


class TestUpload:
    def _post(self, bridge: Bridge, **body: Any) -> httpx.Response:
        payload = {
            "room_id": ROOM,
            "content_type": "image/png",
            "filename": "chart.png",
            "base64": base64.b64encode(PNG).decode("ascii"),
        } | body
        return TestClient(build_app(bridge)).post("/upload", json=payload, headers=AUTH)

    def test_an_encrypted_room_holds_only_ciphertext(self, tmp_path: Path) -> None:
        bridge, homeserver, _ = _rig(tmp_path, FakeNio(encrypted=True))
        resp = self._post(bridge)
        assert resp.status_code == 200
        file = resp.json()["file"]
        assert file["url"] == "mxc://matrix.org/Up"
        [request] = homeserver.requests
        assert request.headers["content-type"] == "application/octet-stream"
        assert request.content != PNG
        plain = decrypt_attachment(
            request.content, file["key"]["k"], file["hashes"]["sha256"], file["iv"]
        )
        assert plain == PNG

    def test_a_plaintext_room_gets_a_url(self, tmp_path: Path) -> None:
        bridge, homeserver, _ = _rig(tmp_path, FakeNio(encrypted=False))
        resp = self._post(bridge)
        assert resp.json() == {"url": "mxc://matrix.org/Up"}
        [request] = homeserver.requests
        assert (request.content, request.headers["content-type"]) == (PNG, "image/png")

    @pytest.mark.parametrize(("status", "answer"), [(413, 422), (500, 502), (429, 502)])
    def test_a_refused_upload_says_whether_to_retry(
        self, tmp_path: Path, status: int, answer: int
    ) -> None:
        bridge, homeserver, _ = _rig(tmp_path)
        homeserver.upload_status = status
        assert self._post(bridge).status_code == answer

    def test_upload_needs_the_gateways_token(self, tmp_path: Path) -> None:
        bridge, homeserver, _ = _rig(tmp_path)
        resp = TestClient(build_app(bridge)).post(
            "/upload", json={}, headers={"Authorization": "Bearer x"}
        )
        assert resp.status_code == 401
        assert homeserver.requests == []

    def test_malformed_base64_is_refused(self, tmp_path: Path) -> None:
        bridge, homeserver, _ = _rig(tmp_path)
        assert self._post(bridge, base64="not base64!").status_code == 400
        assert homeserver.requests == []

    async def test_a_room_not_held_is_refused(self, tmp_path: Path) -> None:
        bridge, homeserver, _ = _rig(tmp_path)
        bridge._evict.add(ROOM)
        with pytest.raises(SendError):
            await bridge.upload(ROOM, PNG, "image/png", "x.png")
        assert homeserver.requests == []
