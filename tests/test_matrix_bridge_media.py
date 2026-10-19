"""Attachments cross the Matrix bridge re-hosted and judged (#491), gateway side.

The rig from ``test_matrix_bridge`` stands in for Conduit and the bridge
process; here both also serve media. What is pinned: the bytes are judged
with the event, they are re-hosted on the side that receives them, no
``mxc://`` URI from the other side is ever delivered, thumbnails never cross,
and an attachment that cannot be judged or fetched never crosses either.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from trentina.defense import Layer
from trentina.gateway.matrix_bridge import appservice as appservice_mod
from trentina.gateway.matrix_bridge.media import (
    FOREIGN,
    MAX_MEDIA_B64,
    MAX_MEDIA_BYTES,
    TOO_LARGE,
    UNAVAILABLE,
    parse_mxc,
    read_attachment,
    strip_media,
)
from trentina.gateway.matrix_bridge.rewrite import judged_view
from trentina.gateway.matrix_bridge.routes import EVENT_BODY_CAP, BridgeEvent
from trentina.httpbody import MAX_BODY_BYTES

from . import test_matrix_bridge as base
from .image_files import picture
from .test_matrix_bridge import _agent_event, _message, _verdict

# The rig from the bridge's own tests, registered here as a fixture.
rig_factory = base.rig_factory

PNG = picture("x")
PNG_B64 = base64.b64encode(PNG).decode("ascii")
UPSTREAM_MXC = "mxc://matrix.org/AbCdEf"
LOCAL_MXC = "mxc://agent1.local/m1"
ENCRYPTED_FILE = {
    "url": "mxc://matrix.org/EnCrYpT",
    "key": {"kty": "oct", "alg": "A256CTR", "ext": True, "k": "c2VjcmV0a2V5", "key_ops": []},
    "iv": "AAAAAAAAAAAAAAAAAAAAAA",
    "hashes": {"sha256": "aGFzaGhhc2hoYXNo"},
    "v": "v2",
}
THUMB = {"thumbnail_url": "mxc://matrix.org/Th", "thumbnail_info": {"w": 8, "h": 8}}


@dataclass
class Media:
    """Conduit's media repository and the bridge's /upload, beside the rig's
    fakes for everything else."""

    stored: dict[str, bytes] = field(default_factory=lambda: {"m1": PNG})
    uploads: list[dict[str, Any]] = field(default_factory=list)
    download_status: int = 200
    hosted: dict[str, Any] = field(default_factory=lambda: {"url": "mxc://matrix.org/Up"})
    upload_status: int = 200
    bridge_uploads: list[dict[str, Any]] = field(default_factory=list)

    def conduit(self, fallback: Any) -> Any:
        def handle(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/_matrix/media/v3/upload":
                assert request.headers["authorization"] == "Bearer as-secret"
                self.uploads.append(
                    {
                        "as": request.url.params.get("user_id"),
                        "type": request.headers["content-type"],
                        "data": request.content,
                    }
                )
                return httpx.Response(
                    200, json={"content_uri": f"mxc://agent1.local/up{len(self.uploads)}"}
                )
            if path.startswith("/_matrix/client/v1/media/download/"):
                media_id = path.rsplit("/", 1)[1]
                if media_id not in self.stored:
                    return httpx.Response(404, json={"errcode": "M_NOT_FOUND"})
                if self.download_status != 200:
                    return httpx.Response(self.download_status)
                return httpx.Response(200, content=self.stored[media_id])
            return fallback(request)

        return handle

    def bridge(self, fallback: Any) -> Any:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path != "/upload":
                return fallback(request)
            self.bridge_uploads.append(json.loads(request.content))
            if self.upload_status != 200:
                return httpx.Response(self.upload_status, json={"error": "no"})
            return httpx.Response(200, json=self.hosted)

        return handle


@pytest.fixture
def make(rig_factory: Any) -> Any:
    """``make(enforcement)``: the bridge rig, with media served on both sides."""

    def build(enforcement: str = "block") -> tuple[Any, Media]:
        rig = rig_factory(enforcement)
        media = Media()
        rig.bridge.appservice._client = httpx.AsyncClient(
            transport=httpx.MockTransport(media.conduit(rig.conduit))
        )
        rig.bridge._client = httpx.AsyncClient(
            transport=httpx.MockTransport(media.bridge(rig.upstream))
        )
        return rig, media

    return build


def _image(event_id: str = "$img", data: str = PNG_B64, **content: Any) -> dict[str, Any]:
    event = _message(event_id)
    event["content"] = {
        "msgtype": "m.image",
        "body": "cat.png",
        "url": UPSTREAM_MXC,
        "info": {"mimetype": "image/png", "size": len(PNG), **THUMB},
    } | content
    event["media"] = {"status": "ok", "content_type": "image/png", "base64": data}
    return event


def _agent_image(event_id: str = "$ai", url: str = LOCAL_MXC, **extra: Any) -> dict[str, Any]:
    event = _agent_event(event_id)
    event["content"] = {
        "msgtype": "m.image",
        "body": "chart.png",
        "url": url,
        "info": {"mimetype": "image/png", **THUMB},
    } | extra
    return event


class TestInbound:
    async def test_an_image_is_judged_and_rehosted_as_the_sender(self, make: Any) -> None:
        rig, media = make()
        assert await rig.bridge.inbound(_image()) == "delivered"
        [upload] = media.uploads
        assert upload == {
            "as": "@remote__scott___m=3amatrix.org:agent1.local",
            "type": "image/png",
            "data": PNG,
        }
        [sent] = rig.conduit.sent
        assert sent["content"]["url"] == "mxc://agent1.local/up1"
        assert sent["content"]["info"] == {"mimetype": "image/png", "size": len(PNG)}
        [scanned] = rig.judged
        assert scanned["attachment"] == PNG_B64, "the layers read the picture"
        assert "url" not in scanned["content"]

    async def test_an_encrypted_file_crosses_as_plain_local_media(self, make: Any) -> None:
        rig, media = make()
        event = _image()
        del event["content"]["url"]
        event["content"]["file"] = ENCRYPTED_FILE
        assert await rig.bridge.inbound(event) == "delivered"
        [sent] = rig.conduit.sent
        assert sent["content"]["url"] == "mxc://agent1.local/up1"
        assert "file" not in sent["content"]
        assert "c2VjcmV0a2V5" not in json.dumps(rig.judged), "key material is never judged"
        assert len(media.uploads) == 1

    async def test_no_upstream_uri_is_ever_delivered(self, make: Any) -> None:
        rig, _ = make()
        await rig.bridge.inbound(_image())
        assert "matrix.org/" not in json.dumps([s["content"] for s in rig.conduit.sent])

    async def test_a_flagged_image_is_withheld_and_never_uploaded(self, make: Any) -> None:
        rig, media = make()
        rig.verdicts.append(_verdict(flagged_by=Layer.L2))
        assert await rig.bridge.inbound(_image()) == "withheld"
        [sent] = rig.conduit.sent
        assert sent["content"]["body"] == "[trentina] withheld: flagged by L2"
        assert media.uploads == []

    async def test_a_binary_no_layer_reads_is_withheld_under_block(self, make: Any) -> None:
        rig, media = make()
        elf = base64.b64encode(b"\x7fELF" + bytes(200)).decode("ascii")
        assert await rig.bridge.inbound(_image(data=elf, msgtype="m.file")) == "withheld"
        [sent] = rig.conduit.sent
        assert "no layer can read" in sent["content"]["body"]
        assert rig.judged[0]["attachment"] == ""
        assert media.uploads == []

    async def test_a_binary_no_layer_reads_is_marked_under_flag(self, make: Any) -> None:
        rig, media = make("flag")
        elf = base64.b64encode(b"\x7fELF" + bytes(200)).decode("ascii")
        assert await rig.bridge.inbound(_image(data=elf, msgtype="m.file")) == "delivered"
        [sent] = rig.conduit.sent
        assert sent["content"]["_trentina_warning"]["binary_unread"] is True
        assert media.uploads[0]["type"] == "application/octet-stream"

    async def test_a_text_file_is_judged_as_text(self, make: Any) -> None:
        rig, media = make()
        notes = base64.b64encode(b"Lunch is at noon.").decode("ascii")
        event = _image(data=notes, msgtype="m.file", info={"mimetype": "text/plain"})
        assert await rig.bridge.inbound(event) == "delivered"
        assert rig.judged[0]["attachment"] == "Lunch is at noon."
        assert media.uploads[0]["type"] == "text/plain"

    @pytest.mark.parametrize(
        ("media", "reason"),
        [
            ({"status": "too_large"}, TOO_LARGE),
            ({"status": "unavailable"}, UNAVAILABLE),
            (None, UNAVAILABLE),
            ({"status": "ok", "base64": "not base64!"}, UNAVAILABLE),
        ],
    )
    async def test_an_attachment_that_did_not_arrive_is_withheld_unjudged(
        self, make: Any, media: Any, reason: str
    ) -> None:
        rig, repo = make()
        event = _image()
        event["media"] = media
        assert await rig.bridge.inbound(event) == "withheld"
        [sent] = rig.conduit.sent
        assert sent["content"]["body"] == f"[trentina] withheld: {reason}"
        assert rig.judged == []
        assert repo.uploads == []
        assert rig.bridge.media_refused == 1

    async def test_media_named_only_in_an_edit_is_rehosted_there(self, make: Any) -> None:
        rig, _ = make()
        await rig.bridge.inbound(_message("$orig"))
        event = _message("$edit", "* new")
        event["content"]["m.new_content"] = {"msgtype": "m.image", "body": "x", "url": UPSTREAM_MXC}
        event["content"]["m.relates_to"] = {"rel_type": "m.replace", "event_id": "$orig"}
        event["media"] = {"status": "ok", "base64": PNG_B64}
        assert await rig.bridge.inbound(event) == "delivered"
        new_content = rig.conduit.sent[-1]["content"]["m.new_content"]
        assert new_content["url"] == "mxc://agent1.local/up1"


class TestOutbound:
    async def _room(self, rig: Any) -> None:
        await rig.bridge.inbound(_message())

    async def test_an_image_is_judged_and_uploaded_upstream(self, make: Any) -> None:
        rig, media = make()
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image()])
        [upload] = media.bridge_uploads
        assert base64.b64decode(upload["base64"]) == PNG
        assert upload["content_type"] == "image/png"
        assert upload["room_id"] == "!ops:matrix.org"
        [sent] = [s for s in rig.upstream.sent if s["path"] == "/send"]
        assert sent["content"]["url"] == "mxc://matrix.org/Up"
        assert sent["content"]["info"] == {"mimetype": "image/png"}
        assert rig.judged[-1]["attachment"] == PNG_B64

    async def test_an_encrypted_room_gets_the_file_object(self, make: Any) -> None:
        rig, media = make()
        media.hosted = {"file": {**ENCRYPTED_FILE, "extra": "dropped"}}
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image()])
        [sent] = [s for s in rig.upstream.sent if s["path"] == "/send"]
        assert sent["content"]["file"] == ENCRYPTED_FILE
        assert "url" not in sent["content"]

    async def test_media_on_another_server_is_refused(self, make: Any) -> None:
        rig, media = make()
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image(url="mxc://evil.example/x")])
        assert media.bridge_uploads == []
        assert not [s for s in rig.upstream.sent if s["path"] == "/send"]
        assert rig.conduit.sent[-1]["content"]["body"].endswith(FOREIGN)
        assert (rig.bridge.media_refused, rig.bridge.outbound_refused) == (1, 1)

    async def test_an_oversize_download_is_refused(
        self, make: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(appservice_mod, "MAX_MEDIA_BYTES", 16)
        rig, media = make()
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image()])
        assert media.bridge_uploads == []
        assert rig.conduit.sent[-1]["content"]["body"].endswith(TOO_LARGE)

    async def test_missing_media_is_refused_not_retried(self, make: Any) -> None:
        rig, media = make()
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image(url="mxc://agent1.local/gone")])
        assert rig.conduit.sent[-1]["content"]["body"].endswith(UNAVAILABLE)
        assert media.bridge_uploads == []

    async def test_a_homeserver_error_is_retried(self, make: Any) -> None:
        rig, media = make()
        media.download_status = 503
        await self._room(rig)
        with pytest.raises(appservice_mod.ConduitError):
            await rig.bridge.outbound("t1", [_agent_image()])
        media.download_status = 200
        await rig.bridge.outbound("t1", [_agent_image()])
        assert len(media.bridge_uploads) == 1

    async def test_a_flagged_image_never_leaves(self, make: Any) -> None:
        rig, media = make()
        await self._room(rig)
        rig.verdicts.append(_verdict(flagged_by=Layer.L3))
        await rig.bridge.outbound("t1", [_agent_image()])
        assert media.bridge_uploads == []
        assert rig.conduit.sent[-1]["content"]["body"].endswith("flagged by L3")

    async def test_an_upload_the_bridge_refuses_is_dropped_and_told(self, make: Any) -> None:
        rig, media = make()
        media.upload_status = 422
        await self._room(rig)
        await rig.bridge.outbound("t1", [_agent_image()])
        assert not [s for s in rig.upstream.sent if s["path"] == "/send"]
        assert "cannot carry it" in rig.conduit.sent[-1]["content"]["body"]


class TestPieces:
    def test_the_signature_beats_the_declared_type(self) -> None:
        assert read_attachment(PNG, "text/plain").content_type == "image/png"
        assert read_attachment(b"\x7fELF" + bytes(8), "text/plain").unread
        assert read_attachment(b"\xff\xfe bad utf-8", "text/plain").unread

    def test_judged_view_leaves_out_uris_keys_and_thumbnails(self) -> None:
        content = {"msgtype": "m.image", "body": "a", "file": ENCRYPTED_FILE, "info": THUMB}
        assert judged_view(content) == {"msgtype": "m.image", "body": "a", "info": {}}
        assert strip_media(content) == judged_view(content)

    @pytest.mark.parametrize(
        "uri",
        ["mxc://matrix.org/../x", "mxc://a/b/c", "https://matrix.org/x", "mxc://a/", 7],
    )
    def test_a_malformed_mxc_is_rejected(self, uri: Any) -> None:
        assert parse_mxc(uri) is None

    def test_the_event_route_takes_a_full_attachment(self) -> None:
        assert EVENT_BODY_CAP > MAX_MEDIA_B64 > MAX_MEDIA_BYTES > MAX_BODY_BYTES
        event = BridgeEvent.model_validate(
            {**_image(), "media": {"status": "ok", "base64": "A" * MAX_MEDIA_B64}}
        )
        assert event.media is not None
