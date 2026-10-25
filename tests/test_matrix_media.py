"""Matrix media and undecrypted events are not forwarded unread (#371).

Under ``unjudged: withhold``, the default, an image download is read by OCR
and judged, any other binary download is refused, and an encrypted room
event the gateway could not decrypt becomes the withheld notice. Under
``annotate`` each forwards with the gap marked.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from trentina.gateway import matrix_proxy
from trentina.gateway.matrix_proxy import (
    WARNING_HEADER,
    _withhold_undecrypted,
)
from trentina.modes import Gaps
from trentina.reserved import WARNING_KEY
from trentina.transforms.view import UndecryptableEvent
from trentina.unpack import scan
from trentina.unpack.ocr import ImageText

from .image_files import picture
from .test_matrix_proxy import AGENT_PEER, _count_judged, _matrix_app, _matrix_profile, _upstream

_DOWNLOAD = "/matrix/_matrix/client/v1/media/download/example.org/abc"
_PNG = picture("x")


def _client(unjudged: str = "withhold") -> TestClient:
    return TestClient(
        _matrix_app({"agent1": _matrix_profile(unjudged=unjudged)}), client=AGENT_PEER
    )


class TestImages:
    def test_an_image_is_read_judged_and_forwarded_intact(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        read: list[bytes] = []

        def reader(images: list[bytes]) -> list[ImageText | None]:
            read.extend(images)
            return [ImageText(["Lunch is at noon."])] * len(images)

        monkeypatch.setattr(scan, "read_images", reader)
        monkeypatch.setattr(matrix_proxy, "gaps_of", lambda verdict: Gaps())
        _upstream(monkeypatch, _PNG, "image/png")
        calls = _count_judged(monkeypatch)
        resp = _client().get(_DOWNLOAD)
        assert (resp.status_code, resp.content) == (200, _PNG)
        assert calls == ["text"]
        assert read == [_PNG], "the layers read the picture's text, not its bytes"

    def test_an_image_ocr_cannot_read_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _upstream(monkeypatch, _PNG, "image/png")
        resp = _client().get(_DOWNLOAD)
        assert resp.status_code == 502
        assert resp.content == b"Matrix response could not be judged"

    def test_an_image_too_large_to_read_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(matrix_proxy, "MAX_IMAGE_BYTES", len(_PNG) - 1)
        _upstream(monkeypatch, _PNG, "image/png")
        calls = _count_judged(monkeypatch)
        assert _client().get(_DOWNLOAD).status_code == 502
        assert calls == []


class TestMediaNoLayerReads:
    @pytest.mark.parametrize(
        "content_type", ["audio/ogg", "video/mp4", "application/octet-stream", "Video/WebM"]
    )
    def test_it_is_refused_under_withhold(
        self, monkeypatch: pytest.MonkeyPatch, content_type: str
    ) -> None:
        _upstream(monkeypatch, b"\x00\x01binary\x02", content_type)
        calls = _count_judged(monkeypatch)
        resp = _client().get(_DOWNLOAD)
        assert resp.status_code == 502
        assert b"binary" not in resp.content
        assert calls == []

    @pytest.mark.parametrize("content_type", ["audio/ogg", "application/octet-stream", "image/png"])
    def test_it_forwards_marked_under_annotate(
        self, monkeypatch: pytest.MonkeyPatch, content_type: str
    ) -> None:
        _upstream(monkeypatch, b"\x00\x01binary\x02", content_type)
        resp = _client("annotate").get(_DOWNLOAD)
        assert (resp.status_code, resp.content) == (200, b"\x00\x01binary\x02")
        assert resp.headers[WARNING_HEADER] == "unknown"

    def test_a_thumbnail_is_media_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _upstream(monkeypatch, b"\x00\x01binary\x02", "video/mp4")
        thumbnail = "/matrix/_matrix/media/v3/thumbnail/example.org/abc"
        assert _client().get(thumbnail).status_code == 502


def _encrypted(event_id: str | None, session: str = "s1", **extra: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "type": "m.room.encrypted",
        "sender": "@a:example.org",
        "content": {
            "algorithm": "m.megolm.v1.aes-sha2",
            "ciphertext": "AwgA",
            "session_id": session,
        },
        **extra,
    }
    if event_id is not None:
        event["event_id"] = event_id
    return event


class _View:
    """What an extractor reports: how many events it decrypted, and which it could not."""

    def __init__(self, *events: UndecryptableEvent, decrypted: int = 1) -> None:
        self.undecryptable = events
        self.decrypted_events = decrypted


class TestUndecryptedEvents:
    def test_only_the_unread_events_are_withheld(self) -> None:
        relation = {"m.relates_to": {"rel_type": "m.thread", "event_id": "$root"}}
        unread = _encrypted("$unread")
        unread["content"].update(relation)
        sync = {
            "rooms": {
                "join": {
                    "!r:example.org": {
                        "timeline": {"events": [unread, _encrypted("$read", "s2")]},
                    }
                }
            }
        }
        view = _View(UndecryptableEvent("$unread", "!r:example.org", "s1", "no_session"))
        assert _withhold_undecrypted(sync, view) == 1
        first, second = sync["rooms"]["join"]["!r:example.org"]["timeline"]["events"]
        assert first["type"] == "m.room.message"
        assert first["content"]["msgtype"] == "m.notice"
        assert "ciphertext" not in first["content"]
        assert first["content"]["m.relates_to"]["event_id"] == "$root"
        assert second["content"]["ciphertext"] == "AwgA", "an event the gateway read is untouched"

    def test_an_event_with_no_id_is_matched_by_its_session(self) -> None:
        sync = {"chunk": [_encrypted(None, "s9"), _encrypted(None, "s2")]}
        view = _View(UndecryptableEvent("", "!r:example.org", "s9", "decryption_disabled"))
        assert _withhold_undecrypted(sync, view) == 1
        assert "ciphertext" not in sync["chunk"][0]["content"]
        assert sync["chunk"][1]["content"]["ciphertext"] == "AwgA"

    def test_nothing_unread_changes_nothing(self) -> None:
        sync = {"chunk": [_encrypted("$a")]}
        before = json.dumps(sync)
        assert _withhold_undecrypted(sync, _View()) == 0
        assert json.dumps(sync) == before

    @pytest.mark.parametrize("view", [_View(decrypted=0), None], ids=["select", "no-view"])
    def test_an_extractor_that_decrypted_nothing_read_none_of_them(self, view: object) -> None:
        olm = {"type": "m.room.encrypted", "content": {"ciphertext": {"curve": {"body": "AwgA"}}}}
        sync = {"chunk": [_encrypted("$a"), _encrypted(None, "s2")], "to_device": {"events": [olm]}}
        assert _withhold_undecrypted(sync, view) == 2
        assert all("ciphertext" not in event["content"] for event in sync["chunk"])
        assert sync["to_device"]["events"][0] == olm, "Olm key traffic is not a room message"

    def test_a_deep_or_odd_payload_is_walked_not_raised(self) -> None:
        nested: Any = _encrypted("$deep")
        for _ in range(200):
            nested = {"wrap": [nested]}
        view = _View(UndecryptableEvent("$deep", "", "s1", "no_session"))
        assert _withhold_undecrypted(nested, view) == 0, "past the walk depth nothing is rebuilt"
        assert _withhold_undecrypted([7, "x", None, {"type": ["m.room.encrypted"]}], view) == 0

    def _sync(self, monkeypatch: pytest.MonkeyPatch, unjudged: str) -> dict[str, Any]:
        body = {
            "chunk": [
                _encrypted("$e1"),
                {
                    "type": "m.room.message",
                    "event_id": "$e2",
                    "content": {"msgtype": "m.text", "body": "hello"},
                },
            ]
        }
        _upstream(monkeypatch, json.dumps(body).encode(), "application/json")
        monkeypatch.setattr(matrix_proxy, "gaps_of", lambda verdict: Gaps())
        resp = _client(unjudged).get("/matrix/_matrix/client/v3/rooms/!r:example.org/messages")
        assert resp.status_code == 200
        return resp.json()

    def test_an_undecrypted_event_is_withheld_and_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = self._sync(monkeypatch, "withhold")
        first, second = answer["chunk"]
        assert first["type"] == "m.room.message"
        assert "ciphertext" not in first["content"]
        assert second["content"]["body"] == "hello", "the judged event forwards as it is"
        assert answer[WARNING_KEY]["undecrypted_withheld"] == 1

    def test_under_annotate_the_ciphertext_forwards(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answer = self._sync(monkeypatch, "annotate")
        assert answer["chunk"][0]["content"]["ciphertext"] == "AwgA"
