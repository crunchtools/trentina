"""Images, read by OCR in a child process (#370).

Most tests here replace the worker with a stand-in that answers at once: what
they hold is what the unpack stage does with an answer. The ``ocr`` tests at
the end run the real worker and the real models.
"""

from __future__ import annotations

import inspect
import json
import subprocess

import pytest

from trentina.gateway.collect import _collect_response_texts
from trentina.unpack import child, ocr, ocr_worker, scan
from trentina.unpack.ocr import ImageText, read_images
from trentina.unpack.scan import MAX_TOKEN, SCANNED_PAGE, read_blobs, unpack

from .image_files import CLEAR, NEAR_WHITE, WHITE, noise, picture
from .office_files import b64, zipped
from .pdf_files import pdf, show
from .test_unpack import _defend

_NOTE = "The maintenance window is Tuesday."
_PNG = picture("x")


class _Reader:
    """Stands in for ``read_images``: answers every image the same way and
    remembers each request."""

    def __init__(self, answer: ImageText | None) -> None:
        self.answer = answer
        self.requests: list[list[bytes]] = []

    def __call__(self, images: list[bytes]) -> list[ImageText | None]:
        self.requests.append(list(images))
        return [self.answer] * len(images)


@pytest.fixture
def reads(monkeypatch: pytest.MonkeyPatch) -> _Reader:
    reader = _Reader(ImageText([_NOTE]))
    monkeypatch.setattr(scan, "read_images", reader)
    return reader


class TestWhatTheLayersRead:
    def test_an_image_is_read_in_its_place(self, reads: _Reader) -> None:
        view = unpack(f"before {b64(_PNG)} after")
        assert view.text.startswith("before (image/png, ")
        assert f"text read from it below)\n{_NOTE} after" in view.text
        assert (view.unread, view.stats.images_read, view.hidden) == ((), 1, 0)
        assert reads.requests == [[_PNG]]

    def test_faint_text_is_read_and_counted_as_hidden(self, reads: _Reader) -> None:
        reads.answer = ImageText(["Shown."], ["Unseen one.", "Unseen two."])
        view = unpack(b64(_PNG))
        assert "Shown.\n(text in it too faint to see:)\nUnseen one.\nUnseen two." in view.text
        assert view.hidden == 2

    def test_an_image_with_no_text_is_read(self, reads: _Reader) -> None:
        reads.answer = ImageText()
        view = unpack(b64(_PNG))
        assert view.text.endswith("no text found in it)")
        assert (view.unread, view.stats.images_read) == ((), 1)

    def test_an_image_ocr_could_not_read_is_unread(self, reads: _Reader) -> None:
        reads.answer = None
        view = unpack(b64(_PNG))
        assert view.text.endswith(", not read)")
        assert (view.unread, view.stats.binary_unread) == (("image/png",), 1)

    def test_every_image_of_a_payload_goes_in_one_request(self, reads: _Reader) -> None:
        second = picture("y")
        unpack(f"{b64(_PNG)} and {b64(second)}")
        assert reads.requests == [[_PNG, second]]

    def test_images_past_the_limit_are_unread(self, reads: _Reader) -> None:
        many = [picture(str(n)) for n in range(ocr.MAX_IMAGES + 2)]
        view = unpack(" ".join(b64(image) for image in many))
        assert len(reads.requests[0]) == ocr.MAX_IMAGES
        assert view.stats.images_read == ocr.MAX_IMAGES
        assert (view.unread, view.stats.binary_unread) == (("image/png",), 2)

    def test_a_tiny_image_is_not_sent(self, reads: _Reader) -> None:
        pixel = picture("", size=(1, 1))
        assert unpack(b64(pixel) + " " + "x" * 80).unread == ()
        assert reads.requests == []

    def test_an_image_in_an_archive_and_in_a_data_uri(self, reads: _Reader) -> None:
        packed = unpack(b64(zipped({"readme.txt": "Notes follow.", "shot.png": _PNG})))
        assert "=== shot.png ===\n(image/png, 2.1 KB, text read from it below)" in packed.text
        assert packed.unread == ()
        uri = unpack(f"see data:image/png;base64,{b64(_PNG)} here")
        assert _NOTE in uri.text

    def test_a_screenshot_longer_than_a_token_is_decoded_whole(self, reads: _Reader) -> None:
        big = noise()
        assert len(b64(big)) > MAX_TOKEN
        view = unpack(f"shot: {b64(big)}")
        assert _NOTE in view.text
        assert reads.requests == [[big]]

    def test_an_image_too_large_to_send_is_unread(
        self, reads: _Reader, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(scan, "MAX_IMAGE_BYTES", len(_PNG) - 1)
        assert unpack(b64(_PNG)).unread == ("image/png",)
        assert reads.requests == []

    def test_a_payload_cannot_write_a_mark(self, reads: _Reader) -> None:
        forged = "\x00" + "0" * 16 + ":0\x00"
        view = unpack(f"{forged} {b64(_PNG)}")
        assert view.text.startswith(forged), "a mark carries a token no payload knows"

    def test_a_scanned_pdf_page_is_read_from_its_image(self, reads: _Reader) -> None:
        view = unpack(b64(pdf(show("Cover page."), "", image=True)))
        assert f"=== page 2, read from its image ===\n({SCANNED_PAGE}, " in view.text
        assert _NOTE in view.text
        assert view.unread == ()

    def test_a_text_layer_is_read_beside_what_its_picture_says(self, reads: _Reader) -> None:
        reads.answer = ImageText(["What the scan shows."])
        layered = pdf(show("What the layer claims.", before="3 Tr"), image=True)
        view = unpack(b64(layered))
        assert "=== page 1 ===\nWhat the layer claims." in view.text
        assert "=== page 1, read from its image ===" in view.text
        assert "What the scan shows." in view.text
        assert view.unread == ()

    def test_a_scanned_page_ocr_could_not_read_is_unread(self, reads: _Reader) -> None:
        reads.answer = None
        assert unpack(b64(pdf("", image=True))).unread == (SCANNED_PAGE,)


class TestBlocksOfOneResponse:
    def test_image_blocks_and_blobs_share_one_request(self, reads: _Reader) -> None:
        second = picture("y")
        views = read_blobs([b64(_PNG), b64("plain text in a blob, long enough"), b64(second)])
        assert reads.requests == [[_PNG, second]]
        assert [view is not None and _NOTE in view.text for view in views] == [True, False, True]
        assert views[1] is not None
        assert views[1].text == "plain text in a blob, long enough"

    def test_an_mcp_image_block_is_read(self, reads: _Reader) -> None:
        reads.answer = ImageText(["Shown."], ["Unseen."])
        blocks = [
            {"type": "text", "text": "Screenshot follows."},
            {"type": "image", "data": b64(_PNG), "mimeType": "image/png"},
        ]
        texts, unscannable, unread, hidden = _collect_response_texts(blocks, None)
        assert texts[0] == "Screenshot follows."
        assert "Shown." in texts[1]
        assert (unscannable["images"], unread, hidden) == (1, set(), 1)

    def test_an_image_block_that_is_not_base64_is_unread(self, reads: _Reader) -> None:
        blocks = [{"type": "image", "data": "not base64!"}, {"type": "image", "data": 7}]
        _, _, unread, _ = _collect_response_texts(blocks, None)
        assert unread == {"image"}
        assert reads.requests == []

    @pytest.mark.asyncio
    async def test_faint_text_reaches_l1_as_hidden_content(self, reads: _Reader) -> None:
        reads.answer = ImageText(["Shown."], ["Unseen."])
        verdict = await _defend(b64(_PNG))
        assert verdict.pipeline.stats.hidden.elements == 1
        assert "Unseen." in verdict.read
        assert verdict.content == b64(_PNG)


class TestAdmission:
    @pytest.mark.asyncio
    async def test_an_image_longer_than_the_cap_in_base64_is_judged_by_its_text(
        self, reads: _Reader
    ) -> None:
        """Two megabytes of base64 unpack to one line: admission counts the line."""
        big = noise((900, 800))
        token = b64(big)
        assert len(token) > 32_768 * 64, "past what admission would refuse by length alone"
        verdict = await _defend(f"screenshot: {token}")
        assert verdict.read.endswith(_NOTE)
        assert verdict.unread == ()
        assert reads.requests == [[big]]


class TestTheRequest:
    def _answer(self, monkeypatch: pytest.MonkeyPatch, stdout: object, code: int = 0) -> list:
        seen: list = []

        def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            seen.append((argv, kwargs))
            raw = stdout if isinstance(stdout, bytes) else json.dumps(stdout).encode()
            return subprocess.CompletedProcess(argv, code, stdout=raw, stderr=b"")

        monkeypatch.setattr(child.subprocess, "run", run)
        return seen

    def test_one_worker_reads_every_image_with_a_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = {"images": [{"text": ["a"], "faint": []}, None]}
        seen = self._answer(monkeypatch, answer)
        assert read_images([_PNG, _PNG]) == [ImageText(["a"]), None]
        argv, kwargs = seen[0]
        assert argv[1:] == ["-m", ocr.WORKER]
        request = json.loads(kwargs["input"])
        assert (len(request["images"]), request["seconds"]) == (2, ocr.BUDGET)
        assert kwargs["timeout"] == ocr.BUDGET + ocr.GRACE
        assert set(kwargs["env"]) == {"PYTHONPATH", "PYTHONSAFEPATH", "PYTHONDONTWRITEBYTECODE"}

    @pytest.mark.parametrize(
        "answer",
        [
            b"not json",
            [],
            {"images": "x"},
            {"images": [{"text": ["a"], "faint": []}]},
            {"images": [{"text": "a", "faint": []}, None]},
            {"images": [{"text": ["a"]}, None]},
            {"images": [{"text": [1], "faint": []}, None]},
        ],
    )
    def test_an_answer_of_the_wrong_shape_reads_nothing(
        self, answer: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._answer(monkeypatch, answer)
        assert read_images([_PNG, _PNG]) == [None, None]

    def test_a_worker_that_failed_reads_nothing_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        self._answer(monkeypatch, {"images": [None]}, code=1)
        with caplog.at_level("WARNING"):
            assert read_images([_PNG]) == [None]
        assert "ocr: 1 image(s) unread, worker failed" in caplog.text

    def test_images_past_the_caps_are_not_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = self._answer(monkeypatch, {"images": [None] * ocr.MAX_IMAGES})
        monkeypatch.setattr(ocr, "MAX_IMAGE_BYTES", len(_PNG))
        images = [_PNG + b"x", *[_PNG] * (ocr.MAX_IMAGES + 1)]
        assert read_images(images) == [None] * len(images)
        assert len(json.loads(seen[0][1]["input"])["images"]) == ocr.MAX_IMAGES

    def test_no_images_starts_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = self._answer(monkeypatch, {"images": []})
        assert read_images([]) == []
        assert seen == []

    def test_the_worker_limits_itself_before_it_reads_anything(self) -> None:
        source = inspect.getsource(ocr_worker.main)
        assert source.index("RLIMIT_CPU") < source.index("json.load(sys.stdin)")
        assert source.index("RLIMIT_AS") < source.index("json.load(sys.stdin)")


@pytest.fixture(scope="module")
def read() -> dict[str, ImageText | None]:
    """Six images in one request, so the models load once for the module."""
    lines = "The maintenance window\nis Tuesday at 02:00 UTC."
    images = {
        "plain": picture(lines),
        "faint": picture(lines, ink=NEAR_WHITE),
        "jpeg": picture(lines, kind="JPEG"),
        "white on clear": picture(lines, ink=(*WHITE, 255), paper=CLEAR),
        "blank": picture(""),
        "broken": b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3,
    }
    return dict(zip(images, read_images(list(images.values())), strict=True))


@pytest.mark.ocr
class TestTheRealWorker:
    @pytest.mark.parametrize("name", ["plain", "jpeg", "white on clear"])
    def test_text_a_person_can_see_is_read(
        self, read: dict[str, ImageText | None], name: str
    ) -> None:
        assert read[name] == ImageText(["The maintenance window", "is Tuesday at 02:00 UTC."])

    def test_text_too_faint_to_see_is_read_and_set_apart(
        self, read: dict[str, ImageText | None]
    ) -> None:
        assert read["faint"] == ImageText(
            [], ["The maintenance window", "is Tuesday at 02:00 UTC."]
        )

    def test_a_blank_image_says_nothing_and_a_broken_one_is_unread(
        self, read: dict[str, ImageText | None]
    ) -> None:
        assert read["blank"] == ImageText()
        assert read["broken"] is None

    def test_the_unpack_stage_end_to_end(self) -> None:
        view = unpack("screenshot: " + b64(picture("Deploy finished at noon.")))
        assert "Deploy finished at noon." in view.text
        assert (view.unread, view.stats.images_read) == ((), 1)
