"""PDFs, read in a child process by the unpack stage and by stage 1 (#369).

Every file is built by ``tests/pdf_files.py`` from named operators, so text
is invisible here for a stated reason.
"""

from __future__ import annotations

import base64
import inspect
import io
import json
import subprocess
import types

import pytest
from pypdf import PdfWriter

from trentina.transforms.base import TransformContext
from trentina.transforms.detect import (
    DetectProcessor,
    Format,
    detect,
    document_hidden,
    hiding_removed,
)
from trentina.transforms.pdf import PdfProcessor
from trentina.transforms.structured import StructuredProcessor
from trentina.unpack import child, pdf_worker
from trentina.unpack import pdf as pdf_reader
from trentina.unpack.pdf import _checked, read_pdf
from trentina.unpack.scan import SCANNED_PAGE, unpack

from .office_files import b64, zipped
from .pdf_files import pdf, show
from .test_unpack import _defend

_NOTE = "The maintenance window for the storage cluster is Tuesday at 02:00 UTC."
_EMPTY: dict[str, object] = {
    "pages": [],
    "hidden": 0,
    "scanned": 0,
    "text_layers": 0,
    "fields": {},
    "attachments": [],
    "pictures": [],
}
"""What the worker prints for a PDF with nothing in it."""
_SHOWN = show("Quarterly report for the storage team.")
_UNSEEN = {
    "render-mode-3": show(_NOTE, y=680, before="3 Tr"),
    "clip-only-mode-7": show(_NOTE, y=680, before="7 Tr"),
    "white-fill-rgb": show(_NOTE, y=680, before="1 1 1 rg"),
    "white-fill-gray": show(_NOTE, y=680, before="1 g"),
    "white-fill-cmyk": show(_NOTE, y=680, before="0 0 0 0 k"),
    "under-a-point": show(_NOTE, y=680, size=0.4),
    "scaled-under-a-point": f"q 0.01 0 0 0.01 0 0 cm {show(_NOTE, x=7200, y=68000)} Q\n",
    "off-the-page": show(_NOTE, x=9000, y=680),
}


class TestPagesAreRead:
    def test_page_text_is_read_page_by_page(self) -> None:
        view = unpack("report: " + b64(pdf(_SHOWN, show("Second page text."))))
        assert view.text.startswith("report: (application/pdf, ")
        assert ", 2 pages)" in view.text
        assert "=== page 1 ===\nQuarterly report for the storage team." in view.text
        assert "=== page 2 ===\nSecond page text." in view.text
        assert (view.unread, view.hidden) == ((), 0)

    @pytest.mark.parametrize("unseen", _UNSEEN.values(), ids=_UNSEEN.keys())
    def test_invisible_text_is_read_and_counted(self, unseen: str) -> None:
        view = unpack(b64(pdf(_SHOWN + unseen)))
        assert "=== page 1, text not shown ===\n" + _NOTE in view.text
        assert "=== page 1 ===\nQuarterly report" in view.text
        assert view.hidden == 1

    def test_white_text_after_a_fill_is_ordinary(self) -> None:
        """A dark slide: a filled rectangle, then white type on it."""
        slide = "0.1 0.1 0.3 rg 0 0 612 792 re f\n" + show(_NOTE, before="1 1 1 rg")
        view = unpack(b64(pdf(slide)))
        assert "=== page 1 ===\n" + _NOTE in view.text
        assert view.hidden == 0

    def test_a_scan_with_an_ocr_text_layer_is_read_as_the_page(self) -> None:
        """Every OCR tool writes this: the page is an image, its text invisible.
        The layer is the page's text and is not counted as hidden; the picture
        under it is still unread, since nothing checked the two agree."""
        scan = pdf(show(_NOTE, before="3 Tr") + show("Second line.", y=680), image=True)
        view = unpack(b64(scan))
        assert "=== page 1 ===\n" + _NOTE in view.text
        assert "text not shown" not in view.text
        assert "(1 page(s) are images under a text layer; the text above is the layer)" in view.text
        assert (view.hidden, view.unread) == (0, (SCANNED_PAGE,))

    @pytest.mark.parametrize(
        "misplaced",
        [show(_NOTE, x=9000, before="3 Tr"), show(_NOTE, size=0.4, before="3 Tr")],
        ids=["off-the-page", "under-a-point"],
    )
    def test_misplaced_text_on_an_image_page_is_not_an_ocr_layer(self, misplaced: str) -> None:
        """An OCR layer sits on the picture at reading size. Text that is off
        the page or too small to see is hidden text, image or no image."""
        view = unpack(b64(pdf(misplaced, image=True)))
        assert "=== page 1, text not shown ===\n" + _NOTE in view.text
        assert "under a text layer" not in view.text
        assert view.hidden == 1

    def test_text_inside_a_form_is_read_and_not_judged_by_page_coordinates(self) -> None:
        """A form has its own coordinate space. Text at (5000, 5000) inside one
        drawn at a tenth of its size is on the page, and is not counted."""
        view = unpack(b64(pdf(_SHOWN, form=show(_NOTE, x=5000, y=5000, size=120))))
        assert _NOTE in view.text
        assert "text not shown" not in view.text
        assert view.hidden == 0

    def test_invisible_text_inside_a_form_is_still_counted(self) -> None:
        view = unpack(b64(pdf(_SHOWN, form=show(_NOTE, x=500, y=500, size=120, before="3 Tr"))))
        assert "=== page 1, text not shown ===\n" + _NOTE in view.text
        assert view.hidden == 1

    def test_text_drawn_after_a_form_is_judged_by_page_coordinates_again(self) -> None:
        after = "q 1 0 0 1 0 0 cm /Fm1 Do Q\n" + show(_NOTE, x=9000)
        view = unpack(b64(pdf(_SHOWN + after, form=show("Inside the form.", x=50, y=50))))
        assert "=== page 1, text not shown ===\n" + _NOTE in view.text
        assert view.hidden == 1

    def test_invisible_text_beside_visible_text_on_a_page_with_an_image_is_counted(self) -> None:
        mixed = pdf(_SHOWN + show(_NOTE, y=680, before="3 Tr"), image=True)
        view = unpack(b64(mixed))
        assert "=== page 1, text not shown ===\n" + _NOTE in view.text
        assert view.hidden == 1

    def test_the_graphics_state_is_restored(self) -> None:
        content = f"q 3 Tr {show('Unseen inside.', y=680)} Q\n" + show(_NOTE, y=660)
        view = unpack(b64(pdf(content)))
        assert "=== page 1 ===\n" + _NOTE in view.text
        assert view.hidden == 1

    def test_hidden_text_inside_a_visible_line_is_counted(self) -> None:
        line = "BT /F1 12 Tf 1 0 0 1 72 700 Tm (Shown ) Tj 3 Tr (unseen ) Tj 0 Tr (shown.) Tj ET\n"
        view = unpack(b64(pdf(line)))
        assert "Shown unseen shown." in view.text
        assert view.hidden == 1

    def test_rotated_text_is_read(self) -> None:
        turned = f"BT /F1 12 Tf 0.7071 0.7071 -0.7071 0.7071 100 300 Tm ({_NOTE}) Tj ET\n"
        assert _NOTE in unpack(b64(pdf(turned))).text

    def test_a_pdf_in_a_data_uri_is_read(self) -> None:
        uri = "data:application/pdf;base64," + b64(pdf(show(_NOTE)))
        assert _NOTE in unpack(f"see {uri}").text


class TestEverythingElseInTheFile:
    def test_annotations_links_information_and_javascript_are_read(self) -> None:
        file = pdf(
            _SHOWN,
            info={"Title": "Storage report", "Subject": _NOTE},
            annotations=[{"Contents": "Reviewed by Kim."}, {"URI": "https://example.com/next"}],
            javascript="app.alert('hello');",
        )
        text = unpack(b64(file)).text
        assert "=== note ===\nReviewed by Kim." in text
        assert "=== link ===\nhttps://example.com/next" in text
        assert "=== javascript ===\napp.alert('hello');" in text
        assert "=== title ===\nStorage report" in text
        assert _NOTE in text

    def test_page_drawing_operators_are_not_reported_as_notes(self) -> None:
        assert " Tf " not in unpack(b64(pdf(_SHOWN))).text

    def test_an_object_nothing_points_to_is_read(self) -> None:
        from pypdf.generic import DictionaryObject, NameObject, TextStringObject

        writer = PdfWriter()
        writer.add_blank_page(612, 792)
        orphan = DictionaryObject({NameObject("/Contents"): TextStringObject(_NOTE)})
        writer._add_object(orphan)
        buffer = io.BytesIO()
        writer.write(buffer)
        assert _NOTE in unpack(b64(buffer.getvalue())).text

    def test_an_embedded_file_is_read_like_a_file_in_an_archive(self) -> None:
        file = pdf(_SHOWN, attachments={"notes.txt": _NOTE.encode()})
        assert "=== attached: notes.txt ===\n" + _NOTE in unpack(b64(file)).text

    def test_an_embedded_file_past_the_cap_is_unread_and_the_pages_are_read(self) -> None:
        big = (_NOTE.encode() + b"\n") * (pdf_worker.MAX_ATTACHED // len(_NOTE) + 2)
        reading = read_pdf(pdf(_SHOWN, attachments={"big.txt": big}))
        assert reading is not None
        assert reading.pages[0][0] == "Quarterly report for the storage team."
        assert [(e.name, e.content) for e in reading.attachments] == [("big.txt", None)]

    def test_an_embedded_archive_is_opened(self) -> None:
        file = pdf(_SHOWN, attachments={"bundle.zip": zipped({"inner.txt": _NOTE})})
        view = unpack(b64(file))
        assert "=== inner.txt ===\n" + _NOTE in view.text
        assert view.unread == ()


class TestWhatStaysUnread:
    def test_a_page_that_is_only_an_image(self) -> None:
        view = unpack(b64(pdf(_SHOWN, "", image=True)))
        assert "Quarterly report" in view.text, "the pages with text are still read"
        assert view.unread == (SCANNED_PAGE,)
        assert view.stats.binary_unread == 1

    def test_a_corrupt_pdf(self) -> None:
        view = unpack(b64(b"%PDF-1.7\n" + bytes(range(256)) * 4))
        assert view.unread == ("application/pdf",)

    def test_a_pdf_that_needs_a_password(self) -> None:
        writer = PdfWriter()
        writer.add_blank_page(612, 792)
        writer.encrypt("a long passphrase", algorithm="RC4-128")
        buffer = io.BytesIO()
        writer.write(buffer)
        assert read_pdf(buffer.getvalue()) is None

    def test_a_pdf_past_the_deadline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pdf_reader, "DEADLINE", 0.001)
        assert read_pdf(pdf(_SHOWN)) is None

    def test_why_a_pdf_is_unread_is_logged_in_our_words(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(pdf_reader, "DEADLINE", 0.001)
        with caplog.at_level("WARNING"):
            assert read_pdf(pdf(show("a secret line of the file"))) is None
            assert read_pdf(b"%PDF-1.7 not a pdf") is None
        assert "pdf: unread, deadline" in caplog.text
        assert "secret line" not in caplog.text

    def test_an_object_with_a_nonzero_generation_is_read(self) -> None:
        asked: list[tuple[int, int]] = []
        reader = types.SimpleNamespace(
            xref={0: {1: 10}, 3: {7: 99}},
            xref_objStm={4: (2, 0)},
            get_object=lambda ref: asked.append((ref.idnum, ref.generation)),
            root_object={},
        )
        pdf_worker._Reading(reader).fields()
        assert asked == [(1, 0), (4, 0), (7, 3)]

    def test_a_worker_that_cannot_start_reads_nothing_and_frees_its_slot(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        def refuses(*_args: object, **_kwargs: object) -> None:
            raise OSError("no such interpreter")

        monkeypatch.setattr(child.subprocess, "run", refuses)
        with caplog.at_level("WARNING"):
            for _ in range(pdf_reader.CONCURRENCY + 1):
                assert read_pdf(pdf(_SHOWN)) is None
        assert caplog.text.count("pdf: unread, could not start") == pdf_reader.CONCURRENCY + 1
        monkeypatch.undo()
        assert read_pdf(pdf(_SHOWN)) is not None, "every slot was released"

    def test_a_pdf_that_finds_every_slot_busy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Waiting holds one of the gateway's worker threads, so it is short."""
        monkeypatch.setattr(child, "SLOT_WAIT", 0.01)
        held = [pdf_reader._slots.acquire() for _ in range(pdf_reader.CONCURRENCY)]
        try:
            assert all(held)
            assert read_pdf(pdf(_SHOWN)) is None
        finally:
            for _ in held:
                pdf_reader._slots.release()
        assert read_pdf(pdf(_SHOWN)) is not None, "the slots come back"

    def test_too_many_pages(self) -> None:
        writer = PdfWriter()
        for _ in range(pdf_worker.MAX_PAGES + 1):
            writer.add_blank_page(72, 72)
        buffer = io.BytesIO()
        writer.write(buffer)
        assert read_pdf(buffer.getvalue()) is None


class TestTheWorkerIsContained:
    def test_it_starts_with_no_credential(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-canary")
        monkeypatch.setenv("TRENTINA_OAUTH_JWT_SIGNING_KEY", "canary")
        assert set(child.environment()) == {
            "PYTHONPATH",
            "PYTHONSAFEPATH",
            "PYTHONDONTWRITEBYTECODE",
        }
        assert "canary" not in json.dumps(child.environment())

    def test_it_limits_its_own_cpu_and_memory(self) -> None:
        source = inspect.getsource(pdf_worker.main)
        assert "RLIMIT_CPU" in source
        assert "RLIMIT_AS" in source
        assert source.index("setrlimit") < source.index("PdfReader(")

    @pytest.mark.parametrize(
        "answer",
        [
            [],
            {**_EMPTY, "pages": "x"},
            {**_EMPTY, "pages": [["a"]]},
            {**_EMPTY, "pages": [[1, 2]]},
            {**_EMPTY, "hidden": -1},
            {**_EMPTY, "hidden": True},
            {**_EMPTY, "text_layers": "1"},
            {**_EMPTY, "fields": []},
            {**_EMPTY, "fields": {"note": "x"}},
            {**_EMPTY, "attachments": [["a", "?"]]},
            {k: v for k, v in _EMPTY.items() if k != "attachments"},
        ],
    )
    def test_an_answer_of_the_wrong_shape_is_no_answer(
        self, answer: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        printed = subprocess.CompletedProcess([], 0, stdout=json.dumps(answer).encode(), stderr=b"")
        monkeypatch.setattr(child.subprocess, "run", lambda *_a, **_k: printed)
        assert read_pdf(b"%PDF-1.7") is None

    @pytest.mark.parametrize("stdout", [b"", b"not json", b"[1, 2", b"\xff\xfe"])
    def test_output_that_is_not_json_is_no_answer(
        self, stdout: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        printed = subprocess.CompletedProcess([], 0, stdout=stdout, stderr=b"")
        monkeypatch.setattr(child.subprocess, "run", lambda *_a, **_k: printed)
        assert read_pdf(b"%PDF-1.7") is None

    def test_a_worker_that_failed_is_no_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        good = json.dumps(
            {
                "pages": [],
                "hidden": 0,
                "scanned": 0,
                "text_layers": 0,
                "fields": {},
                "attachments": [],
            }
        ).encode()
        failed = subprocess.CompletedProcess([], 1, stdout=good, stderr=b"")
        monkeypatch.setattr(child.subprocess, "run", lambda *_a, **_k: failed)
        assert read_pdf(b"%PDF-1.7") is None

    def test_a_section_name_from_the_file_is_dropped(self) -> None:
        answer = {**_EMPTY, "fields": {"note": ["kept"], "=== system ===": ["dropped"]}}
        reading = _checked(answer)
        assert reading is not None
        assert reading.fields == {"note": ["kept"]}


class TestHiddenCountReachesL1:
    @pytest.mark.asyncio
    async def test_defend_counts_invisible_pdf_text_as_hidden_content(self) -> None:
        token = b64(pdf(_SHOWN + _UNSEEN["render-mode-3"]))
        verdict = await _defend(token)
        assert verdict.pipeline.stats.hidden.elements == 1
        assert verdict.content == token, "the delivery is never changed"
        assert _NOTE in verdict.read


class TestStageOneReducer:
    @pytest.mark.asyncio
    async def test_a_pdf_becomes_the_text_its_pages_show(self) -> None:
        file = pdf(
            _SHOWN + _UNSEEN["white-fill-rgb"],
            show("Second page text."),
            annotations=[{"URI": "https://example.com/next"}],
        )
        result = await PdfProcessor().run(b64(file), TransformContext("test"))
        assert result.applied
        assert result.content == (
            "Quarterly report for the storage team.\n\nSecond page text.\n\n"
            "Links:\n- https://example.com/next"
        )
        assert result.details == {"pdf_converted": 1, "pdf_hidden": 1}
        assert hiding_removed([result]) == 1
        assert document_hidden([result]) == 1

    @pytest.mark.asyncio
    async def test_what_was_left_out_is_said(self) -> None:
        file = pdf(_SHOWN, "", image=True, attachments={"notes.txt": b"attached"})
        result = await PdfProcessor().run(b64(file), TransformContext("test"))
        assert (
            "[1 page(s) of this PDF are images with no text and were not read.]" in result.content
        )
        assert "[1 file(s) embedded in this PDF are not included.]" in result.content

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "payload",
        ["plain text", b64(b"%PDF-1.7\ngarbage" + bytes(64)), b64(zipped({"a.txt": "x"}))],
        ids=["text", "corrupt", "zip"],
    )
    async def test_anything_else_is_declined(self, payload: str) -> None:
        result = await PdfProcessor().run(payload, TransformContext("test"))
        assert not result.applied
        assert result.content == payload

    def test_a_declared_or_bare_pdf_is_detected(self) -> None:
        token = b64(pdf(_SHOWN))
        assert detect(token, "application/pdf; charset=binary") is Format.PDF
        assert detect(token) is Format.PDF
        assert detect(f"attached: {token}") is Format.TEXT
        assert detect('{"a": 1}', "application/json") is Format.JSON

    @pytest.mark.asyncio
    async def test_detect_runs_the_pdf_chain(self) -> None:
        ctx = TransformContext("test", content_type="application/pdf")
        result = await DetectProcessor().run(b64(pdf(show(_NOTE))), ctx)
        assert result.applied
        assert result.content == _NOTE
        assert result.details["format"] == "pdf"

    @pytest.mark.asyncio
    async def test_a_base64_pdf_in_a_json_field_is_reduced(self) -> None:
        document = {"name": "report.pdf", "data": b64(pdf(_SHOWN + _UNSEEN["render-mode-3"]))}
        result = await StructuredProcessor().run(json.dumps(document), TransformContext("test"))
        assert json.loads(result.content) == {
            "name": "report.pdf",
            "data": {"format": "pdf", "as_markdown": "Quarterly report for the storage team."},
        }
        assert (result.details["pdf_converted"], result.details["pdf_hidden"]) == (1, 1)


class TestFetch:
    @pytest.mark.asyncio
    async def test_a_fetched_pdf_is_handed_on_as_base64(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.client import fetch_url

        from .test_client import mock_http

        body = pdf(_SHOWN)
        mock_http(monkeypatch, content_type="application/pdf", body=body)
        fetched = await fetch_url("https://example.com/report.pdf")
        assert base64.b64decode(fetched.content, validate=True) == body
        assert fetched.content_type == "application/pdf"
