"""Archives and office files, read inside by the unpack stage (#368).

Everything here is built in memory. Where a test needs an instruction to
see whether the layers would read it, it borrows one from the corpus.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import struct
import tarfile
import time
import zipfile

import pytest

from corpora.owasp import OWASP_TEST_ATTACKS
from trentina.l1.pipeline import run_l1
from trentina.transforms.base import TransformContext
from trentina.transforms.detect import document_hidden, hiding_removed
from trentina.transforms.structured import StructuredProcessor
from trentina.unpack import archive, office
from trentina.unpack.archive import Budget, open_archive
from trentina.unpack.scan import ENCRYPTED_ENTRY, read_blob, unpack

from .office_files import b64, docx, paragraph, pptx, run, xlsx, zipped
from .test_unpack import _defend

_DIRECTIVE = OWASP_TEST_ATTACKS[0]
_NOTE = "The maintenance window for the storage cluster is Tuesday at 02:00 UTC."
_KINDS = {gzip.compress: archive.GZIP, bz2.compress: archive.BZIP2, lzma.compress: archive.XZ}
_PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3


def tarred(files: dict[str, bytes], *, trailing: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive_file:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive_file.addfile(info, io.BytesIO(data))
    return buffer.getvalue() + trailing


class TestArchivesAreRead:
    def test_a_zip_is_read_file_by_file(self) -> None:
        view = unpack("attached: " + b64(zipped({"notes/readme.txt": _NOTE, "empty.txt": ""})))
        assert view.text.startswith("attached: (zip archive, ")
        assert "=== notes/readme.txt ===\n" + _NOTE in view.text
        assert "empty.txt" not in view.text, "an empty file adds nothing to read"
        assert view.unread == ()
        assert view.stats.archives_opened == 1

    @pytest.mark.parametrize(
        "pack",
        [gzip.compress, bz2.compress, lzma.compress],
        ids=["gzip", "bzip2", "xz"],
    )
    def test_a_compressed_stream_is_read(self, pack) -> None:
        view = unpack(b64(pack(_NOTE.encode() * 3)))
        assert _NOTE in view.text
        assert view.unread == ()

    @pytest.mark.parametrize("pack", [gzip.compress, bz2.compress, lzma.compress, bytes])
    def test_a_tar_is_read_bare_or_compressed(self, pack) -> None:
        view = unpack(b64(pack(tarred({"etc/motd": _NOTE.encode()}))))
        assert "=== etc/motd ===\n" + _NOTE in view.text
        assert view.unread == ()

    def test_the_directive_inside_reaches_l1(self) -> None:
        plain = run_l1(_DIRECTIVE).stats.directives.directives_detected
        assert plain >= 1
        inside = unpack(b64(zipped({"a.txt": _NOTE, "b.txt": _DIRECTIVE}))).text
        assert run_l1(inside).stats.directives.directives_detected == plain

    def test_a_file_name_is_read_on_one_line(self) -> None:
        view = unpack(b64(zipped({"a\nb\r\n=== c ===.txt": _NOTE})))
        assert "=== a b === c ===.txt ===\n" in view.text

    def test_base64_inside_a_file_is_decoded_one_level(self) -> None:
        view = unpack(b64(zipped({"config.env": f"MOTD={b64(_NOTE)}"})))
        assert f"MOTD={_NOTE}" in view.text

    @pytest.mark.parametrize(
        "encoded",
        [_NOTE.encode("utf-16"), _NOTE.encode("latin-1"), b"\xef\xbb\xbf" + _NOTE.encode()],
    )
    def test_text_in_another_encoding_is_still_text(self, encoded: bytes) -> None:
        assert _NOTE in unpack(b64(zipped({"note.txt": encoded}))).text

    def test_a_zip_comment_is_read(self) -> None:
        view = unpack(b64(zipped({"a.txt": "x" * 40}, comment=_NOTE.encode())))
        assert "=== (archive comment) ===\n" + _NOTE in view.text

    def test_an_mcp_blob_is_read_the_same_way(self) -> None:
        view = read_blob(b64(zipped({"readme.txt": _NOTE})))
        assert view is not None
        assert _NOTE in view.text
        assert view.unread == ()

    def test_a_data_uri_is_read_the_same_way(self) -> None:
        uri = "data:application/zip;base64," + b64(zipped({"readme.txt": _NOTE}))
        assert _NOTE in unpack(f"see {uri} for details").text


class TestNesting:
    def test_an_archive_inside_an_archive_is_read(self) -> None:
        inner = zipped({"inner.txt": _NOTE})
        view = unpack(b64(gzip.compress(tarred({"bundle.zip": inner}))))
        assert "=== bundle.zip ===\n(zip archive, " in view.text
        assert "=== inner.txt ===\n" + _NOTE in view.text
        assert view.stats.archives_opened == 2

    def test_a_third_level_stays_unread(self) -> None:
        third = zipped({"deep.txt": _NOTE})
        second = tarred({"third.zip": third})
        view = unpack(b64(tarred({"second.tar": second})))
        assert _NOTE not in view.text
        assert view.unread == ("zip archive or office file",)

    def test_an_image_inside_is_still_unread(self) -> None:
        view = unpack(b64(zipped({"readme.txt": _NOTE, "logo.png": _PNG})))
        assert _NOTE in view.text
        assert "=== logo.png ===\n(image/png, " in view.text
        assert view.unread == ("image/png",)


class TestLimits:
    def test_a_bomb_by_ratio_stays_unread(self) -> None:
        bomb = zipped({"zeros.txt": "0" * (archive.RATIO_FLOOR * 8)})
        assert len(bomb) < 2048
        view = unpack(b64(bomb))
        assert view.unread == ("zip archive or office file",)
        assert view.stats.archives_opened == 0

    def test_highly_compressible_text_under_the_floor_is_read(self) -> None:
        text = (_NOTE + "\n") * 200
        assert len(text) < archive.RATIO_FLOOR
        assert unpack(b64(gzip.compress(text.encode()))).unread == ()

    @pytest.mark.parametrize("pack", [gzip.compress, bz2.compress, lzma.compress])
    def test_a_stream_past_the_byte_cap_stays_unread(self, pack) -> None:
        noise = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(256)).hex().encode()
        data = (noise + b"\n") * (archive.MAX_BYTES // len(noise) + 2)
        assert open_archive(pack(data), _KINDS[pack], Budget()) is None

    def test_too_many_files_stays_unread(self) -> None:
        many = zipped({f"f{i}.txt": "x" for i in range(archive.MAX_ENTRIES + 1)})
        assert open_archive(many, archive.ZIP, Budget()) is None

    def test_the_budget_is_shared_by_nested_archives(self) -> None:
        budget = Budget(bytes_left=100)
        assert open_archive(zipped({"a.txt": "a" * 60}), archive.ZIP, budget) is not None
        assert budget.bytes_left == 40
        assert open_archive(zipped({"b.txt": "b" * 60}), archive.ZIP, budget) is None
        assert budget.bytes_left == 40, "a refused archive is not charged"

    def test_a_header_that_lies_about_its_size_is_still_bounded(self) -> None:
        data = bytearray(zipped({"big.txt": "A" * 300_000}))
        # The size fields in the central directory and local header now say 5 bytes.
        for at in _all(bytes(data), b"PK\x01\x02"):
            struct.pack_into("<I", data, at + 24, 5)
        for at in _all(bytes(data), b"PK\x03\x04"):
            struct.pack_into("<I", data, at + 22, 5)
        entries = open_archive(bytes(data), archive.ZIP, Budget(bytes_left=1000))
        assert entries is None or sum(len(e.content or b"") for e in entries) <= 1000

    @pytest.mark.parametrize(
        "broken",
        [
            b"PK\x03\x04" + bytes(40),
            b"\x1f\x8b\x08\x00garbage",
            b"BZh9garbage",
            b"\xfd7zXZ\x00junk",
        ],
        ids=["zip", "gzip", "bzip2", "xz"],
    )
    def test_a_corrupt_archive_stays_unread_and_does_not_raise(self, broken: bytes) -> None:
        view = unpack(b64(broken + bytes(range(256))))
        assert len(view.unread) == 1

    def test_a_large_archive_stays_cheap(self) -> None:
        files = {f"dir/file{i}.txt": (_NOTE + "\n") * 40 for i in range(200)}
        token = b64(zipped(files))
        start = time.perf_counter()
        unpack(token)
        assert time.perf_counter() - start < 2.0


def _all(packed: bytes, magic: bytes) -> list[int]:
    found, at = [], packed.find(magic)
    while at >= 0:
        found.append(at)
        at = packed.find(magic, at + 1)
    return found


class TestBytesNoListingAccountsFor:
    """A zip is read from its directory. What the directory leaves out, another
    reader finds, so the archive is refused instead of half read."""

    def test_a_stub_in_front_of_a_zip(self) -> None:
        payload = _NOTE.encode() + zipped({"a.txt": "listed"})
        assert open_archive(payload, archive.ZIP, Budget()) is None

    def test_a_file_the_directory_does_not_list(self) -> None:
        listed = zipped({"a.txt": "listed"})
        unlisted = zipped({"b.txt": _NOTE})
        local_only = unlisted[: unlisted.index(b"PK\x01\x02")]
        directory_at = listed.index(b"PK\x01\x02")
        spliced = bytearray(listed[:directory_at] + local_only + listed[directory_at:])
        end = spliced.rindex(b"PK\x05\x06")
        struct.pack_into("<I", spliced, end + 16, directory_at + len(local_only))
        with zipfile.ZipFile(io.BytesIO(bytes(spliced))) as still_opens:
            assert still_opens.namelist() == ["a.txt"]
        assert open_archive(bytes(spliced), archive.ZIP, Budget()) is None

    def test_the_descriptor_flag_buys_no_slack(self) -> None:
        """A flagged member's descriptor must be its own checksum and sizes:
        the flag alone does not excuse bytes after its data."""
        listed = bytearray(zipped({"a.txt": "listed"}))
        directory_at = bytes(listed).index(b"PK\x01\x02")
        smuggled = b"<= 24 bytes of text  "
        spliced = bytearray(listed[:directory_at] + smuggled + listed[directory_at:])
        struct.pack_into("<H", spliced, 6, 0x8)
        struct.pack_into("<H", spliced, directory_at + len(smuggled) + 8, 0x8)
        end = spliced.rindex(b"PK\x05\x06")
        struct.pack_into("<I", spliced, end + 16, directory_at + len(smuggled))
        with zipfile.ZipFile(io.BytesIO(bytes(spliced))) as still_opens:
            assert still_opens.read("a.txt") == b"listed"
        assert open_archive(bytes(spliced), archive.ZIP, Budget()) is None

    def test_a_real_data_descriptor_is_accounted_for(self) -> None:
        class _Unseekable(io.RawIOBase):
            def __init__(self) -> None:
                self.written = bytearray()

            def writable(self) -> bool:
                return True

            def write(self, chunk: bytes) -> int:
                self.written += chunk
                return len(chunk)

        sink = _Unseekable()
        with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as streamed:
            streamed.writestr("a.txt", _NOTE)
        packed = bytes(sink.written)
        assert b"PK\x07\x08" in packed, "an unseekable sink makes zipfile write a descriptor"
        entries = open_archive(packed, archive.ZIP, Budget())
        assert entries is not None
        assert entries[0].content == _NOTE.encode()

    def test_an_ordinary_zip_has_nothing_unlisted(self) -> None:
        assert open_archive(zipped({"a.txt": _NOTE, "b/c.txt": "x"}), archive.ZIP, Budget())

    def test_data_after_a_tar_ends(self) -> None:
        payload = tarred({"a.txt": b"listed"}, trailing=_NOTE.encode())
        assert open_archive(payload, archive.TAR, Budget()) is None

    @pytest.mark.parametrize("pack", [gzip.compress, bz2.compress, lzma.compress])
    def test_garbage_after_a_stream_ends(self, pack) -> None:
        assert open_archive(pack(b"listed") + _NOTE.encode(), _KINDS[pack], Budget()) is None

    @pytest.mark.parametrize("pack", [gzip.compress, bz2.compress, lzma.compress])
    def test_a_second_stream_is_read_too(self, pack) -> None:
        entries = open_archive(pack(b"first ") + pack(_NOTE.encode()), _KINDS[pack], Budget())
        assert entries is not None
        assert entries[0].content == b"first " + _NOTE.encode()


class TestEntriesThatCannotBeRead:
    def test_an_encrypted_entry_is_unread_and_the_rest_is_read(self) -> None:
        data = bytearray(zipped({"secret.txt": "x" * 50, "readme.txt": _NOTE}))
        for magic, flags_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            at = bytes(data).index(magic)
            struct.pack_into("<H", data, at + flags_at, 0x1)
        view = unpack(b64(bytes(data)))
        assert "=== secret.txt ===\n(encrypted, not read)" in view.text
        assert _NOTE in view.text
        assert view.unread == (ENCRYPTED_ENTRY,)

    def test_an_lzma_entry_is_not_opened(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_LZMA) as archive_file:
            archive_file.writestr("a.txt", _NOTE)
        entries = open_archive(buffer.getvalue(), archive.ZIP, Budget())
        assert entries is not None
        assert entries[0].content is None

    @pytest.mark.parametrize(
        ("header", "kind"),
        [
            (b"7z\xbc\xaf\x27\x1c", "7z archive"),
            (b"Rar!\x1a\x07\x00", "rar archive"),
            (b"\x28\xb5\x2f\xfd", "zstd"),
        ],
    )
    def test_formats_not_opened_here_stay_unread(self, header: bytes, kind: str) -> None:
        assert unpack(b64(header + bytes(range(256)) * 2)).unread == (kind,)


class TestOfficeFiles:
    def test_a_docx_is_read_as_its_text(self) -> None:
        view = unpack(b64(docx(paragraph(run("The maintenance window "), run("is Tuesday.")))))
        assert view.text.startswith("(docx, ")
        assert "=== word/document.xml ===\nThe maintenance window is Tuesday." in view.text
        assert "<w:t" not in view.text
        assert (view.unread, view.hidden) == ((), 0)

    @pytest.mark.parametrize("flag", ["<w:vanish/>", '<w:vanish w:val="true"/>', "<w:webHidden/>"])
    def test_vanished_text_is_read_and_counted(self, flag: str) -> None:
        view = unpack(b64(docx(paragraph(run("Shown.")), paragraph(run(_NOTE, flag)))))
        assert _NOTE in view.text, "the layers read what Word hides"
        assert view.hidden == 1

    @pytest.mark.parametrize("off", ["0", "false", "off"])
    def test_vanish_switched_off_is_not_hidden(self, off: str) -> None:
        view = unpack(b64(docx(paragraph(run(_NOTE, f'<w:vanish w:val="{off}"/>')))))
        assert view.hidden == 0

    def test_hiding_inherited_from_a_style(self) -> None:
        styles = (
            '<w:style w:styleId="Base"><w:rPr><w:vanish/></w:rPr></w:style>'
            '<w:style w:styleId="Quiet"><w:basedOn w:val="Base"/></w:style>'
        )
        by_run = docx(paragraph(run(_NOTE, '<w:rStyle w:val="Quiet"/>')), styles=styles)
        by_paragraph = docx(paragraph(run(_NOTE), style="Quiet"), styles=styles)
        shown_again = docx(
            paragraph(run(_NOTE, '<w:vanish w:val="0"/>'), style="Quiet"), styles=styles
        )
        assert unpack(b64(by_run)).hidden == 1
        assert unpack(b64(by_paragraph)).hidden == 1
        assert unpack(b64(shown_again)).hidden == 0

    def test_hiding_by_document_default(self) -> None:
        styles = (
            "<w:docDefaults><w:rPrDefault><w:rPr><w:vanish/></w:rPr></w:rPrDefault></w:docDefaults>"
        )
        assert unpack(b64(docx(paragraph(run(_NOTE)), styles=styles))).hidden == 1

    def test_a_style_loop_ends(self) -> None:
        styles = (
            '<w:style w:styleId="A"><w:basedOn w:val="B"/></w:style>'
            '<w:style w:styleId="B"><w:basedOn w:val="A"/></w:style>'
        )
        view = unpack(b64(docx(paragraph(run(_NOTE), style="A"), styles=styles)))
        assert (_NOTE in view.text, view.hidden) == (True, 0)

    def test_another_namespace_prefix_is_read_the_same(self) -> None:
        renamed = docx(paragraph(run("Shown.")), paragraph(run(_NOTE, "<w:vanish/>")), prefix="x")
        view = unpack(b64(renamed))
        assert _NOTE in view.text
        assert view.hidden == 1

    def test_comments_footnotes_and_alt_text_are_read(self) -> None:
        from .office_files import W

        extra = {
            "word/comments.xml": f'<w:comments xmlns:w="{W}"><w:comment><w:p><w:r>'
            f"<w:t>{_NOTE}</w:t></w:r></w:p></w:comment></w:comments>",
            "word/media/drawing.xml": '<d xmlns:x="urn:x"><x:docPr descr="A chart of uptime"/></d>',
        }
        view = unpack(b64(docx(paragraph(run("Body.")), extra=extra)))
        assert "=== word/comments.xml ===\n" + _NOTE in view.text
        assert "[A chart of uptime]" in view.text

    def test_external_links_are_read(self) -> None:
        rels = (
            '<Relationships><Relationship Id="r1" TargetMode="External" '
            'Target="https://example.com/template.dotx"/>'
            '<Relationship Id="r2" Target="media/image1.png"/></Relationships>'
        )
        view = unpack(
            b64(docx(paragraph(run("Body.")), extra={"word/_rels/document.xml.rels": rels}))
        )
        assert "link: https://example.com/template.dotx" in view.text
        assert "media/image1.png" not in view.text

    def test_a_dtd_is_refused_and_the_part_read_raw(self) -> None:
        bomb = (
            '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><d>&b;</d>'
        )
        assert office.parse(bomb.encode()) is None
        view = unpack(b64(docx(paragraph(run("Body.")), extra={"word/settings.xml": bomb})))
        assert "<!ENTITY" in view.text, "unparsed XML is read as it arrived"
        assert "aaaaaaaaaaaaaaaaaaaa" not in view.text

    def test_an_embedded_image_keeps_the_file_unread(self) -> None:
        view = unpack(b64(docx(paragraph(run(_NOTE)), extra={"word/media/image1.png": _PNG})))
        assert _NOTE in view.text
        assert view.unread == ("image/png",)

    def test_an_xlsx_is_read_row_by_row(self) -> None:
        view = unpack(b64(xlsx({"Rota": [["Host", "Owner"], ["db1", "Kim"]]})))
        assert view.text.startswith("(xlsx, ")
        assert "Host | Owner\ndb1 | Kim" in view.text
        assert view.hidden == 0

    def test_a_hidden_sheet_and_an_unused_string_are_read_and_counted(self) -> None:
        book = xlsx(
            {"Rota": [["Host"]], "Scratch": [[_NOTE]]},
            hidden=frozenset({"Scratch"}),
            orphans=("left behind",),
        )
        view = unpack(b64(book))
        assert _NOTE in view.text
        assert "left behind" in view.text
        assert view.hidden == 2

    def test_a_formula_is_read_beside_its_value(self) -> None:
        from .office_files import CONTENT_TYPES, S

        sheet = (
            f'<worksheet xmlns="{S}"><sheetData><row><c t="str"><f>HYPERLINK("https://example.com",'
            '"open")</f><v>open</v></c></row></sheetData></worksheet>'
        )
        book = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "xl/workbook.xml": f'<workbook xmlns="{S}"/>',
                "xl/worksheets/sheet1.xml": sheet,
            }
        )
        assert 'open (=HYPERLINK("https://example.com","open"))' in unpack(b64(book)).text

    def test_a_pptx_is_read_slide_by_slide(self) -> None:
        deck = pptx(["Quarterly review", _NOTE], hidden=frozenset({2}), notes="Speaker notes here.")
        view = unpack(b64(deck))
        assert view.text.startswith("(pptx, ")
        assert "Quarterly review" in view.text
        assert _NOTE in view.text
        assert "Speaker notes here." in view.text
        assert view.hidden == 1

    def test_a_chart_title_is_delivered_by_the_reducer(self) -> None:
        from .office_files import CONTENT_TYPES, A, S

        chart = f'<c xmlns:a="{A}"><a:p><a:r><a:t>Uptime by region</a:t></a:r></a:p></c>'
        book = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "xl/workbook.xml": f'<workbook xmlns="{S}"/>',
                "xl/charts/chart1.xml": chart,
                "docProps/app.xml": "<Properties><Application>Editor</Application></Properties>",
            }
        )
        reduced = office.reduce_base64(b64(book), 140_000)
        assert reduced is not None
        assert reduced[1] == "## Other text\n\nUptime by region"
        assert "Editor" in unpack(b64(book)).text, "the layers read every part"

    def test_a_chart_on_a_hidden_sheet_is_hidden_with_it(self) -> None:
        from .office_files import CONTENT_TYPES, A, R, S

        def chart(title: str) -> str:
            return f'<c xmlns:a="{A}"><a:p><a:r><a:t>{title}</a:t></a:r></a:p></c>'

        def points_to(target: str) -> str:
            return f'<Relationships><Relationship Id="rId1" Target="{target}"/></Relationships>'

        sheets = "".join(
            f'<sheet name="{name}" sheetId="{n}"{state} r:id="rId{n}"/>'
            for n, (name, state) in enumerate([("Shown", ""), ("Scratch", ' state="hidden"')], 1)
        )
        book = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "xl/workbook.xml": f'<workbook xmlns="{S}" xmlns:r="{R}"><sheets>{sheets}'
                "</sheets></workbook>",
                "xl/_rels/workbook.xml.rels": "<Relationships>"
                '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/>'
                '<Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>',
                "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{S}"/>',
                "xl/worksheets/sheet2.xml": f'<worksheet xmlns="{S}"/>',
                "xl/worksheets/_rels/sheet1.xml.rels": points_to("../drawings/drawing1.xml"),
                "xl/worksheets/_rels/sheet2.xml.rels": points_to("../drawings/drawing2.xml"),
                "xl/drawings/drawing1.xml": "<d/>",
                "xl/drawings/drawing2.xml": "<d/>",
                "xl/drawings/_rels/drawing1.xml.rels": points_to("../charts/chart1.xml"),
                "xl/drawings/_rels/drawing2.xml.rels": points_to("../charts/chart2.xml"),
                "xl/charts/chart1.xml": chart("Uptime by region"),
                "xl/charts/chart2.xml": chart(_NOTE),
            }
        )
        reduced = office.reduce_base64(b64(book), 140_000)
        assert reduced is not None
        assert (reduced[1], reduced[2]) == ("## Other text\n\nUptime by region", 1)
        view = unpack(b64(book))
        assert _NOTE in view.text, "the layers still read it"
        assert view.hidden == 1

    def test_a_chart_a_shown_sheet_also_uses_stays_visible(self) -> None:
        from .office_files import CONTENT_TYPES, A, R, S

        sheets = "".join(
            f'<sheet name="{name}" sheetId="{n}"{state} r:id="rId{n}"/>'
            for n, (name, state) in enumerate([("Shown", ""), ("Scratch", ' state="hidden"')], 1)
        )
        to_drawing = (
            '<Relationships><Relationship Id="rId1" Target="../drawings/drawing1.xml"/>'
            "</Relationships>"
        )
        book = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "xl/workbook.xml": f'<workbook xmlns="{S}" xmlns:r="{R}"><sheets>{sheets}'
                "</sheets></workbook>",
                "xl/_rels/workbook.xml.rels": "<Relationships>"
                '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/>'
                '<Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>',
                "xl/worksheets/sheet1.xml": f'<worksheet xmlns="{S}"/>',
                "xl/worksheets/sheet2.xml": f'<worksheet xmlns="{S}"/>',
                "xl/worksheets/_rels/sheet1.xml.rels": to_drawing,
                "xl/worksheets/_rels/sheet2.xml.rels": to_drawing,
                "xl/drawings/drawing1.xml": f'<d xmlns:a="{A}"><a:p><a:r><a:t>Uptime by region'
                "</a:t></a:r></a:p></d>",
            }
        )
        reduced = office.reduce_base64(b64(book), 140_000)
        assert reduced is not None
        assert (reduced[1], reduced[2]) == ("## Other text\n\nUptime by region", 0)

    def test_a_chart_a_shown_slide_also_uses_stays_visible(self) -> None:
        from .office_files import CONTENT_TYPES, A, P

        def slide(show: str) -> str:
            return f'<p:sld xmlns:p="{P}"{show}/>'

        shared = (
            '<Relationships><Relationship Id="rId1" Target="../charts/chart1.xml"/></Relationships>'
        )
        deck = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "ppt/presentation.xml": f'<p:presentation xmlns:p="{P}"/>',
                "ppt/slides/slide1.xml": slide(""),
                "ppt/slides/slide2.xml": slide(' show="0"'),
                "ppt/slides/_rels/slide1.xml.rels": shared,
                "ppt/slides/_rels/slide2.xml.rels": shared,
                "ppt/charts/chart1.xml": f'<c xmlns:a="{A}"><a:p><a:r><a:t>Uptime by region'
                "</a:t></a:r></a:p></c>",
            }
        )
        reduced = office.reduce_base64(b64(deck), 140_000)
        assert reduced is not None
        assert (reduced[1], reduced[2]) == ("## Other text\n\nUptime by region", 0)

    def test_a_relationship_to_a_part_that_is_not_there_is_not_followed(self) -> None:
        from .office_files import CONTENT_TYPES, P

        many = "".join(
            f'<Relationship Id="r{n}" Target="../charts/chart{n}.xml"/>' for n in range(5000)
        )
        deck = zipped(
            {
                "[Content_Types].xml": CONTENT_TYPES,
                "ppt/presentation.xml": f'<p:presentation xmlns:p="{P}"/>',
                "ppt/slides/slide1.xml": f'<p:sld xmlns:p="{P}" show="0"/>',
                "ppt/slides/_rels/slide1.xml.rels": f"<Relationships>{many}</Relationships>",
            }
        )
        start = time.perf_counter()
        assert unpack(b64(deck)).unread == ()
        assert time.perf_counter() - start < 2.0

    def test_a_zip_that_is_not_an_office_file_is_a_zip(self) -> None:
        plain = zipped({"word/document.xml": "<a>not a package</a>"})
        assert unpack(b64(plain)).text.startswith("(zip archive, ")


class TestHiddenCountReachesL1:
    @pytest.mark.asyncio
    async def test_defend_counts_hidden_office_text_as_hidden_content(self) -> None:
        file = docx(paragraph(run("Shown.")), paragraph(run(_NOTE, "<w:vanish/>")))
        verdict = await _defend(b64(file))
        assert verdict.pipeline.stats.hidden.elements == 1
        assert verdict.pipeline.stats.suspicious_detections() >= 1
        assert verdict.content == b64(file), "the delivery is never changed"
        assert _NOTE in verdict.read


class TestStageOneReducer:
    async def _reduce(self, document: object) -> tuple[object, dict]:
        result = await StructuredProcessor().run(json.dumps(document), TransformContext("test"))
        return (json.loads(result.content) if result.applied else None), result.details

    @pytest.mark.asyncio
    async def test_a_base64_docx_field_becomes_its_visible_text(self) -> None:
        file = docx(paragraph(run("Shown to the reader.")), paragraph(run(_NOTE, "<w:vanish/>")))
        reduced, details = await self._reduce({"name": "plan.docx", "data": b64(file)})
        assert reduced == {
            "name": "plan.docx",
            "data": {"format": "docx", "as_markdown": "Shown to the reader."},
        }
        assert (details["office_converted"], details["office_hidden"]) == (1, 1)

    @pytest.mark.asyncio
    async def test_a_workbook_and_a_deck_reduce_to_headed_sections(self) -> None:
        book = xlsx(
            {"Rota": [["Host", "Owner"]], "Scratch": [["x"]]}, hidden=frozenset({"Scratch"})
        )
        deck = pptx(["Quarterly review"], notes="Speaker notes here.")
        reduced, _ = await self._reduce({"book": b64(book), "deck": b64(deck)})
        assert reduced is not None
        assert reduced["book"] == {"format": "xlsx", "as_markdown": "## Rota\n\nHost | Owner"}
        assert reduced["deck"]["as_markdown"] == (
            "## Slide 1\n\nQuarterly review\n\n## Notes 1\n\nSpeaker notes here."
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "token",
        [
            b64(zipped({"readme.txt": _NOTE})),
            b64(_PNG),
            b64(docx(paragraph(run(_NOTE)))).replace("+", "-"),
            b64(docx(paragraph(run(_NOTE)))) + "====",
        ],
        ids=["plain-zip", "image", "url-safe", "bad-padding"],
    )
    async def test_anything_else_is_left_for_the_unpack_stage(self, token: str) -> None:
        reduced, _ = await self._reduce({"data": token, "pad": [1, 2, 3]})
        assert reduced is None or reduced["data"] == token

    @pytest.mark.asyncio
    async def test_an_entry_it_cannot_read_declines(self) -> None:
        data = bytearray(docx(paragraph(run(_NOTE)), extra={"word/secret.xml": "<a>x</a>"}))
        last_local = bytes(data).rindex(b"PK\x03\x04")
        last_central = bytes(data).rindex(b"PK\x01\x02")
        struct.pack_into("<H", data, last_local + 6, 0x1)
        struct.pack_into("<H", data, last_central + 8, 0x1)
        assert office.reduce_base64(b64(bytes(data)), 140_000) is None

    def test_the_hidden_count_is_handed_to_l1(self) -> None:
        from trentina.transforms.base import Cost, TransformResult

        applied = TransformResult(
            name="structured",
            cost=Cost.FREE,
            content="{}",
            applied=True,
            bytes_in=10,
            bytes_out=2,
            details={"office_converted": 1, "office_hidden": 3},
        )
        assert hiding_removed([applied]) == 3
        assert document_hidden([applied]) == 3
        clean = TransformResult(
            name="structured", cost=Cost.FREE, content="{}", applied=True, bytes_in=10, bytes_out=2
        )
        assert hiding_removed([clean]) is None
