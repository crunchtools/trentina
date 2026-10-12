"""Git's wire format as the gateway reads it (#453): no sockets, no I/O."""

from __future__ import annotations

import pytest

from trentina.gateway.git_wire import (
    DELIMITER,
    FLUSH,
    MAX_REQUEST_PACKETS,
    PKT_MAX,
    Command,
    GitRefusedError,
    PktReader,
    RefFilter,
    check_upload_request,
    parse_command,
    parse_repo_path,
    pkt_lines,
    refuse_ref_update,
)
from trentina.outcomes import Outcome

from .git_harness import ONE, TWO, ZERO, pkt

HIDDEN = (b"refs/pull/",)


def _refusal(path: str, raw: bytes | None = None) -> tuple[int, str]:
    with pytest.raises(GitRefusedError) as caught:
        parse_repo_path(path, raw if raw is not None else f"/git/forge/{path}".encode())
    assert caught.value.outcome is Outcome.DENIED_GUARD
    return caught.value.status, caught.value.reason


class TestRepoPath:
    @pytest.mark.parametrize("endpoint", ["info/refs", "git-upload-pack", "git-receive-pack"])
    def test_the_three_endpoints_parse(self, endpoint: str) -> None:
        parsed = parse_repo_path(f"acme/widgets.git/{endpoint}", b"/git/forge/x")
        assert (parsed.owner, parsed.repo, parsed.endpoint) == ("acme", "widgets", endpoint)
        assert parsed.slug == "acme/widgets"

    @pytest.mark.parametrize(
        "spelling",
        [
            "acme/widgets",
            "acme/widgets.git",
            "Acme/Widgets",
            "ACME/WIDGETS.GIT",
            "acme/Widgets.Git",
        ],
    )
    def test_case_and_the_git_suffix_do_not_make_a_different_repository(
        self, spelling: str
    ) -> None:
        assert parse_repo_path(f"{spelling}/info/refs", b"/x").slug == "acme/widgets"

    def test_a_leading_dot_is_a_name(self) -> None:
        assert parse_repo_path("acme/.github/info/refs", b"/x").slug == "acme/.github"

    @pytest.mark.parametrize(
        "path",
        [
            "acme/widgets",
            "acme/widgets/",
            "acme/widgets/HEAD",
            "acme/widgets/objects/info/packs",
            "acme/widgets/info/refs/extra",
            "acme/widgets/info",
            "acme/widgets/git-upload-archive",
            "acme/widgets/git-upload-pack/",
            "acme/team/widgets/info/refs",
            "widgets/info/refs",
            "",
        ],
    )
    def test_any_other_path_is_not_found(self, path: str) -> None:
        assert _refusal(path) == (404, "path")

    @pytest.mark.parametrize(
        "path",
        [
            "../widgets/info/refs",
            "acme/../info/refs",
            "acme/wid..gets/info/refs",
            "acme/x..git/info/refs",
            "acme/./info/refs",
            "acme/.git/info/refs",
            "/widgets/info/refs",
            "acme//info/refs",
            "ac me/widgets/info/refs",
            "acme/wid\\gets/info/refs",
            "acme/wid@gets/info/refs",
            "acme/" + "w" * 101 + "/info/refs",
        ],
    )
    def test_a_name_outside_the_grammar_is_refused(self, path: str) -> None:
        assert _refusal(path) == (400, "name")

    @pytest.mark.parametrize(
        "raw",
        [
            b"/git/forge/acme%2Fwidgets/x/info/refs",
            b"/git/forge/acme/%2e%2e/info/refs",
            b"/git/forge/acme/widgets/info%2Frefs",
            b"/git/forge/acme/widgets%00/info/refs",
        ],
    )
    def test_an_encoded_path_is_refused_whatever_it_decodes_to(self, raw: bytes) -> None:
        assert _refusal("acme/widgets/info/refs", raw) == (400, "name")


class TestPktLines:
    def test_data_and_special_packets(self) -> None:
        data = pkt(b"want a\n") + b"0000" + b"0001" + b"0002" + pkt(b"")
        assert list(pkt_lines(data)) == [b"want a\n", 0, 1, 2, b""]

    def test_a_body_is_walked_in_place(self) -> None:
        body = pkt(b"want a\n") * 3 + b"0000"
        assert list(pkt_lines(body)) == [b"want a\n"] * 3 + [0]
        assert list(pkt_lines(b"")) == []

    def test_a_reader_waits_for_a_whole_line(self) -> None:
        reader = PktReader()
        wire = pkt(b"hello\n")
        reader.feed(wire[:3])
        assert reader.take() is None
        reader.feed(wire[3:7])
        assert reader.take() is None
        reader.feed(wire[7:] + b"PACK")
        assert reader.take() == (wire, b"hello\n")
        assert reader.pending == 4
        reader.feed(b"more")
        assert reader.pending == 8, "taken lines are dropped, what follows is kept"

    @pytest.mark.parametrize(
        "data",
        [b"0003", b"zzzz", b"+0a1x", b"0x1f", b" 00a", b"fff1" + b"x" * 10, b"000", b"0009hi"],
    )
    def test_malformed_framing_is_an_error(self, data: bytes) -> None:
        with pytest.raises(ValueError, match="pkt-line"):
            list(pkt_lines(data))

    def test_many_short_lines_are_read_in_one_pass(self) -> None:
        """Taking a line moves an offset; nothing is shifted per line."""
        reader = PktReader()
        reader.feed(b"0000" * 50_000 + pkt(b"x"))
        taken = 0
        while reader.take() is not None:
            taken += 1
        assert (taken, reader.pending) == (50_001, 0)
        assert len(reader._held) == 200_005, "dropped at the next feed, not line by line"
        reader.feed(b"")
        assert len(reader._held) == 0

    def test_the_longest_line_is_accepted_and_one_more_byte_is_not(self) -> None:
        longest = pkt(b"x" * (PKT_MAX - 4))
        assert len(longest) == PKT_MAX
        assert len(list(pkt_lines(longest))) == 1
        with pytest.raises(ValueError, match="longer"):
            list(pkt_lines(pkt(b"x" * (PKT_MAX - 3))))


class TestPushCommand:
    def test_a_command_with_capabilities(self) -> None:
        payload = ONE + b" " + TWO + b" refs/heads/agent/x\0 report-status side-band-64k\n"
        assert parse_command(payload) == Command(ONE, TWO, "refs/heads/agent/x")

    def test_a_sha256_command(self) -> None:
        old, new = b"a" * 64, b"b" * 64
        assert parse_command(old + b" " + new + b" refs/heads/x") == Command(
            old, new, "refs/heads/x"
        )

    def test_a_shallow_line_updates_nothing(self) -> None:
        assert parse_command(b"shallow " + ONE + b"\n") is None

    @pytest.mark.parametrize(
        "payload",
        [
            b"push-cert\0report-status\n",
            b"certificate version 0.1\n",
            ONE + b" " + TWO + b"\n",
            ONE + b" " + TWO + b" refs/heads/a b\n",
            ONE[:39] + b" " + TWO + b" refs/heads/x\n",
            ONE.upper().replace(b"1", b"A") + b" " + TWO + b" refs/heads/x\n",
            ONE + b" " + b"b" * 64 + b" refs/heads/x\n",
            ONE + b" " + TWO + b" refs/heads/\xff\xfe\n",
            ONE + b" " + TWO + b" refs/heads/x\x07y\n",
            b"shallow nothex\n",
            b"",
        ],
    )
    def test_anything_else_is_malformed(self, payload: bytes) -> None:
        with pytest.raises(GitRefusedError) as caught:
            parse_command(payload)
        assert (caught.value.status, caught.value.reason) == (400, "malformed")

    def test_push_options_are_refused(self) -> None:
        payload = ONE + b" " + TWO + b" refs/heads/agent/x\0report-status push-options atomic\n"
        with pytest.raises(GitRefusedError) as caught:
            parse_command(payload)
        assert (caught.value.status, caught.value.reason) == (403, "push_options")

    @pytest.mark.parametrize(
        ("command", "reason"),
        [
            (Command(ONE, TWO, "refs/heads/agent/x"), None),
            (Command(ZERO, TWO, "refs/heads/agent/new"), None),
            (Command(ONE, ZERO, "refs/heads/agent/x"), "delete"),
            (Command(ONE, b"0" * 64, "refs/heads/agent/x"), "delete"),
            (Command(ONE, ZERO, "refs/tags/v1"), "delete"),
            (Command(ZERO, TWO, "refs/tags/v1"), "tag"),
            (Command(ZERO, TWO, "refs/notes/commits"), "ref_not_listed"),
            (Command(ZERO, TWO, "refs/pull/1/head"), "ref_not_listed"),
            (Command(ZERO, TWO, "HEAD"), "ref_not_listed"),
            (Command(ZERO, TWO, "refs/headsx/y"), "ref_not_listed"),
        ],
    )
    def test_a_delete_a_tag_and_a_non_branch_are_refused(
        self, command: Command, reason: str | None
    ) -> None:
        assert refuse_ref_update(command) == reason


def _v2(command: bytes, *arguments: bytes) -> bytes:
    head = pkt(b"command=" + command + b"\n") + pkt(b"agent=git/2.55.0\n") + b"0001"
    return head + b"".join(pkt(argument + b"\n") for argument in arguments) + b"0000"


class TestUploadRequest:
    def test_a_v2_ls_refs_is_recognized(self) -> None:
        body = _v2(b"ls-refs", b"peel", b"symrefs", b"ref-prefix refs/heads/", b"ref-prefix HEAD")
        assert check_upload_request(body, "version=2", HIDDEN) is True

    def test_a_v2_fetch_is_not_a_listing(self) -> None:
        body = _v2(b"fetch", b"thin-pack", b"want " + ONE, b"have " + TWO, b"done")
        assert check_upload_request(body, "version=2", HIDDEN) is False

    def test_v0_wants_and_haves_pass(self) -> None:
        body = pkt(b"want " + ONE + b" multi_ack side-band-64k\n") + b"0000" + pkt(b"done\n")
        assert check_upload_request(body, None, HIDDEN) is False
        assert check_upload_request(body, "version=1", HIDDEN) is False

    @pytest.mark.parametrize(
        "argument",
        [
            b"ref-prefix refs/pull/",
            b"ref-prefix refs/pull",
            b"ref-prefix refs/pull/7/head",
            b"want-ref refs/pull/7/head",
        ],
    )
    def test_asking_for_a_hidden_namespace_by_name_is_refused(self, argument: bytes) -> None:
        for command in (b"ls-refs", b"fetch"):
            with pytest.raises(GitRefusedError) as caught:
                check_upload_request(_v2(command, argument), "version=2", HIDDEN)
            assert (caught.value.status, caught.value.reason) == (403, "hidden_ref")

    @pytest.mark.parametrize(
        "argument",
        [b"ref-prefix refs/pulled/", b"ref-prefix refs/pull-requests", b"want-ref refs/pulls/1"],
    )
    def test_a_namespace_that_only_starts_the_same_is_not_hidden(self, argument: bytes) -> None:
        assert check_upload_request(_v2(b"fetch", argument), "version=2", HIDDEN) is False

    def test_a_broader_prefix_is_left_to_the_answer_filter(self) -> None:
        assert check_upload_request(_v2(b"ls-refs", b"ref-prefix refs/"), "version=2", HIDDEN)
        assert check_upload_request(_v2(b"ls-refs"), "version=2", HIDDEN)

    def test_a_want_by_object_id_is_not_restricted(self) -> None:
        """Known gap 29: an id learned elsewhere can still be asked for."""
        assert check_upload_request(_v2(b"fetch", b"want " + ONE), "version=2", HIDDEN) is False

    @pytest.mark.parametrize("command", [b"object-info", b"bundle-uri", b"ls-refs2", b""])
    def test_any_other_v2_command_is_refused(self, command: bytes) -> None:
        with pytest.raises(GitRefusedError) as caught:
            check_upload_request(_v2(command), "version=2", HIDDEN)
        assert (caught.value.status, caught.value.reason) == (403, "command")

    def test_a_v2_request_is_one_command_ending_at_its_flush(self) -> None:
        """A second command behind the first would get an answer no filter read."""
        second = _v2(b"fetch", b"want " + ONE) + _v2(b"ls-refs")
        with pytest.raises(GitRefusedError) as caught:
            check_upload_request(second, "version=2", HIDDEN)
        assert (caught.value.status, caught.value.reason) == (403, "command")
        for body in (_v2(b"fetch") + pkt(b"want " + ONE + b"\n"), _v2(b"fetch")[:-4]):
            with pytest.raises(GitRefusedError) as caught:
                check_upload_request(body, "version=2", HIDDEN)
            assert (caught.value.status, caught.value.reason) == (400, "malformed")

    def test_a_v0_body_cannot_carry_a_command_further_in(self) -> None:
        body = pkt(b"want " + ONE + b"\n") + b"0000" + pkt(b"command=ls-refs\n") + b"0000"
        with pytest.raises(GitRefusedError) as caught:
            check_upload_request(body, None, HIDDEN)
        assert (caught.value.status, caught.value.reason) == (400, "protocol")

    def test_a_request_of_too_many_packets_is_refused(self) -> None:
        body = b"0000" * (MAX_REQUEST_PACKETS + 1)
        with pytest.raises(GitRefusedError) as caught:
            check_upload_request(body, None, HIDDEN)
        assert (caught.value.status, caught.value.reason) == (413, "too_large")
        assert check_upload_request(b"0000" * MAX_REQUEST_PACKETS, None, HIDDEN) is False

    def test_the_header_and_the_body_must_agree(self) -> None:
        for body, protocol in ((_v2(b"fetch"), None), (pkt(b"want " + ONE + b"\n"), "version=2")):
            with pytest.raises(GitRefusedError) as caught:
                check_upload_request(body, protocol, HIDDEN)
            assert (caught.value.status, caught.value.reason) == (400, "protocol")

    @pytest.mark.parametrize("body", [b"PACK\x00\x00", b"0009hi", pkt(b"want x\n") + b"junk"])
    def test_a_body_that_is_not_pkt_lines_is_malformed(self, body: bytes) -> None:
        with pytest.raises(GitRefusedError) as caught:
            check_upload_request(body, None, HIDDEN)
        assert (caught.value.status, caught.value.reason) == (400, "malformed")


def _advertisement() -> tuple[list[bytes], list[bytes]]:
    """A v0 advertisement as pkt-lines, and the same with pull refs left out."""
    lines = [
        pkt(b"# service=git-upload-pack\n"),
        b"0000",
        pkt(ONE + b" HEAD\0multi_ack symref=HEAD:refs/heads/main agent=git/2.55.0\n"),
        pkt(ONE + b" refs/heads/main\n"),
        pkt(TWO + b" refs/pull/7/head\n"),
        pkt(TWO + b" refs/pull/7/merge\n"),
        pkt(ONE + b" refs/pulled/not-hidden\n"),
        pkt(ONE + b" refs/tags/v1\n"),
        pkt(TWO + b" refs/tags/v1^{}\n"),
        b"0000",
    ]
    return lines, [line for line in lines if b" refs/pull/" not in line]


class TestRefFilter:
    def test_pull_refs_are_dropped_and_the_rest_is_byte_identical(self) -> None:
        lines, kept = _advertisement()
        listing = RefFilter(HIDDEN)
        assert listing.feed(b"".join(lines)) == b"".join(kept)
        listing.finish()
        assert listing.dropped == 2

    @pytest.mark.parametrize("size", [1, 3, 7, 64])
    def test_it_does_not_matter_how_the_bytes_are_cut(self, size: int) -> None:
        lines, kept = _advertisement()
        wire = b"".join(lines)
        listing = RefFilter(HIDDEN)
        passed = b"".join(listing.feed(wire[at : at + size]) for at in range(0, len(wire), size))
        listing.finish()
        assert passed == b"".join(kept)

    def test_an_ls_refs_answer_is_filtered_by_the_same_rule(self) -> None:
        lines = [
            pkt(ONE + b" HEAD symref-target:refs/heads/main\n"),
            pkt(ONE + b" refs/heads/main\n"),
            pkt(TWO + b" refs/pull/7/head\n"),
            pkt(TWO + b" refs/tags/v1 peeled:" + ONE + b"\n"),
            b"0000",
        ]
        listing = RefFilter(HIDDEN)
        assert listing.feed(b"".join(lines)) == b"".join(lines[:2] + lines[3:])

    def test_a_v2_capability_advertisement_passes_untouched(self) -> None:
        wire = (
            pkt(b"version 2\n")
            + pkt(b"agent=git/2.55.0\n")
            + pkt(b"ls-refs=unborn\n")
            + pkt(b"fetch=shallow wait-for-done\n")
            + b"0000"
        )
        assert RefFilter(HIDDEN).feed(wire) == wire

    def test_every_configured_namespace_is_hidden(self) -> None:
        listing = RefFilter((b"refs/pull/", b"refs/merge-requests/"))
        wire = pkt(ONE + b" refs/merge-requests/3/head\n") + pkt(ONE + b" refs/heads/main\n")
        assert listing.feed(wire) == pkt(ONE + b" refs/heads/main\n")

    def test_a_hidden_ref_on_the_capability_line_ends_the_listing(self) -> None:
        listing = RefFilter(HIDDEN)
        with pytest.raises(ValueError, match="capabilities"):
            listing.feed(pkt(ONE + b" refs/pull/7/head\0multi_ack\n"))

    @pytest.mark.parametrize(
        "line",
        [
            ONE + b" HEAD symref-target:refs/pull/7/head\n",
            ONE + b" HEAD\0multi_ack symref=HEAD:refs/pull/7/head agent=git/2\n",
        ],
    )
    def test_a_kept_line_that_names_a_hidden_ref_ends_the_listing(self, line: bytes) -> None:
        """HEAD pointing into a hidden namespace would carry its name and
        its object id out on a line the name rule keeps."""
        with pytest.raises(ValueError, match="attribute"):
            RefFilter(HIDDEN).feed(pkt(line))

    def test_a_branch_whose_name_merely_contains_the_words_is_kept(self) -> None:
        wire = pkt(ONE + b" refs/heads/refs/pull/7/head\n")
        assert RefFilter(HIDDEN).feed(wire) == wire

    @pytest.mark.parametrize(
        "name",
        [
            b"refs/heads/" + b"a" * 245,
            "refs/heads/fonctionnalit\u00e9".encode(),
            "refs/heads/zero\u200bwidth".encode(),
            b"refs/heads/tab\there",
            b"refs/heads/bell\x07",
            b"refs/heads/\xff\xfe",
        ],
        ids=["too-long", "accented", "zero-width", "tab", "control", "not-utf8"],
    )
    def test_a_ref_whose_name_is_not_one_short_ascii_token_is_not_listed(self, name: bytes) -> None:
        """A name is delivered unjudged, so it is held to what cannot hide anything."""
        kept = pkt(ONE + b" refs/heads/main\n")
        listing = RefFilter(HIDDEN)
        assert listing.feed(kept + pkt(TWO + b" " + name + b"\n") + b"0000") == kept + b"0000"
        assert listing.dropped == 1

    def test_the_longest_listable_name_is_listed(self) -> None:
        wire = pkt(ONE + b" refs/heads/" + b"a" * 244 + b"\n")
        assert RefFilter(HIDDEN).feed(wire) == wire

    def test_only_a_ref_line_is_held_to_the_name_rule(self) -> None:
        """A capability or service line is the forge's own, not a ref someone named."""
        wire = pkt(b"# service=" + b"x" * 300 + b"\n") + pkt(b"agent=git/\xc3\xa9 x\n")
        assert RefFilter(HIDDEN).feed(wire) == wire

    def test_a_listing_cut_inside_a_line_is_an_error(self) -> None:
        listing = RefFilter(HIDDEN)
        assert listing.feed(pkt(ONE + b" refs/heads/main\n")[:-5]) == b""
        with pytest.raises(ValueError, match="before its flush"):
            listing.finish()

    def test_a_listing_that_stops_at_a_line_boundary_without_its_flush_is_an_error(self) -> None:
        listing = RefFilter(HIDDEN)
        listing.feed(pkt(ONE + b" refs/heads/main\n") + pkt(TWO + b" refs/heads/dev\n"))
        with pytest.raises(ValueError, match="before its flush"):
            listing.finish()
        with pytest.raises(ValueError, match="before its flush"):
            RefFilter(HIDDEN).finish()

    def test_a_stream_that_is_not_pkt_lines_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="pkt-line"):
            RefFilter(HIDDEN).feed(b"<html>not git</html>")

    def test_special_packets_pass(self) -> None:
        wire = b"0000" + b"0001" + b"0002"
        assert RefFilter(HIDDEN).feed(wire) == wire
        assert (FLUSH, DELIMITER) == (0, 1)
