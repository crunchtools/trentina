"""The internal tools' responses are delivered in parts too (#446).

``fetch``, ``read`` and ``content`` judge at their own ingress
(``tools/judged.py``), so the router's paging never saw them: over the
admission cap they were refused, or read head-only under flag. These drive the
router end to end. Only the edges are faked, as in ``mode_harness``: the page,
and the layers' model calls. The cut uses the stand-in tokenizer of
``test_paging`` (a word is a token).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from tests.refusal_shape import refused
from trentina import config as config_mod
from trentina import database
from trentina.errors import ContentSizeError
from trentina.gateway import internal, paging
from trentina.gateway.context import PartsOffer, profile_context
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.modes import Mode
from trentina.outcomes import Outcome
from trentina.tools.content import judge_content
from trentina.tools.fetch import fetch_page

from .judge_key import with_judge_key
from .mode_harness import BENIGN, EXTRACTION, MALICIOUS, Layers, allowlist, layers
from .test_paging import _document, _words

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from trentina.quarantine.classifier import ClassifierResult

URL = "https://example.com/long"
FETCH = f"web{NAMESPACE_SEP}fetch_tool"
READ = f"web{NAMESPACE_SEP}read_tool"
CONTENT = f"web{NAMESPACE_SEP}content_tool"
READER = f"web{NAMESPACE_SEP}{paging.READ_PART_TOOL}"
LONG = _document(1_000)  # four parts of 250 words
HOSTILE = "w600"  # a word of part 3


@pytest.fixture(autouse=True)
def _paging(env: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("TRENTINA_PART_TOKENS", "300")
    monkeypatch.setenv("TRENTINA_READ_ROOTS", str(env))
    monkeypatch.setattr(paging, "token_starts", lambda text: [a for a, _ in _words(text)])
    config_mod._config = None
    paging.reset()
    from trentina.server import mcp

    saved = internal._server
    internal.register_internal_server(mcp)
    yield
    internal._server = saved
    paging.reset()
    config_mod._config = None


def _profile(
    *, reader: bool = True, modes: tuple[str, ...] = ("block", "flag", "redact")
) -> Profile:
    allow = ["*"] if reader else ["fetch_tool", "read_tool", "content_tool"]
    profile = Profile(
        name="agent1",
        short_names=False,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="block", modes=list(modes)),
        backends={"web": Backend(url="internal://web", tools_allow=allow)},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return with_judge_key(profile)


def _where(fakes: Layers, word: str = HOSTILE) -> None:
    """L2 flags whatever it is handed that holds ``word``, and nothing else."""

    async def classify(text: str, *_args: Any, **_kwargs: Any) -> ClassifierResult:
        return MALICIOUS if word in text.split() else BENIGN

    fakes.classify.side_effect = classify


class _Gateway:
    """One profile behind the real router, with the audit rows it wrote."""

    def __init__(self, profile: Profile | None = None) -> None:
        self.profile = profile or _profile()
        self.audit = MagicMock()

    async def send(self, name: str, **arguments: Any) -> dict[str, Any]:
        with patch("trentina.gateway.router._audit", self.audit):
            return await route_jsonrpc(
                self.profile,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )

    async def fetch(self, **arguments: Any) -> dict[str, Any]:
        """A fetch's own JSON: what the tool returned, as the agent reads it."""
        resp = await self.send(FETCH, url=URL, trentina_preprocess=False, **arguments)
        assert "result" in resp, resp
        return json.loads(resp["result"]["content"][0]["text"])

    async def read(self, **arguments: Any) -> dict[str, Any]:
        resp = await self.send(READER, **arguments)
        return resp.get("result") or resp["error"]

    def outcomes(self) -> list[tuple[str, str, Outcome]]:
        return [(c.args[1], c.args[2], c.args[3]) for c in self.audit.call_args_list]


def _body(result: dict[str, Any]) -> str:
    blocks = [b["text"] for b in result["content"]]
    assert blocks[0].startswith("[TRENTINA] Part ")
    assert blocks[-1].startswith("[TRENTINA] End of part ")
    return str(blocks[1])


def _blocklist_rows() -> list[tuple[str, int]]:
    rows = database.get_db().execute("SELECT source, blocked FROM detections").fetchall()
    return [(row[0], row[1]) for row in rows]


class TestAFetchTooLargeToJudgeInOneCall:
    async def test_part_one_is_the_tools_own_shape_and_says_where_the_rest_is(
        self, env: Path
    ) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            first = await gateway.fetch()
        marker = first[paging.PART_KEY]
        assert next(iter(first)) == paging.PART_KEY  # read before the content, as a header is
        assert (marker["part"], marker["parts"], marker["next"]) == (1, 4, 2)
        assert f'{READER}(handle="{marker["handle"]}", part=2)' in marker["read_next"]
        assert FETCH in marker["read_next"]
        assert first["content"] == "".join(part.text for part in paging.held("agent1")[0].parts[:1])
        assert first["scan"] == {"layers": "complete", "disposition": "delivered"}

    async def test_the_parts_read_in_order_are_the_page(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            first = await gateway.fetch()
            handle = first[paging.PART_KEY]["handle"]
            rest = [await gateway.read(handle=handle) for _ in range(3)]
        assert first["content"] + "".join(_body(part) for part in rest) == LONG
        assert rest[-1][paging.PART_KEY] == {"part": 4, "parts": 4, "delivered": [1, 2, 3, 4]}
        assert paging.held("agent1") == []
        # Every part is audited as the fetch it is part of.
        assert gateway.outcomes() == [("web", "fetch_tool", Outcome.OK)] * 4

    async def test_each_part_is_judged_once_and_only_when_asked_for(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            first = await gateway.fetch()
            assert fakes.classify.await_count == 1
            assert fakes.classify.await_args.args[0] == first["content"]
            assert "part 1 of 4" in fakes.detect.await_args.kwargs["layer1_context"]
            await gateway.read(handle=first[paging.PART_KEY]["handle"])
            assert fakes.classify.await_count == 2

    async def test_a_page_within_the_whole_size_is_not_cut(self, env: Path) -> None:
        with layers(env, payload=_document(400)):
            first = await _Gateway().fetch()
        assert paging.PART_KEY not in first
        assert first["content"] == _document(400)

    async def test_a_profile_that_cannot_read_part_two_is_handed_the_page_whole(
        self, env: Path
    ) -> None:
        with layers(env, payload=LONG):
            first = await _Gateway(_profile(reader=False)).fetch()
        assert paging.PART_KEY not in first
        assert first["content"] == LONG
        assert paging.held("agent1") == []

    async def test_standalone_nothing_is_cut(self, env: Path) -> None:
        with layers(env, payload=LONG):
            answer = await fetch_page(URL, Mode.FLAG, preprocess=False)
        assert paging.PART_KEY not in answer
        assert answer["content"] == LONG

    async def test_a_profile_bound_with_no_offer_is_not_cut(self, env: Path) -> None:
        """The router makes the offer; a caller it did not dispatch has none."""
        with layers(env, payload=LONG), profile_context(_profile()):
            answer = await fetch_page(URL, Mode.FLAG, preprocess=False)
        assert paging.PART_KEY not in answer


class TestOverTheAdmissionCap:
    """What was refused under block and redact, and read head-only under flag."""

    @pytest.fixture(autouse=True)
    def _small_cap(self, monkeypatch: pytest.MonkeyPatch, _paging: None) -> None:
        monkeypatch.setenv("QUARANTINE_CONTEXT_TOKENS", "700")
        # Admission counts in the unit the stand-in tokenizer cuts in.
        monkeypatch.setattr("trentina.defense.count_tokens", lambda text: len(text.split()))
        config_mod._config = None

    async def test_block_delivers_it_in_parts_where_it_refused(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            first = await gateway.fetch()
            rest = [await gateway.read(handle=first[paging.PART_KEY]["handle"]) for _ in range(3)]
        assert first["content"] + "".join(_body(part) for part in rest) == LONG

    async def test_flag_reads_every_part_whole(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            first = await gateway.fetch(trentina_mode="flag")
        assert "_trentina_warning" not in first  # no l2_truncated, no l3_truncated

    async def test_standalone_it_is_refused_as_before(self, env: Path) -> None:
        with layers(env, payload=LONG), pytest.raises(Exception, match="over the admission cap"):
            await fetch_page(URL, Mode.BLOCK, preprocess=False)

    async def test_content_is_judged_and_handed_back_in_parts(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            resp = await gateway.send(CONTENT, content=LONG, trentina_preprocess=False)
        first = json.loads(resp["result"]["content"][0]["text"])
        assert first[paging.PART_KEY]["parts"] == 4

    async def test_content_standalone_is_still_told_to_split_it(self, env: Path) -> None:
        with layers(env, payload=LONG), pytest.raises(ContentSizeError):
            await judge_content(LONG, Mode.BLOCK)

    async def test_content_past_the_most_parts_is_still_refused(self, env: Path) -> None:
        offer = PartsOffer("web", "content_tool", CONTENT, READER)
        huge = _document(6_000)  # 16 parts of 300 is 4,800
        with (
            layers(env, payload=huge),
            profile_context(_profile(), parts=offer),
            pytest.raises(ContentSizeError),
        ):
            await judge_content(huge, Mode.BLOCK)


class TestAFlaggedPart:
    async def test_block_refuses_it_and_puts_the_url_on_the_blocklist(self, env: Path) -> None:
        """The source is the URL, as for a page flagged whole: not the tool."""
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes)
            first = await gateway.fetch()
            handle = first[paging.PART_KEY]["handle"]
            second = await gateway.read(handle=handle)
            assert _blocklist_rows() == []
            third = await gateway.read(handle=handle)
        assert _body(second).startswith("w250 ")
        assert third["isError"] is False
        assert HOSTILE not in json.dumps(third)
        assert third["_trentina_refusal"]["part"] == 3
        assert _blocklist_rows() == [(URL, 1)]

        with layers(env, payload=LONG):
            again = await gateway.send(FETCH, url=URL, trentina_preprocess=False)
        assert "on the blocklist" in json.dumps(refused(again))

    async def test_flag_does_not_read_on_once_block_has_blocklisted_the_source(
        self, env: Path
    ) -> None:
        """A fresh flag fetch of a blocklisted URL is refused; so is the rest
        of one already held. redact reads on, as it does for a fresh call."""
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes)
            first = await gateway.fetch()
            handle = first[paging.PART_KEY]["handle"]
            await gateway.read(handle=handle)
            await gateway.read(handle=handle)
            flagged = await gateway.read(handle=handle, part=3, trentina_mode="flag")
            asked = fakes.classify.await_count
            redacted = await gateway.read(
                handle=handle, part=3, trentina_mode={"redact": "What changed?"}
            )
        assert flagged["isError"] is False
        assert "on the blocklist" in flagged["content"][0]["text"]
        assert HOSTILE not in json.dumps(flagged)
        assert asked == 3  # refused unread, as the tool refuses before any bytes arrive
        assert "on the blocklist" not in json.dumps(redacted)

    async def test_block_refuses_a_flagged_part_one_and_holds_nothing(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes, "w7")
            resp = await gateway.send(FETCH, url=URL, trentina_preprocess=False)
        assert "flagged by" in json.dumps(refused(resp))
        assert paging.held("agent1") == []
        assert _blocklist_rows() == [(URL, 1)]

    async def test_flag_delivers_it_with_its_warning_and_blocklists_nothing(
        self, env: Path
    ) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes)
            first = await gateway.fetch(trentina_mode="flag")
            handle = first[paging.PART_KEY]["handle"]
            await gateway.read(handle=handle)
            third = await gateway.read(handle=handle)
            fourth = await gateway.read(handle=handle)
        assert HOSTILE in _body(third).split()
        assert third["_trentina_warning"]["flagged_by"]
        assert fourth["_trentina_warning"]["earlier_parts_flagged"] == [3]
        assert _blocklist_rows() == [(URL, 0)]

    async def test_a_flagged_part_one_marks_the_response(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes, "w7")
            first = await gateway.fetch(trentina_mode="flag")
            assert first["_trentina_warning"]["flagged_by"]
            assert first[paging.PART_KEY]["flagged_at"] == 1
            # block does not deliver what follows a flagged part.
            second = await gateway.read(
                handle=first[paging.PART_KEY]["handle"], trentina_mode="block"
            )
        assert second["isError"] is False
        assert "part 1 was flagged" in second["content"][0]["text"]

    async def test_an_allowlisted_source_is_refused_and_not_blocklisted(
        self, env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        allowlist(tmp_path, monkeypatch)
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes)
            first = await gateway.fetch()
            handle = first[paging.PART_KEY]["handle"]
            await gateway.read(handle=handle)
            third = await gateway.read(handle=handle)
        assert third["isError"] is False
        assert _blocklist_rows() == [("https://example.com/long", 0)]


class TestRedact:
    async def test_the_question_is_asked_of_each_part(self, env: Path) -> None:
        answer = EXTRACTION["content"]["extracted_text"]
        # Eight words a line, so 1,000 words and four parts, each holding the answer.
        page = "".join(f"{answer} w{i} x{i} y{i}\n" for i in range(125))
        gateway = _Gateway()
        with layers(env, payload=page) as fakes:
            first = await gateway.fetch(trentina_mode={"redact": "What changed?"})
            second = await gateway.read(handle=first[paging.PART_KEY]["handle"])
            asked = [call.args for call in fakes.extract.await_args_list]
        assert first[paging.PART_KEY]["parts"] == 4
        assert first["content"]["extracted_text"] == answer
        assert "w0" not in json.dumps(first["content"])
        assert answer in _body(second)
        assert [args[1] for args in asked] == ["What changed?", "What changed?"]
        assert "w0" in asked[0][0].split()
        assert "w40" not in asked[0][0].split()
        assert "w40" in asked[1][0].split()


class TestTheOtherFamilies:
    async def test_a_file_is_delivered_in_parts(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG):
            resp = await gateway.send(READ, path=str(env / "doc.txt"))
            first = json.loads(resp["result"]["content"][0]["text"])
            second = await gateway.read(handle=first[paging.PART_KEY]["handle"])
        assert first[paging.PART_KEY]["parts"] == 4
        assert _body(second).startswith("w250 ")

    async def test_a_later_part_of_a_file_is_recorded_against_its_path(self, env: Path) -> None:
        gateway = _Gateway()
        with layers(env, payload=LONG) as fakes:
            _where(fakes, "w300")
            resp = await gateway.send(READ, path=str(env / "doc.txt"))
            first = json.loads(resp["result"]["content"][0]["text"])
            await gateway.read(handle=first[paging.PART_KEY]["handle"])
        assert _blocklist_rows() == [(str((env / "doc.txt").resolve()), 1)]
