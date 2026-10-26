"""A response too large to judge in one call is delivered in judged parts (#340).

No model is needed. The cut is tested against a stand-in tokenizer that
makes every run of non-space characters a token, so sizes are counted in
words; the router is driven end to end with a fake backend and a fake
perimeter that judges each part as told.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from trentina import config as config_mod
from trentina.gateway import paging
from trentina.gateway.backend import BackendCall, _tool_list_cache
from trentina.gateway.ingress_defense import IngressDecision
from trentina.gateway.modes_policy import MODE_PARAM, mode_instructions
from trentina.gateway.profile import AuthConfig, Backend, DefenseConfig, Profile
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.outcomes import Outcome
from trentina.quarantine.classifier import GUARD_TOKENS

ROUTER = "trentina.gateway.router"
MCP = "trentina.transports.mcp"
URL = "http://docs:8000/mcp"
GET, SEND = "get_doc", "send_doc"
READER = f"web{NAMESPACE_SEP}{paging.READ_PART_TOOL}"
PART_TOKENS = 300  # whole up to 400 words; a 1,000-word text is four parts of 250


def _words(text: str) -> list[tuple[int, int]]:
    return [match.span() for match in re.finditer(r"\S+", text)]


def _document(words: int, *, every: int = 10) -> str:
    """``words`` distinct words, a newline after every ``every``-th."""
    return "".join(f"w{i}" + ("\n" if i % every == every - 1 else " ") for i in range(words))


@pytest.fixture(autouse=True)
def _paging(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("TRENTINA_PART_TOKENS", str(PART_TOKENS))
    monkeypatch.setattr(paging, "token_starts", lambda text: [a for a, _ in _words(text)])
    config_mod._config = None
    paging.reset()
    _tool_list_cache[URL] = [{"name": SEND}, {"name": GET, "annotations": {"readOnlyHint": True}}]
    yield
    paging.reset()
    config_mod._config = None


def _profile(
    modes: list[str] | None = None, *, reader: bool = True, name: str = "agent1"
) -> Profile:
    backends = {"docs": Backend(url=URL, tools_allow=["*"])}
    if reader:
        backends["web"] = Backend(url="internal://web", tools_allow=["*"])
    profile = Profile(
        name=name,
        short_names=False,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="block", modes=modes or ["block"]),
        backends=backends,
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    return profile


class _Perimeter:
    """Stands in for ``scan_tool_response``: clean unless a part is listed."""

    def __init__(self, **decisions: IngressDecision) -> None:
        self.decisions = decisions
        self.default = IngressDecision(warning=None)
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> IngressDecision:
        self.calls.append(kwargs)
        text = kwargs["content_blocks"][0]["text"]
        for marker, decision in self.decisions.items():
            if marker in text.split():
                return decision
        return self.default


def _flagged(mode: str = "block", alternatives: list[str] | None = None) -> IngressDecision:
    return IngressDecision(
        warning={"flagged_by": "L2", "risk_level": "high", "blocked": True},
        blocked=True,
        refusal={
            "reason": "flagged by L2",
            "mode": mode,
            "flagged_by": "L2",
            "alternatives": alternatives or [],
        },
    )


GAP = IngressDecision(
    warning={"l3_unavailable": True, "blocked": True},
    blocked=True,
    refusal={
        "reason": "not fully judged: L3 unavailable",
        "mode": "block",
        "gaps": ["l3_unavailable"],
        "alternatives": [],
    },
)


class _Gateway:
    """One profile, one fake backend, one fake perimeter, and the audit rows."""

    def __init__(self, profile: Profile | None = None, **decisions: IngressDecision) -> None:
        self.profile = profile or _profile()
        self.perimeter = _Perimeter(**decisions)
        self.backend = AsyncMock()
        self.audit = MagicMock()

    async def _send(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with (
            patch(f"{ROUTER}.call_backend_tool", self.backend),
            patch(f"{ROUTER}.scan_tool_response", self.perimeter),
            patch(f"{MCP}.scan_tool_response", self.perimeter),
            patch(f"{ROUTER}._audit", self.audit),
        ):
            return await route_jsonrpc(
                self.profile,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )

    async def call(self, text: str, tool: str = GET, **arguments: Any) -> dict[str, Any]:
        self.backend.side_effect = [
            BackendCall(
                content=[{"type": "text", "text": text}], is_error=False, structured_content=None
            )
        ]
        resp = await self._send(f"docs{NAMESPACE_SEP}{tool}", arguments)
        return resp["result"]

    async def read(self, **arguments: Any) -> dict[str, Any]:
        resp = await self._send(READER, arguments)
        return resp.get("result") or resp["error"]

    def outcomes(self) -> list[tuple[str, str, Outcome]]:
        return [(c.args[1], c.args[2], c.args[3]) for c in self.audit.call_args_list]


def _body(result: dict[str, Any]) -> str:
    """A delivered part's own text: the block between the header and the footer."""
    blocks = [b["text"] for b in result["content"]]
    assert blocks[0].startswith("[TRENTINA] Part ")
    assert blocks[-1].startswith("[TRENTINA] End of part ")
    return str(blocks[1])


class TestCut:
    def test_a_text_within_the_whole_size_is_not_cut(self) -> None:
        assert paging.cut(_document(400)) is None

    def test_one_word_over_is_two_parts(self) -> None:
        parts = paging.cut(_document(401))
        assert parts is not None and len(parts) == 2

    def test_the_parts_are_the_text_with_nothing_between_them(self) -> None:
        text = _document(1_000)
        parts = paging.cut(text)
        assert parts is not None
        assert "".join(part.text for part in parts) == text

    def test_parts_are_near_equal_and_none_is_over_the_whole_size(self) -> None:
        parts = paging.cut(_document(1_000))
        assert parts is not None and len(parts) == 4
        sizes = [len(_words(part.text)) for part in parts]
        assert max(sizes) <= 400
        assert max(sizes) - min(sizes) <= PART_TOKENS // paging.BOUNDARY_SLACK

    def test_a_cut_lands_on_a_line_break_when_one_is_near(self) -> None:
        parts = paging.cut(_document(1_000, every=7))
        assert parts is not None
        assert all(part.text.endswith("\n") for part in parts[:-1])

    def test_a_blank_line_is_preferred_to_a_line_break(self) -> None:
        text = _document(1_000).replace("w239\n", "w239\n\n")
        parts = paging.cut(text)
        assert parts is not None
        assert parts[0].text.endswith("w239\n\n")

    def test_without_a_break_the_cut_is_at_a_token(self) -> None:
        text = "x".join(f"w{i}" for i in range(50)) + " " + _document(1_000).replace("\n", " ")
        parts = paging.cut(text)
        assert parts is not None
        assert "".join(part.text for part in parts) == text

    def test_the_lead_in_is_the_end_of_the_part_before(self) -> None:
        parts = paging.cut(_document(1_000))
        assert parts is not None
        assert parts[0].lead_in == ""
        for before, part in itertools.pairwise(parts):
            assert before.text.endswith(part.lead_in)
            assert len(_words(part.lead_in)) == GUARD_TOKENS

    def test_the_lead_in_never_reaches_behind_the_part_before(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_PART_TOKENS", "30")
        config_mod._config = None
        parts = paging.cut(_document(100))
        assert parts is not None
        for before, part in itertools.pairwise(parts):
            assert len(part.lead_in) <= len(before.text)
            assert before.text.endswith(part.lead_in)

    def test_over_the_ceiling_is_not_cut(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It is refused at admission, as every over-cap response was."""
        monkeypatch.setenv("TRENTINA_MAX_PARTS", "2")
        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "500")
        config_mod._config = None
        assert paging.cut(_document(600)) is not None
        assert paging.cut(_document(601)) is None

    def test_paging_off_cuts_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_PART_TOKENS", "0")
        config_mod._config = None
        assert paging.cut(_document(5_000)) is None

    def test_without_a_tokenizer_nothing_is_cut(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(paging, "token_starts", lambda _text: None)
        assert paging.cut(_document(5_000)) is None

    @pytest.mark.parametrize("cap", [100, 150, 330, 1_000])
    def test_a_part_and_its_lead_in_are_always_admitted_together(
        self, monkeypatch: pytest.MonkeyPatch, cap: int
    ) -> None:
        """A low admission cap shrinks the parts: room is kept for the lead-in
        and for a part that runs over because the cut before it moved back."""
        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", str(cap))
        config_mod._config = None
        config = config_mod.get_config()
        assert config.whole_tokens <= cap
        for every in (7, 10, 1_000_000):
            parts = paging.cut(_document(min(cap * 5, config.paged_tokens), every=every))
            assert parts is not None
            for part in parts:
                assert len(_words(part.lead_in)) + len(_words(part.text)) <= cap

    @pytest.mark.parametrize("cap", [1, 2, 64, 65])
    def test_a_cap_too_small_for_a_lead_in_turns_paging_off(
        self, monkeypatch: pytest.MonkeyPatch, cap: int
    ) -> None:
        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", str(cap))
        config_mod._config = None
        config = config_mod.get_config()
        assert config.part_target_tokens == 0
        assert config.whole_tokens == config.paged_tokens == cap
        assert paging.cut(_document(5_000)) is None

    def test_the_reserved_lead_in_is_l2s_guard_band(self) -> None:
        assert config_mod.PART_LEAD_TOKENS == GUARD_TOKENS
        assert config_mod.PART_SLACK == paging.BOUNDARY_SLACK


class TestStore:
    def _hold(self, profile: str = "agent1", words: int = 1_000) -> paging.Paged:
        from trentina.defense import Provenance
        from trentina.modes import Mode

        parts = paging.cut(_document(words))
        assert parts is not None
        return paging.hold(
            paging.Origin(profile, "docs", GET, GET, is_error=False, acted=False),
            parts,
            mode=Mode.BLOCK,
            prompt=None,
            provenance=Provenance.EXTERNAL,
            l3_context=None,
            hidden=None,
        )

    def test_a_handle_finds_its_response(self) -> None:
        paged = self._hold()
        assert paging.find("agent1", paged.handle) is paged

    def test_handles_are_long_and_never_repeat(self) -> None:
        handles = {self._hold(profile=f"p{i}").handle for i in range(20)}
        assert len(handles) == 20
        assert all(len(handle) == 32 for handle in handles)

    @pytest.mark.parametrize("handle", ["0" * 32, "", None, 7, ["x"], {"a": 1}])
    def test_a_handle_never_issued_finds_nothing(self, handle: Any) -> None:
        self._hold()
        assert paging.find("agent1", handle) is None

    def test_another_profiles_handle_finds_nothing(self) -> None:
        paged = self._hold()
        assert paging.find("agent2", paged.handle) is None
        assert paging.listing("agent2") == []

    def test_an_idle_response_expires(self, monkeypatch: pytest.MonkeyPatch) -> None:
        paged = self._hold()
        clock = paging.time.monotonic()
        monkeypatch.setattr(paging.time, "monotonic", lambda: clock + 601)
        assert paging.find("agent1", paged.handle) is None

    def test_an_idle_response_is_dropped_without_anyone_paging_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._hold()
        clock = paging.time.monotonic()
        monkeypatch.setattr(paging.time, "monotonic", lambda: clock + 601)
        paging.expire()
        assert paging._store == {}

    def test_evicting_many_at_once_keeps_the_most_recently_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(paging, "MAX_OPEN_PER_PROFILE", 1_000)
        held = [self._hold(words=500) for _ in range(6)]
        paging.find("agent1", held[0].handle)  # read again: now the newest
        monkeypatch.setattr(paging, "MAX_BYTES_PER_PROFILE", held[0].size * 3 + 10)
        last = self._hold(words=500)
        kept = {p.handle for p in paging.held("agent1")}
        assert kept == {held[0].handle, held[5].handle, last.handle}

    def test_reading_a_part_keeps_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        paged = self._hold()
        clock = paging.time.monotonic()
        monkeypatch.setattr(paging.time, "monotonic", lambda: clock + 500)
        assert paging.find("agent1", paged.handle) is paged
        monkeypatch.setattr(paging.time, "monotonic", lambda: clock + 1_000)
        assert paging.find("agent1", paged.handle) is paged

    def test_a_profile_holds_a_few_and_the_oldest_goes(self) -> None:
        held = [self._hold() for _ in range(paging.MAX_OPEN_PER_PROFILE + 1)]
        assert paging.find("agent1", held[0].handle) is None
        assert all(paging.find("agent1", p.handle) is p for p in held[1:])

    def test_one_profile_filling_up_does_not_evict_another(self) -> None:
        other = self._hold(profile="agent2")
        for _ in range(paging.MAX_OPEN_PER_PROFILE + 2):
            self._hold()
        assert paging.find("agent2", other.handle) is other

    def test_the_byte_cap_evicts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        first = self._hold()
        monkeypatch.setattr(paging, "MAX_BYTES_PER_PROFILE", first.size + 10)
        second = self._hold()
        assert paging.find("agent1", first.handle) is None
        assert paging.find("agent1", second.handle) is second

    def test_the_gateway_wide_cap_evicts_across_profiles(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = self._hold(profile="agent1")
        monkeypatch.setattr(paging, "MAX_BYTES", first.size + 10)
        second = self._hold(profile="agent2")
        assert paging.find("agent1", first.handle) is None
        assert paging.find("agent2", second.handle) is second


class TestFirstPart:
    async def test_a_small_response_is_delivered_as_it_always_was(self) -> None:
        gateway = _Gateway()
        result = await gateway.call(_document(400))
        assert result["content"] == [{"type": "text", "text": _document(400)}]
        assert paging.PART_KEY not in result
        assert paging.listing("agent1") == []

    async def test_a_large_response_arrives_as_part_one(self) -> None:
        text = _document(1_000)
        gateway = _Gateway()
        result = await gateway.call(text)
        head, body, foot = (block["text"] for block in result["content"])
        assert head.startswith(f"[TRENTINA] Part 1 of 4 of the docs{NAMESPACE_SEP}{GET} response.")
        assert "not the whole response" in head
        assert text.startswith(body) and len(body) < len(text)
        handle = result[paging.PART_KEY]["handle"]
        assert f'{READER}(handle="{handle}", part=2)' in foot
        assert f"Do not call docs{NAMESPACE_SEP}{GET} again" in foot
        assert result[paging.PART_KEY] == {
            "part": 1,
            "parts": 4,
            "delivered": [1],
            "handle": handle,
            "next": 2,
        }
        assert result["isError"] is False
        assert gateway.outcomes() == [("docs", GET, Outcome.OK)]

    async def test_only_the_first_part_is_judged_by_the_first_call(self) -> None:
        gateway = _Gateway()
        result = await gateway.call(_document(1_000))
        assert len(gateway.perimeter.calls) == 1
        judged = gateway.perimeter.calls[0]
        assert judged["content_blocks"] == [{"type": "text", "text": _body(result)}]
        assert judged["lead_in"] == ""
        assert "part 1 of 4" in judged["l3_context"]

    async def test_a_profile_that_cannot_read_parts_is_not_paged(self) -> None:
        text = _document(1_000)
        gateway = _Gateway(_profile(reader=False))
        result = await gateway.call(text)
        assert result["content"] == [{"type": "text", "text": text}]
        assert paging.listing("agent1") == []

    async def test_a_response_with_an_image_is_not_paged(self) -> None:
        gateway = _Gateway()
        gateway.backend.side_effect = [
            BackendCall(
                content=[
                    {"type": "text", "text": _document(1_000)},
                    {"type": "image", "data": "aGk=", "mimeType": "image/png"},
                ],
                is_error=False,
                structured_content=None,
            )
        ]
        resp = await gateway._send(f"docs{NAMESPACE_SEP}{GET}", {})
        assert paging.PART_KEY not in resp["result"]
        assert len(resp["result"]["content"]) == 2

    async def test_structured_content_follows_the_text_as_json(self) -> None:
        gateway = _Gateway()
        gateway.backend.side_effect = [
            BackendCall(
                content=[{"type": "text", "text": _document(1_000)}],
                is_error=False,
                structured_content={"note": "tail marker"},
            )
        ]
        resp = await gateway._send(f"docs{NAMESPACE_SEP}{GET}", {})
        first = resp["result"]
        assert "structuredContent" not in first
        handle = first[paging.PART_KEY]["handle"]
        for _ in range(first[paging.PART_KEY]["parts"] - 1):
            last = await gateway.read(handle=handle)
        assert _body(last).endswith('{"note":"tail marker"}')

    async def test_a_backends_own_part_marker_is_not_delivered(self) -> None:
        gateway = _Gateway()
        gateway.backend.side_effect = [
            BackendCall(
                content=[{"type": "text", "text": "short"}],
                is_error=False,
                structured_content={paging.PART_KEY: {"part": 1, "parts": 1}, "v": 1},
            )
        ]
        resp = await gateway._send(f"docs{NAMESPACE_SEP}{GET}", {})
        assert paging.PART_KEY not in resp["result"]
        assert paging.PART_KEY not in resp["result"].get("structuredContent", {})


class TestReadPart:
    async def test_every_part_in_turn_is_the_whole_response(self) -> None:
        text = _document(1_000)
        gateway = _Gateway()
        first = await gateway.call(text)
        handle = first[paging.PART_KEY]["handle"]
        bodies = [_body(first)]
        for number in (2, 3, 4):
            result = await gateway.read(handle=handle, part=number)
            assert result["content"][0]["text"].startswith(f"[TRENTINA] Part {number} of 4")
            bodies.append(_body(result))
        assert "".join(bodies) == text
        assert gateway.backend.await_count == 1

    async def test_a_part_is_judged_with_the_end_of_the_one_before(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        second = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        judged = gateway.perimeter.calls[-1]
        assert judged["content_blocks"] == [{"type": "text", "text": _body(second)}]
        assert _body(first).endswith(judged["lead_in"])
        assert len(_words(judged["lead_in"])) == GUARD_TOKENS
        assert "part 2 of 4" in judged["l3_context"]
        assert judged["backend_name"] == "docs" and judged["tool_name"] == GET

    async def test_the_last_part_says_so_and_releases_the_handle(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        for number in (2, 3):
            await gateway.read(handle=handle, part=number)
        last = await gateway.read(handle=handle, part=4)
        assert last["content"][0]["text"].endswith("response: the last.")
        assert "Nothing remains to read" in last["content"][-1]["text"]
        assert "handle" not in last[paging.PART_KEY]
        assert last[paging.PART_KEY]["delivered"] == [1, 2, 3, 4]
        after = await gateway.read(handle=handle, part=1)
        assert after["content"][0]["text"] == paging.UNKNOWN_HANDLE

    async def test_no_part_number_is_the_next_one_not_read(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        assert (await gateway.read(handle=handle))[paging.PART_KEY]["part"] == 2
        assert (await gateway.read(handle=handle))[paging.PART_KEY]["part"] == 3

    async def test_a_part_can_be_read_again(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        once = await gateway.read(handle=handle, part=2)
        again = await gateway.read(handle=handle, part=2)
        assert _body(once) == _body(again)

    @pytest.mark.parametrize("part", [0, 5, -1, "2", 2.0, True])
    async def test_a_part_that_does_not_exist(self, part: Any) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        result = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=part)
        assert result["isError"] is False
        assert "has 4 parts; ask for one of 1 to 4" in result["content"][0]["text"]
        assert gateway.outcomes()[-1] == ("docs", GET, Outcome.DENIED_GUARD)

    async def test_every_unknown_handle_is_refused_in_the_same_words(self) -> None:
        mine = _Gateway()
        first = await mine.call(_document(1_000))
        theirs = _Gateway(_profile(name="agent2"))
        answers = [
            await theirs.read(handle=first[paging.PART_KEY]["handle"], part=2),
            await theirs.read(handle="f" * 32, part=2),
            await mine.read(handle="f" * 32),
            await mine.read(handle=12),
        ]
        assert {a["content"][0]["text"] for a in answers} == {paging.UNKNOWN_HANDLE}
        assert all(a["isError"] is False and paging.PART_KEY not in a for a in answers)
        assert theirs.outcomes()[-1] == ("web", paging.READ_PART_TOOL, Outcome.DENIED_GUARD)

    async def test_a_profile_that_lost_the_tool_loses_the_rest_of_its_response(self) -> None:
        """A reload that takes a tool away is not outlived by a handle."""
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        gateway.profile.backends["docs"].tools_allow = [SEND]
        refused = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert refused["content"][0]["text"] == paging.UNKNOWN_HANDLE
        assert len(gateway.perimeter.calls) == 1

    async def test_no_arguments_lists_what_is_held(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        listed = await gateway.read()
        (held,) = listed["structuredContent"]["held"]
        assert held["handle"] == first[paging.PART_KEY]["handle"]
        assert (held["tool"], held["parts"], held["delivered"]) == (
            f"docs{NAMESPACE_SEP}{GET}",
            4,
            [1],
        )
        assert 0 < held["expires_in_seconds"] <= 600
        assert listed["isError"] is False

    async def test_nothing_held_says_so(self) -> None:
        listed = await _Gateway().read()
        assert listed["structuredContent"] == {"held": []}
        assert "No responses are held" in listed["content"][0]["text"]

    async def test_each_part_read_writes_one_row_for_the_tool_that_was_called(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert gateway.outcomes() == [("docs", GET, Outcome.OK), ("docs", GET, Outcome.OK)]
        assert gateway.audit.call_args.args[5] == "part 2/4"
        assert gateway.audit.call_args.kwargs["bytes_delivered"] > 0

    async def test_a_tool_that_may_write_is_never_called_again(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000), tool=SEND)
        assert "a tool that writes would act again" in first["content"][-1]["text"]
        await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert gateway.backend.await_count == 1


class TestBlock:
    async def test_a_flagged_part_is_refused_and_so_is_every_later_one(self) -> None:
        gateway = _Gateway(w600=_flagged())
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        await gateway.read(handle=handle, part=2)
        third = await gateway.read(handle=handle, part=3)
        text = third["content"][0]["text"]
        assert third["isError"] is False
        assert text.startswith("[TRENTINA] Refused part 3 of 4 of the")
        assert "(flagged by L2). Nothing from part 3 was delivered." in text
        assert "Parts 1 to 2 of it were delivered before this was found" in text
        assert "untrusted data" in text
        assert "Part 4 is withheld as well." in text
        assert "No other mode is available under your policy" in text
        assert "w600" not in str(third)
        assert third["_trentina_refusal"]["part"] == 3
        assert third["_trentina_warning"]["parts"] == 4

        judged = len(gateway.perimeter.calls)
        fourth = await gateway.read(handle=handle, part=4)
        assert fourth["isError"] is False
        assert (
            "part 3 was flagged by L2, so the response is withheld from there on"
            in (fourth["content"][0]["text"])
        )
        # Withheld on the response's mark, and judged all the same: the mode
        # decides what is delivered, never whether the layers run.
        assert len(gateway.perimeter.calls) == judged + 1
        assert "w900" not in str(fourth)
        assert gateway.outcomes()[-2:] == [
            ("docs", GET, Outcome.BLOCKED_DEFENSE),
            ("docs", GET, Outcome.BLOCKED_DEFENSE),
        ]

    async def test_parts_before_the_flag_can_still_be_read_again(self) -> None:
        gateway = _Gateway(w600=_flagged())
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        await gateway.read(handle=handle, part=2)
        await gateway.read(handle=handle, part=3)
        second = await gateway.read(handle=handle, part=2)
        assert second["isError"] is False
        assert second[paging.PART_KEY]["flagged_at"] == 3

    async def test_a_flagged_first_part_delivers_nothing(self) -> None:
        gateway = _Gateway(w5=_flagged())
        first = await gateway.call(_document(1_000))
        text = first["content"][0]["text"]
        assert first["isError"] is False
        assert "Refused part 1 of 4" in text
        assert "delivered before this was found" not in text
        assert "Parts 2 to 4 are withheld as well." in text
        assert "w5 " not in str(first)

    async def test_a_flagged_first_part_of_a_call_that_may_write_says_it_ran(self) -> None:
        gateway = _Gateway(w5=_flagged())
        first = await gateway.call(_document(1_000), tool=SEND)
        texts = [block["text"] for block in first["content"]]
        assert "was executed and the backend reported no error" in texts[0]
        assert "do not repeat the call" in texts[0]
        assert "Refused part 1 of 4" in texts[1]
        assert first["isError"] is False
        assert first["_trentina_refusal"]["executed"] is True

    async def test_redact_is_offered_when_the_policy_has_it(self) -> None:
        gateway = _Gateway(_profile(["block", "redact"]), w600=_flagged(alternatives=["redact"]))
        first = await gateway.call(_document(1_000))
        await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        third = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=3)
        assert (
            "Your policy allows retrying for this part and the rest with "
            f'{MODE_PARAM}={{"redact": "<what you need>"}} on {READER}.'
        ) in third["content"][0]["text"]

    async def test_a_gap_refuses_its_own_part_and_marks_nothing(self) -> None:
        gateway = _Gateway(w300=GAP)
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        second = await gateway.read(handle=handle, part=2)
        text = second["content"][0]["text"]
        assert second["isError"] is False
        assert "Refused part 2 of 4" in text and "(not fully judged: L3 unavailable)" in text
        assert "The gap is this part's, not the response's" in text
        assert "Ask for part 2 again." in text
        # The layers answer the next time: the part is delivered and the
        # response goes on, unmarked.
        gateway.perimeter.decisions.clear()
        again = await gateway.read(handle=handle, part=2)
        third = await gateway.read(handle=handle, part=3)
        assert again["isError"] is False and third["isError"] is False
        assert "flagged_at" not in third[paging.PART_KEY]
        assert third[paging.PART_KEY]["delivered"] == [1, 2, 3]


class TestOrder:
    async def test_a_part_is_not_read_before_the_parts_in_front_of_it(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        skipped = await gateway.read(handle=handle, part=4)
        text = skipped["content"][0]["text"]
        assert skipped["isError"] is False
        assert "Part 4" in text and "cannot be read yet" in text and "part 2 is next" in text
        assert f'{READER}(handle="{handle}", part=2)' in text
        assert len(gateway.perimeter.calls) == 1
        assert gateway.outcomes()[-1] == ("docs", GET, Outcome.DENIED_GUARD)
        # Nothing was released: the response is still there to read in order.
        assert (await gateway.read(handle=handle, part=2))["isError"] is False

    async def test_a_flagged_part_cannot_be_read_around(self) -> None:
        """block withholds a flagged part and every later one, whichever is asked first."""
        gateway = _Gateway(w300=_flagged())
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        third = await gateway.read(handle=handle, part=3)
        assert "cannot be read yet" in third["content"][0]["text"]
        second = await gateway.read(handle=handle, part=2)
        assert "Refused part 2 of 4" in second["content"][0]["text"]
        third = await gateway.read(handle=handle, part=3)
        assert "part 2 was flagged by L2" in third["content"][0]["text"]
        assert "w500" not in str(third)

    async def test_a_gap_holds_the_parts_behind_it(self) -> None:
        gateway = _Gateway(w300=GAP)
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        await gateway.read(handle=handle, part=2)
        third = await gateway.read(handle=handle, part=3)
        assert "part 2 is next" in third["content"][0]["text"]


class TestPolicyNow:
    async def test_a_mode_taken_away_by_a_reload_is_gone_for_a_held_response(self) -> None:
        gateway = _Gateway(_profile(["block", "flag"]))
        first = await gateway.call(_document(1_000), **{MODE_PARAM: "flag"})
        gateway.profile.defense.modes = ["block"]
        refused = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert refused["code"] == -32602
        assert len(gateway.perimeter.calls) == 1
        allowed = await gateway.read(
            handle=first[paging.PART_KEY]["handle"], part=2, **{MODE_PARAM: "block"}
        )
        assert allowed["isError"] is False
        assert gateway.perimeter.calls[-1]["mode"].value == "block"


class TestNotCut:
    """What the router does with a response the cut declines: what it always did."""

    @pytest.mark.parametrize("mode", ["block", "flag"])
    async def test_over_the_ceiling_takes_the_path_every_response_took(
        self, monkeypatch: pytest.MonkeyPatch, mode: str
    ) -> None:
        monkeypatch.setenv("TRENTINA_MAX_PARTS", "2")
        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "500")
        config_mod._config = None
        text = _document(601)
        gateway = _Gateway(_profile(["block", "flag"]))
        result = await gateway.call(text, **{MODE_PARAM: mode})
        (judged,) = gateway.perimeter.calls
        # Whole, to the perimeter, whose admission refuses it or reads its head.
        assert judged["content_blocks"] == [{"type": "text", "text": text}]
        assert judged.get("lead_in", "") == ""
        assert paging.PART_KEY not in result
        assert paging.listing("agent1") == []

    async def test_without_a_tokenizer_the_response_is_judged_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(paging, "token_starts", lambda _text: None)
        text = _document(1_000)
        gateway = _Gateway()
        result = await gateway.call(text)
        assert gateway.perimeter.calls[0]["content_blocks"] == [{"type": "text", "text": text}]
        assert paging.PART_KEY not in result


class TestFlag:
    async def test_a_flagged_part_is_delivered_with_its_warning(self) -> None:
        flagged = IngressDecision(warning={"flagged_by": "L3", "risk_level": "medium"})
        gateway = _Gateway(_profile(["flag", "block"]), w300=flagged)
        first = await gateway.call(_document(1_000), **{MODE_PARAM: "flag"})
        handle = first[paging.PART_KEY]["handle"]
        second = await gateway.read(handle=handle, part=2)
        texts = [block["text"] for block in second["content"]]
        assert second["isError"] is False
        assert "w300" in texts[1].split()
        assert texts[2].startswith("[TRENTINA WARNING] Part 2 was flagged by layer L3")
        assert texts[3].startswith("[TRENTINA] End of part 2 of 4.")
        assert second["_trentina_warning"]["flagged_by"] == "L3"

    async def test_later_parts_say_an_earlier_one_was_flagged(self) -> None:
        flagged = IngressDecision(warning={"flagged_by": "L3", "risk_level": "medium"})
        gateway = _Gateway(_profile(["flag", "block"]), w300=flagged)
        first = await gateway.call(_document(1_000), **{MODE_PARAM: "flag"})
        handle = first[paging.PART_KEY]["handle"]
        await gateway.read(handle=handle, part=2)
        third = await gateway.read(handle=handle, part=3)
        assert third["_trentina_warning"] == {"earlier_parts_flagged": [2]}
        assert third["isError"] is False

    async def test_a_read_that_names_no_mode_runs_in_the_first_calls(self) -> None:
        gateway = _Gateway(_profile(["block", "flag"]))
        first = await gateway.call(_document(1_000), **{MODE_PARAM: "flag"})
        await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert [call["mode"].value for call in gateway.perimeter.calls] == ["flag", "flag"]

    async def test_a_read_may_name_a_mode_its_policy_allows(self) -> None:
        gateway = _Gateway(_profile(["block", "flag"]))
        first = await gateway.call(_document(1_000))
        handle = first[paging.PART_KEY]["handle"]
        await gateway.read(handle=handle, part=2, **{MODE_PARAM: "flag"})
        assert gateway.perimeter.calls[-1]["mode"].value == "flag"

    async def test_a_read_may_not_name_a_mode_outside_its_policy(self) -> None:
        gateway = _Gateway()
        first = await gateway.call(_document(1_000))
        refused = await gateway.read(
            handle=first[paging.PART_KEY]["handle"], part=2, **{MODE_PARAM: "flag"}
        )
        assert refused["code"] == -32602
        assert len(gateway.perimeter.calls) == 1
        assert gateway.outcomes()[-1] == ("docs", GET, Outcome.DENIED_GUARD)


class TestRedact:
    async def test_the_question_runs_on_each_part(self) -> None:
        gateway = _Gateway(_profile(["block", "redact"]))
        gateway.perimeter.default = IngressDecision(warning=None, extraction='{"answer": "x"}')
        first = await gateway.call(_document(1_000), **{MODE_PARAM: {"redact": "the dates"}})
        second = await gateway.read(handle=first[paging.PART_KEY]["handle"], part=2)
        assert _body(first) == '{"answer": "x"}' == _body(second)
        assert [call["prompt"] for call in gateway.perimeter.calls] == ["the dates", "the dates"]
        assert "w10" not in str(first)


def test_the_instructions_say_how_parts_are_read() -> None:
    text = mode_instructions(_profile(["block", "flag"]))
    assert "arrives in parts" in text and "read_part" in text


def test_the_instructions_say_nothing_of_parts_with_paging_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRENTINA_PART_TOKENS", "0")
    config_mod._config = None
    assert "parts" not in mode_instructions(_profile(["block", "flag"]))


def test_the_first_part_reads_as_incomplete_and_the_briefing_as_a_fragment() -> None:
    parts = paging.cut(_document(1_000))
    assert parts is not None
    from trentina.defense import Provenance
    from trentina.modes import Mode

    paged = paging.hold(
        paging.Origin("agent1", "docs", GET, GET, is_error=False, acted=False),
        parts,
        mode=Mode.BLOCK,
        prompt=None,
        provenance=Provenance.EXTERNAL,
        l3_context=None,
        hidden=None,
    )
    assert "not the whole response" in paging.header(paged, 1)
    assert "repeat the end of part 1" in paging.part_briefing(paged, 2)
    assert "repeat" not in paging.part_briefing(paged, 1)
    assert "calling it again starts over" in paging.footer(paged, 1, "read_part")
