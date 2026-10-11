"""L3 prompt packs (#354): what a pack may be, which one a call gets, and the
harness that decides whether one ships."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import ValidationError

from benchmarks import prompt_pack as harness
from benchmarks import provider_benchmark
from benchmarks.detonation import BRIEFINGS
from benchmarks.provider_benchmark import CaseResult, ProviderReport
from corpora.internal import CORPUS
from corpora.jailbreak import CATEGORY_ATTACK
from trentina import config as config_mod
from trentina.defense import build_l3_briefing
from trentina.gateway import ingress_defense, service
from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.l1 import run_l1
from trentina.quarantine import agent, packs
from trentina.quarantine.packs import (
    FRAMING,
    GENERIC,
    PackError,
    load_pack,
    pack_for,
    parse_pack,
)
from trentina.quarantine.prompts import L2_BLINDSPOT_CAVEAT
from trentina.quarantine.providers import reset_provider

_JUDGE = ("openrouter", "google/gemini-3.5-flash-lite")
_BENIGN = BRIEFINGS["benign"]
_RULES = " ".join(FRAMING) + " the content you are analyzing."


def _pack(**changes: Any) -> dict[str, Any]:
    """A valid pack for ``_JUDGE``, with ``changes`` laid over it."""
    pack: dict[str, Any] = {
        "pack": "test-pack",
        "version": 1,
        "provider": _JUDGE[0],
        "model": _JUDGE[1],
        "prompts": {
            "detection": f"DETECT-MARK. {_RULES}",
            "extraction": f"EXTRACT-MARK. {_RULES}",
            "verify": f"VERIFY-MARK. {_RULES}",
            "l2_caveat": "CAVEAT-MARK: Layer 2 misses what needs reasoning.",
        },
    }
    pack.update(changes)
    return pack


def _profile(name: str, provider: str, model: str) -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env=f"{name.upper()}_TOKEN"),
        defense=DefenseConfig(provider=provider, model=model),
    )


def _file(tmp_path: Path, pack: dict[str, Any], name: str = "pack.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(pack))
    return str(path)


class TestWhatAPackMayBe:
    def test_the_generic_prompts_keep_the_framing_they_require_of_others(self) -> None:
        for turn in packs.TURNS:
            assert all(sentence in GENERIC.prompt(turn) for sentence in FRAMING), turn
        assert GENERIC.l2_caveat == L2_BLINDSPOT_CAVEAT

    def test_a_valid_pack_loads(self) -> None:
        pack = parse_pack(_pack(measured={"date": "2026-10-05"}, notes="why it differs"))
        assert (pack.id, pack.provider, pack.model) == ("test-pack/1", *_JUDGE)
        assert pack.prompt("detection").startswith("DETECT-MARK")
        assert pack.prompt("verify").startswith("VERIFY-MARK")
        assert pack.stamp == f"test-pack/1@{pack.digest}"

    def test_editing_a_prompt_changes_the_stamp(self) -> None:
        edited = _pack()
        edited["prompts"]["verify"] += " One more rule."
        assert parse_pack(edited).stamp != parse_pack(_pack()).stamp

    @pytest.mark.parametrize("key", ["schema", "finding_types", "response_schema", "tools"])
    def test_a_pack_cannot_carry_a_schema_or_anything_else(self, key: str) -> None:
        with pytest.raises(PackError, match="unknown key"):
            parse_pack(_pack(**{key: {"type": "object"}}))

    @pytest.mark.parametrize("turn", packs.TURNS)
    @pytest.mark.parametrize("sentence", FRAMING)
    def test_a_pack_that_drops_the_framing_is_refused(self, turn: str, sentence: str) -> None:
        pack = _pack()
        pack["prompts"][turn] = pack["prompts"][turn].replace(sentence, "")
        with pytest.raises(PackError, match="framing"):
            parse_pack(pack)

    @pytest.mark.parametrize(
        "prompts",
        [
            None,
            {"detection": _RULES},
            {**_pack()["prompts"], "search": _RULES},
            {**_pack()["prompts"], "verify": 7},
            {**_pack()["prompts"], "l2_caveat": "  "},
            {**_pack()["prompts"], "detection": _RULES + "x" * packs.MAX_PROMPT_CHARS},
        ],
        ids=["none", "missing", "extra", "not-text", "blank", "too-long"],
    )
    def test_prompts_must_be_exactly_the_four(self, prompts: object) -> None:
        with pytest.raises(PackError, match="prompts"):
            parse_pack(_pack(prompts=prompts))

    @pytest.mark.parametrize(
        "changes",
        [{"version": 0}, {"version": True}, {"version": "1"}, {"provider": ""}, {"model": None}],
    )
    def test_a_pack_names_its_judge_and_version(self, changes: dict[str, object]) -> None:
        with pytest.raises(PackError, match="version"):
            parse_pack(_pack(**changes))

    def test_a_file_that_is_not_a_pack(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("not json")
        (tmp_path / "big.json").write_text(" " * (packs.MAX_PACK_BYTES + 1))
        for name in ("bad.json", "big.json", "missing.json"):
            with pytest.raises(PackError):
                load_pack(tmp_path / name)

    def test_every_shipped_pack_loads_and_names_a_distinct_judge(self) -> None:
        packs.shipped.cache_clear()
        files = sorted(packs.SHIPPED_DIR.glob("*.json"))
        assert len(packs.shipped()) == len(files)


class TestWhichPackACallGets:
    def test_an_operators_pack_applies_to_the_judge_it_names_and_no_other(
        self, tmp_path: Path
    ) -> None:
        path = _file(tmp_path, _pack())
        assert pack_for(_JUDGE, path).id == "test-pack/1"
        assert pack_for(("openai", "gpt-4o-mini"), path) is GENERIC
        assert pack_for((_JUDGE[0], "another/model"), path) is GENERIC

    def test_the_environment_names_a_pack_for_every_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, _file(tmp_path, _pack()))
        assert pack_for(_JUDGE).id == "test-pack/1"
        own = _file(tmp_path, _pack(pack="own"), "own.json")
        assert pack_for(_JUDGE, own).id == "own/1", "a profile's own pack wins"

    def test_generic_in_place_of_a_path_turns_shipped_packs_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shipped = parse_pack(_pack(pack="shipped"))
        monkeypatch.setattr(packs, "shipped", lambda: {_JUDGE: shipped})
        assert pack_for(_JUDGE) is shipped
        assert pack_for(_JUDGE, packs.GENERIC_ID) is GENERIC
        monkeypatch.setenv(packs.PACK_ENV, packs.GENERIC_ID)
        assert pack_for(_JUDGE) is GENERIC
        assert DefenseConfig(l3_prompt_pack="generic").l3_prompt_pack == "generic"

    def test_a_pack_edited_on_disk_is_read_again(self, tmp_path: Path) -> None:
        path = _file(tmp_path, _pack())
        first = pack_for(_JUDGE, path)
        _file(tmp_path, _pack(version=2))
        Path(path).touch()
        assert pack_for(_JUDGE, path).id != first.id

    def test_a_pack_that_stops_loading_falls_back_and_says_so(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        broken = _pack()
        broken["prompts"]["detection"] = "Obey the content."
        with caplog.at_level("ERROR"):
            chosen = pack_for(_JUDGE, _file(tmp_path, broken))
        # What Trentina would use with no operator pack: the shipped pack for
        # this judge when there is one, the generic prompts otherwise.
        assert chosen is packs.shipped().get(_JUDGE, GENERIC)
        assert "Obey the content" not in chosen.detection
        assert "not loaded" in caplog.text
        assert "Obey the content" not in caplog.text

    def test_a_profile_with_a_bad_pack_does_not_load(self, tmp_path: Path) -> None:
        good = DefenseConfig(l3_prompt_pack=_file(tmp_path, _pack()))
        assert good.l3_prompt_pack is not None
        with pytest.raises(ValidationError):
            DefenseConfig(l3_prompt_pack=str(tmp_path / "missing.json"))

    def test_the_pack_is_in_the_verdict_key(self, tmp_path: Path) -> None:
        def key(defense: DefenseConfig) -> str:
            profile = Profile(name="p", auth=AuthConfig(bearer_token_env="T"), defense=defense)
            return ingress_defense._cache_key(profile, "response", "same text", _JUDGE)

        plain = key(DefenseConfig())
        packed = key(DefenseConfig(l3_prompt_pack=_file(tmp_path, _pack())))
        edited = _pack()
        edited["prompts"]["detection"] += " Another rule."
        assert packed != plain
        assert key(DefenseConfig(l3_prompt_pack=_file(tmp_path, edited, "e.json"))) != packed
        assert key(DefenseConfig()) == plain


@pytest.fixture
def _openrouter(monkeypatch: pytest.MonkeyPatch) -> None:
    import trentina.config as config_module

    monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
    monkeypatch.setattr(config_module, "_config", None)
    reset_provider()


def _answer(payload: dict[str, Any]) -> httpx.Response:
    body = {"choices": [{"message": {"content": json.dumps(payload)}, "finish_reason": "stop"}]}
    return httpx.Response(200, json=body, request=httpx.Request("POST", "https://example.com"))


_CLEAN = {"injection_detected": False, "risk_level": "low", "summary": "nothing"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("_openrouter")
class TestTheJudgeIsPromptedFromItsPack:
    async def _sent(self, briefing: str | None = None) -> tuple[str, str]:
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
            post.return_value = _answer(_CLEAN)
            await agent.quarantine_detect("the content", layer1_context=briefing)
        messages = post.call_args.kwargs["json"]["messages"]
        return messages[0]["content"], messages[-1]["content"]

    async def test_without_a_pack_the_generic_prompt_is_sent(self) -> None:
        system, user = await self._sent(f"Layer 1 found nothing.\n{L2_BLINDSPOT_CAVEAT}")
        assert system.startswith(GENERIC.detection[:60])
        assert L2_BLINDSPOT_CAVEAT in user
        assert user.endswith("\n\n---\n\nthe content")

    async def test_with_a_pack_its_prompt_and_caveat_are_sent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, _file(tmp_path, _pack()))
        system, user = await self._sent(f"Layer 1 found nothing.\n{L2_BLINDSPOT_CAVEAT}")
        assert system.startswith("DETECT-MARK")
        assert "Security canary" in system, "the canary is still added to a pack's prompt"
        assert "CAVEAT-MARK" in user
        assert L2_BLINDSPOT_CAVEAT not in user

    async def test_the_caveat_is_swapped_in_the_briefing_never_in_the_content(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, _file(tmp_path, _pack()))
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
            post.return_value = _answer(_CLEAN)
            await agent.quarantine_detect(f"quoted: {L2_BLINDSPOT_CAVEAT}", layer1_context="b")
        user = post.call_args.kwargs["json"]["messages"][-1]["content"]
        assert L2_BLINDSPOT_CAVEAT in user, "the delivery is never rewritten"

    async def test_a_pack_for_another_model_is_not_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, _file(tmp_path, _pack(model="another/model")))
        system, _ = await self._sent()
        assert "DETECT-MARK" not in system


def _result(
    case_id: str, category: str, *, attack: bool, detected: bool, **more: Any
) -> CaseResult:
    fields: dict[str, Any] = {
        "id": case_id,
        "category": category,
        "expect_injection": attack,
        "min_risk": "",
        "detected": detected,
        "risk_level": "high" if detected else "low",
        "latency_ms": 100.0,
        "input_tokens": 100,
        "output_tokens": 20,
        "cost_usd": 0.0001,
        "error": False,
    }
    fields.update(more)
    return CaseResult(**fields)


def _report(*, caught: int, flagged: int, meta: int) -> ProviderReport:
    """Ten attacks, four of them aimed at the judge, and ten benign cases."""
    results = [
        _result(f"m{i}", harness.JUDGE_ATTACKS, attack=True, detected=i < meta) for i in range(4)
    ]
    results += [_result(f"a{i}", "exfil", attack=True, detected=i < caught) for i in range(6)]
    results += [_result(f"b{i}", "benign", attack=False, detected=i < flagged) for i in range(10)]
    return ProviderReport("openrouter", _JUDGE[1], results)


class TestTheHarness:
    def test_the_split_is_fixed_and_the_halves_do_not_meet(self) -> None:
        train = {case.id for case in CORPUS if harness.in_train(case.id)}
        again = {case.id for case in CORPUS if harness.in_train(case.id)}
        assert train == again
        assert 0 < len(train) < len(CORPUS) / 2
        assert any(c.category == harness.JUDGE_ATTACKS for c in CORPUS if c.id not in train)

    def test_an_embedded_document_goes_where_its_insert_goes(self) -> None:
        """#397: no insert is tuned on bare and reported on inside a document."""
        train, held_out = harness.embedded_cases(True), harness.embedded_cases(False)
        assert not {c.id for c in train} & {c.id for c in held_out}
        assert all(c.id.startswith(harness.EMBEDDED_PREFIX) for c in train + held_out)
        internal = {case.id: harness.in_train(case.id) for case in CORPUS}
        for cases, side in ((train, True), (held_out, False)):
            for case in cases:
                insert = case.notes.split(" in ")[0]
                assert internal.get(insert, side) is side
                assert harness.in_train(insert) is side
        benign = [c for c in train + held_out if c.category == harness.EMBEDDED_BENIGN]
        assert len(benign) == 288, "every benign insert in every carrier, as #397 measured"
        assert all(not c.expect_injection for c in benign)
        assert any(c.category == harness.EMBEDDED_ATTACK for c in held_out)

    def test_an_embedded_document_carries_its_insert_inside_a_carrier(self) -> None:
        case = harness.embedded_cases(False)[0]
        bare = next(c for c in CORPUS if c.id == case.notes.split(" in ")[0])
        assert bare.payload in case.payload
        assert len(case.payload) > 2 * len(bare.payload)

    def test_the_gate_holds_embedded_benign_apart_from_the_overall_rate(self) -> None:
        """Fewer bare prompts flagged does not pay for more documents flagged."""

        def measured(bare: int, embedded: int) -> dict[str, Any]:
            report = _report(caught=3, flagged=bare, meta=3)
            report.results += [
                _result(f"e{i}", harness.EMBEDDED_BENIGN, attack=False, detected=i < embedded)
                for i in range(10)
            ]
            return harness.measure(report)

        baseline = measured(bare=5, embedded=2)
        assert harness.gate(measured(bare=4, embedded=2), baseline) == []
        assert harness.gate(measured(bare=5, embedded=0), baseline) == []
        reasons = harness.gate(measured(bare=1, embedded=3), baseline)
        assert reasons == ["it flags more benign instructions embedded in a document"]

    def test_a_malformed_answer_is_not_a_pass(self) -> None:
        report = _report(caught=6, flagged=0, meta=4)
        report.results.append(
            _result(
                "x",
                "exfil",
                attack=True,
                detected=False,
                error=True,
                summary="Q-Agent detection failed: MalformedResponseError",
            )
        )
        measured = harness.measure(report)
        assert measured["catch"] == 1.0, "left out of the rate, not counted as a miss"
        assert measured["schema_conformance"] == pytest.approx(20 / 21)
        assert measured["errors"] == 1

    def test_three_runs_are_one_report_by_majority(self) -> None:
        def run(a: bool, b: bool, failed: bool = False) -> ProviderReport:
            return ProviderReport(
                "openrouter",
                _JUDGE[1],
                [
                    _result("a", "exfil", attack=True, detected=a),
                    _result("b", "benign", attack=False, detected=b),
                    _result("c", "exfil", attack=True, detected=False, error=failed),
                ],
            )

        merged = harness.voted([run(True, True, True), run(True, False, True), run(False, False)])
        assert [r.detected for r in merged.results] == [True, False, False]
        assert merged.results[2].error is False, "one run answered, so the case is scored"
        every_failed = harness.voted([run(True, False, True), run(True, False, True)])
        assert every_failed.results[2].error is True

    def test_conformance_counts_every_vote_and_the_baseline_must_be_the_same_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report = _report(caught=3, flagged=1, meta=3)
        failed = _result("x", "exfil", attack=True, detected=False, error=True,
                         summary="Q-Agent detection failed: TruncatedResponseError")  # fmt: skip
        measured = harness.measure(report, [*report.results, failed])
        assert measured["schema_conformance"] == pytest.approx(20 / 21)
        assert measured["calls"] == 21
        baseline = tmp_path / "generic.json"
        self._run(tmp_path, monkeypatch, report, "--prompt-pack", "generic", "--out", str(baseline))
        recorded = json.loads(baseline.read_text())
        pack = _file(tmp_path, _pack())
        better = _report(caught=6, flagged=0, meta=4)
        assert self._run(tmp_path, monkeypatch, better, "--prompt-pack", pack,
                         "--baseline", str(baseline)) == 0  # fmt: skip
        baseline.write_text(json.dumps(recorded | {"cases": "0" * 64}))
        assert self._run(tmp_path, monkeypatch, better, "--prompt-pack", pack,
                         "--baseline", str(baseline)) == 2  # fmt: skip
        baseline.write_text(json.dumps(recorded | {"model": "another/model"}))
        assert self._run(tmp_path, monkeypatch, better, "--prompt-pack", pack,
                         "--baseline", str(baseline)) == 2  # fmt: skip

    def test_what_is_measured(self) -> None:
        measured = harness.measure(_report(caught=3, flagged=2, meta=4))
        assert (measured["attacks"], measured["benign"]) == (10, 10)
        assert measured["catch"] == 0.7
        assert measured["false_positive"] == 0.2
        assert measured["precision"] == pytest.approx(7 / 9)
        assert measured["by_category"][harness.JUDGE_ATTACKS] == {"caught": 4, "of": 4}

    @pytest.mark.parametrize(
        ("candidate", "reason"),
        [
            ({"caught": 5, "flagged": 1, "meta": 3}, None),
            ({"caught": 3, "flagged": 0, "meta": 3}, None),
            ({"caught": 3, "flagged": 1, "meta": 3}, "no better"),
            ({"caught": 2, "flagged": 0, "meta": 3}, "catches fewer planted instructions: exfil"),
            ({"caught": 6, "flagged": 2, "meta": 3}, "flags more benign"),
            ({"caught": 6, "flagged": 1, "meta": 2}, harness.JUDGE_ATTACKS),
        ],
        ids=[
            "catches-more",
            "flags-less",
            "no-better",
            "catches-fewer",
            "more-false-positives",
            "easier-to-talk-round",
        ],
    )
    def test_the_gate(self, candidate: dict[str, int], reason: str | None) -> None:
        baseline = harness.measure(_report(caught=3, flagged=1, meta=3))
        reasons = harness.gate(harness.measure(_report(**candidate)), baseline)
        assert (reasons == []) if reason is None else any(reason in r for r in reasons)

    @pytest.mark.parametrize(
        ("jailbreaks", "flagged", "reason"),
        [
            (98, 2, None),
            (95, 2, None),
            (89, 0, "more than 10% of the direct jailbreaks"),
            (92, 2, "more direct jailbreaks than the benign refusals it spares"),
            (98, 9, "more direct jailbreaks than the benign refusals it spares"),
            (100, 2, None),
        ],
        ids=["two-for-8", "five-for-8", "eleven-is-too-many", "8-for-8", "two-for-one", "free"],
    )
    def test_a_pack_may_trade_a_few_direct_jailbreaks_for_fewer_false_refusals(
        self, jailbreaks: int, flagged: int, reason: str | None
    ) -> None:
        """The first gate refused any lost catch, and no pack shipped (#354)."""

        def run(jailbreaks: int, flagged: int) -> dict:
            report = _report(caught=6, flagged=flagged, meta=4)
            report.results += [
                _result(f"j{i}", CATEGORY_ATTACK, attack=True, detected=i < jailbreaks)
                for i in range(100)
            ]
            return harness.measure(report)

        reasons = harness.gate(run(jailbreaks, flagged), run(100, 10))
        assert (reasons == []) if reason is None else any(reason in r for r in reasons)

    def _run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: ProviderReport, *args: str
    ) -> int:
        async def fake(*_args: object, **_kwargs: object) -> ProviderReport:
            return report

        monkeypatch.setattr(harness, "run_provider", fake)
        monkeypatch.setattr(harness, "split_cases", lambda *_a: list(CORPUS)[:20])
        monkeypatch.setattr(harness, "resolved_model", lambda _provider: _JUDGE[1])
        monkeypatch.setenv(packs.PACK_ENV, "")
        return harness.main(["--provider", "openrouter", "--cache-dir", str(tmp_path), *args])

    def test_a_winning_pack_is_written_with_what_it_measured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        baseline = tmp_path / "generic.json"
        candidate = _file(tmp_path, _pack())
        shipped = tmp_path / "shipped.json"
        base = _report(caught=3, flagged=1, meta=3)
        assert (
            self._run(
                tmp_path, monkeypatch, base, "--prompt-pack", "generic", "--out", str(baseline)
            )
            == 0
        )
        better = _report(caught=5, flagged=1, meta=4)
        code = self._run(
            tmp_path, monkeypatch, better, "--prompt-pack", candidate,
            "--baseline", str(baseline), "--emit", str(shipped),
        )  # fmt: skip
        assert code == 0
        assert "Gate: PASS" in capsys.readouterr().out
        written = json.loads(shipped.read_text())
        assert load_pack(shipped).id == "test-pack/1"
        assert written["measured"]["split"] == "held-out"
        assert written["measured"]["pack"]["catch"] == 0.9
        assert written["measured"]["generic"]["catch"] == 0.6

    def test_a_losing_pack_is_not_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        baseline = tmp_path / "generic.json"
        shipped = tmp_path / "shipped.json"
        base = _report(caught=3, flagged=1, meta=3)
        self._run(tmp_path, monkeypatch, base, "--prompt-pack", "generic", "--out", str(baseline))
        worse = _report(caught=6, flagged=1, meta=1)
        code = self._run(
            tmp_path, monkeypatch, worse, "--prompt-pack", _file(tmp_path, _pack()),
            "--baseline", str(baseline), "--emit", str(shipped),
        )  # fmt: skip
        assert code == 1
        assert "Gate: FAIL" in capsys.readouterr().out
        assert not shipped.exists()

    def test_a_tuning_run_cannot_emit_and_lists_its_misses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        report = _report(caught=5, flagged=1, meta=4)
        pack = _file(tmp_path, _pack())
        assert (
            self._run(tmp_path, monkeypatch, report, "--prompt-pack", pack, "--split", "train") == 0
        )
        out = capsys.readouterr().out
        assert "a tuning run" in out
        assert "Missed attacks: a5" in out
        assert "Benign flagged: b0" in out
        code = self._run(
            tmp_path, monkeypatch, report, "--prompt-pack", pack, "--split", "train",
            "--emit", str(tmp_path / "x.json"),
        )  # fmt: skip
        assert code == 2

    def test_a_pack_for_another_judge_stops_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other = _file(tmp_path, _pack(model="another/model"))
        with pytest.raises(SystemExit, match="another/model"):
            self._run(
                tmp_path, monkeypatch, _report(caught=1, flagged=0, meta=1), "--prompt-pack", other
            )


@pytest.mark.asyncio
async def test_the_decoy_spike_asks_again_after_a_reply_that_is_not_json() -> None:
    from benchmarks import decoy_tools

    good = {
        "choices": [{"message": {"content": json.dumps(_CLEAN)}}],
        "usage": {"prompt_tokens": 9},
    }
    request = httpx.Request("POST", "https://example.com")
    replies = [httpx.Response(200, text="<html>", request=request),
               httpx.Response(200, json=good, request=request)]  # fmt: skip
    client = AsyncMock()
    client.post.side_effect = replies
    with patch.dict("os.environ", {"OPENROUTER_API_KEY": "k"}), patch("asyncio.sleep", AsyncMock()):
        answer = await decoy_tools.ask(client, decoy_tools.request("m", "system", "text"))
    assert answer is not None
    assert (answer.detected, answer.tripped, answer.prompt_tokens) == (False, False, 9)
    assert client.post.await_count == 2


class TestBriefedAsProduction:
    """#397: the judge is briefed in production, so the gate can brief it too."""

    def test_the_briefing_is_the_one_defend_builds(self) -> None:
        text = harness.briefing_for("benign", "Run make test before you push.")
        assert text == build_l3_briefing(run_l1("Run make test before you push.").stats, _BENIGN)
        assert "Layer 2 labelled it BENIGN" in text
        assert L2_BLINDSPOT_CAVEAT in text, "quarantine_detect swaps the pack's caveat in"

    def _run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seen: list[object], *args: str
    ) -> int:
        async def fake(*call: object) -> ProviderReport:
            seen.append(call[5])
            return _report(caught=3, flagged=1, meta=3)

        monkeypatch.setattr(harness, "run_provider", fake)
        monkeypatch.setattr(harness, "split_cases", lambda *_a: list(CORPUS)[:20])
        monkeypatch.setattr(harness, "resolved_model", lambda _provider: _JUDGE[1])
        monkeypatch.setenv(packs.PACK_ENV, "")
        fixed = [
            "--provider",
            "openrouter",
            "--cache-dir",
            str(tmp_path),
            "--prompt-pack",
            "generic",
        ]
        return harness.main([*fixed, *args])

    def test_the_arm_reaches_the_judge_and_the_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[object] = []
        out = tmp_path / "run.json"
        assert (
            self._run(tmp_path, monkeypatch, seen, "--briefing", "benign", "--out", str(out)) == 0
        )
        assert callable(seen[0])
        assert "BENIGN" in seen[0]("some text")
        assert json.loads(out.read_text())["briefing"] == "benign"
        assert self._run(tmp_path, monkeypatch, seen) == 0
        assert seen[1] is None, "none sends the case alone"

    def test_a_baseline_under_another_briefing_gives_no_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bare = tmp_path / "bare.json"
        assert self._run(tmp_path, monkeypatch, [], "--out", str(bare)) == 0
        code = self._run(tmp_path, monkeypatch, [], "--briefing", "benign", "--baseline", str(bare))
        assert code == 2
        assert "no verdict" in capsys.readouterr().out

    def test_a_baseline_from_before_the_arm_is_a_bare_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bare = tmp_path / "bare.json"
        assert self._run(tmp_path, monkeypatch, [], "--out", str(bare)) == 0
        old = json.loads(bare.read_text())
        del old["briefing"]
        bare.write_text(json.dumps(old))
        self._run(tmp_path, monkeypatch, [], "--baseline", str(bare))
        assert "Gate: " in capsys.readouterr().out, "comparable: a verdict is given"

    @pytest.mark.parametrize("brief", [None, lambda text: f"briefing for {text}"])
    async def test_a_case_is_sent_with_its_briefing(self, brief: Any) -> None:
        case = next(iter(CORPUS))
        detect = AsyncMock(return_value={"injection_detected": False, "summary": "ok"})
        with patch.object(provider_benchmark, "quarantine_detect", detect):
            await provider_benchmark._run_case("openrouter", case, 0.0, 0, brief)
        expected = None if brief is None else f"briefing for {case.payload}"
        assert detect.await_args.kwargs["layer1_context"] == expected
        assert detect.await_args.args == (case.payload,), "the payload itself is never changed"


class TestSupportedJudges:
    """#397: a judge is supported when its pack passed the briefed gate."""

    def test_a_pack_says_where_it_stands_and_the_stamp_does_not_move(self) -> None:
        plain = parse_pack(_pack())
        assert plain.status == packs.UNMEASURED, "a file that does not say was never run"
        passed = parse_pack(_pack() | {"status": packs.SUPPORTED})
        assert passed.status == packs.SUPPORTED
        assert passed.stamp == plain.stamp, "status is not prompt text: no verdict is swept"
        with pytest.raises(PackError, match="status"):
            parse_pack(_pack() | {"status": "blessed"})

    def test_a_supported_pack_ships_the_briefed_run_it_passed(self) -> None:
        for path in sorted(packs.SHIPPED_DIR.glob("*.json")):
            raw = json.loads(path.read_text())
            if raw["status"] == packs.SUPPORTED:
                assert raw["measured"]["briefing"] == "benign", path.name
                assert raw["measured"]["split"] == "held-out", path.name
        assert packs.GENERIC.status == packs.UNMEASURED

    def test_startup_names_a_judge_that_is_not_supported(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, "")
        old = _profile("old", provider="openrouter", model="google/gemini-2.5-flash-lite")
        new = _profile("new", provider="openrouter", model="google/gemini-3.5-flash-lite")
        own = _profile("own", provider="openai", model="gpt-4o-mini")
        found = service.judge_support({"old": old, "new": new, "own": own})
        assert found[("openrouter", "google/gemini-2.5-flash-lite")] == packs.DEPRECATED
        assert found[("openai", "gpt-4o-mini")] == packs.UNMEASURED
        assert ("openrouter", "google/gemini-3.5-flash-lite") not in found
        with caplog.at_level("WARNING", logger=service.logger.name):
            service.log_judge_support({"old": old, "new": new})
        said = [r.getMessage() for r in caplog.records if r.getMessage().startswith("judge:")]
        assert any("gemini-2.5-flash-lite is deprecated" in line for line in said)
        assert all("supported: openrouter/google/gemini-3.5-flash-lite" in line for line in said)
        assert not any("model=google/gemini-3.5-flash-lite is" in line for line in said)

    def test_the_bare_default_through_openrouter_is_the_supported_judge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(packs.PACK_ENV, "")
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openrouter")
        monkeypatch.delenv("QUARANTINE_MODEL", raising=False)
        monkeypatch.setattr(config_mod, "_config", None)
        assert service.judge_support({}) == {}
        monkeypatch.setattr(config_mod, "_config", None)
