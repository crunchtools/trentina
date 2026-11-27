"""The boundary-review eval suite is well-formed, and its grader grades (#90).

No network: the model calls themselves are run by hand with ANTHROPIC_API_KEY
set (docs/by-hand.md). This keeps EVAL.yml, the fixtures and the
grading rules from rotting in between.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

import httpx
import pytest

from tests.boundary_review_eval import (
    DEFAULT_EVAL,
    REPO,
    Client,
    EvalSetupError,
    cheap_match,
    load_suite,
    over_severity,
    run,
    run_case,
)

SKILL = DEFAULT_EVAL.parent / "SKILL.md"


def _finding(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "file": "x.py",
        "line": 1,
        "obligation": "O1",
        "verdict": "UNSOUND",
        "severity": "high",
        "title": "",
        "evidence": [],
        "scenario": "",
        "fix": "",
    }
    return {**base, **kw}


class TestSuite:
    def test_loads_with_enough_cases(self) -> None:
        suite = load_suite(DEFAULT_EVAL)
        kinds = [c["kind"] for c in suite["cases"]]
        assert kinds.count("known_bad") >= 6
        assert kinds.count("control") >= 2

    def test_every_fixture_exists_and_parses(self) -> None:
        suite = load_suite(DEFAULT_EVAL)
        base = (DEFAULT_EVAL.parent / suite["fixtures_dir"]).resolve()
        assert base.is_relative_to(REPO)
        for case in suite["cases"]:
            ast.parse((base / case["fixture"]).read_text())

    def test_every_expected_obligation_is_defined_in_the_skill(self) -> None:
        skill = SKILL.read_text()
        suite = load_suite(DEFAULT_EVAL)
        for case in suite["cases"]:
            for item in case.get("must_find", []):
                for code in item["obligations"]:
                    assert f"| {code} " in skill, (case["name"], code)

    def test_fixtures_carry_no_history(self) -> None:
        """The answer is not in the file: no issue number, no "Reduced from" (#300)."""
        suite = load_suite(DEFAULT_EVAL)
        base = (DEFAULT_EVAL.parent / suite["fixtures_dir"]).resolve()
        for case in suite["cases"]:
            text = (base / case["fixture"]).read_text()
            assert not re.search(r"#\d{2,}|Reduced from|\bbefore the fix\b", text), case["name"]

    def test_skill_frontmatter_names_its_directory(self) -> None:
        head = SKILL.read_text().split("---")[1]
        assert "name: trentina-boundary-review" in head
        assert "allowed-tools:" in head


class TestGrader:
    def test_obligation_code_matches(self) -> None:
        assert cheap_match({"obligations": ["O4"]}, [_finding(obligation="O4 OUTCOME-FIDELITY")])

    def test_keyword_matches_case_insensitively(self) -> None:
        found = [_finding(obligation="O9", title="Refusal echoes Detected_At")]
        assert cheap_match({"obligations": ["O2"], "keywords": ["detected_at"]}, found)

    def test_neither_is_a_miss(self) -> None:
        assert not cheap_match({"obligations": ["O6"], "keywords": ["redirect"]}, [_finding()])

    def test_severity_ceiling_is_inclusive(self) -> None:
        found = [_finding(severity="low"), _finding(severity="medium"), _finding(severity="high")]
        assert [f["severity"] for f in over_severity(found, "medium")] == ["medium", "high"]

    async def test_refuses_to_run_without_a_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(EvalSetupError, match="ANTHROPIC_API_KEY"):
            await run(DEFAULT_EVAL, [])


def _message(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        json={"stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(body)}]},
    )


SUITE = load_suite(DEFAULT_EVAL)
CASES = {c["name"]: c for c in SUITE["cases"]}


async def _run(
    name: str,
    findings: list[dict[str, Any]],
    judge_yes: bool,
    spurious: tuple[int, ...] = (),
    seen: list[str] | None = None,
    skip: int | None = None,
) -> Any:
    """Run one case against a mocked API: the reviewer returns ``findings``,
    the judge answers ``judge_yes`` for every id it is asked about and calls
    the findings at ``spurious`` indexes spurious. ``seen`` collects the
    reviewer's user turn; the judge leaves the finding at ``skip`` ungraded."""

    def api(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["x-api-key"] == "k"
        assert body["output_config"]["format"]["type"] == "json_schema"
        content = body["messages"][0]["content"]
        if body["model"] == SUITE["reviewer_model"]:
            assert "trentina-boundary-review" in body["system"]
            if seen is not None:
                seen.append(content)
            return _message({"findings": findings, "proved": []})
        ids = re.findall(r"id=([\w-]+)", content)
        answer: dict[str, Any] = {
            "verdicts": [{"id": i, "yes": judge_yes, "reason": ""} for i in ids]
        }
        if "extras" in body["output_config"]["format"]["schema"]["properties"]:
            answer["extras"] = [
                {"index": i, "valid": i not in spurious, "reason": ""}
                for i in range(len(findings))
                if i != skip
            ]
        return _message(answer)

    skill = SKILL.read_text()
    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as http:
        return await run_case(Client("k", http), SUITE, skill, CASES[name], DEFAULT_EVAL.parent)


class TestMockedRun:
    """One case end to end over a mocked Messages API: request shape and grading."""

    async def test_a_known_bad_case_found_passes(self) -> None:
        found = [_finding(obligation="O5", title="classify blocks the event loop")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, judge_yes=True)
        assert result.passed, result.notes

    async def test_the_judge_can_veto_a_keyword_hit(self) -> None:
        found = [_finding(obligation="O5", title="unrelated regex")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, judge_yes=False)
        assert not result.passed

    async def test_a_control_flagged_fails(self) -> None:
        found = [_finding(obligation="O2", severity="high", title="head only")]
        result = await _run("ctrl_01_flag_mode_truncated_head", found, judge_yes=False)
        assert not result.passed

    async def test_a_network_failure_is_a_setup_error(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as http:
            with pytest.raises(EvalSetupError, match="ConnectError"):
                await Client("k", http).structured(
                    model="m", system="s", user="u", schema={}, max_tokens=1
                )

    async def test_a_control_left_alone_passes(self) -> None:
        found = [_finding(obligation="O13", severity="low", title="missing TRUST comment")]
        result = await _run("ctrl_01_flag_mode_truncated_head", found, judge_yes=False)
        assert result.passed, result.notes

    async def test_the_reviewer_never_sees_the_fixture_name(self) -> None:
        seen: list[str] = []
        await _run("ctrl_01_flag_mode_truncated_head", [], judge_yes=False, seen=seen)
        assert 'path="case_09.py"' in seen[0]
        assert "ctrl" not in seen[0]
        assert "boundary-review/" not in seen[0]

    async def test_a_line_outside_the_file_fails(self) -> None:
        found = [_finding(obligation="O5", line=555, title="classify blocks the event loop")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, judge_yes=True)
        assert not result.passed
        assert any("outside the file" in n for n in result.notes)

    async def test_a_spurious_extra_at_medium_fails_a_known_bad_case(self) -> None:
        found = [
            _finding(obligation="O5", title="classify blocks the event loop"),
            _finding(obligation="O9", severity="medium", title="invented channel"),
        ]
        result = await _run("bad_02_sync_classify_in_coroutine", found, True, spurious=(1,))
        assert not result.passed
        assert result.spurious == 1

    async def test_a_spurious_low_extra_is_counted_not_failed(self) -> None:
        found = [
            _finding(obligation="O5", title="classify blocks the event loop"),
            _finding(obligation="O13", severity="low", title="missing TRUST comment"),
        ]
        result = await _run("bad_02_sync_classify_in_coroutine", found, True, spurious=(1,))
        assert result.passed, result.notes
        assert result.spurious == 1

    async def test_a_finding_the_judge_skips_fails(self) -> None:
        found = [_finding(obligation="O5", title="classify blocks the event loop")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, True, skip=0)
        assert not result.passed
        assert any("ungraded" in n for n in result.notes)

    async def test_a_fixture_outside_the_repository_is_refused(self) -> None:
        case = {**CASES["bad_02_sync_classify_in_coroutine"], "fixture": "/etc/hostname"}
        async with httpx.AsyncClient(transport=httpx.MockTransport(_unreachable)) as http:
            with pytest.raises(EvalSetupError, match="outside the repository"):
                await run_case(Client("k", http), SUITE, "", case, DEFAULT_EVAL.parent)


def _unreachable(_request: httpx.Request) -> httpx.Response:
    raise AssertionError("no request may be sent for a refused fixture")
