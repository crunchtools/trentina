"""`trentina.testing` — the public conformance suite for plugin authors.

Phase 6 PR4. Two halves: the static, load-bearing `scan_imports` (the import
boundary) and the full async `conformance` (behavioural probes over a built
transform). The benign fixture `petit-plus:dedupe` must pass both; a plugin
that violates the import boundary or misbehaves must fail by a NAMED check.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from trentina.testing import conformance, run_transform, scan_imports
from trentina.testing.suite import _Scan, scan_source
from trentina.transforms.base import Applied, Declined, Transform, TransformContext, TransformResult

if TYPE_CHECKING:
    import pytest

FIXTURE_REF = "petit-plus:dedupe"


def _violations(source: str) -> list[str]:
    scan = _Scan()
    scan_source(source, scan)
    return scan.violations


class TestImportScan:
    def test_benign_fixture_has_no_violations(self) -> None:
        assert scan_imports("petit-plus") == []

    def test_public_imports_are_allowed(self) -> None:
        source = (
            "from trentina.transforms.base import Transform\n"
            "from trentina.testing import conformance\n"
            "import trentina.transports.base\n"
        )
        assert _violations(source) == []

    def test_private_trentina_import_is_a_violation(self) -> None:
        assert _violations("from trentina.core.gate import gate") == [
            "private-import:trentina.core.gate"
        ]
        assert _violations("import trentina.plugins.registry") == [
            "private-import:trentina.plugins.registry"
        ]
        # The bare package, without `.base`, is private too.
        assert _violations("import trentina.transforms") == ["private-import:trentina.transforms"]

    def test_network_and_subprocess_imports_are_violations(self) -> None:
        assert _violations("import httpx") == ["forbidden-import:httpx"]
        assert _violations("import socket") == ["forbidden-import:socket"]
        assert _violations("from subprocess import run") == ["forbidden-import:subprocess"]
        assert _violations("from urllib.request import urlopen") == ["forbidden-import:urllib"]

    def test_unparseable_source_is_a_violation(self) -> None:
        assert _violations("def (:::") == ["unparseable-source"]

    def test_not_installed_distribution(self) -> None:
        assert scan_imports("no-such-distribution-xyz") == ["not-installed"]


class TestConformance:
    def test_benign_fixture_passes(self) -> None:
        from petit_plus import make

        result = asyncio.run(conformance(FIXTURE_REF, make({})))
        assert result.ok, result.failures

    def test_run_transform_helper(self) -> None:
        from petit_plus import make

        result = asyncio.run(run_transform(make({}), "a\na\nb"))
        assert isinstance(result, Applied)
        assert result.content == "a\nb"

    def test_a_plugin_that_logs_the_payload_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _dist: [])

        class Leaky(Transform):
            name = "leaky"

            async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
                logging.getLogger("plugin").warning("processing %s", payload)
                return Declined("x")

        result = asyncio.run(conformance("x:leaky", Leaky()))
        assert "logs-payload" in result.failures

    def test_a_plugin_that_amplifies_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _dist: [])

        class Amplify(Transform):
            name = "amplify"

            async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
                return Applied(payload * 100)

        result = asyncio.run(conformance("x:amplify", Amplify()))
        assert "amplifies" in result.failures

    def test_a_plugin_that_raises_on_input_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _dist: [])

        class Crashes(Transform):
            name = "crashes"

            async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
                raise RuntimeError("boom")

        result = asyncio.run(conformance("x:crashes", Crashes()))
        assert any(f.startswith("raised-on-empty") for f in result.failures)

    def test_a_name_mismatch_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _dist: [])

        class Wrong(Transform):
            name = "not-the-entry-point"

            async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
                return Declined("x")

        result = asyncio.run(conformance("x:expected", Wrong()))
        assert "name-mismatch" in result.failures

    def test_malformed_applied_on_amplify_is_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An `Applied` whose content is not a string is flagged, not crashed on."""
        monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _dist: [])

        class BadApplied(Transform):
            name = "bad"

            async def run(self, payload: str, _ctx: TransformContext, /) -> object:
                return Applied(None)

        result = asyncio.run(conformance("x:bad", BadApplied()))
        assert "bad-result-on-amplify" in result.failures


class TestScanBranches:
    def test_no_files_distribution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("trentina.testing.suite.im.files", lambda _dist: [])
        assert scan_imports("whatever") == ["no-files"]

    def test_no_python_source_does_not_pass_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A distribution with files but no readable .py source is a violation,
        not a silent pass — the import scan does not fail open."""

        class _CompiledOnly:
            suffix = ".so"

        monkeypatch.setattr("trentina.testing.suite.im.files", lambda _dist: [_CompiledOnly()])
        assert scan_imports("whatever") == ["no-python-source"]
