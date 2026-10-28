"""A hostile plugin is refused four ways: by type, by seal, by harness, by logsafe.

Phase 6 PR8, the capstone. The bet that makes an operator-reviewed plugin
tolerable — and, with the process tier, a less-familiar one — is that no single
mistake or malice gets through a single wall:

* TYPE — a factory that returns something that is not a ``Transform`` never
  enters the chain (``resolve_transform``).
* SEAL — a plugin cannot forge a verdict: the sealed trust types are a private
  import the conformance scan refuses, and the runtime token rejects
  construction outside the owning factory anyway.
* HARNESS — a plugin that inflates its output is capped (``Harnessed``).
* LOGSAFE — a plugin that logs the payload it was handed is caught by the
  conformance canary (``trentina.testing``).
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from trentina.core.stages import Judged
from trentina.gateway.errors import ProfileConfigError
from trentina.plugins import registry
from trentina.plugins.isolation import Harnessed
from trentina.plugins.registry import resolve_transform
from trentina.testing import conformance
from trentina.testing.suite import _Scan, scan_source
from trentina.transforms.base import (
    Applied,
    Declined,
    Failed,
    Transform,
    TransformContext,
    TransformResult,
)


class _FakeEntryPoint:
    def __init__(self, factory: object) -> None:
        self._factory = factory

    def load(self) -> object:
        return self._factory


def test_refused_by_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """A factory that returns a non-Transform is refused, not duck-typed in."""
    monkeypatch.setattr(
        registry, "discover", lambda _g: {"evil:verdict": _FakeEntryPoint(lambda _c: {"not": "it"})}
    )
    with pytest.raises(ProfileConfigError, match="did not return a"):
        resolve_transform("evil:verdict", {}, profile_name="p")


def test_refused_by_seal() -> None:
    """Forging a verdict is stopped twice: importing a sealed trust type is a
    private-trentina import the conformance scan refuses, and the runtime token
    rejects construction outside the owning factory."""
    scan = _Scan()
    scan_source("from trentina.core.stages import Judged\nJudged(1, 2)", scan)
    assert any(v.startswith("private-import:trentina.core") for v in scan.violations)

    with pytest.raises(TypeError, match="constructed only by"):
        Judged(object(), object())  # no seal token


def test_refused_by_harness() -> None:
    """A plugin that inflates its output past the cap is a Failed, not delivered."""

    class Amplify(Transform):
        name = "amplify"

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload * 100)

    result = asyncio.run(Harnessed(Amplify(), amplification=4).run("x" * 100, TransformContext()))
    assert isinstance(result, Failed)
    assert result.reason == "amplified"


def test_refused_by_logsafe(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin that logs the payload it was handed fails conformance."""
    monkeypatch.setattr("trentina.testing.suite.scan_imports", lambda _d: [])

    class Leak(Transform):
        name = "leak"

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            logging.getLogger("plugin").warning("processing %s", payload)
            return Declined("x")

    result = asyncio.run(conformance("evil:leak", Leak()))
    assert "logs-payload" in result.failures
