"""The in-process harness bounds every plugin: deadline, result type, amplification.

Phase 6 PR5. A plugin's `run` is wrapped in `Harnessed` before it reaches the
composition. A hang, a wrong return, an amplifying rewrite or a raise each
become a `Failed` — a value the composition already knows how to handle —
rather than a stall, a surprise, or a propagated exception. The contract
attributes pass through, so the channel/kind locks and the composition are blind
to the wrapping.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from trentina.channels import Channel, Kind
from trentina.plugins.isolation import Harnessed
from trentina.transforms.base import Applied, Cost, Declined, Failed, Transform, TransformContext

if TYPE_CHECKING:
    import pytest


class _Inner(Transform):
    """A configurable stand-in plugin."""

    name = "inner"
    cost = Cost.METERED
    kind = Kind.TEXT
    channels = frozenset({Channel.TOOL, Channel.TOOL_DESCRIPTION})

    def __init__(self, behaviour: str) -> None:
        self._behaviour = behaviour

    async def run(self, payload: str, _ctx: TransformContext, /) -> object:
        if self._behaviour == "amplify":
            return Applied(payload * 10)
        if self._behaviour == "bad":
            return {"not": "a result"}
        if self._behaviour == "bad_content":
            return Applied(None)  # content is not a string
        if self._behaviour == "raise":
            raise RuntimeError("boom")
        return Applied(payload.upper())


def _run(h: Harnessed, payload: str) -> object:
    return asyncio.run(h.run(payload, TransformContext()))


def test_contract_attributes_pass_through() -> None:
    h = Harnessed(_Inner("ok"))
    assert h.name == "inner"
    assert h.cost is Cost.METERED
    assert h.kind is Kind.TEXT
    assert h.channels == frozenset({Channel.TOOL, Channel.TOOL_DESCRIPTION})
    assert h.api_version == 1


def test_a_clean_result_passes_through() -> None:
    result = _run(Harnessed(_Inner("ok")), "abc")
    assert isinstance(result, Applied)
    assert result.content == "ABC"


def test_an_amplifying_result_becomes_failed() -> None:
    result = _run(Harnessed(_Inner("amplify"), amplification=4), "x" * 100)
    assert isinstance(result, Failed)
    assert result.reason == "amplified"


def test_amplification_is_measured_in_utf8_bytes_at_the_boundary() -> None:
    """At exactly the cap, pass; one byte over, fail — measured in UTF-8 bytes,
    not characters (a multibyte payload must not slip the cap)."""

    class Fixed(_Inner):
        def __init__(self, out: str) -> None:
            super().__init__("ok")
            self._out = out

        async def run(self, payload: str, _ctx: TransformContext, /) -> object:
            return Applied(self._out)

    # Input is 2 bytes ("é"); cap 4 -> 8 bytes allowed. 8 bytes passes, 9 fails.
    at_limit = _run(Harnessed(Fixed("x" * 8), amplification=4), "é")
    assert isinstance(at_limit, Applied)
    over = _run(Harnessed(Fixed("x" * 9), amplification=4), "é")
    assert isinstance(over, Failed)
    assert over.reason == "amplified"


def test_a_non_result_becomes_failed() -> None:
    result = _run(Harnessed(_Inner("bad")), "abc")
    assert isinstance(result, Failed)
    assert result.reason == "not_a_result"


def test_an_applied_with_non_string_content_becomes_failed() -> None:
    result = _run(Harnessed(_Inner("bad_content")), "abc")
    assert isinstance(result, Failed)
    assert result.reason == "not_a_result"


def test_a_raise_becomes_failed() -> None:
    result = _run(Harnessed(_Inner("raise")), "abc")
    assert isinstance(result, Failed)
    assert result.reason == "error"


def test_a_declined_passes_through() -> None:
    class Decliner(_Inner):
        async def run(self, payload: str, _ctx: TransformContext, /) -> object:
            return Declined("not my shape")

    result = _run(Harnessed(Decliner("ok")), "abc")
    assert isinstance(result, Declined)


def test_a_failed_passes_through() -> None:
    """A plugin's own `Failed` is carried through unchanged — a floor plugin's
    failure must still refuse the call, not be masked by the harness."""

    class Failer(_Inner):
        async def run(self, payload: str, _ctx: TransformContext, /) -> object:
            return Failed("my own reason")

    result = _run(Harnessed(Failer("ok")), "abc")
    assert isinstance(result, Failed)
    assert result.reason == "my own reason"


def test_a_raise_logs_the_kind_not_the_message(caplog: pytest.LogCaptureFixture) -> None:
    """The caught exception is logged by its KIND, never its message (#262), so
    a plugin cannot smuggle the payload into the log by raising with it."""

    class Secret(_Inner):
        async def run(self, payload: str, _ctx: TransformContext, /) -> object:
            raise RuntimeError("SUPERSECRET-" + payload)

    with caplog.at_level(logging.WARNING, logger="trentina.plugins.isolation"):
        result = _run(Harnessed(Secret("ok")), "zqx7secretpayload")
    assert isinstance(result, Failed)
    assert "zqx7secretpayload" not in caplog.text
    assert "SUPERSECRET" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_registry_wraps_a_plugin_in_the_harness() -> None:
    """The real fixture resolves to a Harnessed transform through the registry;
    an in-tree transform (named without a colon) is not wrapped."""
    from trentina.gateway.drivers import build_transforms
    from trentina.gateway.profile import PreProcessConfig

    built = build_transforms(
        PreProcessConfig(processors=["petit-plus:dedupe"]), channel=Channel.TOOL
    )
    assert isinstance(built[0], Harnessed)
    assert built[0].name == "dedupe"

    in_tree = build_transforms(PreProcessConfig(processors=["detect"]), channel=Channel.TOOL)
    assert not isinstance(in_tree[0], Harnessed)
