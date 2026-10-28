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
from trentina.plugins.isolation import Harnessed, Isolated, _result_from_worker
from trentina.transforms.base import Applied, Cost, Declined, Failed, Transform, TransformContext
from trentina.unpack import child

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


def _build(ref: str) -> object:
    from trentina.gateway.drivers import build_transforms
    from trentina.gateway.profile import PreProcessConfig

    return build_transforms(PreProcessConfig(processors=[ref]), channel=Channel.TOOL)[0]


def test_registry_isolates_a_plugin_by_default() -> None:
    """A plugin resolves to the process tier (Isolated) by default; an in-tree
    transform (no colon) is unwrapped."""
    built = _build("petit-plus:dedupe")
    assert isinstance(built, Isolated)
    assert built.name == "dedupe"
    assert not isinstance(_build("detect"), (Isolated, Harnessed))


def test_inline_opt_down_uses_the_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    """TRENTINA_PLUGIN_INLINE opts a plugin down to the in-process harness."""
    monkeypatch.setenv("TRENTINA_PLUGIN_INLINE", "1")
    assert isinstance(_build("petit-plus:dedupe"), Harnessed)


class TestWorkerResultMapping:
    def test_phrases_map_to_failed(self) -> None:
        assert _result_from_worker(child.DEADLINE) == Failed("deadline")
        assert _result_from_worker(child.NO_SLOT) == Failed("no_slot")
        assert _result_from_worker(child.NOT_STARTED) == Failed("not_started")
        assert _result_from_worker(child.FAILED) == Failed("error")
        assert _result_from_worker(child.TOO_LARGE) == Failed("amplified")

    def test_json_body_maps_to_the_outcome(self) -> None:
        applied = _result_from_worker(b'{"kind":"applied","content":"x","details":{}}')
        assert applied == Applied("x")
        assert _result_from_worker(b'{"kind":"declined","reason":"r"}') == Declined("r")
        assert _result_from_worker(b'{"kind":"failed","reason":"r"}') == Failed("r")

    def test_malformed_body_is_failed_error(self) -> None:
        assert _result_from_worker(b"not json") == Failed("error")
        assert _result_from_worker(b'{"kind":"invalid"}') == Failed("error")


def test_isolated_runs_a_plugin_end_to_end() -> None:
    """The real fixture runs in a child process and comes back Applied — the
    whole process-isolation path."""
    built = _build("petit-plus:dedupe")
    result = asyncio.run(built.run("a\na\nb", TransformContext()))
    assert isinstance(result, Applied)
    assert result.content == "a\nb"


def test_the_worker_environment_holds_no_credential() -> None:
    """The child the worker runs in carries only the import path, no secret."""
    env = child.environment()
    assert not any("KEY" in k or "TOKEN" in k or "SECRET" in k for k in env)
