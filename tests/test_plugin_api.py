"""The out-of-tree transform plugin registry: discovery, resolution, fail-closed.

Phase 6. A transform plugin is an installed distribution exposing a factory in
the `trentina.transforms.v1` entry-point group. The fixture `petit-plus:dedupe`
(`tests/fixtures/plugins/petit_plus`, a dev dependency) is the benign worked
example; these tests drive the registry against it and against every refusal
path an operator's typo or a bad plugin would hit — each a ProfileConfigError
that NAMES the operator-authored thing, because a config-load refusal is read
by an operator, not an agent.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from trentina.channels import Channel
from trentina.gateway.drivers import build_transforms
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.profile import MatrixPreProcessConfig, PreProcessConfig, ToolPreProcess
from trentina.plugins import registry
from trentina.plugins.registry import TRANSFORM_GROUP, discover, resolve_transform
from trentina.transforms.base import Applied, Transform, TransformContext, TransformResult

FIXTURE_REF = "petit-plus:dedupe"


class _FakeEntryPoint:
    """Stands in for an installed entry point whose factory the test controls."""

    def __init__(self, factory: object) -> None:
        self._factory = factory

    def load(self) -> object:
        return self._factory


def test_fixture_is_discoverable() -> None:
    """The dev-installed fixture shows up under its `dist:name` key."""
    assert FIXTURE_REF in discover(TRANSFORM_GROUP)


def test_profile_accepts_a_plugin_ref() -> None:
    """A `dist:name` ref passes the PluginRef shape and rides in the chain."""
    assert PreProcessConfig(processors=[FIXTURE_REF]).processors == [FIXTURE_REF]


def test_per_tool_override_rejects_a_plugin_ref() -> None:
    """A plugin is named only at the operator-held profile/channel level, never
    in a per-tool override an agent could sit closer to."""
    with pytest.raises(ValidationError):
        ToolPreProcess(processors=[FIXTURE_REF])
    with pytest.raises(ValidationError):
        ToolPreProcess(required=[FIXTURE_REF])
    assert ToolPreProcess(processors=["detect"]).processors == ["detect"]


def test_profile_still_rejects_a_typoed_builtin() -> None:
    """A bare name that is neither a built-in nor shaped like a ref is refused
    at YAML load, exactly as before plugins existed — the typo trap holds."""
    with pytest.raises(ValidationError):
        PreProcessConfig(processors=["detct"])


def test_build_transforms_resolves_and_runs_the_plugin() -> None:
    """The registry builds the plugin, the channel/kind locks pass it, and it
    is a real transform that does its job."""
    built = build_transforms(PreProcessConfig(processors=[FIXTURE_REF]), channel=Channel.TOOL)
    assert len(built) == 1
    assert isinstance(built[0], Transform)
    assert built[0].name == "dedupe"
    result = asyncio.run(built[0].run("a\na\nb", TransformContext()))
    assert isinstance(result, Applied)
    assert result.content == "a\nb"


def test_unknown_distribution_is_refused_by_name() -> None:
    with pytest.raises(ProfileConfigError, match="is not installed"):
        resolve_transform("no-such-dist:x", {}, profile_name="p")


def test_known_distribution_unknown_entry_is_refused_by_name() -> None:
    with pytest.raises(ProfileConfigError, match="exposes no transform"):
        resolve_transform("petit-plus:nope", {}, profile_name="p")


def test_plugin_refused_on_the_wrong_kind_channel() -> None:
    """`dedupe` is a TEXT transform; the matrix channel supplies DOCUMENT, so
    the lock refuses it at load rather than failing mid-request."""
    with pytest.raises(ProfileConfigError):
        build_transforms(MatrixPreProcessConfig(processors=[FIXTURE_REF]), channel=Channel.MATRIX)


def test_plugin_returning_non_transform_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A factory that returns something other than a Transform is refused by
    name, not passed into the chain as a duck-typed stand-in."""
    monkeypatch.setattr(
        registry, "discover", lambda _group: {"x:y": _FakeEntryPoint(lambda _c: object())}
    )
    with pytest.raises(ProfileConfigError, match="did not return a"):
        resolve_transform("x:y", {}, profile_name="p")


def test_plugin_with_unsupported_api_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Transform built against a future contract is refused by name at load,
    never with an AttributeError at the first request."""

    class FromFuture(Transform):
        name = "future"
        api_version = 99

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload)

    monkeypatch.setattr(
        registry, "discover", lambda _group: {"x:future": _FakeEntryPoint(lambda _c: FromFuture())}
    )
    with pytest.raises(ProfileConfigError, match="api_version"):
        resolve_transform("x:future", {}, profile_name="p")


def test_plugin_that_raises_on_build_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A factory that throws yields a clean config refusal, not an opaque
    traceback that aborts the whole load."""

    def boom(_config: object) -> Transform:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(registry, "discover", lambda _group: {"x:y": _FakeEntryPoint(boom)})
    with pytest.raises(ProfileConfigError, match="failed to load or build"):
        resolve_transform("x:y", {}, profile_name="p")


def test_plugin_with_raising_api_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin whose api_version access throws is refused by name, not left to
    abort the load with an opaque traceback."""

    class Raises(Transform):
        name = "raises"

        @property
        def api_version(self) -> int:
            raise RuntimeError("boom")

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload)

    monkeypatch.setattr(
        registry, "discover", lambda _group: {"x:raises": _FakeEntryPoint(lambda _c: Raises())}
    )
    with pytest.raises(ProfileConfigError, match="api_version"):
        resolve_transform("x:raises", {}, profile_name="p")


def test_plugin_name_must_match_the_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    """A profile naming `dist:entry` must receive a transform that calls itself
    `entry`; a mismatch is an identity swap and is refused."""

    class Other(Transform):
        name = "other"

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload)

    monkeypatch.setattr(
        registry, "discover", lambda _group: {"x:expected": _FakeEntryPoint(lambda _c: Other())}
    )
    with pytest.raises(ProfileConfigError, match="named 'other', not 'expected'"):
        resolve_transform("x:expected", {}, profile_name="p")


def test_plugin_with_non_int_api_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unhashable or non-int api_version is a clean refusal, not a TypeError
    from the set-membership check."""

    class Weird(Transform):
        name = "weird"
        api_version = (1,)

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload)

    monkeypatch.setattr(
        registry, "discover", lambda _group: {"x:weird": _FakeEntryPoint(lambda _c: Weird())}
    )
    with pytest.raises(ProfileConfigError, match="api_version"):
        resolve_transform("x:weird", {}, profile_name="p")


def test_plugin_config_is_scalar_only_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """The factory receives only the chain's scalar knobs — never the pydantic
    model or the key provider. That boundary is the whole safety of the config."""
    captured: dict[str, object] = {}

    class Capture(Transform):
        name = "cap"

        async def run(self, payload: str, _ctx: TransformContext, /) -> TransformResult:
            return Applied(payload)

    def factory(config: object) -> Transform:
        assert isinstance(config, dict)
        captured.update(config)
        return Capture()

    # build_transforms discovers the catalog once; patch the binding it uses.
    monkeypatch.setattr(
        "trentina.gateway.drivers.discover", lambda _group: {"x:cap": _FakeEntryPoint(factory)}
    )
    build_transforms(
        PreProcessConfig(processors=["x:cap"], skip_sample_bytes=512), channel=Channel.TOOL
    )
    assert set(captured) == {"skip_sample_bytes", "target_bytes"}
    assert captured["skip_sample_bytes"] == 512


_PLUGIN_PROFILE = """
profiles:
  josui:
    auth:
      bearer_token_env: TRENTINA_TEST_TOKEN
    preprocess:
      enabled: true
      processors: ["petit-plus:dedupe"]
"""


def test_loader_accepts_a_clean_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A profile naming the benign fixture loads: its import scan is clean."""
    from trentina.gateway.loader import load_profiles

    monkeypatch.setenv("TRENTINA_TEST_TOKEN", "tok")
    cfg = tmp_path / "profiles.yaml"
    cfg.write_text(_PLUGIN_PROFILE)
    assert "josui" in load_profiles(cfg).profiles


def test_loader_refuses_a_plugin_that_violates_the_import_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loader runs `scan_imports` for each referenced plugin and refuses by
    name — a forbidden network import stands in for any violation."""
    from trentina.gateway.loader import load_profiles

    monkeypatch.setattr(
        "trentina.testing.suite.scan_imports", lambda _dist: ["forbidden-import:socket"]
    )
    monkeypatch.setenv("TRENTINA_TEST_TOKEN", "tok")
    cfg = tmp_path / "profiles.yaml"
    cfg.write_text(_PLUGIN_PROFILE)
    with pytest.raises(ProfileConfigError, match="violates the plugin contract"):
        load_profiles(cfg)
