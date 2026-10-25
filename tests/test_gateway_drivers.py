"""The one driver registry: parity with config, the channel lock, the kind lock.

There is one driver role and one table, in `gateway/drivers.py`. Until #167
there were two registries, each with its own parity test and only one of them
with a channel lock — which is how the text-processor table ended up with no
lock at all: it was written once, in the half nobody copied it out of. One
mechanism now, so this file covers everything with the same tests.

Four properties earn the file:

REGISTRY/LITERAL PARITY. The table is declared twice — once as a dict, once as
a `Literal` in `profile.py` that makes pydantic reject an unknown name at YAML
load. A driver in the table but not the Literal exists, is wired in, passes
its own tests, and can be named by no profile. It is dead on arrival and
nothing else fails to say so.

THE CHANNEL LOCK. A processor declares the ingresses it understands, and
selecting one elsewhere fails at config load rather than at 3am. The failure
it prevents is silent either way: a Matrix processor pointed at alert-ingress
JSON finds no Matrix event shape and falls through to generic rules on a
payload nobody checked it against; a text reducer pointed at the wrong shape
declines forever and looks like it is working.

THE KIND LOCK. A channel hands its processors a string or a parsed document,
never both. Without this the mismatch is an AttributeError deep in a request.

IT FIRES AT STARTUP. `loader._check_drivers` builds every driver a profile
names and throws the result away. Without that call the refusal moves to
whenever traffic first hits the path, which is a latent outage rather than a
lock.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast, get_args

import pytest

from trentina.channels import Channel, Kind
from trentina.gateway.drivers import (
    CHANNEL_KIND,
    TRANSFORMS,
    build_transforms,
)
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles
from trentina.gateway.profile import (
    _DEFAULT_PROCESSORS,
    MatrixPreProcessConfig,
    PreProcessConfig,
    ProcessorName,
)
from trentina.transforms import Cost


class TestRegistryAndConfigAgree:
    def test_every_registered_processor_is_configurable(self) -> None:
        assert set(TRANSFORMS) == set(get_args(ProcessorName))

    def test_every_default_processor_is_registered(self) -> None:
        assert set(_DEFAULT_PROCESSORS) <= set(TRANSFORMS)
        assert set(PreProcessConfig().processors) <= set(TRANSFORMS)

    def test_defaults_are_all_free_text(self) -> None:
        """A METERED default would spend LLM money for every profile that
        merely switched transformation on; a DOCUMENT default would not run."""
        built = build_transforms(PreProcessConfig(), channel=Channel.TOOL)
        assert all(p.cost is Cost.FREE for p in built)
        assert all(p.kind is Kind.TEXT for p in built)

    def test_matrix_default_is_read_everything(self) -> None:
        """A patch release must never silently narrow a deployment's scan."""
        assert MatrixPreProcessConfig().processors == []

    def test_every_channel_declares_a_kind(self) -> None:
        assert set(CHANNEL_KIND) == set(Channel)

    def test_every_driver_is_reachable_on_some_channel(self) -> None:
        """A driver whose kind matches no channel is configurable and dead."""
        for name in TRANSFORMS:
            reachable = [ch for ch in Channel if _buildable(name, ch)]
            assert reachable, f"{name} cannot run on any channel"


def _buildable(name: str, channel: Channel) -> bool:
    cfg: Any = (
        MatrixPreProcessConfig(processors=[cast("Any", name)])
        if CHANNEL_KIND[channel] is Kind.DOCUMENT
        else PreProcessConfig(processors=[cast("Any", name)])
    )
    try:
        build_transforms(cfg, channel=channel)
    except ProfileConfigError:
        return False
    return True


class TestChannelAndKindLocks:
    def test_text_processors_resolve_in_configured_order(self) -> None:
        cfg = PreProcessConfig(processors=["petit", "email"])
        built = build_transforms(cfg, channel=Channel.TOOL)
        assert [p.name for p in built] == ["petit", "email"]

    def test_document_processor_refused_on_a_text_channel(self) -> None:
        """`select` reads parsed JSON; the tool channel hands it a string."""
        cfg = PreProcessConfig(processors=["select"])
        with pytest.raises(ProfileConfigError, match="not valid on the tool"):
            build_transforms(cfg, channel=Channel.TOOL, profile_name="p")

    def test_the_kind_lock_catches_what_the_channel_lock_misses(self) -> None:
        """Belt and braces, and the braces are the point.

        Every shipped driver declares channels that already match its kind, so
        the channel lock fires first and this never triggers in production.
        It exists for the next driver whose channel list is wrong — without
        it, that mismatch is an AttributeError deep inside a request.
        """

        class _WrongKind:
            name = "petit"
            cost = Cost.FREE
            kind = Kind.DOCUMENT
            channels = frozenset({Channel.TOOL})

            async def run(self, payload: str, ctx: Any) -> Any:
                raise AssertionError("never called")

        original = TRANSFORMS["petit"]
        TRANSFORMS["petit"] = lambda _cfg, _keys: cast("Any", _WrongKind())
        try:
            cfg = PreProcessConfig(processors=["petit"])
            with pytest.raises(ProfileConfigError, match="consumes document"):
                build_transforms(cfg, channel=Channel.TOOL, profile_name="p")
        finally:
            TRANSFORMS["petit"] = original

    def test_text_processor_refused_on_the_matrix_channel(self) -> None:
        cfg = MatrixPreProcessConfig(processors=["petit"])
        with pytest.raises(ProfileConfigError, match="not valid on the matrix"):
            build_transforms(cfg, channel=Channel.MATRIX, profile_name="p")

    def test_matrix_channel_takes_at_most_one(self) -> None:
        """Chaining is defined for str -> str. A document processor returns
        selected strings, which the next one cannot consume."""
        cfg = MatrixPreProcessConfig(processors=["select", "matrix"])
        with pytest.raises(ProfileConfigError, match="at most one"):
            build_transforms(cfg, channel=Channel.MATRIX, profile_name="p")

    def test_empty_chain_is_the_no_op(self) -> None:
        """No `full` processor: reading everything is what naming nothing means."""
        assert build_transforms(MatrixPreProcessConfig(), channel=Channel.MATRIX) == []
        assert build_transforms(PreProcessConfig(processors=[]), channel=Channel.TOOL) == []

    def test_unknown_name_fails_closed(self) -> None:
        cfg = PreProcessConfig.model_construct(processors=["nope"])
        with pytest.raises(ProfileConfigError, match="unknown transform"):
            build_transforms(cfg, channel=Channel.TOOL, profile_name="p")


class TestTheLockFiresAtStartup:
    """A lock that fires on the first request to use the driver is not a lock.

    Nothing in the shipped registry can trigger it from YAML: the `Literal`
    blocks unknown names and every shipped name is valid somewhere. So a
    registered name is swapped for a driver with the wrong channels — a name
    pydantic accepts, so the refusal can only come from the lock. That is the
    regression this guards: the next driver added with channels that do not
    match where it is wired.
    """

    def test_a_profile_naming_a_wrong_channel_processor_refuses_to_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _MatrixOnly:
            name = "petit"
            cost = Cost.FREE
            kind = Kind.TEXT
            channels = frozenset({Channel.MATRIX})

            async def run(self, payload: str, ctx: Any) -> Any:
                raise AssertionError("never called")

        monkeypatch.setitem(TRANSFORMS, "petit", lambda _cfg, _keys: cast("Any", _MatrixOnly()))
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  josui:
    auth:
      bearer_token_env: TRENTINA_TEST_TOKEN
    preprocess:
      enabled: true
      processors: ["petit"]
    backends:
      mcp-slack:
        url: http://mcp-slack:8005/mcp
        tools_allow: ["*"]
"""
        )
        monkeypatch.setenv("TRENTINA_TEST_TOKEN", "tok")
        with pytest.raises(ProfileConfigError, match="not valid on the tool"):
            load_profiles(cfg)
