"""A route plugin, installed as an operator installs one, resolved or refused (#535 R13a).

Each test builds a real distribution on ``sys.path`` — a module and a dist-info
with ``RECORD`` and ``entry_points.txt`` — so ``importlib.metadata`` finds it as
it finds anything ``pip`` installed, and ``resolve_route`` reads it as the
gateway will: scan the source, then load, build and register.
"""

from __future__ import annotations

import builtins
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.transports import registry
from trentina.transports.base import Route

if TYPE_CHECKING:
    from collections.abc import Iterator

_CLEAN = """
from dataclasses import dataclass
from typing import Any

from trentina.transports.base import SPINE_REFUSALS, Admitted, Bearer, Context, Grant
from trentina.transports.base import Instance, OperatorOrigin, RefusedError, Route, Wire


@dataclass(frozen=True)
class AcmeAdmitted(Admitted):
    path: str = ""


class Acme(Route[AcmeAdmitted, Context]):
    name = "acme"
    methods = ("GET",)
    auth = Bearer()
    refusals = SPINE_REFUSALS
    max_request_bytes = 4096

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> AcmeAdmitted:
        return AcmeAdmitted(OperatorOrigin("api"), path=wire.path)

    async def deliver(self, admitted: AcmeAdmitted, ctx: Context) -> Any:
        return await ctx.upstream.send("GET", admitted.path, headers={})

    def render(self, refused: RefusedError) -> Any:
        return refused.reason


def make(options):
    return Acme()
"""

#: Imports a dialer, and marks that its module ran: the scan must stop it first.
_HOSTILE = """
import socket
import builtins
builtins.ACME_HOSTILE_RAN = True


def make(options):
    return None
"""

_NOT_A_ROUTE = """
def make(options):
    return object()
"""


def _install(root: Path, dist: str, module: str, source: str, entry: str = "acme") -> None:
    """Install ``source`` as ``module`` in distribution ``dist``, exposing ``entry``."""
    (root / module).mkdir()
    (root / module / "__init__.py").write_text(source, encoding="utf-8")
    info = root / f"{dist.replace('-', '_')}-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\nVersion: 1.0\n")
    (info / "entry_points.txt").write_text(f"[{registry.ROUTE_GROUP}]\n{entry} = {module}:make\n")
    (info / "RECORD").write_text(
        f"{module}/__init__.py,,\n{info.name}/METADATA,,\n{info.name}/entry_points.txt,,\n"
        f"{info.name}/RECORD,,\n"
    )


@pytest.fixture
def site(tmp_path: Path) -> Iterator[Path]:
    """A directory on ``sys.path`` to install into; the routes it registers are removed."""
    before = dict(registry.ROUTES)
    sys.path.insert(0, str(tmp_path))
    try:
        yield tmp_path
    finally:
        sys.path.remove(str(tmp_path))
        for name in [m for m in sys.modules if m.startswith("acme_")]:
            del sys.modules[name]
        registry.ROUTES.clear()
        registry.ROUTES.update(before)


def test_a_clean_route_plugin_is_resolved_and_registered(site: Path) -> None:
    _install(site, "acme-route", "acme_route", _CLEAN)
    route = registry.resolve_route("acme-route:acme", {})
    assert isinstance(route, Route)
    assert registry.ROUTES["acme"] is route
    assert route.path == "/proxy/acme/{instance}/{path:path}"


def test_a_plugin_that_reaches_past_the_contract_never_runs(site: Path) -> None:
    _install(site, "acme-hostile", "acme_hostile", _HOSTILE)
    with pytest.raises(ProfileConfigError, match="forbidden-import:socket"):
        registry.resolve_route("acme-hostile:acme", {})
    assert not hasattr(builtins, "ACME_HOSTILE_RAN"), "the plugin's module ran before its scan"


def test_a_factory_that_builds_no_route_is_refused(site: Path) -> None:
    _install(site, "acme-other", "acme_other", _NOT_A_ROUTE)
    with pytest.raises(ProfileConfigError, match="did not return"):
        registry.resolve_route("acme-other:acme", {})


def test_a_route_named_for_another_entry_is_refused(site: Path) -> None:
    _install(site, "acme-renamed", "acme_renamed", _CLEAN, entry="other")
    with pytest.raises(ProfileConfigError, match="free route name"):
        registry.resolve_route("acme-renamed:other", {})


@pytest.mark.usefixtures("site")
def test_a_plugin_that_is_not_installed_is_refused() -> None:
    with pytest.raises(ProfileConfigError, match="not installed"):
        registry.resolve_route("nobody-here:acme", {})
