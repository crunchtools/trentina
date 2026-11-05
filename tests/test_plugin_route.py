"""A route plugin, installed as an operator installs one, resolved or refused (#535 R13a).

Each test builds a real distribution on ``sys.path`` — a module and a dist-info
with ``RECORD`` and ``entry_points.txt`` — so ``importlib.metadata`` finds it as
it finds anything ``pip`` installed, and ``resolve_route`` reads it as the
gateway will: scan the source, then load, build and register.
"""

from __future__ import annotations

import asyncio
import builtins
import importlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.testing import route_conformance
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


def test_a_plugin_named_in_proxies_is_mounted_and_serves(
    site: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole path an operator takes: install, declare an instance and a
    grant in proxies:, and the spine serves it — the token injected by the spine
    into a request the plugin never saw it in."""
    import yaml

    from tests import perimeter_golden as g
    from tests.perimeter_golden import Call, bearer, drive, reply

    _install(site, "acme-route", "acme_route", _CLEAN)
    monkeypatch.setenv("ACME_TOKEN", "acme-secret-value-for-the-plugin")
    document = {
        "proxies": {
            "acme1": {
                "type": "acme-route:acme",
                "origins": {"api": "https://api.acme.example"},
                "credential": {"header": "Authorization", "prefix": "Bearer "},
            }
        },
        "profiles": {
            "agent1": {
                "auth": {"bearer_token_env": "GOLDEN_AGENT1_TOKEN"},
                "proxies": {"acme1": {"origins": ["api"], "token_env": "ACME_TOKEN"}},
            }
        },
    }
    path = tmp_path / "profiles.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    monkeypatch.setattr(g, "SPELLING", {"config": path})

    async def run() -> tuple[Any, list[dict[str, Any]]]:
        async with g.stack(monkeypatch) as s:
            s.net.handlers["api.acme.example"] = reply(200, '{"from":"acme"}')
            exchange = await drive(
                s.app, Call("GET", "/proxy/acme/acme1/things", headers=bearer("agent1"))
            )
            return exchange, s.net.seen

    exchange, seen = asyncio.run(run())
    status = next(m["status"] for m in exchange["messages"] if m["type"] == "start")
    assert status == 200
    [sent] = seen
    assert sent["url"] == "https://api.acme.example/things"
    assert ["authorization", "Bearer acme-secret-value-for-the-plugin"] in sent["headers"]
    assert "acme" not in registry.BUILTIN_ROUTES


#: A route that breaks each behavioural rule the suite holds: it logs what the
#: caller sent, raises outside the contract, and echoes a refusal's detail.
_CARELESS = _CLEAN.replace(
    '        return AcmeAdmitted(OperatorOrigin("api"), path=wire.path)',
    "        import logging\n"
    "        logging.getLogger('acme').warning('path %s', wire.path)\n"
    "        raise ValueError(wire.path)",
).replace("        return refused.reason", "        return f'{refused.reason}: {refused.detail}'")


def test_route_conformance_passes_a_clean_route(site: Path) -> None:
    _install(site, "acme-route", "acme_route", _CLEAN)
    route = registry.resolve_route("acme-route:acme", {})
    result = asyncio.run(route_conformance("acme-route:acme", route))
    assert result.ok, result.failures


def test_route_conformance_names_each_breach(site: Path) -> None:
    _install(site, "acme-careless", "acme_careless", _CARELESS)
    route = importlib.import_module("acme_careless").make({})
    result = asyncio.run(route_conformance("acme-careless:acme", route))
    assert set(result.failures) == {
        "raised-on-admit:ValueError",
        "logs-payload",
        "render-echoes-detail",
    }


def test_route_conformance_holds_the_declaration(site: Path) -> None:
    _install(site, "acme-route", "acme_route", _CLEAN, entry="other")
    route = importlib.import_module("acme_route").make({})
    result = asyncio.run(route_conformance("acme-route:other", route))
    assert "name" in result.failures
