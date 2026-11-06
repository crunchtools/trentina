"""A route plugin is held to the route lists before it loads (#535 R13a).

A route runs in the gateway's process with live streams, so the contract is all
that holds it: it gets no socket, no file, no process and no way into the
gateway's own state. ``scan_route_source`` refuses each way to one. Every entry
on each list has a case here, so an entry that stops being refused fails, and a
plausible route plugin's source still passes.
"""

from __future__ import annotations

import pytest

from trentina.testing.suite import (
    FORBIDDEN_MODULES,
    ROUTE_FORBIDDEN_ATTRIBUTES,
    ROUTE_FORBIDDEN_MODULES,
    ROUTE_FORBIDDEN_NAMES,
    _Scan,
    scan_route_source,
)


def _violations(source: str) -> list[str]:
    scan = _Scan()
    scan_route_source(source, scan)
    return scan.violations


#: What a route plugin legitimately writes: the contract, the standard data
#: modules, and asyncio's waiting (not its dialers).
_BENIGN = """
import asyncio
import json
from dataclasses import dataclass
from typing import Any

from trentina.transports.base import Admitted, Bearer, Context, OperatorOrigin, Route


@dataclass(frozen=True)
class AcmeAdmitted(Admitted):
    path: str = ""


class Acme(Route[AcmeAdmitted, Context]):
    def __init__(self) -> None:
        self.name = "acme"

    async def deliver(self, admitted: AcmeAdmitted, ctx: Context) -> Any:
        await asyncio.sleep(0)
        body = json.loads(await ctx.body.read() or b"{}")
        content = json.dumps(body).encode()
        return await ctx.upstream.send("POST", admitted.path, headers={}, content=content)
"""


def test_a_plausible_route_passes() -> None:
    assert _violations(_BENIGN) == []


def test_the_route_list_holds_every_transform_entry() -> None:
    assert FORBIDDEN_MODULES <= ROUTE_FORBIDDEN_MODULES


@pytest.mark.parametrize("module", sorted(ROUTE_FORBIDDEN_MODULES))
def test_a_forbidden_module_is_refused_imported(module: str) -> None:
    assert f"forbidden-import:{module}" in _violations(f"import {module}\n")


@pytest.mark.parametrize("module", sorted(ROUTE_FORBIDDEN_MODULES))
def test_a_forbidden_module_is_refused_imported_from(module: str) -> None:
    assert f"forbidden-import:{module}" in _violations(f"from {module} import thing\n")


@pytest.mark.parametrize("name", sorted(ROUTE_FORBIDDEN_NAMES))
def test_a_forbidden_name_is_refused(name: str) -> None:
    assert f"forbidden-name:{name}" in _violations(f"x = {name}\n")


@pytest.mark.parametrize("attribute", sorted(ROUTE_FORBIDDEN_ATTRIBUTES))
def test_a_forbidden_attribute_is_refused(attribute: str) -> None:
    assert f"forbidden-attribute:{attribute}" in _violations(f"x = thing.{attribute}\n")


@pytest.mark.parametrize(
    "source",
    [
        "x = ().__class__.__bases__[0].__subclasses__()\n",
        "x = f.__globals__\n",
        "x = obj.__dict__\n",
        "x = __builtins__\n",
    ],
)
def test_reaching_past_the_contract_by_dunder_is_refused(source: str) -> None:
    assert _violations(source), source


@pytest.mark.parametrize(
    "module",
    ["trentina.gateway.upstream", "trentina.transports.perimeter", "trentina.reach.egress"],
)
def test_a_private_trentina_module_is_refused(module: str) -> None:
    assert f"private-import:{module}" in _violations(f"import {module}\n")


def test_asyncio_dialing_by_any_route_is_refused() -> None:
    source = "import asyncio\nasync def go():\n    await asyncio.open_connection('h', 443)\n"
    assert "forbidden-attribute:open_connection" in _violations(source)


def test_unparseable_source_cannot_be_vouched_for() -> None:
    assert _violations("def (:\n") == ["unparseable-source"]
