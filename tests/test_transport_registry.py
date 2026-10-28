"""The transport registry: its own table, its own parity test (the #167 lesson).

Phase 6 PR7. Transports are Trentina's second plugin registry, kept apart from
the transform registry with a parity test of their own. Today the only built-in
is ``mcp``; transport PLUGINS are refused by name until the ``Face``/``Carrier``
contract is frozen in 3.0.0.
"""

from __future__ import annotations

from typing import get_args

import pytest

from trentina.gateway.errors import ProfileConfigError
from trentina.transports.base import Carrier, Face
from trentina.transports.mcp import mcp_transport
from trentina.transports.registry import TRANSPORTS, build_transport


def test_registry_and_literal_agree() -> None:
    """The table and the ``TransportName`` Literal in profile.py declare the same
    built-ins — a transport registered but not nameable, or named but not built,
    is dead on arrival."""
    from trentina.gateway.profile import TransportName

    assert set(TRANSPORTS) == set(get_args(TransportName))


def test_mcp_resolves_to_the_shared_transport() -> None:
    assert build_transport("mcp") is mcp_transport


def test_a_transport_plugin_is_refused_until_3_0_0() -> None:
    with pytest.raises(ProfileConfigError, match="transport plugins are accepted from"):
        build_transport("acme-mcp:sse")


def test_an_unknown_transport_is_refused() -> None:
    with pytest.raises(ProfileConfigError, match="unknown transport"):
        build_transport("sse")


def test_the_contract_carries_an_api_version() -> None:
    """The compat anchor for when transport plugins unlock."""
    assert mcp_transport.face.api_version == 1
    assert mcp_transport.carrier.api_version == 1
    assert Face.api_version == 1
    assert Carrier.api_version == 1
