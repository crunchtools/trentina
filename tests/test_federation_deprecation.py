"""D2b: the interim static-bearer federation path warns at load (#592).

First-class federation (edge-key auth + scan-once trust) supersedes mounting
another gateway over a shared static bearer. The old arrangement still works
but is deprecated (removed in 3.2.0), so the loader warns — by profile and
backend name only, never the URL (#262).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from trentina.gateway.loader import _check_interim_federation
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile

if TYPE_CHECKING:
    import pytest

GATEWAY_URL = "https://lotor.example/gateway/josui/mcp"


def _profile(backend: Backend) -> Profile:
    return Profile(
        name="breetai",
        auth=AuthConfig(bearer_token_env="B"),
        backends={"lotor": backend},
    )


def test_a_static_bearer_gateway_backend_warns(caplog: pytest.LogCaptureFixture) -> None:
    profile = _profile(Backend(url=GATEWAY_URL, tools_allow=["*"]))
    with caplog.at_level(logging.WARNING):
        _check_interim_federation("breetai", profile)
    assert any("interim static-bearer federation" in r.message for r in caplog.records)
    # The URL is never in the message (the logging rule).
    assert all("lotor.example" not in r.getMessage() for r in caplog.records)


def test_a_federated_block_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    profile = _profile(Backend(url=GATEWAY_URL, tools_allow=["*"], federated=FederatedConfig()))
    with caplog.at_level(logging.WARNING):
        _check_interim_federation("breetai", profile)
    assert not caplog.records


def test_a_plain_mcp_backend_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    # No "gateway" segment: an ordinary MCP server, not a Trentina federation
    # endpoint, must not be mistaken for the interim path.
    profile = _profile(Backend(url="https://api.example/foo/mcp", tools_allow=["*"]))
    with caplog.at_level(logging.WARNING):
        _check_interim_federation("breetai", profile)
    assert not caplog.records


def test_gateway_elsewhere_in_the_path_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    # "gateway" present but NOT the antepenultimate segment: not the
    # .../gateway/<profile>/mcp shape, so no warning (the detection is exact).
    profile = _profile(Backend(url="https://api.example/gateway/a/b/mcp", tools_allow=["*"]))
    with caplog.at_level(logging.WARNING):
        _check_interim_federation("breetai", profile)
    assert not caplog.records
