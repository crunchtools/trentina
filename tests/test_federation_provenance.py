"""A1: a federated tool's upstream origin is visible; its name stays short (#592).

Provenance is Trentina's job internally and in the audit/diagnostic, not a cost
the agent pays in every tool name — so a federated tool keeps the same short,
token-cheap served name a leaf backend's tool would, and the diagnostic (and the
audit's backend column) carry the origin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from trentina.gateway import aggregate
from trentina.gateway.diagnose import diagnose_tool_visibility
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile

if TYPE_CHECKING:
    import pytest

URL = "https://lotor.example/gateway/x/mcp"


def _tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"do {name}",
        "inputSchema": {"type": "object", "properties": {}},
    }


def _offer(monkeypatch: pytest.MonkeyPatch, tools: list[dict[str, Any]]) -> None:
    async def fake(_n: str, _b: Backend, _p: Profile) -> list[dict[str, Any]]:
        return [dict(t) for t in tools]

    monkeypatch.setattr(aggregate, "list_backend_tools", fake)


def _profile(*, federated: bool) -> Profile:
    backend = Backend(url=URL, federated=FederatedConfig() if federated else None)
    profile = Profile(
        name="agent", auth=AuthConfig(bearer_token_env="A"), backends={"up": backend}
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


async def test_the_diagnostic_marks_a_federated_tools_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _offer(monkeypatch, [_tool("list_reports")])
    result = await diagnose_tool_visibility(_profile(federated=True), "up", "list_reports")
    assert result["visible"] is True
    assert result["backend"] == "up"  # origin: which backend
    assert result["federated"] is True  # ...and that it is a federated upstream


async def test_a_leaf_backend_is_not_marked_federated(monkeypatch: pytest.MonkeyPatch) -> None:
    _offer(monkeypatch, [_tool("list_reports")])
    result = await diagnose_tool_visibility(_profile(federated=False), "up", "list_reports")
    assert result["federated"] is False


async def test_a_federated_tool_keeps_a_short_token_cheap_name() -> None:
    # No agent-facing prefix: the federated backend's tools get the same short
    # names a leaf backend's would (short-naming already strips a backend-name
    # prefix), so the agent pays nothing for provenance.
    from tests.federation_harness import downstream_profile, federated_pair

    def down(up_port: int) -> Profile:
        profile = downstream_profile(upstream_port=up_port)
        next(iter(profile.backends.values())).federated = FederatedConfig()
        return profile

    async with federated_pair(downstream=down) as fed, fed.downstream_client() as client:
        names = {t["name"] for t in await client.list_tools()}
    assert "echo" in names, names
    # Not prefixed with the backend key ("fed") or any federation tag.
    assert not any(n.startswith("fed_") for n in names), names
