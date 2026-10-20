"""One net under every gateway admin tool: an agent profile learns nothing
about another profile.

The four tools leak differently — an audit aggregate, a backend directory, a
cache count, a config diff — so each got its own scoping and its own tests.
What they share is the property that matters, and it is worth asserting once,
in one place, over all of them: run the tool as `beta`, and nothing that
belongs to `alpha` may appear in the answer.

The strings this checks for are deliberately distinctive. A profile name, a
backend name, a URL host and a tool name are the four shapes a leak has taken
in this codebase so far.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import ListToolsResult, Tool

from trentina.database import record_detection, record_gateway_call
from trentina.gateway import compress
from trentina.gateway.backend import _tool_list_cache
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import (
    load_profiles,
    register_active_config,
)
from trentina.gateway.router import _profile_tools_cache
from trentina.outcomes import Outcome
from trentina.tools.cache import cache_flush
from trentina.tools.reconnect import reconnect_backend
from trentina.tools.reload import reload_profiles
from trentina.tools.stats import get_trentina_stats

pytestmark = pytest.mark.asyncio

ALPHA_URL = "http://alpha-only-host:1/mcp"
BETA_URL = "http://beta-host:1/mcp"

# Everything alpha owns, spelled so a substring check cannot false-negative.
ALPHA_SECRETS = (
    "alpha",
    "alpha-only-backend",
    "alpha-only-host",
    "alpha_only_tool",
)

YAML = f"""\
profiles:
  alpha:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      alpha-only-backend:
        url: {ALPHA_URL}
        tools_allow: ["alpha_only_tool"]
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      beta-backend:
        url: {BETA_URL}
"""

# The edit each tool is run against: alpha moves, beta does not.
EDITED_YAML = YAML.replace(
    '        tools_allow: ["alpha_only_tool"]\n',
    '        tools_allow: ["alpha_only_tool"]\n        tools_deny: ["alpha_only_tool"]\n',
)


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Two profiles, alpha busy: cached tools, audit rows, a detection."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "trentina.db"))
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)

    _tool_list_cache[ALPHA_URL] = [{"name": "alpha_only_tool"}]
    _tool_list_cache[BETA_URL] = [{"name": "beta_tool"}]
    _profile_tools_cache["alpha"] = [{"name": "alpha-only-backend__alpha_only_tool"}]
    _profile_tools_cache["beta"] = [{"name": "beta-backend__beta_tool"}]

    record_gateway_call("alpha", "alpha-only-backend", "alpha_only_tool", Outcome.OK.value, 5)
    record_detection(
        source_type="url",
        source="alpha:alpha-only-backend:alpha_only_tool",
        domain="alpha-only-host",
        layer1_stats={},
        risk_level="high",
        profile="alpha",
    )
    yield path
    compress._profiles = None


async def _stats() -> dict[str, Any]:
    return await get_trentina_stats()


async def _flush_all() -> dict[str, Any]:
    return await cache_flush()


async def _flush_alphas_backend() -> dict[str, Any]:
    return await cache_flush("alpha-only-backend")


async def _reconnect_alphas_backend() -> dict[str, Any]:
    return await reconnect_backend("alpha-only-backend")


async def _reconnect_own() -> dict[str, Any]:
    async def ok(_url: str, _headers: Any, *_: Any) -> ListToolsResult:
        return ListToolsResult(tools=[Tool(name="beta_tool", description="", input_schema={})])

    with patch("trentina.gateway.backend._do_list_tools", side_effect=ok):
        return await reconnect_backend("beta-backend")


async def _reload() -> dict[str, Any]:
    return await reload_profiles()


# (label, call, the argument the caller passed in). A refusal quotes the name
# it was given, which is the caller's own string and not a disclosure — so it
# is removed from the answer before the check, and nothing else is forgiven.
ADMIN_CALLS: list[tuple[str, Callable[[], Any], str | None]] = [
    ("quarantine_stats", _stats, None),
    ("cache_flush (all in scope)", _flush_all, None),
    ("cache_flush (another profile's backend)", _flush_alphas_backend, "alpha-only-backend"),
    (
        "reconnect_backend (another profile's backend)",
        _reconnect_alphas_backend,
        "alpha-only-backend",
    ),
    ("reconnect_backend (own)", _reconnect_own, None),
    ("reload_profiles", _reload, None),
]


@pytest.mark.parametrize(("label", "call", "echoed"), ADMIN_CALLS, ids=[c[0] for c in ADMIN_CALLS])
async def test_no_admin_tool_hands_an_agent_another_profiles_shape(
    gateway: Path, label: str, call: Callable[[], Any], echoed: str | None
) -> None:
    """Run it as beta. Nothing of alpha's may come back."""
    gateway.write_text(EDITED_YAML, encoding="utf-8")
    profiles = compress.get_profiles() or {}

    with (
        profile_context(profiles["beta"]),
        patch(
            "trentina.gateway.sessions.session_registry.broadcast_tools_changed",
            AsyncMock(return_value=0),
        ),
    ):
        result = await call()

    answer = str(result).replace(echoed, "<asked-for>") if echoed else str(result)
    leaked = [secret for secret in ALPHA_SECRETS if secret in answer]
    assert not leaked, f"{label} leaked {leaked}: {answer}"


@pytest.mark.usefixtures("gateway")
async def test_the_fixture_would_catch_a_leak() -> None:
    """The net is only worth having if an unscoped answer trips it.

    Runs the same stats call as the operator, which is entitled to the whole
    gateway — if THAT does not contain alpha's names, the assertions above are
    passing on an empty database rather than on scoping.
    """
    profiles = compress.get_profiles() or {}
    operator = profiles["alpha"].model_copy(update={"role": "operator"})

    with profile_context(operator):
        result = await get_trentina_stats()

    assert [s for s in ALPHA_SECRETS if s in str(result)]
