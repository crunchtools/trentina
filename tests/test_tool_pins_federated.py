"""E1a: a held federated tool shows up in `tool_pins list` (#592).

Field note from running federation: on breetai, `tool_pins list backend=lotor`
returned `held: []` while the raw `tool_pins` table held several pending — the
operator could not see, by name, what the federated secondary was holding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trentina import perimeter_db
from trentina.gateway import compress
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import Profile
from trentina.gateway.tool_pins import backend_id
from trentina.tools.pins import manage_tool_pins

pytestmark = pytest.mark.asyncio

LOTOR_URL = "https://lotor:8019/gateway/josui/mcp"

YAML = f"""\
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      lotor:
        url: {LOTOR_URL}
        federated: {{}}
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Profile]:
    monkeypatch.setenv("OP_TOKEN", "o")
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    try:
        return dict(config.profiles)
    finally:
        pass


@pytest.fixture(autouse=True)
def _drop_profiles() -> object:
    yield
    compress._profiles = None


async def test_a_held_federated_tool_is_listed(gateway: dict[str, Profile]) -> None:
    # lotor's tool is held primary under backend_id(the federated backend url).
    perimeter_db.put_pin(
        backend_id(LOTOR_URL), "send_message", approved=None, pending=("h", "{}"), rejected=False
    )
    with profile_context(gateway["op"]):
        result = await manage_tool_pins("list", "lotor")
    assert "error" not in result, result
    assert any(h["tool"] == "send_message" for h in result["held"]), result


async def test_approve_by_name_releases_a_federated_hold(gateway: dict[str, Profile]) -> None:
    perimeter_db.put_pin(
        backend_id(LOTOR_URL), "send_message", approved=None, pending=("h", "{}"), rejected=False
    )
    with profile_context(gateway["op"]):
        approved = await manage_tool_pins("approve", "lotor", "send_message")
        after = await manage_tool_pins("list", "lotor")
    assert approved == {"backend": "lotor", "tool": "send_message", "action": "approve"}
    assert not any(h["tool"] == "send_message" for h in after["held"]), after


async def test_an_unknown_backend_is_not_found(gateway: dict[str, Profile]) -> None:
    with profile_context(gateway["op"]):
        result = await manage_tool_pins("list", "nope")
    assert "error" in result
    assert "not found" in result["error"]


async def test_an_agent_cannot_manage_pins() -> None:
    # Pins belong to a backend's whole surface, so only the operator may list
    # or release them; an agent profile is refused without learning anything.
    agent = Profile.model_validate(
        {
            "name": "ag",
            "auth": {"bearer_token_env": "A"},
            "backends": {"lotor": {"url": LOTOR_URL, "federated": {}}},
        }
    )
    with profile_context(agent):
        result = await manage_tool_pins("list", "lotor")
    assert "error" in result
    assert "operator" in result["error"].lower()
