"""The program's acceptance (#633): an agent provisions a federated edge.

Everything else in this program is tested a piece at a time. This is the claim
those pieces were built for, end to end and through nothing but the two
operator tools: starting from a gateway that has never heard of federation,
mint the keys, declare the ingress, declare the backend, and finish with an
edge that would actually authenticate — no file editing, no shell, no restart.

The last assertion is the one that matters. It does not check that the config
looks right; it mints the JWT the downstream would really send and verifies it
against the peer key the upstream really holds.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

from trentina import config as config_mod
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.edge_key import (
    load_private_key,
    load_public_key,
    sign_edge_jwt,
    verify_edge_jwt,
)
from trentina.gateway.loader import get_active_config, load_profiles, register_active_config
from trentina.gateway.profile import federation_audience
from trentina.tools.config import manage_config
from trentina.tools.keygen import federation_keygen

pytestmark = pytest.mark.anyio

#: The downstream reaches the upstream's ingress profile here, and the edge
#: JWT's audience is taken from the profile name in this URL.
UPSTREAM_URL = "https://upstream.example/gateway/fed-ingress/mcp"

#: A gateway that knows nothing about federation yet: one operator seat, and a
#: consumer profile with no backends but its own tools.
BARE = """\
# Nothing federated here yet.
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: OP_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - config_tool
          - federation_keygen_tool
  down:
    auth:
      bearer_token_env: DOWN_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow:
          - fetch_tool
    defense:
      enforcement: block
"""


@pytest.fixture
def gateway(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.setenv("OP_TOKEN", "o" * 20)
    monkeypatch.setenv("DOWN_TOKEN", "d" * 20)
    config_mod._config = None
    path = tmp_path / "config" / "profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(BARE, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield path
    config_mod._config = None


async def _op(*args: Any) -> dict[str, Any]:
    """One call as the operator, the way an Operator agent would make it."""
    operator = (get_active_config() or pytest.fail("no gateway")).config.profiles["op"]
    with profile_context(operator):
        if args and args[0] == "keygen":
            return await federation_keygen(args[1])
        return await manage_config(*args)


async def _set(path: str, value: Any) -> dict[str, Any]:
    """A write, reading the current hash first, as the tool requires."""
    read = await _op("get")
    result = await _op("set", path, value, read["hash"])
    assert result.get("applied") is True, result
    return result


async def test_an_operator_provisions_a_federated_edge_with_no_shell_and_no_restart(
    gateway: pathlib.Path,
) -> None:
    before = gateway.read_text(encoding="utf-8")

    # 1. Each side mints its own key. Only the public halves ever come back.
    signing = await _op("keygen", "ingress-signing")
    edge = await _op("keygen", "edge-to-upstream")
    assert "PRIVATE" not in str(signing) + str(edge)

    # 2. The upstream ingress: who may authenticate, and the key it vouches
    #    for responses with. `federation.peers` IS this profile's
    #    authentication, so it has to be writable in one go — a profile with
    #    neither auth nor peers does not load.
    await _set(
        "profiles.fed-ingress",
        {
            "federation": {
                "peers": {"down": {"public_key": edge["public_key"]}},
                "signing_key_name": "ingress-signing",
            },
            # What the ingress actually offers a peer: a real backend, plus
            # read_part so a paged response can be collected. An ingress may
            # offer no other internal tool (FEDERATION_INTERNAL_ALLOW).
            "backends": {
                "shared": {"url": "http://shared:8000/mcp", "tools_allow": ["*"]},
                "web": {"url": "internal://web", "tools_allow": ["read_part_tool"]},
            },
            "defense": {"enforcement": "block"},
        },
    )

    # 3. The downstream side: a federated backend pointing at that ingress,
    #    signing with the edge key by name.
    await _set(
        "profiles.down.backends.upstream",
        {
            "url": UPSTREAM_URL,
            "tools_allow": ["*"],
            "federated": {"edge_key_name": "edge-to-upstream"},
        },
    )

    # Both sides are live in the running gateway, with no restart.
    running = (get_active_config() or pytest.fail("no gateway")).config.profiles
    ingress = running["fed-ingress"].federation
    backend = running["down"].backends["upstream"].federated
    assert ingress is not None and ingress.signing_key is not None
    assert backend is not None and backend.edge_key is not None

    # The edge would authenticate: the token the downstream really mints
    # verifies against the peer key the upstream really holds, and names the
    # peer as the actor.
    audience = federation_audience(UPSTREAM_URL)
    assert audience == "fed-ingress"
    token = sign_edge_jwt(
        load_private_key(backend.edge_key.get_secret_value()), sub="down", aud=audience
    )
    peer, caller = verify_edge_jwt(
        token,
        {name: load_public_key(p.public_key) for name, p in ingress.peers.items()},
        aud=audience,
    )
    assert (peer, caller) == ("down", "down")

    # And the file a person reads is still the file they wrote, plus the edge.
    after = gateway.read_text(encoding="utf-8")
    assert after.startswith("# Nothing federated here yet.")
    assert "fetch_tool" in before and "fetch_tool" in after


async def test_turning_on_scan_once_trust_is_the_one_step_left_to_a_person(
    gateway: pathlib.Path,
) -> None:
    """The edge above is authenticated and double-scanning, which is where #592
    says to stop and prove it works. Going further — serving an upstream's
    response WITHOUT scanning it — is the one setting the API will not write."""
    await _op("keygen", "edge-to-upstream")
    await _set(
        "profiles.down.backends.upstream",
        {
            "url": UPSTREAM_URL,
            "tools_allow": ["*"],
            "federated": {"edge_key_name": "edge-to-upstream"},
        },
    )
    before = gateway.read_text(encoding="utf-8")

    read = await _op("get")
    refused = await _op(
        "set",
        "profiles.down.backends.upstream.federated.trust_verdict",
        {"public_key": "x", "perimeter_stamp": "y"},
        read["hash"],
    )

    assert "not writable through this tool" in refused["error"]
    assert gateway.read_text(encoding="utf-8") == before
