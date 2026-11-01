"""The program's acceptance (#633): an agent provisions a federated edge.

Everything else in this program is tested a piece at a time. This is the claim
those pieces were built for, end to end and through nothing but the two
operator tools: starting from a gateway that has never heard of federation,
mint the keys, declare the ingress, declare the backend, and finish with an
edge that would actually authenticate — no file editing, no shell, no restart.

The last assertion is the one that matters. It does not check that the config
looks right; it mints the JWT the primary would really send and verifies it
against the peer key the secondary really holds.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

from trentina import config as config_mod
from trentina.gateway import approver, pending
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.federation_keys import (
    load_private_key,
    load_public_key,
    sign_primary_jwt,
    verify_primary_jwt,
)
from trentina.gateway.loader import get_active_config, load_profiles, register_active_config
from trentina.gateway.profile import federation_audience
from trentina.tools.config import manage_config
from trentina.tools.keygen import federation_keygen
from trentina.tools.token import profile_token

pytestmark = pytest.mark.anyio

#: The primary reaches the secondary's ingress profile here, and the edge
#: JWT's audience is taken from the profile name in this URL.
SECONDARY_URL = "https://secondary.example/gateway/fed-ingress/mcp"

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
    # A person can approve on this gateway, so trust can be proposed (#637).
    monkeypatch.setenv(
        "TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier("correct horse battery staple")
    )
    pending.clear()
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
        if args and args[0] == "mint-token":
            return await profile_token(args[1])
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
    edge = await _op("keygen", "edge-to-secondary")
    assert "PRIVATE" not in str(signing) + str(edge)

    # 2. The secondary ingress: who may authenticate, and the key it vouches
    #    for responses with. `federation.peers` IS this profile's
    #    authentication, so it has to be writable in one go — a profile with
    #    neither auth nor peers does not load.
    await _set(
        "profiles.fed-ingress",
        {
            "federation": {
                "peers": {"down": {"public_key": edge["public_key"]}},
                "secondary_key_name": "ingress-signing",
            },
            # What the ingress actually offers a peer: a real backend, plus
            # read_part so a paged response can be collected. An ingress's
            # internal tools are limited to FEDERATION_INTERNAL_ALLOW.
            "backends": {
                "shared": {"url": "http://shared:8000/mcp", "tools_allow": ["*"]},
                "web": {"url": "internal://web", "tools_allow": ["read_part_tool"]},
            },
            "defense": {"enforcement": "block"},
        },
    )

    # 3. The primary side: a federated backend pointing at that ingress,
    #    signing with the primary key by name.
    await _set(
        "profiles.down.backends.secondary",
        {
            "url": SECONDARY_URL,
            "tools_allow": ["*"],
            "federated": {"primary_key_name": "edge-to-secondary"},
        },
    )

    # Both sides are live in the running gateway, with no restart.
    running = (get_active_config() or pytest.fail("no gateway")).config.profiles
    ingress = running["fed-ingress"].federation
    backend = running["down"].backends["secondary"].federated
    assert ingress is not None and ingress.secondary_key is not None
    assert backend is not None and backend.primary_key is not None

    # The edge would authenticate: the token the primary really mints
    # verifies against the peer key the secondary really holds, and names the
    # peer as the actor.
    audience = federation_audience(SECONDARY_URL)
    assert audience == "fed-ingress"
    token = sign_primary_jwt(
        load_private_key(backend.primary_key.get_secret_value()), sub="down", aud=audience
    )
    peer, caller = verify_primary_jwt(
        token,
        {name: load_public_key(p.public_key) for name, p in ingress.peers.items()},
        aud=audience,
    )
    assert (peer, caller) == ("down", "down")

    # And the file a person reads is still the file they wrote, plus the edge.
    after = gateway.read_text(encoding="utf-8")
    assert after.startswith("# Nothing federated here yet.")
    assert "fetch_tool" in before and "fetch_tool" in after


async def test_turning_on_scan_once_trust_waits_for_a_person(
    gateway: pathlib.Path,
) -> None:
    """The link above is authenticated and double-scanning, which is where #592
    says to stop and prove it works. Going further — serving a secondary's
    response WITHOUT scanning it — the operator may now propose, but only a
    person can agree to (#637). The file does not move until they do."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    await _op("keygen", "primary-to-secondary")
    await _set(
        "profiles.down.backends.secondary",
        {
            "url": SECONDARY_URL,
            "tools_allow": ["*"],
            "federated": {"primary_key_name": "primary-to-secondary"},
        },
    )
    before = gateway.read_text(encoding="utf-8")

    read = await _op("get")
    staged = await _op(
        "set",
        "profiles.down.backends.secondary.federated.trust_verdict",
        {
            "public_key": public_pem,
            "perimeter_stamp": "v7:guard-small@abc123:0.7",
            "judge": "openrouter/google/gemini-3.5-flash-lite/pack-1",
        },
        read["hash"],
    )

    assert staged["staged"] is True
    assert staged["awaiting"] == "federation trust"
    assert gateway.read_text(encoding="utf-8") == before

    # And approving it is what applies it — the whole point of the mechanism.
    from trentina.gateway import pending

    await pending.approve(pending.Kind.FEDERATION_TRUST)
    assert gateway.read_text(encoding="utf-8") != before
    assert "trust_verdict" in gateway.read_text(encoding="utf-8")


async def test_an_operator_adds_a_whole_new_agent_profile_in_band(
    gateway: pathlib.Path,
) -> None:
    """#635, and the step that was missing from #633's own promise.

    Before this, a new profile could not be added to a running gateway at all.
    Its token had to be an environment variable, and a profile naming one that
    is not set does not merely need a restart — it fails validation, so the
    write is refused and the file restored. Nothing about it was recoverable
    from inside the gateway.

    So this is the whole provisioning loop with no shell, no file editing and
    no restart: mint the token, write the profile, and watch it come up
    authenticating with what was minted.
    """
    del gateway  # the fixture stands up the gateway this runs against
    minted = await _op("mint-token", "newagent")
    assert minted["token"].startswith("trt_")

    await _set(
        "profiles.newagent",
        {
            "auth": {"bearer_token_name": "newagent"},
            "backends": {"web": {"url": "internal://web", "tools_allow": ["fetch_tool"]}},
        },
    )

    running = (get_active_config() or pytest.fail("no gateway")).config.profiles
    assert "newagent" in running, "the profile is serving without a restart"
    auth = running["newagent"].auth
    assert auth is not None and auth.bearer_token is not None
    assert auth.bearer_token.get_secret_value() == minted["token"]

    # And it authenticates: the token the agent was given is the one the
    # gateway will accept.
    from trentina.gateway.auth import verify_bearer

    verify_bearer(f"Bearer {minted['token']}", running["newagent"])


async def test_the_token_is_returned_once_and_never_again(gateway: pathlib.Path) -> None:
    """The only credential any Trentina tool hands back, so the shape of that
    exception matters: once, at creation, and rotation is a new name."""
    del gateway  # as above
    first = await _op("mint-token", "newagent")
    again = await _op("mint-token", "newagent")
    assert "already exists" in again["error"]
    assert first["token"] not in str(again)
