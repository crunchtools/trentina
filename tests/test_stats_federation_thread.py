"""``quarantine_stats`` reads the perimeter store for real, from its worker (5.0.1).

The bug this exists for shipped in 5.0.0 and reached production: an operator's
``quarantine_stats`` raised ``internal tool 'quarantine_stats_tool' call failed:
ProgrammingError`` on any gateway with a federation link. The chain is
``get_trentina_stats`` -> ``asyncio.to_thread(_snapshot, ...)`` ->
``_gateway_stats`` -> ``_federation`` -> ``link_report`` ->
``tool_pins.pending`` -> ``perimeter_db.list_pending_pins``, and that last read
used a connection bound to the event loop's thread.

``tests/test_federation_report.py`` covers the report's SHAPE and patches
``trentina.gateway.tool_pins.pending`` to a dict lookup to do it, which is the
right call there — that file is about what an operator is shown, and standing up
a store per case would say nothing about it. It is also exactly why the defect
shipped: the one function that breaks was the one replaced, in every test that
could have reached it.

So this file patches NOTHING on the read path. It stands up the real perimeter
store, puts a real pin in it, and calls the real tool. That is the only
arrangement that would have failed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trentina import perimeter_db
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.tool_pins import backend_id
from trentina.tools.stats import get_trentina_stats

pytestmark = pytest.mark.asyncio

WIKI_URL = "https://wiki.example/mcp"

PEER_PEM = (
    Ed25519PrivateKey.generate()
    .public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)

# Indented for the YAML block scalar below. Built here rather than inline
# because an f-string may not carry a backslash on 3.11, which the CI matrix
# still tests.
_PEM_BLOCK = "\n".join(f"            {line}" for line in PEER_PEM.strip().splitlines())

YAML = f"""\
profiles:
  ops:
    role: operator
    defense:
      provider: ollama  # keyless; the operator runs the gateway's own calls
    auth:
      bearer_token_env: TEST_OPS_TOKEN
    backends:
      admin:
        url: internal://web
  # The shared seat is an AGENT seat, which the loader requires: a derived
  # operator ingress would offer a peer this gateway's own admin tools. So the
  # caller and the link are two profiles, which is the shape production runs.
  josui:
    auth:
      bearer_token_env: TEST_JOSUI_TOKEN
    federation:
      secondary_key_env: TEST_SIGNING_KEY
      peers:
        breetai:
          public_key: |
{_PEM_BLOCK}
    backends:
      wiki:
        url: {WIKI_URL}
        tools_allow: ["*"]
"""


@pytest.fixture
def shared_seat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """An operator seat that shares itself, plus one tool really held pending."""
    monkeypatch.setenv("TEST_OPS_TOKEN", "ops-token")
    monkeypatch.setenv("TEST_JOSUI_TOKEN", "josui-token")
    monkeypatch.setenv(
        "TEST_SIGNING_KEY",
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode(),
    )
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)

    # A real row in the real store, on the loop's thread, as the gateway writes
    # one when a backend's tool definition changes.
    perimeter_db.put_pin(
        backend_id(WIKI_URL),
        "wiki_read",
        approved=("hash-of-the-approved-definition", '{"name": "wiki_read"}'),
        pending=("hash-of-the-changed-definition", '{"name": "wiki_read", "v": 2}'),
        rejected=False,
    )
    return config.profiles


async def test_an_operator_gets_its_federation_report_without_a_thread_error(
    shared_seat: dict,
) -> None:
    """The failure, as production had it: this raised ProgrammingError."""
    with profile_context(shared_seat["ops"]):
        result = await get_trentina_stats()

    assert result["scope"] == "gateway"
    (shared,) = result["federation"]["shared"]
    assert shared["seat"] == "josui"
    assert shared["ingress"] == "josui-federation"


async def test_the_count_is_the_one_in_the_store_not_a_stand_in(
    shared_seat: dict,
) -> None:
    """A fix that returned an empty report would satisfy the test above.

    The pin written in the fixture has to arrive, so the assertion is on the
    number the store actually holds — which is what makes this a test of the
    read rather than of the absence of an exception.
    """
    with profile_context(shared_seat["ops"]):
        result = await get_trentina_stats()

    (shared,) = result["federation"]["shared"]
    assert shared["held_for_approval"] == 1, shared


async def test_the_worker_left_no_reader_bound(shared_seat: dict) -> None:
    """``snapshot_reader`` clears ``_local.reader`` on the way out.

    A leaked reader would make the next write from that worker go to a
    read-only connection, and the pool reuses threads.
    """
    with profile_context(shared_seat["ops"]):
        await get_trentina_stats()

    def still_bound() -> Any:
        return getattr(perimeter_db._local, "reader", None)

    assert await asyncio.to_thread(still_bound) is None
