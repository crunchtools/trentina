"""E1c: pass a federated peer's pin-hold state to the downstream (#592).

Two additive ``_meta`` signals, both read only for a federated backend and
designed per the cto ruling:

* a tools/list held COUNT — the upstream tells a downstream how many tools it
  is withholding in that caller's slice, without their names;
* a call-refusal MAPPING — the upstream's pin call gate answers ``tool_held``,
  which the downstream re-authors as its own ``tool_held_upstream`` ("held
  upstream, awaiting approval"), never relaying the peer's text.

Driven directly (no server, no model): the helpers are pure.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from trentina.gateway import aggregate, surface, tool_pins
from trentina.gateway import backend as backend_mod
from trentina.gateway.backend import BackendCall
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    FederatedConfig,
    FederationConfig,
    Profile,
)
from trentina.gateway.surface import BackendSurface, Stage, Surface
from trentina.outcomes import Outcome
from trentina.reserved import PINS_KEY, REFUSAL_KEY
from trentina.transports.mcp import (
    _federated_hold_refusal,
    _mirror_refusal_meta,
    _route_tools_list,
)

UP_URL = "http://up:9000/mcp"


def _federated_backend() -> Backend:
    return Backend(url=UP_URL, tools_allow=["*"], federated=FederatedConfig())


def _call(meta: dict[str, Any] | None, text: str = "ordinary peer content") -> BackendCall:
    """A federated peer's tool result carrying ``meta`` and one text block. Shared
    by every hold-mapping case; the text lets one test prove it is not relayed."""
    return BackendCall(
        content=[{"type": "text", "text": text}],
        is_error=False,
        structured_content=None,
        meta=meta,
    )


# --- Signal 2: the downstream maps a peer's tool_held to its own words ---


def test_a_peer_tool_held_becomes_tool_held_upstream() -> None:
    call = _call({REFUSAL_KEY: {"reason": tool_pins.TOOL_HELD_REASON}}, text="SECRET peer wording")
    assembled = _federated_hold_refusal(_federated_backend(), call, stripped=0)
    assert assembled is not None
    assert assembled.outcome is Outcome.DENIED_GUARD
    assert assembled.result[REFUSAL_KEY]["reason"] == tool_pins.TOOL_HELD_UPSTREAM_REASON
    # The peer's content is discarded unread, not relayed.
    assert "SECRET" not in assembled.result["content"][0]["text"]
    assert "held upstream" in assembled.result[REFUSAL_KEY]["detail"]


def test_a_non_federated_backend_is_never_hold_mapped() -> None:
    plain = Backend(url=UP_URL, tools_allow=["*"])
    call = _call({REFUSAL_KEY: {"reason": tool_pins.TOOL_HELD_REASON}})
    assert _federated_hold_refusal(plain, call, stripped=0) is None


@pytest.mark.parametrize(
    "meta",
    [
        pytest.param(None, id="no-meta"),
        pytest.param({}, id="empty-meta"),
        pytest.param({REFUSAL_KEY: {"reason": "defense"}}, id="other-reason"),
        pytest.param({REFUSAL_KEY: {"detail": "x"}}, id="no-reason"),
    ],
)
def test_only_the_exact_tool_held_reason_maps(meta: dict[str, Any] | None) -> None:
    assert _federated_hold_refusal(_federated_backend(), _call(meta), stripped=0) is None


# --- Signal 2 emit: the upstream mirrors a root refusal reason into _meta ---


def _ingress() -> Profile:
    return Profile(
        name="lotor",
        auth=AuthConfig(bearer_token_env="UP"),
        defense=DefenseConfig(provider="ollama"),
        federation=FederationConfig(),
        backends={},
    )


def _plain_profile() -> Profile:
    return Profile(
        name="solo",
        auth=AuthConfig(bearer_token_env="UP"),
        defense=DefenseConfig(provider="ollama"),
        backends={},
    )


def test_mirror_copies_only_the_reason_for_an_ingress() -> None:
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": "..."}],
            "isError": False,
            REFUSAL_KEY: {
                "reason": "tool_held",
                "detail": "secret peer wording",
                "alternatives": [],
            },
        },
    }
    out = _mirror_refusal_meta(_ingress(), response)
    mirrored = out["result"]["_meta"][REFUSAL_KEY]
    assert mirrored == {"reason": "tool_held"}  # reason only — never the detail
    assert "detail" not in mirrored


def test_mirror_is_a_noop_off_an_ingress() -> None:
    response = {"result": {"content": [], "isError": False, REFUSAL_KEY: {"reason": "tool_held"}}}
    out = _mirror_refusal_meta(_plain_profile(), response)
    assert "_meta" not in out["result"]


def test_mirror_leaves_a_clean_result_alone() -> None:
    response = {"result": {"content": [{"type": "text", "text": "ok"}], "isError": False}}
    out = _mirror_refusal_meta(_ingress(), response)
    assert "_meta" not in out["result"]


# --- Signal 1 read: the downstream records a peer's reported held count ---


def _tools_result(meta: Any, n_tools: int = 5) -> SimpleNamespace:
    return SimpleNamespace(meta=meta, tools=[object()] * n_tools)


def test_a_federated_peer_held_count_is_recorded() -> None:
    backend_mod._federated_held_upstream.pop(UP_URL, None)
    backend_mod._read_federated_held(_federated_backend(), _tools_result({PINS_KEY: {"held": 3}}))
    assert backend_mod._federated_held_upstream.get(UP_URL) == 3


def test_held_may_exceed_the_listed_count() -> None:
    # A withheld tool is absent from the list, so a peer holding its only tool
    # reports held=1 and lists 0 — the count must NOT be bounded by the listing.
    backend_mod._federated_held_upstream.pop(UP_URL, None)
    result = _tools_result({PINS_KEY: {"held": 1}}, n_tools=0)
    backend_mod._read_federated_held(_federated_backend(), result)
    assert backend_mod._federated_held_upstream.get(UP_URL) == 1


@pytest.mark.parametrize(
    "meta",
    [
        pytest.param(None, id="no-meta"),
        pytest.param({PINS_KEY: {"held": -1}}, id="negative"),
        pytest.param({PINS_KEY: {"held": True}}, id="bool"),
        pytest.param({PINS_KEY: {"held": "3"}}, id="string"),
    ],
)
def test_a_bad_held_count_is_ignored(meta: Any) -> None:
    backend_mod._federated_held_upstream.pop(UP_URL, None)
    backend_mod._read_federated_held(_federated_backend(), _tools_result(meta, n_tools=5))
    assert backend_mod._federated_held_upstream.get(UP_URL) is None


def test_a_missing_report_clears_a_stale_held_count() -> None:
    # A peer that reported a count and then stops must not leave the downstream
    # showing the old number forever.
    backend_mod._federated_held_upstream[UP_URL] = 4
    backend_mod._read_federated_held(_federated_backend(), _tools_result(None))
    assert backend_mod._federated_held_upstream.get(UP_URL) is None


def test_a_non_federated_backend_reports_no_upstream_held() -> None:
    plain = Backend(url="http://other:9000/mcp", tools_allow=["*"])
    backend_mod._federated_held_upstream.pop(plain.url, None)
    backend_mod._read_federated_held(plain, _tools_result({PINS_KEY: {"held": 2}}))
    assert backend_mod._federated_held_upstream.get(plain.url) is None


# --- held accounting: local count scoped to the allowed slice ---


def _tool(name: str) -> dict[str, Any]:
    return {"name": name, "description": f"{name} tool", "inputSchema": {"type": "object"}}


def test_held_in_allowed_slice_counts_only_allowlisted_holds() -> None:
    offered = [_tool("a"), _tool("b"), _tool("c")]
    unheld = [_tool("a")]  # b and c are held
    wildcard = Backend(url=UP_URL, tools_allow=["*"])
    assert aggregate._held_in_allowed_slice(wildcard, offered, unheld) == 2
    # An allowlist that admits only a and b: c's hold is outside the slice.
    narrowed = Backend(url=UP_URL, tools_allow=["a", "b"])
    assert aggregate._held_in_allowed_slice(narrowed, offered, unheld) == 1


# --- Signal 1 emit + held_total ---


def test_held_total_sums_the_backend_holds() -> None:
    s = Surface(
        backends={
            "x": BackendSurface(Stage(), Stage(), Stage(), held=2),
            "y": BackendSurface(Stage(), Stage(), Stage(), held=1),
        },
        served=Stage(),
    )
    surface.record_surface("lotor", s)
    try:
        assert surface.held_total("lotor") == 3
        assert surface.held_total("absent") == 0
    finally:
        surface.forget_surface("lotor")


@pytest.mark.asyncio
async def test_tools_list_carries_the_held_count_for_an_ingress() -> None:
    profile = _ingress()
    aggregate._profile_tools_cache[profile.name] = []
    surface.record_surface(
        profile.name,
        Surface(
            backends={"fed": BackendSurface(Stage(), Stage(), Stage(), held=4)},
            served=Stage(),
        ),
    )
    try:
        resp = await _route_tools_list(profile, 1)
        assert resp["result"]["_meta"][PINS_KEY] == {"held": 4}
    finally:
        aggregate._profile_tools_cache.pop(profile.name, None)
        surface.forget_surface(profile.name)


@pytest.mark.asyncio
async def test_tools_list_has_no_held_meta_off_an_ingress() -> None:
    profile = _plain_profile()
    aggregate._profile_tools_cache[profile.name] = []
    try:
        resp = await _route_tools_list(profile, 1)
        assert "_meta" not in resp["result"]
    finally:
        aggregate._profile_tools_cache.pop(profile.name, None)
