"""B2: the federated paging proxy (#592).

A federated peer pages a large response (part 1 + a marker under
``_meta._trentina_part``, the rest held on the peer). The downstream holds a
proxy under the peer's handle and forwards ``read_part`` to the peer, re-judging
each part, instead of re-paging or orphaning the rest.

The end-to-end path (a real large response actually cut by the upstream) needs
the L2 tokenizer/model and is covered where that runs; here the pieces are
driven directly with the peer call and the scan mocked, so the proxy's delivery,
relay-not-reframe, teardown and shape-checks are verified without a model.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr

from trentina.core.stages import Arrived
from trentina.defense import Provenance
from trentina.gateway import paging, parts
from trentina.gateway.backend import BackendCall
from trentina.gateway.modes_policy import policy_for
from trentina.gateway.profile import AuthConfig, Backend, FederatedConfig, Profile
from trentina.modes import Mode
from trentina.transports.mcp import _federated_continuation

HANDLE = "a" * 32


@pytest.fixture(autouse=True)
def _fresh_store() -> None:
    # The paging store is module-global; each test starts from empty so a held
    # handle (e.g. the collision test's) does not leak into the next.
    paging.reset()


def _profile() -> Profile:
    profile = Profile(
        name="downstream",
        auth=AuthConfig(bearer_token_env="D"),
        backends={"fed": Backend(url="https://lotor/gateway/up/mcp", federated=FederatedConfig())},
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


def _origin() -> paging.Origin:
    return paging.Origin(
        profile="downstream", backend="fed", tool="echo", label="echo",
        is_error=False, acted=False,
    )


def _policy(profile: Profile):
    return policy_for(profile, profile.backends["fed"], "echo")


def _proxied(count: int = 3) -> paging.Paged:
    up = paging.Upstream(backend="fed", reader="read_part", handle=HANDLE, count=count)
    paged = paging.hold_federated(
        _origin(),
        up,
        mode=Mode.FLAG,
        prompt=None,
        provenance=Provenance.EXTERNAL,
        l3_context=None,
        hidden=None,
    )
    assert paged is not None
    paged.delivered.add(1)
    return paged


def _peer_part(number: int, count: int, *, text: str, last: bool) -> BackendCall:
    body: dict[str, Any] = {"part": number, "parts": count, "delivered": list(range(1, number + 1))}
    if not last:
        body["handle"] = HANDLE
        body["next"] = number + 1
        body["reader"] = "read_part"
    return BackendCall(
        content=[{"type": "text", "text": text}],
        is_error=False,
        structured_content=None,
        meta={paging.PART_KEY: body},
    )


def _clean_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scan(**_: Any) -> SimpleNamespace:
        return SimpleNamespace(warning=None, blocked=False, refusal=None, extraction=None)

    monkeypatch.setattr(parts, "scan_tool_response", scan)


# --- pure shape / store units ---


def test_federated_upstream_reads_a_valid_marker() -> None:
    meta = {paging.PART_KEY: {"part": 1, "parts": 4, "handle": HANDLE, "next": 2, "reader": "rp"}}
    up = paging.federated_upstream("fed", meta)
    assert up is not None
    assert (up.backend, up.reader, up.handle, up.count) == ("fed", "rp", HANDLE, 4)


@pytest.mark.parametrize(
    "meta",
    [
        None,
        {},
        {paging.PART_KEY: "not-a-dict"},
        {paging.PART_KEY: {"parts": 4, "reader": "read_part"}},  # no handle
        {paging.PART_KEY: {"handle": "short", "parts": 4, "reader": "read_part"}},  # bad handle
        {paging.PART_KEY: {"handle": HANDLE, "parts": 1, "reader": "read_part"}},  # < 2 parts
        {paging.PART_KEY: {"handle": HANDLE, "parts": 4}},  # no reader
    ],
)
def test_federated_upstream_refuses_a_bad_marker(meta: dict[str, Any] | None) -> None:
    assert paging.federated_upstream("fed", meta) is None


def test_with_part_marker_writes_root_and_meta_with_reader() -> None:
    body = {"part": 1, "parts": 2, "handle": HANDLE, "next": 2}
    out = paging.with_part_marker({"content": [], "isError": False}, body, reader="read_part")
    assert next(iter(out)) == paging.PART_KEY  # first, as a header
    assert out["_meta"][paging.PART_KEY]["reader"] == "read_part"
    assert "reader" not in out[paging.PART_KEY]  # the root copy stays clean


def test_hold_federated_uses_the_peer_handle_and_refuses_a_collision() -> None:
    paged = _proxied()
    assert paged.handle == HANDLE
    assert paged.count == 3
    assert paged.upstream is not None
    # A second hold on the same handle is refused, not overwritten.
    again = paging.hold_federated(
        _origin(),
        paging.Upstream(backend="fed", reader="read_part", handle=HANDLE, count=3),
        mode=Mode.FLAG, prompt=None, provenance=Provenance.EXTERNAL, l3_context=None, hidden=None,
    )
    assert again is None


# --- the forwarding delivery ---


async def test_a_proxied_part_relays_the_peer_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_scan(monkeypatch)
    monkeypatch.setattr(
        parts, "call_backend_tool",
        lambda *a, **k: _done(_peer_part(2, 3, text="[part 2 of 3] body-two", last=False)),
    )
    profile, paged = _profile(), _proxied()
    assembled = await parts._deliver_part(
        profile, paged, 2, mode=Mode.FLAG, prompt=None, policy=_policy(profile)
    )
    text = json.dumps(assembled.result)
    assert "body-two" in text  # the peer's own block, relayed
    assert assembled.result[paging.PART_KEY]["part"] == 2  # our continuation marker, at root
    assert 2 in paged.delivered


async def test_the_last_proxied_part_releases_the_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_scan(monkeypatch)
    monkeypatch.setattr(
        parts, "call_backend_tool",
        lambda *a, **k: _done(_peer_part(3, 3, text="[part 3 of 3] body-three", last=True)),
    )
    profile, paged = _profile(), _proxied()
    paged.delivered.update({1, 2})
    await parts._deliver_part(
        profile, paged, 3, mode=Mode.FLAG, prompt=None, policy=_policy(profile)
    )
    assert paging.find("downstream", HANDLE) is None  # released on the last part


async def test_an_expired_upstream_is_a_clean_unknown_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_scan(monkeypatch)
    # The peer answers without a part marker — it no longer holds the rest.
    gone = BackendCall(content=[{"type": "text", "text": "[trentina] unknown handle"}],
                       is_error=False, structured_content=None, meta={})
    monkeypatch.setattr(parts, "call_backend_tool", lambda *a, **k: _done(gone))
    profile, paged = _profile(), _proxied()
    assembled = await parts._deliver_part(
        profile, paged, 2, mode=Mode.FLAG, prompt=None, policy=_policy(profile)
    )
    assert paging.UNKNOWN_HANDLE in json.dumps(assembled.result)
    assert paging.find("downstream", HANDLE) is None  # released


async def _done(value: Any) -> Any:
    return value


# --- recognition at the response boundary (_assemble's federated branch) ---


def _served_profile() -> Profile:
    # short_names off so read_part is served as "web__read_part" without the name
    # registry; an internal backend is what makes this profile able to page.
    profile = Profile(
        name="downstream",
        short_names=False,
        auth=AuthConfig(bearer_token_env="D"),
        backends={
            "web": Backend(url="internal://web", tools_allow=["*"]),
            "fed": Backend(url="https://lotor/gateway/up/mcp", federated=FederatedConfig()),
        },
    )
    profile.auth.bearer_token = SecretStr("t")
    return profile


def _continuation(profile: Profile, meta: dict[str, Any] | None) -> dict[str, Any]:
    result = {"content": [{"type": "text", "text": "[part 1 of 3] body-one"}], "isError": False}
    call = BackendCall(
        content=result["content"], is_error=False, structured_content=None, meta=meta
    )
    arrived = Arrived(content_blocks=[], structured=None, stripped=0, is_error=False, acted=False)
    return _federated_continuation(
        profile, profile.backends["fed"], "fed", "echo", call, result,
        mode=Mode.FLAG, prompt=None, provenance=Provenance.EXTERNAL,
        reduced=None, arrived=arrived,
    )


def _marker(**over: Any) -> dict[str, Any]:
    body = {"part": 1, "parts": 3, "handle": HANDLE, "next": 2, "reader": "rp", **over}
    return {paging.PART_KEY: body}


def test_a_federated_part_one_holds_a_proxy_and_is_marked() -> None:
    profile = _served_profile()
    out = _continuation(profile, _marker())
    assert out[paging.PART_KEY]["handle"] == HANDLE  # our continuation marker, at root
    served = f"web__{paging.READ_PART_TOOL}"
    assert out["_meta"][paging.PART_KEY]["reader"] == served  # our reader, not the peer's
    held = paging.find("downstream", HANDLE)
    assert held is not None and held.upstream is not None  # a proxy, under the peer's handle
    assert held.upstream.reader == "rp"  # the peer's reader, for the forwarded call


def test_a_non_federated_backend_is_left_alone() -> None:
    profile = _served_profile()
    profile.backends["fed"].federated = None
    out = _continuation(profile, _marker())
    assert paging.PART_KEY not in out  # not recognized as federated; untouched
    assert paging.find("downstream", HANDLE) is None


def test_a_response_without_a_peer_marker_is_left_alone() -> None:
    profile = _served_profile()
    out = _continuation(profile, {})
    assert paging.PART_KEY not in out
    assert paging.find("downstream", HANDLE) is None


def test_a_profile_that_cannot_read_a_part_does_not_proxy() -> None:
    # No internal backend: nothing serves read_part, so the rest cannot be read
    # here. Leave the response as part 1 rather than hold a proxy we can't drive.
    profile = _profile()  # only the federated backend
    out = _continuation(profile, _marker())
    assert paging.PART_KEY not in out
    assert paging.find("downstream", HANDLE) is None
