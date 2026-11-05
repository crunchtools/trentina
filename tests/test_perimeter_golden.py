"""The golden oracle: the perimeter routes do exactly what 6.7.0 did (#535 R1).

Every case here was recorded on the code BEFORE the spine (``tests/golden/``);
see ``tests/perimeter_golden.py`` for what a record holds and which seams are
fake. A port that changes one observable byte fails here.

    uv run python scripts/record_golden.py --record   # re-record (pre-spine only)
    uv run python scripts/record_golden.py --check    # check (or plain pytest)

Re-recording is NOT how a failure is fixed. The fixtures are the contract; the
only differences allowed are the ones named in ``DELTAS``, each a deliberate
tightening listed in the CHANGELOG.
"""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from tests import perimeter_golden as g
from tests.perimeter_golden import Call, Stack, bearer, drive, reply

Case = Callable[[pytest.MonkeyPatch], Awaitable[dict[str, Any]]]
CASES: dict[str, Case] = {}

#: Observable differences the port is ALLOWED to make, by case. Each is a
#: change to an audit row only — nothing an agent receives — listed in the
#: CHANGELOG; every other difference is a failure. The spine has one rule where
#: the routes had several, and each delta is a row that now says more:
#:   * the row names the instance (``http:github``) once it is bound, before the
#:     route's own rails; http named it only after them. A request to no
#:     instance is ``<route>:-`` on every route; git wrote ``git``.
#:   * the row's tool is the HTTP method until the route says otherwise; git
#:     wrote ``-`` before it had parsed the service.
#:   * what ``admit`` established is on the row before the slot, so a busy
#:     refusal records the destination it refused; http set it after the slot.
DELTAS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}


def _first_row(**changes: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def apply(record: dict[str, Any]) -> dict[str, Any]:
        record["gateway_calls"][0].update(changes)
        return record

    return apply


def _busy_names_its_destination(record: dict[str, Any]) -> dict[str, Any]:
    served = next(r for r in record["gateway_calls"] if r["error_message"] is None)
    for row in record["gateway_calls"]:
        if row["error_message"] == "busy":
            row["destination"] = served["destination"]
            row["destination_kind"] = served["destination_kind"]
    return record


for _case in ("http-bad-path", "http-method-not-listed", "http-path-not-listed"):
    DELTAS[_case] = _first_row(backend="http:github")
DELTAS["http-busy"] = _busy_names_its_destination
DELTAS["git-bad-endpoint"] = _first_row(tool="GET")
DELTAS["git-bad-service"] = _first_row(tool="GET")
DELTAS["git-unknown-remote"] = _first_row(backend="git:-", tool="GET")
DELTAS["git-not-granted-profile"] = _first_row(backend="git:-", tool="GET")


def case(name: str) -> Callable[[Case], Case]:
    def deco(fn: Case) -> Case:
        CASES[name] = fn
        return fn

    return deco


def http(scenario: Callable[[Stack], Awaitable[Any]]) -> Case:
    async def run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        return await g.record_http(monkeypatch, scenario)

    return run


async def one(s: Stack, call: Call) -> list[dict[str, Any]]:
    return [await drive(s.app, call)]


def single(host: str, handler: g.Handler | None, call: Call) -> Case:
    """A case of one request, with ``host`` answering as ``handler`` scripts."""

    async def sc(s: Stack) -> Any:
        if handler is not None:
            s.net.handlers[host] = handler
        return await one(s, call)

    return http(sc)


async def concurrent(s: Stack, calls: list[Call], release: asyncio.Event, held: int) -> list[Any]:
    """Run ``calls`` at once against an upstream that waits on ``release``;
    let it go once ``held`` requests are parked upstream and the rest returned."""
    tasks = [asyncio.create_task(drive(s.app, c)) for c in calls]
    for _ in range(500):
        if len(s.net.seen) >= held and sum(t.done() for t in tasks) >= len(calls) - held:
            break
        await asyncio.sleep(0.01)
    release.set()
    results = await asyncio.gather(*tasks)
    # Which request lost the race is not the contract; how many did, and how, is.
    return sorted(json.dumps(r, sort_keys=True) for r in results)


# =========================================================================== /proxy/http

GH = "/proxy/http/github"
JSON_HDR = {"content-type": "application/json"}


def _gh(profile: str = "agent1", **kw: Any) -> dict[str, str]:
    return {**bearer(profile), **JSON_HDR, **kw}


def _ok(s: Stack, **kw: Any) -> None:
    s.net.handlers["api.github.com"] = reply(200, '{"name":"widgets"}', **kw)


@case("http-get")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        _ok(s)
        return await one(
            s,
            Call(
                "GET",
                f"{GH}/repos/acme/widgets",
                headers={**bearer("agent1"), "x-github-api-version": "2022-11-28", "x-other": "1"},
                query="per_page=5",
            ),
        )

    return await http(sc)(mp)


@case("http-post-json")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        s.net.handlers["api.github.com"] = reply(201, '{"id":7}')
        return await one(
            s,
            Call(
                "POST", f"{GH}/repos/acme/widgets/issues", headers=_gh(), body=[b'{"title": "hi"}']
            ),
        )

    return await http(sc)(mp)


@case("http-post-chunked-body")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        s.net.handlers["api.github.com"] = reply(201, '{"id":8}')
        return await one(
            s,
            Call(
                "POST",
                f"{GH}/repos/acme/widgets/issues",
                headers=_gh(),
                body=[b'{"title":', b' "split', b' body"}'],
            ),
        )

    return await http(sc)(mp)


_HTTP_REQUESTS: dict[str, Call] = {
    "http-unauthorized": Call(
        "GET", f"{GH}/repos/acme/widgets", headers={"authorization": "Bearer nope"}
    ),
    "http-no-token": Call("GET", f"{GH}/repos/acme/widgets"),
    "http-unknown-upstream": Call(
        "GET", "/proxy/http/gitlab/repos/acme/widgets", headers=bearer("agent1")
    ),
    "http-not-granted": Call("GET", f"{GH}/repos/acme/widgets", headers=bearer("agent3")),
    "http-method-not-listed": Call("DELETE", f"{GH}/repos/acme/widgets", headers=bearer("agent1")),
    "http-path-not-listed": Call("GET", f"{GH}/repos/other/widgets", headers=bearer("agent1")),
    "http-bad-path": Call("GET", f"{GH}/repos/acme/%2e%2e/secrets", headers=bearer("agent1")),
    "http-not-json": Call(
        "POST", f"{GH}/repos/acme/widgets/issues", headers=_gh(), body=[b"title=hi"]
    ),
    "http-malformed-json": Call(
        "POST", f"{GH}/repos/acme/widgets/issues", headers=_gh(), body=[b'{"a": 1, "a": 2}']
    ),
    "http-binary-body": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers={**bearer("agent1"), "content-type": "application/octet-stream"},
        body=[b"\x00\x01\x02\xff" * 32],
    ),
    "http-credential-in-request": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers=_gh(),
        body=[json.dumps({"body": "key " + "AK" + "IA" + "IOSFODNN7EXAMPLE"}).encode()],
    ),
    "http-flagged-request": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers=_gh(),
        body=[json.dumps({"body": g.INJECT}).encode()],
    ),
    "http-unjudged-request": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers=_gh(),
        body=[json.dumps({"body": g.UNJUDGED}).encode()],
    ),
    "http-flag-mode-forwards-flagged": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers=_gh("agent2"),
        body=[json.dumps({"body": g.INJECT}).encode()],
    ),
    "http-client-gone-during-body": Call(
        "POST",
        f"{GH}/repos/acme/widgets/issues",
        headers=_gh(),
        body=[b'{"title":', b' "x"}'],
        gone_after_chunks=1,
    ),
}
CASES.update(
    {
        n: single("api.github.com", reply(200, '{"name":"widgets"}'), c)
        for n, c in _HTTP_REQUESTS.items()
    }
)


_HTTP_RESPONSES: dict[str, g.Handler] = {
    "http-response-flagged": reply(200, json.dumps({"text": g.INJECT})),
    "http-response-unjudged": reply(200, json.dumps({"text": g.UNJUDGED})),
    "http-response-binary": reply(
        200, b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, content_type="image/png"
    ),
    "http-response-text": reply(200, "plain words", content_type="text/plain"),
    "http-upstream-redirect": reply(302, "", headers={"location": "https://evil.example/"}),
    "http-upstream-404": reply(404, '{"message":"Not Found"}'),
    "http-upstream-500": reply(500, '{"message":"boom"}'),
    "http-upstream-encoded": reply(
        200, gzip.compress(b'{"a":1}'), headers={"content-encoding": "gzip"}
    ),
    "http-upstream-connect-fail": reply(raises=httpx.ConnectError("golden")),
    "http-upstream-idle": reply(raises=httpx.ReadTimeout("golden")),
    "http-upstream-chunked": reply(200, chunks=[b'{"a":', b"1,", b'"b":2}']),
}
CASES.update(
    {
        n: single(
            "api.github.com", h, Call("GET", f"{GH}/repos/acme/widgets", headers=bearer("agent1"))
        )
        for n, h in _HTTP_RESPONSES.items()
    }
)


@case("http-denied-address")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        _ok(s)
        s.net.addresses = [g.PRIVATE_ADDRESS]
        return await one(s, Call("GET", f"{GH}/repos/acme/widgets", headers=bearer("agent1")))

    return await http(sc)(mp)


@case("http-busy")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        release = asyncio.Event()
        s.net.handlers["api.github.com"] = reply(200, '{"ok":1}', wait=release)
        calls = [
            Call("GET", f"{GH}/repos/acme/widgets", headers=bearer("agent1")) for _ in range(9)
        ]
        return await concurrent(s, calls, release, held=8)

    return await http(sc)(mp)


# =========================================================================== /proxy/git

GIT = "/proxy/git/forge"
SHA_A = "a" * 40
SHA_B = "b" * 40
ZERO = "0" * 40


def pkt(line: str) -> bytes:
    data = line.encode()
    return f"{len(data) + 4:04x}".encode() + data


FLUSH = b"0000"


def advertisement(service: str) -> bytes:
    return (
        pkt(f"# service={service}\n")
        + FLUSH
        + pkt(f"{SHA_A} HEAD\0multi_ack side-band-64k ofs-delta report-status\n")
        + pkt(f"{SHA_A} refs/heads/main\n")
        + pkt(f"{SHA_B} refs/pull/1/head\n")
        + pkt(f"{SHA_B} refs/tags/v1\n")
        + FLUSH
    )


def _refs(service: str) -> g.Handler:
    return reply(200, advertisement(service), content_type=f"application/x-{service}-advertisement")


UPLOAD_REQ = pkt(f"want {SHA_A} side-band-64k\n") + FLUSH + pkt("done\n")
PACK = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x5a" * 40


def _push_body(ref: str, old: str = ZERO, new: str = SHA_B) -> list[bytes]:
    commands = pkt(f"{old} {new} {ref}\0report-status side-band-64k\n") + FLUSH
    # Three chunks, the pack arriving in the same chunk as the flush.
    return [commands[:20], commands[20:] + PACK[:10], PACK[10:]]


def _git_call(
    method: str,
    tail: str,
    *,
    profile: str = "agent1",
    query: str = "",
    body: list[bytes] | None = None,
    ctype: str | None = None,
    repo: str = "acme/widgets.git",
    protocol: str | None = None,
    **kw: Any,
) -> Call:
    headers = dict(bearer(profile)) if profile else {}
    if protocol is not None:
        headers["git-protocol"] = protocol
    if ctype:
        headers["content-type"] = ctype
    return Call(method, f"{GIT}/{repo}/{tail}", headers=headers, query=query, body=body or [], **kw)


_GIT_CASES: dict[str, tuple[g.Handler | None, Call]] = {
    "git-refs-fetch": (
        _refs("git-upload-pack"),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-refs-fetch-v2": (
        reply(
            200,
            pkt("version 2\n") + pkt("ls-refs\n") + pkt("fetch\n") + FLUSH,
            content_type="application/x-git-upload-pack-advertisement",
        ),
        _git_call("GET", "info/refs", query="service=git-upload-pack", protocol="version=2"),
    ),
    "git-ls-refs-v2": (
        reply(
            200,
            pkt(f"{SHA_A} refs/heads/main\n") + pkt(f"{SHA_B} refs/pull/1/head\n") + FLUSH,
            content_type="application/x-git-upload-pack-result",
        ),
        _git_call(
            "POST",
            "git-upload-pack",
            protocol="version=2",
            ctype="application/x-git-upload-pack-request",
            body=[pkt("command=ls-refs\n") + b"0001" + pkt("peel\n") + FLUSH],
        ),
    ),
    "git-protocol-refused": (
        _refs("git-upload-pack"),
        _git_call("GET", "info/refs", query="service=git-upload-pack", protocol="version=0"),
    ),
    "git-refs-push": (
        _refs("git-receive-pack"),
        _git_call("GET", "info/refs", query="service=git-receive-pack"),
    ),
    "git-refs-push-not-granted": (
        _refs("git-receive-pack"),
        _git_call("GET", "info/refs", query="service=git-receive-pack", repo="acme/gadgets.git"),
    ),
    "git-repo-denied": (
        _refs("git-upload-pack"),
        _git_call(
            "GET", "info/refs", query="service=git-upload-pack", repo="acme/widgets-private.git"
        ),
    ),
    "git-repo-not-listed": (
        _refs("git-upload-pack"),
        _git_call("GET", "info/refs", query="service=git-upload-pack", repo="other/widgets.git"),
    ),
    "git-bad-service": (
        _refs("git-upload-pack"),
        _git_call("GET", "info/refs", query="service=git-shell"),
    ),
    "git-bad-endpoint": (_refs("git-upload-pack"), _git_call("GET", "objects/info/packs")),
    "git-unknown-remote": (
        _refs("git-upload-pack"),
        Call(
            "GET",
            "/proxy/git/gitlab/acme/widgets.git/info/refs",
            headers=bearer("agent1"),
            query="service=git-upload-pack",
        ),
    ),
    "git-unauthorized": (
        _refs("git-upload-pack"),
        Call("GET", f"{GIT}/acme/widgets.git/info/refs", query="service=git-upload-pack"),
    ),
    "git-not-granted-profile": (
        _refs("git-upload-pack"),
        _git_call("GET", "info/refs", query="service=git-upload-pack", profile="agent3"),
    ),
    "git-upload-pack": (
        reply(200, b"0008NAK\n" + PACK, content_type="application/x-git-upload-pack-result"),
        _git_call(
            "POST",
            "git-upload-pack",
            body=[UPLOAD_REQ],
            ctype="application/x-git-upload-pack-request",
        ),
    ),
    "git-upload-pack-gzip": (
        reply(200, b"0008NAK\n" + PACK, content_type="application/x-git-upload-pack-result"),
        Call(
            "POST",
            f"{GIT}/acme/widgets.git/git-upload-pack",
            headers={
                **bearer("agent1"),
                "content-type": "application/x-git-upload-pack-request",
                "content-encoding": "gzip",
            },
            body=[gzip.compress(UPLOAD_REQ)],
        ),
    ),
    "git-push": (
        reply(
            200,
            pkt("unpack ok\n") + pkt("ok refs/heads/agent1/topic\n") + FLUSH,
            content_type="application/x-git-receive-pack-result",
        ),
        _git_call(
            "POST",
            "git-receive-pack",
            body=_push_body("refs/heads/agent1/topic"),
            ctype="application/x-git-receive-pack-request",
        ),
    ),
    "git-push-ref-denied": (
        reply(200, b""),
        _git_call(
            "POST",
            "git-receive-pack",
            body=_push_body("refs/heads/main"),
            ctype="application/x-git-receive-pack-request",
        ),
    ),
    "git-push-tag": (
        reply(200, b""),
        _git_call(
            "POST",
            "git-receive-pack",
            body=_push_body("refs/tags/v2"),
            ctype="application/x-git-receive-pack-request",
        ),
    ),
    "git-push-delete": (
        reply(200, b""),
        _git_call(
            "POST",
            "git-receive-pack",
            body=_push_body("refs/heads/agent1/topic", old=SHA_A, new=ZERO),
            ctype="application/x-git-receive-pack-request",
        ),
    ),
    "git-push-client-gone": (
        reply(200, b""),
        _git_call(
            "POST",
            "git-receive-pack",
            body=_push_body("refs/heads/agent1/topic"),
            ctype="application/x-git-receive-pack-request",
            gone_after_chunks=1,
        ),
    ),
    "git-upstream-403": (
        reply(403, "denied by forge", content_type="text/plain"),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-upstream-404": (
        reply(404, "no such repo", content_type="text/plain"),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-upstream-500": (
        reply(500, "forge broke", content_type="text/plain"),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-upstream-redirect": (
        reply(302, "", headers={"location": "https://evil.example/"}),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-upstream-connect-fail": (
        reply(raises=httpx.ConnectError("golden")),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-upstream-idle": (
        reply(raises=httpx.ReadTimeout("golden")),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
    "git-refs-chunked": (
        reply(
            200,
            chunks=[advertisement("git-upload-pack")[:30], advertisement("git-upload-pack")[30:]],
            content_type="application/x-git-upload-pack-advertisement",
        ),
        _git_call("GET", "info/refs", query="service=git-upload-pack"),
    ),
}

CASES.update({n: single("git.example.com", h, c) for n, (h, c) in _GIT_CASES.items()})


@case("git-busy")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        release = asyncio.Event()
        s.net.handlers["git.example.com"] = reply(
            200,
            advertisement("git-upload-pack"),
            wait=release,
            content_type="application/x-git-upload-pack-advertisement",
        )
        calls = [_git_call("GET", "info/refs", query="service=git-upload-pack") for _ in range(9)]
        return await concurrent(s, calls, release, held=8)

    return await http(sc)(mp)


# =========================================================================== /proxy/llm

LLM = "/proxy/llm/anthropic/v1/messages"


def _msg(text: str = "hello", **extra: Any) -> bytes:
    return json.dumps(
        {
            "model": "claude-golden",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": text}],
            **extra,
        }
    ).encode()


def _llm_call(body: bytes | None = None, profile: str = "agent1", **kw: Any) -> Call:
    headers = (
        {**bearer(profile), "content-type": "application/json", "anthropic-version": "2023-06-01"}
        if profile
        else {"content-type": "application/json"}
    )
    headers.update(kw.pop("headers", {}))
    return Call("POST", kw.pop("path", LLM), headers=headers, body=[body or _msg()], **kw)


COMPLETION = json.dumps(
    {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "hi there"}],
        "stop_reason": "end_turn",
    }
)


def _sse(*texts: str) -> list[bytes]:
    frames = [b'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1"}}\n\n']
    for t in texts:
        frames.append(
            b"event: content_block_delta\ndata: "
            + json.dumps(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": t},
                }
            ).encode()
            + b"\n\n"
        )
    frames.append(b'event: message_stop\ndata: {"type":"message_stop"}\n\n')
    return frames


_LLM_CASES: dict[str, tuple[g.Handler, Call]] = {
    "llm-messages": (reply(200, COMPLETION), _llm_call()),
    "llm-x-api-key": (
        reply(200, COMPLETION),
        _llm_call(
            profile="", headers={"x-api-key": g.TOKENS["agent1"], "anthropic-version": "2023-06-01"}
        ),
    ),
    "llm-stream": (
        reply(200, chunks=_sse("one ", "two ", "three"), content_type="text/event-stream"),
        _llm_call(_msg(stream=True)),
    ),
    "llm-stream-flagged-completion": (
        reply(200, chunks=_sse("sure ", g.INJECT, " done"), content_type="text/event-stream"),
        _llm_call(_msg(stream=True)),
    ),
    "llm-completion-flagged": (
        reply(200, COMPLETION.replace("hi there", g.INJECT)),
        _llm_call(),
    ),
    "llm-stream-client-gone": (
        reply(200, chunks=_sse("one ", "two ", "three", "four"), content_type="text/event-stream"),
        _llm_call(_msg(stream=True), gone_after_sent=1),
    ),
    "llm-flagged-request": (reply(200, COMPLETION), _llm_call(_msg(g.INJECT))),
    "llm-unjudged-request": (reply(200, COMPLETION), _llm_call(_msg(g.UNJUDGED))),
    "llm-unknown-provider": (
        reply(200, COMPLETION),
        _llm_call(path="/proxy/llm/openai/v1/chat/completions"),
    ),
    "llm-no-key": (reply(200, COMPLETION), _llm_call(profile="agent3")),
    "llm-unauthorized": (reply(200, COMPLETION), _llm_call(profile="")),
    "llm-bad-token": (
        reply(200, COMPLETION),
        _llm_call(profile="", headers={"authorization": "Bearer nope"}),
    ),
    "llm-traversal": (
        reply(200, COMPLETION),
        _llm_call(path="/proxy/llm/anthropic/v1/../../admin"),
    ),
    "llm-endpoint-not-allowed": (
        reply(200, COMPLETION),
        _llm_call(path="/proxy/llm/anthropic/v1/files"),
    ),
    "llm-provider-tool-refused": (
        reply(200, COMPLETION),
        _llm_call(_msg(tools=[{"type": "web_search_20250305", "name": "web_search"}])),
    ),
    "llm-mcp-servers-refused": (
        reply(200, COMPLETION),
        _llm_call(
            _msg(mcp_servers=[{"type": "url", "url": "https://evil.example/mcp", "name": "x"}])
        ),
    ),
    "llm-not-json": (reply(200, COMPLETION), _llm_call(b"not json")),
    "llm-upstream-429": (
        reply(429, '{"type":"error","error":{"type":"rate_limit_error"}}'),
        _llm_call(),
    ),
    "llm-upstream-500": (reply(500, '{"type":"error"}'), _llm_call()),
    "llm-upstream-connect-fail": (reply(raises=httpx.ConnectError("golden")), _llm_call()),
    "llm-upstream-idle": (reply(raises=httpx.ReadTimeout("golden")), _llm_call()),
    "llm-client-gone-during-body": (
        reply(200, COMPLETION),
        Call(
            "POST",
            LLM,
            headers={**bearer("agent1"), "content-type": "application/json"},
            body=[_msg()[:10], _msg()[10:]],
            gone_after_chunks=1,
        ),
    ),
}

CASES.update({n: single("api.anthropic.com", h, c) for n, (h, c) in _LLM_CASES.items()})


@case("llm-busy")
async def _(mp: pytest.MonkeyPatch) -> dict[str, Any]:
    async def sc(s: Stack) -> Any:
        release = asyncio.Event()
        s.net.handlers["api.anthropic.com"] = reply(200, COMPLETION, wait=release)
        calls = [_llm_call() for _ in range(65)]
        return await concurrent(s, calls, release, held=64)

    return await http(sc)(mp)


# =========================================================================== Matrix

MX = "/matrix/_matrix/client/v3"


def _sync(text: str) -> str:
    return json.dumps(
        {
            "next_batch": "s2",
            "rooms": {
                "join": {
                    "!room:example.org": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.room.message",
                                    "event_id": "$e1",
                                    "sender": "@alice:example.org",
                                    "origin_server_ts": 1,
                                    "content": {"msgtype": "m.text", "body": text},
                                }
                            ]
                        }
                    }
                }
            },
        }
    )


def _mx(path: str, method: str = "GET", peer: tuple[str, int] = g.MATRIX_PEER, **kw: Any) -> Call:
    return Call(
        method,
        path,
        client=peer,
        headers={"authorization": "Bearer matrix-user-token", **kw.pop("headers", {})},
        **kw,
    )


_MX_CASES: dict[str, tuple[g.Handler, Call]] = {
    "matrix-sync-clean": (reply(200, _sync("hello there")), _mx(f"{MX}/sync", query="since=s1")),
    "matrix-sync-injection": (reply(200, _sync(g.INJECT)), _mx(f"{MX}/sync")),
    "matrix-sync-unjudged": (reply(200, _sync(g.UNJUDGED)), _mx(f"{MX}/sync")),
    "matrix-sync-chunked": (
        reply(200, chunks=[_sync("hi").encode()[:25], _sync("hi").encode()[25:]]),
        _mx(f"{MX}/sync"),
    ),
    "matrix-versions": (
        reply(200, '{"versions":["v1.11"]}'),
        _mx("/matrix/_matrix/client/versions"),
    ),
    "matrix-send": (
        reply(200, '{"event_id":"$sent"}'),
        _mx(
            f"{MX}/rooms/!room:example.org/send/m.room.message/txn1",
            method="PUT",
            headers={"content-type": "application/json"},
            body=[b'{"msgtype":"m.text","body":"out"}'],
        ),
    ),
    "matrix-text-response": (
        reply(200, "plain text", content_type="text/plain"),
        _mx(f"{MX}/account/whoami"),
    ),
    "matrix-media": (
        reply(200, b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, content_type="image/png"),
        _mx("/matrix/_matrix/client/v1/media/download/example.org/abc"),
    ),
    "matrix-redirect": (
        reply(302, "", headers={"location": "https://cdn.example.org/x"}),
        _mx("/matrix/_matrix/client/v1/media/download/example.org/abc"),
    ),
    "matrix-unknown-peer": (reply(200, _sync("x")), _mx(f"{MX}/sync", peer=("10.1.1.1", 1))),
    "matrix-forwarded-for": (
        reply(200, _sync("x")),
        _mx(f"{MX}/sync", headers={"x-forwarded-for": "10.89.2.5"}),
    ),
    "matrix-not-matrix-path": (reply(200, "x"), _mx("/matrix/notmatrix/thing")),
    "matrix-traversal": (reply(200, "x"), _mx("/matrix/_matrix/../../etc/passwd")),
    "matrix-upstream-500": (reply(500, '{"errcode":"M_UNKNOWN"}'), _mx(f"{MX}/sync")),
    "matrix-upstream-401": (reply(401, '{"errcode":"M_UNKNOWN_TOKEN"}'), _mx(f"{MX}/sync")),
    "matrix-upstream-connect-fail": (reply(raises=httpx.ConnectError("golden")), _mx(f"{MX}/sync")),
}

CASES.update({n: single("matrix.example.org", h, c) for n, (h, c) in _MX_CASES.items()})


# =========================================================================== CONNECT

HOST = "api.example.com"


def _connect(target: str) -> bytes:
    return f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()


def tunnel_case(
    head: bytes,
    then: bytes = b"",
    *,
    peer: str = g.TUNNEL_PEER,
    refuse: bool = False,
    private: bool = False,
) -> Case:
    """A case of one tunnel: ``head``, then ``then`` once the tunnel is up."""

    async def run(mp: pytest.MonkeyPatch) -> dict[str, Any]:
        async def sc(port: int, _origin: g.FakeOrigin) -> Any:
            if private:
                from trentina.gateway import upstream
                from trentina.reach import egress

                mp.setattr(egress, "_lookup", lambda _h, _p: [g.PRIVATE_ADDRESS])
                upstream.forget_checked()
            return [await g.tunnel(port, head, then, peer=peer)]

        return await g.record_tunnel(mp, sc, refuse=refuse)

    return run


HELLO = g.client_hello(HOST)
CASES["connect-tunnel"] = tunnel_case(_connect(f"{HOST}:443"), HELLO + b"app-data")
CASES["connect-host-not-listed"] = tunnel_case(
    _connect("other.example.org:443"), g.client_hello("other.example.org")
)
CASES["connect-port"] = tunnel_case(_connect(f"{HOST}:8443"), HELLO)
CASES["connect-sni-mismatch"] = tunnel_case(
    _connect(f"{HOST}:443"), g.client_hello("other.example.org")
)
CASES["connect-no-sni"] = tunnel_case(_connect(f"{HOST}:443"), g.client_hello(None))
CASES["connect-not-tls"] = tunnel_case(
    _connect(f"{HOST}:443"), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
)
CASES["connect-bad-head"] = tunnel_case(b"GET http://api.example.com/ HTTP/1.1\r\n\r\n")
CASES["connect-unknown-caller"] = tunnel_case(_connect(f"{HOST}:443"), HELLO, peer=g.STRANGER_PEER)
CASES["connect-origin-refused"] = tunnel_case(_connect(f"{HOST}:443"), HELLO, refuse=True)
CASES["connect-denied-address"] = tunnel_case(_connect(f"{HOST}:443"), HELLO, private=True)


# =========================================================================== the check


@pytest.mark.parametrize("name", sorted(CASES))
def test_golden(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    record = asyncio.run(CASES[name](monkeypatch))
    path = g.fixture_path(name)
    if g.RECORDING:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(g.dump(record), encoding="utf-8")
        return
    assert path.exists(), f"no fixture for {name}; record on the pre-spine commit"
    expected = json.loads(path.read_text(encoding="utf-8"))
    actual = json.loads(g.dump(record))
    if name in DELTAS:
        expected = DELTAS[name](expected)
    assert actual == expected


def test_every_fixture_has_a_case() -> None:
    """A fixture whose case was deleted is a contract nobody checks any more."""
    recorded = {p.stem for p in g.FIXTURES.glob("*.json")}
    assert recorded <= set(CASES), sorted(recorded - set(CASES))
