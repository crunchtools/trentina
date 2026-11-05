"""``forward``: an agent-chosen URL, held to its hosts and judged both ways (#535 R15).

Driven through the real spine as the golden oracle drives the other routes —
real ``defend()``, egress guard and pinned request; fake models and network
(``tests/perimeter_golden.py``) — over a gateway declared purely in config.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
import yaml

from tests import perimeter_golden as g
from tests.perimeter_golden import Call, bearer, drive, reply

HOST = "aeb-fixture.test"
FETCH = "/proxy/forward/bench/fetch"

_CONFIG = {
    "proxies": {"bench": {"type": "forward", "hosts": [HOST, "other.example"]}},
    "profiles": {
        "agent1": {
            "auth": {"bearer_token_env": "GOLDEN_AGENT1_TOKEN"},
            "proxies": {"bench": {"hosts": [HOST], "methods": ["GET", "POST"]}},
        }
    },
}


async def _run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, call: Call, handler: g.Handler, **net: Any
) -> tuple[int, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """The status, the JSON body (or text), what reached the upstream, the rows."""
    path = tmp_path / "profiles.yaml"
    path.write_text(yaml.safe_dump(_CONFIG), encoding="utf-8")
    monkeypatch.setattr(g, "SPELLING", {"config": path})
    async with g.stack(monkeypatch) as s:
        s.net.handlers[HOST] = handler
        if "addresses" in net:
            s.net.addresses = net["addresses"]
        exchange = await drive(s.app, call)
        await asyncio.sleep(0.05)
        status = next(m["status"] for m in exchange["messages"] if m["type"] == "start")
        text = "".join(m["body"] for m in exchange["messages"] if m["type"] == "body")
        try:
            body = json.loads(text)
        except ValueError:
            body = {"text": text}
        return status, body, s.net.seen, g.rows("gateway_calls")


def _fetch(url: str, method: str = "GET", body: bytes | None = None) -> Call:
    return Call(
        method,
        FETCH,
        headers={**bearer("agent1"), "content-type": "application/json"},
        query=urlencode({"url": url}),
        body=[body] if body else [],
    )


def _go(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, call: Call, handler: g.Handler, **net: Any
) -> Any:
    return asyncio.run(_run(monkeypatch, tmp_path, call, handler, **net))


class TestWhereItGoes:
    def test_a_listed_host_is_fetched_with_no_token(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        status, body, seen, rows = _go(
            monkeypatch, tmp_path, _fetch(f"https://{HOST}/api?k=v"), reply(200, '{"ok":1}')
        )
        assert (status, body) == (200, {"ok": 1})
        [sent] = seen
        assert sent["url"] == f"https://{HOST}/api?k=v"
        assert "authorization" not in {name for name, _ in sent["headers"]}
        assert [(r["backend"], r["outcome"]) for r in rows] == [("forward:bench", "ok")]

    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("https://other.example/x", "host_not_listed"),  # the instance's, not the grant's
            ("https://elsewhere.example/x", "host_not_listed"),
            ("https://10.0.0.7/x", "host_not_listed"),  # an address is never a host
            (f"https://{HOST}:8443/x", "port"),
            ("ftp://aeb-fixture.test/x", "bad_url"),
            ("http://[::1/x", "bad_url"),  # malformed: a refusal, never a 500
            (f"http://{HOST}:0/x", "port"),  # :0 is asked for, not the default
            ("not a url", "bad_url"),
        ],
    )
    def test_anywhere_else_is_refused_before_a_lookup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str, reason: str
    ) -> None:
        _, body, seen, _ = _go(monkeypatch, tmp_path, _fetch(url), reply(200, "{}"))
        assert body["error"]["reason"] == reason
        assert body["blocked"] is True
        assert seen == []

    def test_a_method_the_grant_does_not_list_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _, body, seen, _ = _go(
            monkeypatch, tmp_path, _fetch(f"https://{HOST}/x", "DELETE"), reply(200, "{}")
        )
        assert body["error"]["reason"] == "method_not_listed"
        assert seen == []


class TestThePrivateAddressRule:
    def test_a_name_resolving_to_a_private_address_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _, body, seen, rows = _go(
            monkeypatch,
            tmp_path,
            _fetch(f"https://{HOST}/x"),
            reply(200, "{}"),
            addresses=[g.PRIVATE_ADDRESS],
        )
        assert (body["error"]["reason"], body["blocked"]) == ("denied_guard", True)
        assert seen == []
        assert rows[0]["error_message"] == "non_global_address"

    def test_a_name_on_the_private_names_list_may_resolve_there(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from trentina import config as config_mod

        monkeypatch.setenv("TRENTINA_FETCH_PRIVATE_NAMES", HOST)
        monkeypatch.setattr(config_mod, "_config", None)
        status, _, seen, _ = _go(
            monkeypatch,
            tmp_path,
            _fetch(f"https://{HOST}/x"),
            reply(200, "{}"),
            addresses=[g.PRIVATE_ADDRESS],
        )
        assert status == 200
        assert len(seen) == 1

    def test_a_private_name_is_exempt_from_the_port_rule_too(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A benchmark's fixtures listen on ports the runner picks (cto, #535);
        the name's env opt-in covers the port, and only that name's."""
        from trentina import config as config_mod

        monkeypatch.setenv("TRENTINA_FETCH_PRIVATE_NAMES", HOST)
        monkeypatch.setattr(config_mod, "_config", None)
        status, _, seen, _ = _go(
            monkeypatch, tmp_path, _fetch(f"http://{HOST}:8443/x"), reply(200, "{}")
        )
        assert (status, len(seen)) == (200, 1)
        _, body, seen, _ = _go(
            monkeypatch, tmp_path, _fetch("http://other.example:8443/x"), reply(200, "{}")
        )
        assert (body["error"]["reason"], seen) == ("port", [])

    def test_a_listed_name_that_does_not_resolve_is_not_containment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Unreachable is not refused: a deny marker here would score a dead
        name as a block (SPEC R15)."""
        status, body, seen, rows = _go(
            monkeypatch, tmp_path, _fetch(f"https://{HOST}/x"), reply(200, "{}"), addresses=[]
        )
        assert (status, body["error"]["reason"]) == (502, "upstream_unreachable")
        assert "blocked" not in body
        assert seen == []
        assert rows[0]["outcome"] == "backend_error"


class TestWhatItCarries:
    def test_a_flagged_request_never_leaves(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        payload = json.dumps({"q": g.INJECT}).encode()
        _, body, seen, _ = _go(
            monkeypatch, tmp_path, _fetch(f"https://{HOST}/x", "POST", payload), reply(200, "{}")
        )
        assert (body["error"]["reason"], body["blocked"]) == ("flagged", True)
        assert seen == []

    def test_a_credential_in_the_url_never_leaves(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
        _, body, seen, _ = _go(
            monkeypatch, tmp_path, _fetch(f"https://{HOST}/x?key={key}"), reply(200, "{}")
        )
        assert body["error"]["reason"] == "credential_in_request"
        assert seen == []

    def test_a_flagged_response_is_withheld_and_marked(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _, body, seen, _ = _go(
            monkeypatch,
            tmp_path,
            _fetch(f"https://{HOST}/x"),
            reply(200, json.dumps({"text": g.INJECT})),
        )
        assert (body["error"]["reason"], body["blocked"], body["executed"]) == (
            "response_flagged",
            True,
            True,
        )
        assert len(seen) == 1


class TestAFailureIsNotContainment:
    """The deny marker is the benchmark's containment signal: an upstream that
    could not be reached was not contained, and must not read as if it were."""

    @pytest.mark.parametrize(
        ("handler", "reason"),
        [
            (reply(raises=__import__("httpx").ConnectError("golden")), "upstream_failed"),
            (reply(302, "", headers={"location": "https://evil.example/"}), "redirect"),
        ],
    )
    def test_no_deny_marker_on_a_backend_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, handler: g.Handler, reason: str
    ) -> None:
        _, body, _, _ = _go(monkeypatch, tmp_path, _fetch(f"https://{HOST}/x"), handler)
        assert body["error"]["reason"] == reason
        assert "blocked" not in body


def test_an_endpoint_it_does_not_serve_carries_no_deny_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A bench's WebSocket case reaches /ws here; not served is not contained."""
    call = Call("GET", "/proxy/forward/bench/ws", headers=bearer("agent1"), query="url=x")
    status, body, seen, _ = _go(monkeypatch, tmp_path, call, reply(200, "{}"))
    assert (status, body["error"]["reason"], seen) == (404, "not_found", [])
    assert "blocked" not in body
