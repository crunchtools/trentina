"""The terminating egress route (#511): resolve, judge, re-originate, judge back.

The network and the judge are the seams. ``checked_target``/``open_pinned`` are
replaced by a fake that records what would be sent and returns a scripted
response; ``defend``/``gaps_of`` are stubbed so the route's decisions are
tested without a live L2/L3.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal

import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from trentina import config as config_mod
from trentina import database as database_mod
from trentina.gateway import egress_http
from trentina.gateway.profile import AuthConfig, EgressGrant, EgressUpstream, Profile

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

_AWS_KEY = "AK" + "IA" + "IOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "trentina.db"
    monkeypatch.setenv("QUARANTINE_DB", str(path))
    config_mod._config = None
    database_mod._db = None
    yield path
    database_mod._db = None
    config_mod._config = None


def _rows(path: Path) -> list[sqlite3.Row]:
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT profile, backend, tool, outcome, error_message, destination, "
            "destination_kind, bytes_arrived, bytes_delivered FROM gateway_calls ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


class _FakeResp:
    def __init__(self, status: int = 200, ct: str = "application/json", body: bytes = b'{"ok":1}'):
        self.status_code = status
        self.headers = httpx.Headers({"content-type": ct})
        self._body = body

    async def aiter_raw(self) -> AsyncIterator[bytes]:
        yield self._body


class _Net:
    """The fake network seam: records sent requests, returns a scripted response."""

    def __init__(self) -> None:
        self.sent: list[SimpleNamespace] = []
        self.resp: Any = _FakeResp()
        self.raises: Exception | None = None

    @asynccontextmanager
    async def open_pinned(
        self,
        method: str,
        url: str,
        target: Any,
        *,
        idle: float,
        headers: dict[str, str],
        content: Any,
    ) -> AsyncIterator[Any]:
        self.sent.append(SimpleNamespace(method=method, url=url, headers=headers, content=content))
        if self.raises is not None:
            raise self.raises
        yield self.resp


def _clean_verdict() -> SimpleNamespace:
    return SimpleNamespace(
        flagged=False, flagged_by=None, risk_level="low", content="x", pipeline=None
    )


def _stub_judge(monkeypatch: pytest.MonkeyPatch, *, req: Any = None, resp: Any = None) -> None:
    """Stub the request judge (outbound's lazy defend/gaps_of) and the response
    judge (egress_http's defend/gaps_of). Default: everything clean."""
    from trentina import defense as defense_mod
    from trentina import modes as modes_mod
    from trentina.modes import Gaps

    async def req_defend(*_a: Any, **_k: Any) -> Any:
        return req if req is not None else _clean_verdict()

    async def resp_defend(*_a: Any, **_k: Any) -> Any:
        return resp if resp is not None else _clean_verdict()

    monkeypatch.setattr(defense_mod, "defend", req_defend)
    monkeypatch.setattr(modes_mod, "gaps_of", lambda _v: Gaps())
    monkeypatch.setattr(egress_http, "defend", resp_defend)
    monkeypatch.setattr(egress_http, "gaps_of", lambda _v: Gaps())


def _profile(
    enforcement: Literal["block", "flag"] = "block",
    *,
    with_cred: bool = True,
    guarded: bool = False,
) -> Profile:
    grant = EgressGrant(
        token_env="AGENT_GH" if with_cred else None,
        methods=["GET", "POST"],
        paths=["/repos/*"],
        enforcement=enforcement,
    )
    if with_cred:
        from pydantic import SecretStr

        grant.token = SecretStr("forge-token")
    from trentina.gateway.profile import GuardedExecutionConfig

    guard = (
        GuardedExecutionConfig(policy="No bulk customer data leaves.", egress_http=["gh"])
        if guarded
        else None
    )
    p = Profile(
        name="agent1",
        auth=AuthConfig(bearer_token_env="TOK"),
        egress_http={"gh": grant},
        guarded_execution=guard,
    )
    from pydantic import SecretStr

    p.auth.bearer_token = SecretStr("agent1-tok")
    return p


def _upstream(**kw: Any) -> EgressUpstream:
    base: dict[str, Any] = {
        "upstream": "https://api.github.com",
        "credential": {"header": "Authorization", "prefix": "Bearer "},
    }
    base.update(kw)
    return EgressUpstream(**base)


class _Harness(SimpleNamespace):
    client: TestClient
    net: _Net
    profiles: dict[str, Profile]


def _harness(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enforcement: Literal["block", "flag"] = "block",
    with_cred: bool = True,
    upstream: EgressUpstream | None = None,
    guarded: bool = False,
) -> _Harness:
    net = _Net()
    monkeypatch.setattr(egress_http, "open_pinned", net.open_pinned)

    async def _target(_profile: Any, _host: str) -> Any:
        return object()

    monkeypatch.setattr(egress_http, "checked_target", _target)
    up = upstream if upstream is not None else _upstream()
    active = SimpleNamespace(config=SimpleNamespace(egress_upstreams={"gh": up}))
    monkeypatch.setattr(egress_http, "get_active_config", lambda: active)
    profiles = {"agent1": _profile(enforcement, with_cred=with_cred, guarded=guarded)}

    async def endpoint(request: Request) -> Response:
        return await egress_http.serve(request, profiles)

    app = Starlette(
        routes=[Route("/egress/{upstream}/{path:path}", endpoint, methods=egress_http.METHODS)]
    )
    return _Harness(client=TestClient(app), net=net, profiles=profiles)


_AUTH = {"authorization": "Bearer agent1-tok"}


class TestWhoIsCalling:
    def test_unknown_token_is_401_and_sends_nothing(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x", headers={"authorization": "Bearer nope"})
        assert resp.status_code == 401
        assert h.net.sent == []
        assert _rows(audit_db) == []

    def test_unknown_upstream_and_missing_grant_are_one_refusal(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/nope/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "unknown_upstream"
        assert h.net.sent == []


class TestRails:
    def test_method_not_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.request("DELETE", "/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "method_not_listed"
        assert h.net.sent == []

    def test_path_not_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/users/x", headers=_AUTH)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "path_not_listed"
        assert h.net.sent == []

    def test_compressed_body_is_refused_unread(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.post(
            "/egress/gh/repos/x", headers={**_AUTH, "content-encoding": "gzip"}, content=b"\x1f\x8b"
        )
        assert resp.status_code == 415
        assert resp.json()["block_reason"] == "malformed_body"
        assert h.net.sent == []


class TestRequestJudging:
    def test_clean_request_forwards_injecting_the_credential(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x", headers={**_AUTH, "x-secret": "no"})
        assert resp.status_code == 200
        assert resp.content == b'{"ok":1}'
        [sent] = h.net.sent
        assert sent.url == "https://api.github.com/repos/x"
        # The caller's own auth never leaves; the profile's token is injected.
        assert sent.headers["authorization"] == "Bearer forge-token"
        assert "x-secret" not in sent.headers
        [row] = _rows(audit_db)
        assert (row["backend"], row["outcome"], row["destination_kind"]) == (
            "egress:gh",
            "ok",
            "egress",
        )

    def test_credential_in_body_blocks_before_sending(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        _stub_judge(monkeypatch)  # injection clean; the AWS key is the signal
        h = _harness(monkeypatch)
        resp = h.client.post(
            "/egress/gh/repos/x",
            headers=_AUTH,
            content=json.dumps({"k": f"ship {_AWS_KEY}"}).encode(),
        )
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "credential_in_request"
        assert h.net.sent == []
        [row] = _rows(audit_db)
        assert row["outcome"] == "blocked_defense"
        assert row["error_message"] == "credential_in_request"

    def test_flagged_request_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.defense import Layer

        flagged = SimpleNamespace(flagged=True, flagged_by=Layer.L2, risk_level="high")
        _stub_judge(monkeypatch, req=flagged)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "flagged"
        assert h.net.sent == []

    def test_flag_mode_forwards_a_flagged_request_with_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.defense import Layer

        flagged = SimpleNamespace(flagged=True, flagged_by=Layer.L2, risk_level="high")
        _stub_judge(monkeypatch, req=flagged)
        h = _harness(monkeypatch, enforcement="flag")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 200
        assert resp.headers["x-trentina-warning"] == "high"
        assert len(h.net.sent) == 1


class TestResponseJudging:
    def test_flagged_response_blocks_and_says_executed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.defense import Layer

        flagged = SimpleNamespace(flagged=True, flagged_by=Layer.L2, risk_level="high")
        _stub_judge(monkeypatch, resp=flagged)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        marker = resp.json()
        assert marker["block_reason"] == "response_flagged"
        assert marker["executed"] is True  # the request did reach the destination
        assert len(h.net.sent) == 1

    def test_flag_mode_delivers_a_flagged_response_with_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.defense import Layer

        flagged = SimpleNamespace(flagged=True, flagged_by=Layer.L2, risk_level="high")
        _stub_judge(monkeypatch, resp=flagged)
        h = _harness(monkeypatch, enforcement="flag")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 200
        assert resp.headers["x-trentina-warning"] == "high"

    def test_binary_response_is_withheld_under_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        h.net.resp = _FakeResp(ct="application/octet-stream", body=b"\x00\x01\x02")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "response_binary"

    def test_unjudged_response_is_withheld_under_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Response fail-closed: a blocking gap withholds the response, executed."""
        from trentina.modes import Gaps

        _stub_judge(monkeypatch)  # request clean
        # Make only the RESPONSE judge report a blocking gap.
        monkeypatch.setattr(egress_http, "gaps_of", lambda _v: Gaps(oversize=True))
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 403
        marker = resp.json()
        assert marker["block_reason"] == "response_unjudged"
        assert marker["executed"] is True

    def test_binary_response_is_delivered_with_a_warning_under_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Gap 32 (#511): a binary response is unread; flag delivers it annotated."""
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch, enforcement="flag")
        h.net.resp = _FakeResp(ct="application/octet-stream", body=b"\x00\x01\x02")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 200
        assert resp.content == b"\x00\x01\x02"
        assert resp.headers["x-trentina-warning"] == "binary_unread"


class TestUpstreamErrors:
    def test_a_redirect_is_refused_as_executed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina.errors import EgressRefusedError as GuardRefusedError

        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        h.net.raises = GuardRefusedError("redirect")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 502
        marker = resp.json()
        assert marker["block_reason"] == "redirect"
        assert marker["executed"] is True  # the upstream answered the 3xx

    def test_a_connect_failure_is_not_executed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        h.net.raises = httpx.ConnectError("refused")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 502
        assert resp.json()["block_reason"] == "upstream_failed"
        assert "executed" not in resp.json()  # nothing left the gateway


class TestBodyFidelity:
    def test_verbatim_duplicate_key_is_judged_as_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocker: what is judged is what is sent. A secret hidden in a duplicate
        key of a verbatim body is seen because the raw bytes are judged."""
        _stub_judge(monkeypatch)  # injection clean; the key is the signal
        h = _harness(monkeypatch)  # default upstream is verbatim
        body = b'{"k":"' + _AWS_KEY.encode() + b'","k":"ok"}'
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=body)
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "credential_in_request"
        assert h.net.sent == []

    def test_non_utf8_verbatim_body_is_binary_under_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A UTF-16/binary verbatim body is judged by no layer as what the
        destination parses, so block refuses it (nothing sent)."""
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=b"\xff\xfe\x00k\x00v")
        assert resp.status_code == 403
        assert resp.json()["block_reason"] == "binary_body"
        assert h.net.sent == []

    def test_non_utf8_verbatim_body_forwards_with_warning_under_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch, enforcement="flag")
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=b"\xff\xfe\x00k")
        assert resp.status_code == 200
        assert resp.headers["x-trentina-warning"] == "binary_unread"
        assert len(h.net.sent) == 1

    def test_json_upstream_refuses_a_duplicate_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch, upstream=_upstream(body="json"))
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=b'{"k":"a","k":"b"}')
        assert resp.status_code == 400
        assert resp.json()["block_reason"] == "not_json"
        assert h.net.sent == []


class TestPathRail:
    def test_an_encoded_question_mark_is_bad_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Blocker: a decoded '?' must not let the matched path and sent path diverge."""
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch)
        resp = h.client.get("/egress/gh/repos/x%3Ffoo", headers=_AUTH)
        assert resp.status_code == 400
        assert resp.json()["block_reason"] == "bad_path"
        assert h.net.sent == []


class TestResponseTokenScrub:
    def test_an_echoed_injected_token_is_cut_from_the_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#7: the agent never holds the token, even if the upstream echoes it."""
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch, enforcement="flag")
        h.net.resp = _FakeResp(body=b'{"you_sent":"Bearer forge-token"}')
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 200
        assert b"forge-token" not in resp.content
        assert b"[REDACTED]" in resp.content


class TestFlagAudit:
    def test_a_flag_mode_finding_is_recorded(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        """#5: the researcher grant is not a blind spot — the finding is audited."""
        from trentina.defense import Layer

        flagged = SimpleNamespace(flagged=True, flagged_by=Layer.L2, risk_level="high")
        _stub_judge(monkeypatch, req=flagged)
        h = _harness(monkeypatch, enforcement="flag")
        resp = h.client.get("/egress/gh/repos/x", headers=_AUTH)
        assert resp.status_code == 200
        [row] = _rows(audit_db)
        assert (row["outcome"], row["error_message"]) == ("ok", "flagged")


class TestReloadHold:
    def test_an_agent_reload_cannot_add_or_widen_egress_http(self) -> None:
        """#511: which destinations an agent may reach is operator-only, held
        like git on an agent reload (the shared perimeter-hold loop)."""
        from trentina.tools.reload import _hold_perimeter_fields

        before = Profile(name="a", auth=AuthConfig(bearer_token_env="T"))
        grant = EgressGrant(methods=["GET"], paths=["/x"], token_env=None)
        after = Profile(name="a", auth=AuthConfig(bearer_token_env="T"), egress_http={"gh": grant})
        held = _hold_perimeter_fields(before, after)
        assert "egress_http" in held
        assert after.egress_http == {}  # the self-granted block was dropped


class TestLoaderCrossChecks:
    def test_credential_without_token_is_refused_at_load(self) -> None:
        """#15: an upstream expecting a credential with a grant that names no
        token would send unauthenticated — refused at load, not at runtime."""
        from trentina.gateway.errors import ProfileConfigError
        from trentina.gateway.loader import _load_egress_upstreams

        section = {
            "gh": {
                "upstream": "https://api.github.com",
                "credential": {"header": "Authorization", "prefix": "Bearer "},
            }
        }
        grant = EgressGrant(methods=["GET"], paths=["/x"], token_env=None)
        registry = {
            "a": Profile(name="a", auth=AuthConfig(bearer_token_env="T"), egress_http={"gh": grant})
        }
        with pytest.raises(ProfileConfigError, match="both be set or both absent"):
            _load_egress_upstreams(section, registry)


class TestJsonUpstream:
    def test_a_non_json_body_is_refused_for_a_json_upstream(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_judge(monkeypatch)
        h = _harness(monkeypatch, upstream=_upstream(body="json"))
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=b"not json")
        assert resp.status_code == 400
        assert resp.json()["block_reason"] == "not_json"
        assert h.net.sent == []


class TestGatekeeper:
    """#511: the guarded-execution hook, wired into the request path."""

    @staticmethod
    def _patch_judge(monkeypatch: pytest.MonkeyPatch, result: Any) -> list[dict[str, Any]]:
        """Patch ``judge_egress`` to record its kwargs and return ``result()``."""
        calls: list[dict[str, Any]] = []

        async def _stub(*_a: Any, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return result()

        monkeypatch.setattr(egress_http, "judge_egress", _stub)
        return calls

    def test_a_refusal_blocks_before_sending(
        self, monkeypatch: pytest.MonkeyPatch, audit_db: Path
    ) -> None:
        from trentina.gateway.gatekeeper import CallFacts, GateRefusal

        _stub_judge(monkeypatch)
        refusal = GateRefusal(
            "bulk_private_data",
            CallFacts("egress:gh", "POST", "d", "egress", True, None),
        )
        self._patch_judge(monkeypatch, lambda: refusal)
        h = _harness(monkeypatch, guarded=True)
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, json={"a": 1})
        assert resp.status_code == 403
        body = resp.json()
        assert body["block_reason"] == "gatekeeper"  # the caller sees only the bucket
        assert "executed" not in body  # nothing was sent
        assert h.net.sent == []
        [row] = _rows(audit_db)
        assert row["outcome"] == "denied_gatekeeper"
        # the audit keeps the judge's own reason and facts, not just "gatekeeper"
        assert "bulk_private_data" in row["error_message"]

    def test_a_guarded_get_to_a_new_path_is_intent_judged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_judge(monkeypatch)
        calls = self._patch_judge(monkeypatch, lambda: None)
        h = _harness(monkeypatch, guarded=True)
        resp = h.client.get("/egress/gh/repos/x?page=2", headers=_AUTH)
        assert resp.status_code == 200
        assert len(h.net.sent) == 1  # allowed, forwarded
        assert len(calls) == 1  # a bodyless GET still has its intent judged

    def test_the_judge_reads_a_revealed_redacted_copy_not_the_raw_body(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_judge(monkeypatch)
        calls = self._patch_judge(monkeypatch, lambda: None)
        h = _harness(monkeypatch, guarded=True)
        # %41%42 is percent-encoded "AB": forwarded verbatim, but the judge must
        # see it decoded (judge_input reveals before the external judge reads it).
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, content=b"%41%42")
        assert resp.status_code == 200
        assert "AB" in calls[0]["document"]  # revealed for the judge
        [sent] = h.net.sent
        assert sent.content == b"%41%42"  # forwarded byte-for-byte

    def test_an_allow_forwards_the_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        calls = self._patch_judge(monkeypatch, lambda: None)
        h = _harness(monkeypatch, guarded=True)
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, json={"a": 1})
        assert resp.status_code == 200
        assert len(h.net.sent) == 1
        assert len(calls) == 1  # the hook ran and let it through

    def test_flag_mode_never_asks_the_gatekeeper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_judge(monkeypatch)
        calls = self._patch_judge(monkeypatch, lambda: None)
        h = _harness(monkeypatch, enforcement="flag", guarded=True)
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, json={"a": 1})
        assert resp.status_code == 200
        assert calls == []  # flag is the researcher grant; no intent judgment
        assert len(h.net.sent) == 1

    def test_an_unguarded_upstream_never_asks_the_gatekeeper(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_judge(monkeypatch)
        calls = self._patch_judge(monkeypatch, lambda: None)
        h = _harness(monkeypatch, guarded=False)
        resp = h.client.post("/egress/gh/repos/x", headers=_AUTH, json={"a": 1})
        assert resp.status_code == 200
        assert calls == []
        assert len(h.net.sent) == 1
