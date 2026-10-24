"""The reading half of the egress route (#511): pure, no I/O."""

from __future__ import annotations

import time
from http import HTTPStatus
from typing import Any

import pytest

from trentina.gateway.egress_policy import (
    BASE_REQUEST_HEADERS,
    REASONS,
    EgressRefusedError,
    build_url,
    canonical_query,
    forward_request_headers,
    request_document,
    response_headers,
)
from trentina.gateway.profile import EgressUpstream


def _upstream(**kw: Any) -> EgressUpstream:
    return EgressUpstream(upstream="https://api.example.com", **kw)


class TestUpstreamOrigin:
    """The upstream validator is a security boundary: the host is the operator's."""

    @pytest.mark.parametrize(
        "bad",
        [
            "http://api.example.com",  # not https
            "https://user:pw@api.example.com",  # userinfo
            "https://api.example.com:8443",  # explicit port
            "https://api.example.com/v3",  # path
            "https://api.example.com/?q=1",  # query
            "https://api.example.com/#frag",  # fragment
            "https://API.Example.COM",  # not a lower-case dns name
            "https://127.0.0.1",  # an IP literal, not a dns name
        ],
    )
    def test_a_non_origin_upstream_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="https://"):
            EgressUpstream(upstream=bad)

    def test_a_valid_origin_is_normalized(self) -> None:
        up = EgressUpstream(upstream="https://api.example.com/")
        assert up.upstream == "https://api.example.com"
        assert up.host == "api.example.com"


class TestReasons:
    def test_refusal_reason_must_be_in_the_closed_set(self) -> None:
        with pytest.raises(ValueError, match="closed set"):
            EgressRefusedError(HTTPStatus.FORBIDDEN, "not_a_reason")

    def test_a_known_reason_is_accepted(self) -> None:
        err = EgressRefusedError(HTTPStatus.FORBIDDEN, "flagged")
        assert err.reason in REASONS
        assert err.executed is False


class TestQueryAndUrl:
    def test_canonical_query_keeps_duplicate_keys(self) -> None:
        assert canonical_query("a=1&a=2&b=3") == "a=1&a=2&b=3"

    def test_canonical_query_normalizes_encoding(self) -> None:
        assert canonical_query("q=a%20b") == "q=a+b"

    def test_empty_query_is_empty(self) -> None:
        assert canonical_query("") == ""

    def test_url_is_built_from_origin_and_path(self) -> None:
        assert build_url(_upstream(), "repos/x", "k=1") == "https://api.example.com/repos/x?k=1"

    def test_url_has_no_query_when_none(self) -> None:
        assert build_url(_upstream(), "repos/x", "") == "https://api.example.com/repos/x"


class TestHeaders:
    def test_credential_and_forwarding_headers_never_go_upstream(self) -> None:
        arrived = [
            ("Authorization", "Bearer caller-token"),
            ("Cookie", "session=abc"),
            ("X-Forwarded-For", "10.0.0.1"),
            ("Accept", "application/json"),
        ]
        out = forward_request_headers(arrived, _upstream())
        assert "authorization" not in out
        assert "cookie" not in out
        assert not any(k.startswith("x-forwarded") for k in out)
        assert out["accept"] == "application/json"
        assert out["user-agent"] == "trentina-egress"

    def test_only_base_and_declared_headers_pass(self) -> None:
        up = _upstream(headers_allow=["X-GitHub-Api-Version"])
        arrived = [("X-GitHub-Api-Version", "2026-01"), ("X-Secret-Thing", "no")]
        out = forward_request_headers(arrived, up)
        assert out["x-github-api-version"] == "2026-01"
        assert "x-secret-thing" not in out

    def test_base_request_headers_are_lowercase_safe(self) -> None:
        assert "accept" in BASE_REQUEST_HEADERS

    def test_set_cookie_is_dropped_from_the_response(self) -> None:
        out = response_headers([("Set-Cookie", "x=1"), ("Content-Type", "application/json")])
        lowered = {k.lower(): v for k, v in out.items()}
        assert "set-cookie" not in lowered
        assert lowered["content-type"] == "application/json"


class TestRequestDocument:
    def test_document_carries_line_query_headers_and_body(self) -> None:
        doc = request_document(
            "POST", "/v1/x", "a=1", {"content-type": "application/json"}, '{"k": "v"}'
        )
        assert doc.splitlines()[0] == "POST /v1/x"
        assert "?a=1" in doc  # the query line is prefixed so the first param is seen
        assert "content-type: application/json" in doc
        assert '"k": "v"' in doc

    def test_the_first_query_parameter_is_seen_by_the_credential_patterns(self) -> None:
        from trentina.credential_shapes import kinds

        doc = request_document("GET", "/x", "token=" + "A" * 40, {}, None)
        assert kinds(doc)  # a secret in the FIRST param is not missed

    def test_document_rendering_is_linear(self) -> None:
        big = '{"t": "' + "a" * 2_000_000 + '"}'
        start = time.perf_counter()
        request_document("POST", "/x", "k=" + "v" * 500_000, {}, big)
        assert time.perf_counter() - start < 2.0
